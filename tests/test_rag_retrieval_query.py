from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.admission import AdmissionReviewStore
from ams.models import canonical_json, sha256_text
from ams.provider_auth import ProviderAuthPreflightStore
from ams.rag_embedding_job import RAGEmbeddingJobStore
from ams.rag_embedding_receipt import RAGEmbeddingReceiptStore
from ams.rag_index_plan import RAGIndexPlanStore
from ams.rag_retrieval_query import RAGRetrievalQueryStore
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.store import JsonStore


class RAGRetrievalQueryTest(unittest.TestCase):
    def test_retrieval_query_records_hash_only_source_refs_and_taint_labels(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            receipt = _simulated_receipt(root, store)
            query_hash = _query_hash("where is the current status?")

            query = RAGRetrievalQueryStore(store).create(
                rag_embedding_receipt_id=receipt["rag_embedding_receipt_id"],
                query_sha256=query_hash,
                query_length=28,
                query_ref="discord://chan/msg",
                retrieval_mode="simulated_refs",
                top_k=3,
                taint_labels=["project", "hash_refs", "operator_review"],
            )

            self.assertEqual(query["status"], "ready_for_operator_review")
            self.assertEqual(query["reason_codes"], ["rag_retrieval_query.simulated_refs_ready"])
            self.assertEqual(query["source_ref_count"], 3)
            self.assertFalse(query["query_text_stored"])
            self.assertFalse(query["raw_corpus_stored"])
            self.assertIn("hash_refs", query["taint_labels"])
            for source_ref in query["source_refs"]:
                self.assertFalse(source_ref["content_stored"])
                self.assertTrue(str(source_ref["score_ref_sha256"]).startswith("sha256:"))
                for forbidden in ("text", "content", "raw", "raw_content", "query", "corpus", "embedding", "vector"):
                    self.assertNotIn(forbidden, source_ref)
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_retrieval_query_blocks_when_receipt_not_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            job = _ready_job(root, store)
            blocked_auth = ProviderAuthPreflightStore(store).create(
                subject_kind="rag_embedding_job",
                subject_id=job["rag_embedding_job_id"],
                provider="openai",
                operation="rag.embedding.provider_call",
                present_env_names=[],
            )
            receipt = RAGEmbeddingReceiptStore(store).create(
                rag_embedding_job_id=job["rag_embedding_job_id"],
                provider_auth_preflight_id=blocked_auth["provider_auth_preflight_id"],
                receipt_mode="external_observed",
                external_vector_store_ref="openai_file_search://vs_blocked",
            )

            query = RAGRetrievalQueryStore(store).create(
                rag_embedding_receipt_id=receipt["rag_embedding_receipt_id"],
                query_sha256=_query_hash("blocked"),
                query_length=7,
                retrieval_mode="external_observed",
            )

            self.assertEqual(query["status"], "blocked")
            self.assertEqual(query["source_refs"], [])
            self.assertIn("rag_retrieval_query.receipt_not_recorded", query["reason_codes"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_retrieval_query_requires_hash_refs_taint_label(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            receipt = _simulated_receipt(root, store)

            with self.assertRaises(ValueError):
                RAGRetrievalQueryStore(store).create(
                    rag_embedding_receipt_id=receipt["rag_embedding_receipt_id"],
                    query_sha256=_query_hash("missing taint"),
                    query_length=13,
                    taint_labels=["project"],
                )

    def test_replay_catches_retrieval_query_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            receipt = _simulated_receipt(root, store)
            query = RAGRetrievalQueryStore(store).create(
                rag_embedding_receipt_id=receipt["rag_embedding_receipt_id"],
                query_sha256=_query_hash("tamper"),
                query_length=6,
                top_k=2,
            )
            state = store.load()
            state["rag_retrieval_queries"][query["rag_retrieval_query_id"]]["query_text_stored"] = True
            state["rag_retrieval_queries"][query["rag_retrieval_query_id"]]["source_refs"][0]["content_stored"] = True
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            errors = "\n".join(replay["errors"])
            self.assertIn("rag_retrieval_query.hash_mismatch", errors)

    def test_replay_oracle_covers_retrieval_queries(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            receipt = _simulated_receipt(root, store)
            RAGRetrievalQueryStore(store).create(
                rag_embedding_receipt_id=receipt["rag_embedding_receipt_id"],
                query_sha256=_query_hash("oracle"),
                query_length=6,
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("rag_retrieval_queries", collections)


def _simulated_receipt(root: Path, store: JsonStore) -> dict:
    job = _ready_job(root, store)
    auth = ProviderAuthPreflightStore(store).create(
        subject_kind="rag_embedding_job",
        subject_id=job["rag_embedding_job_id"],
        provider="local",
        operation="rag.embedding.provider_call",
        auth_mode="none",
    )
    return RAGEmbeddingReceiptStore(store).create(
        rag_embedding_job_id=job["rag_embedding_job_id"],
        provider_auth_preflight_id=auth["provider_auth_preflight_id"],
        receipt_mode="simulated_success",
    )


def _ready_job(root: Path, store: JsonStore) -> dict:
    (root / "README.md").write_text("alpha beta gamma\n" * 12, encoding="utf-8")
    plan = RAGIndexPlanStore(store).create(
        source_root=root,
        allowed_globs=["*.md"],
        chunk_chars=40,
        embedding_provider="local",
        vector_store_provider="local",
    )
    admissions = AdmissionReviewStore(store)
    capability = admissions.create(
        subject_kind="rag_index_plan",
        subject_id=plan["rag_index_plan_id"],
        operation="capability.rag_embedding.provider_call",
        request={"provider": "local"},
        status="allow",
        reason_codes=["test.allow"],
    )
    resource = admissions.create(
        subject_kind="rag_index_plan",
        subject_id=plan["rag_index_plan_id"],
        operation="resource.rag_embedding.vector_store",
        request={"provider": "local"},
        status="allow",
        reason_codes=["test.allow"],
    )
    return RAGEmbeddingJobStore(store).create(
        rag_index_plan_id=plan["rag_index_plan_id"],
        capability_admission_review_id=capability["admission_review_id"],
        resource_admission_review_id=resource["admission_review_id"],
        batch_size=2,
    )


def _query_hash(text: str) -> str:
    return sha256_text(canonical_json(["test-query", text]))


if __name__ == "__main__":
    unittest.main()
