from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.admission import AdmissionReviewStore
from ams.provider_auth import ProviderAuthPreflightStore
from ams.rag_embedding_job import RAGEmbeddingJobStore
from ams.rag_embedding_receipt import RAGEmbeddingReceiptStore
from ams.rag_index_plan import RAGIndexPlanStore
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.store import JsonStore


class ProviderAuthReceiptTest(unittest.TestCase):
    def test_openai_auth_preflight_blocks_missing_env_without_secret_storage(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            preflight = ProviderAuthPreflightStore(store).create(
                subject_kind="rag_embedding_job",
                subject_id="job_missing_env",
                provider="openai",
                operation="rag.embedding.provider_call",
                surface="api",
                model="text-embedding-3-small",
                present_env_names=[],
            )

            self.assertEqual(preflight["status"], "blocked")
            self.assertEqual(preflight["required_env_names"], ["OPENAI_API_KEY"])
            self.assertEqual(preflight["absent_env_names"], ["OPENAI_API_KEY"])
            self.assertFalse(preflight["secret_material_stored"])
            self.assertEqual(preflight["credential_fingerprints"], [])
            self.assertFalse(preflight["network_probe_allowed"])
            self.assertFalse(preflight["provider_call_allowed"])
            self.assertNotIn("sk-", str(preflight))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_local_auth_preflight_ready_without_env_or_probe(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            preflight = ProviderAuthPreflightStore(store).create(
                subject_kind="rag_embedding_job",
                subject_id="job_local",
                provider="local",
                operation="rag.embedding.provider_call",
                auth_mode="none",
            )

            self.assertEqual(preflight["status"], "ready")
            self.assertEqual(preflight["reason_codes"], ["provider_auth.not_required"])
            self.assertEqual(preflight["credential_refs"], [])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_receipt_planned_only_is_hash_only_and_no_provider_call(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            job = _ready_job(root, store)

            receipt = RAGEmbeddingReceiptStore(store).create(
                rag_embedding_job_id=job["rag_embedding_job_id"],
                receipt_mode="planned_only",
            )

            self.assertEqual(receipt["status"], "recorded")
            self.assertFalse(receipt["provider_call_observed"])
            self.assertFalse(receipt["vector_write_observed"])
            self.assertFalse(receipt["raw_content_stored"])
            self.assertFalse(receipt["embeddings_stored"])
            self.assertFalse(receipt["vectors_stored"])
            self.assertEqual(receipt["totals"]["observed_embedding_outputs"], 0)
            self.assertEqual(receipt["totals"]["observed_vector_writes"], 0)
            for payload in [*receipt["batch_receipts"], *receipt["vector_receipts"]]:
                for forbidden in ("text", "content", "raw", "raw_content", "embedding", "embeddings", "vector", "vectors"):
                    self.assertNotIn(forbidden, payload)
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_external_observed_receipt_requires_ready_auth(self) -> None:
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
                external_vector_store_ref="openai_file_search://vs_test",
            )

            self.assertEqual(receipt["status"], "blocked")
            self.assertIn("rag_embedding_receipt.provider_auth_ready_required", receipt["reason_codes"])
            self.assertTrue(receipt["provider_call_observed"])
            self.assertTrue(receipt["vector_write_observed"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_external_observed_receipt_records_hash_refs_with_ready_auth(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            job = _ready_job(root, store)
            ready_auth = ProviderAuthPreflightStore(store).create(
                subject_kind="rag_embedding_job",
                subject_id=job["rag_embedding_job_id"],
                provider="local",
                operation="rag.embedding.provider_call",
                auth_mode="none",
            )

            receipt = RAGEmbeddingReceiptStore(store).create(
                rag_embedding_job_id=job["rag_embedding_job_id"],
                provider_auth_preflight_id=ready_auth["provider_auth_preflight_id"],
                receipt_mode="external_observed",
                external_vector_store_ref="local://vector-store/test",
            )

            self.assertEqual(receipt["status"], "recorded")
            self.assertEqual(receipt["reason_codes"], ["rag_embedding_receipt.external_observed"])
            self.assertEqual(receipt["totals"]["observed_embedding_outputs"], len(job["planned_vectors"]))
            self.assertEqual(receipt["totals"]["observed_vector_writes"], len(job["planned_vectors"]))
            for vector_receipt in receipt["vector_receipts"]:
                self.assertTrue(str(vector_receipt["embedding_output_sha256"]).startswith("sha256:"))
                self.assertIn("vector_ref_id", vector_receipt)
                self.assertNotIn("vector", vector_receipt)
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_provider_auth_and_receipt_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            job = _ready_job(root, store)
            auth = ProviderAuthPreflightStore(store).create(
                subject_kind="rag_embedding_job",
                subject_id=job["rag_embedding_job_id"],
                provider="local",
                operation="rag.embedding.provider_call",
                auth_mode="none",
            )
            receipt = RAGEmbeddingReceiptStore(store).create(
                rag_embedding_job_id=job["rag_embedding_job_id"],
                provider_auth_preflight_id=auth["provider_auth_preflight_id"],
                receipt_mode="simulated_success",
            )
            state = store.load()
            state["provider_auth_preflights"][auth["provider_auth_preflight_id"]]["secret_material_stored"] = True
            state["rag_embedding_receipts"][receipt["rag_embedding_receipt_id"]]["totals"]["simulated_vectors"] = 999
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            errors = "\n".join(replay["errors"])
            self.assertIn("provider_auth.hash_mismatch", errors)
            self.assertIn("rag_embedding_receipt.hash_mismatch", errors)

    def test_replay_oracle_covers_provider_auth_and_embedding_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            job = _ready_job(root, store)
            auth = ProviderAuthPreflightStore(store).create(
                subject_kind="rag_embedding_job",
                subject_id=job["rag_embedding_job_id"],
                provider="local",
                operation="rag.embedding.provider_call",
                auth_mode="none",
            )
            RAGEmbeddingReceiptStore(store).create(
                rag_embedding_job_id=job["rag_embedding_job_id"],
                provider_auth_preflight_id=auth["provider_auth_preflight_id"],
                receipt_mode="simulated_success",
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("provider_auth_preflights", collections)
            self.assertIn("rag_embedding_receipts", collections)


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


if __name__ == "__main__":
    unittest.main()
