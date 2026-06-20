from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.admission import AdmissionReviewStore
from ams.artifact_quarantine import DownloadedArtifactQuarantineStore
from ams.rag_embedding_job import RAGEmbeddingJobStore
from ams.rag_index_plan import RAGIndexPlanStore
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.store import JsonStore


class RAGEmbeddingJobTest(unittest.TestCase):
    def test_quarantine_records_no_download_no_raw_content(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")

            quarantine = DownloadedArtifactQuarantineStore(store).create(
                source_uri="https://example.invalid/research.pdf",
                source_type="url",
                declared_media_type="application/pdf",
            )

            self.assertEqual(quarantine["download_status"], "not_downloaded")
            self.assertEqual(quarantine["quarantine_status"], "quarantined")
            self.assertFalse(quarantine["network_fetch_allowed"])
            self.assertFalse(quarantine["raw_content_stored"])
            for forbidden in ("text", "content", "raw", "raw_content", "bytes"):
                self.assertNotIn(forbidden, quarantine)
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_quarantine_approval_requires_operator_review_and_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")

            with self.assertRaises(ValueError):
                DownloadedArtifactQuarantineStore(store).create(
                    source_uri="https://example.invalid/research.pdf",
                    source_type="url",
                    download_status="downloaded_external",
                    quarantine_status="approved_for_index",
                )

    def test_embedding_job_blocks_without_provider_plan_or_admissions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "README.md").write_text("alpha beta gamma\n" * 8, encoding="utf-8")
            store = JsonStore(root / "store.json")
            plan = RAGIndexPlanStore(store).create(source_root=root, allowed_globs=["*.md"], chunk_chars=32)

            job = RAGEmbeddingJobStore(store).create(rag_index_plan_id=plan["rag_index_plan_id"])

            self.assertEqual(job["status"], "blocked")
            self.assertIn("rag_embedding_job.embedding_provider_not_requested", job["reason_codes"])
            self.assertIn("rag_embedding_job.vector_store_provider_not_requested", job["reason_codes"])
            self.assertIn("rag_embedding_job.capability_review_required", job["reason_codes"])
            self.assertFalse(job["provider_gate"]["provider_call_allowed"])
            self.assertFalse(job["provider_gate"]["vector_write_allowed"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_embedding_job_ready_only_after_admission_reviews(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "README.md").write_text("alpha beta gamma\n" * 12, encoding="utf-8")
            store = JsonStore(root / "store.json")
            plan = RAGIndexPlanStore(store).create(
                source_root=root,
                allowed_globs=["*.md"],
                chunk_chars=40,
                embedding_provider="openai",
                embedding_model="text-embedding-3-small",
                embedding_dimensions=1536,
                vector_store_provider="openai_file_search",
            )
            admissions = AdmissionReviewStore(store)
            capability = admissions.create(
                subject_kind="rag_index_plan",
                subject_id=plan["rag_index_plan_id"],
                operation="capability.rag_embedding.provider_call",
                request={"provider": "openai", "model": "text-embedding-3-small"},
                status="allow",
                reason_codes=["test.allow"],
            )
            resource = admissions.create(
                subject_kind="rag_index_plan",
                subject_id=plan["rag_index_plan_id"],
                operation="resource.rag_embedding.vector_store",
                request={"provider": "openai_file_search", "batch_size": 2},
                status="allow",
                reason_codes=["test.allow"],
            )

            job = RAGEmbeddingJobStore(store).create(
                rag_index_plan_id=plan["rag_index_plan_id"],
                capability_admission_review_id=capability["admission_review_id"],
                resource_admission_review_id=resource["admission_review_id"],
                batch_size=2,
            )

            self.assertEqual(job["status"], "ready_for_operator_review")
            self.assertEqual(job["reason_codes"], ["rag_embedding_job.ready_for_operator_review"])
            self.assertTrue(job["provider_gate"]["capability_allowed"])
            self.assertTrue(job["provider_gate"]["resource_allowed"])
            self.assertFalse(job["provider_gate"]["provider_call_allowed"])
            self.assertFalse(job["provider_gate"]["vector_write_allowed"])
            self.assertEqual(job["chunk_count"], len(plan["chunks"]))
            self.assertEqual(len(job["planned_vectors"]), len(plan["chunks"]))
            for vector_ref in job["planned_vectors"]:
                for forbidden in ("text", "content", "raw", "raw_content", "embedding", "vector"):
                    self.assertNotIn(forbidden, vector_ref)
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_embedding_job_blocks_quarantined_artifact_until_approved(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "README.md").write_text("alpha beta gamma\n" * 12, encoding="utf-8")
            store = JsonStore(root / "store.json")
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
            quarantine = DownloadedArtifactQuarantineStore(store).create(
                source_uri="https://example.invalid/unknown.txt",
                source_type="url",
            )

            job = RAGEmbeddingJobStore(store).create(
                rag_index_plan_id=plan["rag_index_plan_id"],
                capability_admission_review_id=capability["admission_review_id"],
                resource_admission_review_id=resource["admission_review_id"],
                downloaded_artifact_quarantine_ids=[quarantine["downloaded_artifact_quarantine_id"]],
            )

            self.assertEqual(job["status"], "blocked")
            self.assertIn("rag_embedding_job.quarantine_not_approved", job["reason_codes"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_quarantine_and_embedding_job_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "README.md").write_text("alpha beta gamma\n" * 12, encoding="utf-8")
            store = JsonStore(root / "store.json")
            plan = RAGIndexPlanStore(store).create(
                source_root=root,
                allowed_globs=["*.md"],
                embedding_provider="local",
                vector_store_provider="local",
            )
            quarantine = DownloadedArtifactQuarantineStore(store).create(
                source_uri="https://example.invalid/unknown.txt",
                source_type="url",
            )
            job = RAGEmbeddingJobStore(store).create(rag_index_plan_id=plan["rag_index_plan_id"])
            state = store.load()
            state["downloaded_artifact_quarantines"][quarantine["downloaded_artifact_quarantine_id"]][
                "network_fetch_allowed"
            ] = True
            state["rag_embedding_jobs"][job["rag_embedding_job_id"]]["planned_vectors"][0]["vector_status"] = "written"
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            errors = "\n".join(replay["errors"])
            self.assertIn("downloaded_artifact_quarantine.hash_mismatch", errors)
            self.assertIn("rag_embedding_job.hash_mismatch", errors)

    def test_replay_oracle_covers_new_rag_ledgers(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "README.md").write_text("alpha beta gamma\n" * 12, encoding="utf-8")
            store = JsonStore(root / "store.json")
            plan = RAGIndexPlanStore(store).create(
                source_root=root,
                allowed_globs=["*.md"],
                embedding_provider="local",
                vector_store_provider="local",
            )
            DownloadedArtifactQuarantineStore(store).create(
                source_uri="https://example.invalid/unknown.txt",
                source_type="url",
            )
            RAGEmbeddingJobStore(store).create(rag_index_plan_id=plan["rag_index_plan_id"])

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("downloaded_artifact_quarantines", collections)
            self.assertIn("rag_embedding_jobs", collections)


if __name__ == "__main__":
    unittest.main()
