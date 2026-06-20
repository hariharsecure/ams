from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from ams_codex.models import hash_without as _hash_without, sha256_text
from ams_codex.rag_index_plan import RAGIndexPlanStore, _snapshot_hash
from ams_codex.rag_local_vector_trial import RAGLocalVectorTrialStore
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.store import JsonStore


class RAGLocalVectorTrialTest(unittest.TestCase):
    def test_local_vector_trial_retrieves_hash_only_refs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "README.md").write_text("status bundle receiver\n" * 12, encoding="utf-8")
            store = JsonStore(root / "store.json")
            plan = RAGIndexPlanStore(store).create(
                source_root=root,
                allowed_globs=["*.md"],
                chunk_chars=40,
                embedding_provider="local",
                vector_store_provider="local",
            )

            trial = RAGLocalVectorTrialStore(store).create(
                rag_index_plan_id=plan["rag_index_plan_id"],
                query_text="receiver status",
                top_k=2,
            )

            self.assertEqual(trial["status"], "allow", trial["reason_codes"])
            self.assertEqual(trial["reason_codes"], ["rag_local_vector_trial.allow"])
            self.assertEqual(trial["top_k"], 2)
            self.assertIn("hash_refs", trial["taint_labels"])
            self.assertLessEqual(trial["source_ref_count"], trial["top_k"])
            self.assertFalse(trial["query"]["query_text_stored"])
            self.assertFalse(trial["local_adapter"]["vector_payload_stored"])
            self.assertGreater(trial["source_ref_count"], 0)
            for source_ref in trial["source_refs"]:
                self.assertFalse(source_ref["content_stored"])
                self.assertFalse(source_ref["embedding_stored"])
                self.assertFalse(source_ref["vector_stored"])
                for forbidden in ("text", "content", "raw", "embedding", "vector", "tokens", "features"):
                    self.assertNotIn(forbidden, source_ref)
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_local_vector_boundary_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "README.md").write_text("alpha beta gamma\n" * 8, encoding="utf-8")
            store = JsonStore(root / "store.json")
            plan = RAGIndexPlanStore(store).create(
                source_root=root,
                allowed_globs=["*.md"],
                chunk_chars=40,
                embedding_provider="local",
                vector_store_provider="local",
            )
            trial = RAGLocalVectorTrialStore(store).create(
                rag_index_plan_id=plan["rag_index_plan_id"],
                query_text="alpha",
            )
            state = store.load()
            record = state["rag_local_vector_trials"][trial["rag_local_vector_trial_id"]]
            record["boundaries"]["network_call_performed"] = True
            record["rag_local_vector_trial_sha256"] = _hash_without(record, "rag_local_vector_trial_sha256")
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("rag_local_vector_trial.network_call_performed_not_false", "\n".join(replay["errors"]))

    def test_local_vector_trial_does_not_read_traversal_source_paths(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"
            root.mkdir()
            outside = Path(td) / "outside.md"
            outside_text = "outside secret alpha\n"
            outside.write_text(outside_text, encoding="utf-8")
            (root / "README.md").write_text("inside alpha\n", encoding="utf-8")
            store = JsonStore(root / "store.json")
            plan = RAGIndexPlanStore(store).create(
                source_root=root,
                allowed_globs=["*.md"],
                chunk_chars=40,
                embedding_provider="local",
                vector_store_provider="local",
            )
            state = store.load()
            forged = state["rag_index_plans"][plan["rag_index_plan_id"]]
            outside_sha = "sha256:" + hashlib.sha256(outside.read_bytes()).hexdigest()
            forged["source_files"] = [
                {
                    "path": "../outside.md",
                    "sha256": outside_sha,
                    "size_bytes": outside.stat().st_size,
                    "media_type": "text/plain",
                    "chunk_count": 1,
                }
            ]
            forged["chunks"] = [
                {
                    "chunk_id": "ragchunk_forged_traversal",
                    "source_path": "../outside.md",
                    "chunk_index": 0,
                    "char_start": 0,
                    "char_end": len(outside_text),
                    "chunk_sha256": sha256_text(outside_text),
                    "embedding_status": "not_embedded",
                }
            ]
            forged["source_snapshot_sha256"] = _snapshot_hash(forged["source_files"], forged["skipped_files"])
            forged["plan_sha256"] = _hash_without(forged, "plan_sha256")
            store.save(state, validate=False)

            trial = RAGLocalVectorTrialStore(store).create(
                rag_index_plan_id=plan["rag_index_plan_id"],
                query_text="outside secret alpha",
            )

            self.assertEqual(trial["status"], "defer")
            self.assertEqual(trial["source_ref_count"], 0)
            self.assertEqual(trial["source_verification"]["verified_chunk_count"], 0)
            self.assertEqual(trial["source_verification"]["file_mismatch_count"], 1)
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_oracle_covers_local_vector_trials(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "README.md").write_text("alpha beta gamma\n" * 8, encoding="utf-8")
            store = JsonStore(root / "store.json")
            plan = RAGIndexPlanStore(store).create(
                source_root=root,
                allowed_globs=["*.md"],
                chunk_chars=40,
                embedding_provider="local",
                vector_store_provider="local",
            )
            RAGLocalVectorTrialStore(store).create(
                rag_index_plan_id=plan["rag_index_plan_id"],
                query_text="alpha",
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("rag_local_vector_trials", collections)


if __name__ == "__main__":
    unittest.main()
