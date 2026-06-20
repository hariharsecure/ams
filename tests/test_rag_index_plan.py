from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from ams_codex.rag_index_plan import RAGIndexPlanStore
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.store import JsonStore


class RAGIndexPlanTest(unittest.TestCase):
    def test_plan_records_local_chunk_hashes_without_raw_content_or_downloads(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "README.md").write_text("alpha beta gamma\n" * 20, encoding="utf-8")
            (root / "notes.txt").write_text("not included", encoding="utf-8")
            store = JsonStore(root / "store.json")

            plan = RAGIndexPlanStore(store).create(
                source_root=root,
                allowed_globs=["*.md"],
                chunk_chars=40,
            )

            self.assertEqual(plan["embedding"]["provider"], "none")
            self.assertEqual(plan["embedding"]["status"], "not_requested")
            self.assertFalse(plan["source_policy"]["downloaded_files_allowed"])
            self.assertFalse(plan["source_policy"]["raw_content_stored"])
            self.assertEqual(plan["downloaded_artifacts"], [])
            self.assertEqual([source["path"] for source in plan["source_files"]], ["README.md"])
            self.assertGreater(len(plan["chunks"]), 1)
            for chunk in plan["chunks"]:
                self.assertNotIn("text", chunk)
                self.assertNotIn("content", chunk)
                self.assertTrue(chunk["chunk_sha256"].startswith("sha256:"))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_plan_denies_symlink_sources(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "outside.md"
            target.write_text("secret-ish", encoding="utf-8")
            link = root / "linked.md"
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlink unavailable")
            store = JsonStore(root / "store.json")

            plan = RAGIndexPlanStore(store).create(
                source_root=root,
                allowed_globs=["linked.md"],
            )

            self.assertEqual(plan["source_files"], [])
            self.assertEqual(plan["skipped_files"], [{"path": "linked.md", "reason": "symlink_denied"}])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_rag_plan_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "README.md").write_text("alpha beta gamma", encoding="utf-8")
            store = JsonStore(root / "store.json")
            plan = RAGIndexPlanStore(store).create(source_root=root, allowed_globs=["*.md"])
            state = store.load()
            state["rag_index_plans"][plan["rag_index_plan_id"]]["chunks"][0]["chunk_sha256"] = "sha256:" + "0" * 64
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("rag_index_plan.hash_mismatch", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_rag_index_plans(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "README.md").write_text("alpha beta gamma", encoding="utf-8")
            store = JsonStore(root / "store.json")
            RAGIndexPlanStore(store).create(source_root=root, allowed_globs=["*.md"])

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("rag_index_plans", collections)


if __name__ == "__main__":
    unittest.main()
