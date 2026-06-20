from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ams.cli import cmd_doc_retirement_plan
from ams.doc_retirement import DocRetirementPlanStore, _hash_without
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.store import JsonStore


class DocRetirementPlanTest(unittest.TestCase):
    def test_doc_retirement_plan_records_generated_status_without_raw_body(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")

            plan = DocRetirementPlanStore(store).create(source_root=root, label="test-doc-plan")

            self.assertEqual(plan["status"], "defer")
            self.assertFalse(plan["live_boundaries"]["file_rewritten"])
            self.assertFalse(plan["policy"]["raw_markdown_stored"])
            self.assertFalse(plan["generated_status"]["raw_content_stored"])
            self.assertEqual(plan["generated_status"]["recommended_path"], "GENERATED_STATUS.md")
            self.assertGreater(plan["action_summary"]["action_count"], 0)
            self.assertIn("replace_manual_status_with_generated_snapshot", plan["action_summary"]["by_kind"])
            self.assertIn("doc_retirement_plan.oversized_control_docs", plan["reason_codes"])
            serialized = str(plan)
            self.assertNotIn("secret body", serialized)
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_doc_retirement_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            plan = DocRetirementPlanStore(store).create(source_root=root, label="test-doc-plan")
            state = store.load()
            state["doc_retirement_plans"][plan["doc_retirement_plan_id"]]["action_summary"]["action_count"] = 999
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_retirement_plan.hash_mismatch", "\n".join(replay["errors"]))

    def test_replay_rejects_rehashed_file_rewrite_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            plan = DocRetirementPlanStore(store).create(source_root=root, label="test-doc-plan")
            state = store.load()
            record = state["doc_retirement_plans"][plan["doc_retirement_plan_id"]]
            record["live_boundaries"]["file_rewritten"] = True
            record["doc_retirement_plan_sha256"] = _hash_without(record, "doc_retirement_plan_sha256")
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_retirement_plan.file_rewritten_not_false", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_doc_retirement_plans(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            DocRetirementPlanStore(store).create(source_root=root, label="test-doc-plan")

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("doc_retirement_plans", collections)

    def test_cli_returns_nonzero_for_defer(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            args = SimpleNamespace(
                store=str(root / "store.json"),
                source_root=str(root),
                label="test-doc-plan",
                include_local_session_metadata=False,
                session_window_days=92,
            )

            self.assertEqual(cmd_doc_retirement_plan(args), 1)


def _minimal_repo(root: Path, *, oversized_status: bool) -> Path:
    root.mkdir(exist_ok=True)
    (root / "AGENTS.md").write_text("# Agent Instructions\n\nStatus: active\nUpdated: 2026-06-12\n", encoding="utf-8")
    (root / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
    (root / "README.md").write_text("# Demo\n\nStatus: active\nUpdated: 2026-06-12\n", encoding="utf-8")
    status_body = "# Status\n\nStatus: active\nUpdated: 2026-06-12\n\nsecret body\n"
    if oversized_status:
        status_body += "\n".join(f"- generated historical line {index}" for index in range(901)) + "\n"
    (root / "STATUS.md").write_text(status_body, encoding="utf-8")
    (root / "MILESTONE_34_DOC_RETIREMENT.md").write_text(
        "# MILESTONE-34\n\nStatus: complete\nDate: 2026-06-12\n\n## Verification\n\nok\n\n## Next Risk\n\nNone.\n",
        encoding="utf-8",
    )
    return root


if __name__ == "__main__":
    unittest.main()
