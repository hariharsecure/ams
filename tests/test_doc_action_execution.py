from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ams.cli import cmd_doc_action_execution_plan
from ams.doc_action_execution import DocActionExecutionPlanStore, _hash_without
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.store import JsonStore


class DocActionExecutionPlanTest(unittest.TestCase):
    def test_doc_action_execution_plan_selects_preview_batch_without_raw_body(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")

            plan = DocActionExecutionPlanStore(store).create(
                source_root=root,
                label="test-doc-action-execution",
                max_actions=1,
            )

            self.assertEqual(plan["status"], "defer")
            self.assertEqual(plan["action_summary"]["action_count"], 1)
            self.assertEqual(plan["skipped_action_count"], plan["source_plan_ref"]["action_count"] - 1)
            self.assertFalse(plan["live_boundaries"]["file_rewritten"])
            self.assertFalse(plan["live_boundaries"]["file_deleted"])
            self.assertFalse(plan["policy"]["write_allowed"])
            self.assertTrue(plan["policy"]["preview_only"])
            self.assertFalse(plan["readiness"]["live_execution_allowed"])
            selected = plan["selected_actions"][0]
            self.assertTrue(selected["preview_only"])
            self.assertFalse(selected["live_boundary"])
            self.assertFalse(selected["raw_content_stored"])
            self.assertEqual(selected["source_ref"]["path"], "STATUS.md")
            self.assertTrue(selected["source_ref"]["exists"])
            self.assertRegex(selected["source_ref"]["sha256"], r"^sha256:[0-9a-f]{64}$")
            serialized = str(plan)
            self.assertNotIn("secret body", serialized)
            state = store.load()
            self.assertIn(plan["source_plan_ref"]["doc_retirement_plan_id"], state["doc_retirement_plans"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_missing_source_plan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            plan = DocActionExecutionPlanStore(store).create(source_root=root, label="test-doc-action-execution")
            state = store.load()
            source_id = plan["source_plan_ref"]["doc_retirement_plan_id"]
            del state["doc_retirement_plans"][source_id]
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_execution_plan.source_plan_missing", "\n".join(replay["errors"]))

    def test_replay_rejects_rehashed_file_rewrite_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            plan = DocActionExecutionPlanStore(store).create(source_root=root, label="test-doc-action-execution")
            state = store.load()
            record = state["doc_action_execution_plans"][plan["doc_action_execution_plan_id"]]
            record["live_boundaries"]["file_rewritten"] = True
            record["doc_action_execution_plan_sha256"] = _hash_without(record, "doc_action_execution_plan_sha256")
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_execution_plan.file_rewritten_not_false", "\n".join(replay["errors"]))

    def test_replay_rejects_rehashed_source_ref_outside_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            plan = DocActionExecutionPlanStore(store).create(source_root=root, label="test-doc-action-execution")
            state = store.load()
            record = state["doc_action_execution_plans"][plan["doc_action_execution_plan_id"]]
            selected = record["selected_actions"][0]
            selected["source_ref"]["under_source_root"] = False
            selected["preview_sha256"] = "sha256:" + ("0" * 64)
            record["doc_action_execution_plan_sha256"] = _hash_without(record, "doc_action_execution_plan_sha256")
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_execution_plan.source_ref_outside_root", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_doc_action_execution_plans(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            DocActionExecutionPlanStore(store).create(source_root=root, label="test-doc-action-execution")

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("doc_action_execution_plans", collections)

    def test_cli_returns_success_for_reviewable_defer_preview(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            args = SimpleNamespace(
                store=str(root / "store.json"),
                source_root=str(root),
                label="test-doc-action-execution",
                include_local_session_metadata=False,
                session_window_days=92,
                max_actions=1,
                action_kind=[],
            )

            self.assertEqual(cmd_doc_action_execution_plan(args), 0)


def _minimal_repo(root: Path, *, oversized_status: bool) -> Path:
    root.mkdir(exist_ok=True)
    (root / "AGENTS.md").write_text("# Agent Instructions\n\nStatus: active\nUpdated: 2026-06-12\n", encoding="utf-8")
    (root / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
    (root / "README.md").write_text("# Demo\n\nStatus: active\nUpdated: 2026-06-12\n", encoding="utf-8")
    (root / "MAP.md").write_text("# Map\n\nStatus: active\nUpdated: 2026-06-12\n", encoding="utf-8")
    status_body = "# Status\n\nStatus: active\nUpdated: 2026-06-12\n\nsecret body\n"
    if oversized_status:
        status_body += "\n".join(f"- generated historical line {index}" for index in range(901)) + "\n"
    (root / "STATUS.md").write_text(status_body, encoding="utf-8")
    (root / "MILESTONE_56_DOC_ACTION_EXECUTION_PLAN.md").write_text(
        "# MILESTONE-56\n\nStatus: complete\nDate: 2026-06-13\n\n## Verification\n\nok\n\n## Next Risk\n\nNone.\n",
        encoding="utf-8",
    )
    return root


if __name__ == "__main__":
    unittest.main()
