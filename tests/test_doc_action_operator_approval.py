from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.doc_action_execution import DocActionExecutionPlanStore, _hash_without as _execution_hash_without
from ams.doc_action_operator_approval import (
    REQUIRED_READBACK_PHRASES,
    REQUIRED_REVIEW_STEPS,
    DocActionOperatorApprovalPacketStore,
    _hash_without,
)
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.store import JsonStore


class DocActionOperatorApprovalPacketTest(unittest.TestCase):
    def test_ready_packet_is_inert_and_requires_readback(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            execution_plan = DocActionExecutionPlanStore(store).create(
                source_root=root,
                label="test-doc-action-execution",
                max_actions=2,
            )

            packet = DocActionOperatorApprovalPacketStore(store).create(
                doc_action_execution_plan_id=execution_plan["doc_action_execution_plan_id"],
                source_root=root,
                label="test-doc-action-operator-approval",
            )

            self.assertEqual(packet["status"], "ready_for_operator_review")
            self.assertTrue(all(packet["required_gates"].values()))
            self.assertEqual(packet["approval_request"]["required_review_steps"], REQUIRED_REVIEW_STEPS)
            self.assertEqual(packet["approval_request"]["required_readback_phrases"], REQUIRED_READBACK_PHRASES)
            self.assertFalse(packet["approval_request"]["operator_readback_captured"])
            self.assertFalse(packet["approval_request"]["raw_readback_stored"])
            self.assertFalse(packet["approval_granted"])
            self.assertFalse(packet["live_execution_allowed"])
            self.assertFalse(packet["file_rewrite_allowed"])
            self.assertFalse(packet["file_move_allowed"])
            self.assertFalse(packet["file_delete_allowed"])
            self.assertFalse(packet["archive_create_allowed"])
            self.assertEqual(packet["approval_actions"], [])
            self.assertEqual(packet["execution_actions"], [])
            self.assertEqual(packet["plan_summary"]["selected_action_count"], 1)
            self.assertTrue(packet["plan_summary"]["source_hashes_captured"])
            self.assertNotIn("secret body", str(packet))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_packet_authority_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            execution_plan = DocActionExecutionPlanStore(store).create(source_root=root, label="test-doc-action-execution")
            packet = _create_ready_packet(store, root, execution_plan)
            state = store.load()
            record = state["doc_action_operator_approval_packets"][packet["doc_action_operator_approval_packet_id"]]
            record["approval_granted"] = True
            record["doc_action_operator_approval_packet_sha256"] = _hash_without(
                record,
                "doc_action_operator_approval_packet_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_operator_approval.approval_granted_not_false", "\n".join(replay["errors"]))

    def test_replay_catches_stale_execution_plan_after_packet(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            execution_plan = DocActionExecutionPlanStore(store).create(source_root=root, label="test-doc-action-execution")
            _create_ready_packet(store, root, execution_plan)
            state = store.load()
            record = state["doc_action_execution_plans"][execution_plan["doc_action_execution_plan_id"]]
            record["policy"]["write_allowed"] = True
            record["doc_action_execution_plan_sha256"] = _execution_hash_without(
                record,
                "doc_action_execution_plan_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            joined = "\n".join(replay["errors"])
            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_operator_approval.execution_plan_hash_mismatch", joined)
            self.assertIn("doc_action_execution_plan.policy_write_allowed_not_false", joined)

    def test_replay_catches_plan_summary_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            execution_plan = DocActionExecutionPlanStore(store).create(source_root=root, label="test-doc-action-execution")
            packet = _create_ready_packet(store, root, execution_plan)
            state = store.load()
            record = state["doc_action_operator_approval_packets"][packet["doc_action_operator_approval_packet_id"]]
            record["plan_summary"]["selected_action_count"] = 0
            record["doc_action_operator_approval_packet_sha256"] = _hash_without(
                record,
                "doc_action_operator_approval_packet_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_operator_approval.plan_summary_mismatch", "\n".join(replay["errors"]))

    def test_replay_catches_source_doc_plan_ref_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            execution_plan = DocActionExecutionPlanStore(store).create(source_root=root, label="test-doc-action-execution")
            packet = _create_ready_packet(store, root, execution_plan)
            state = store.load()
            record = state["doc_action_operator_approval_packets"][packet["doc_action_operator_approval_packet_id"]]
            record["source_doc_retirement_plan_id"] = "docplan_wrong"
            record["source_doc_retirement_plan_sha256"] = "sha256:" + ("0" * 64)
            record["doc_action_operator_approval_packet_sha256"] = _hash_without(
                record,
                "doc_action_operator_approval_packet_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            joined = "\n".join(replay["errors"])
            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_operator_approval.source_doc_retirement_plan_id_mismatch", joined)
            self.assertIn("doc_action_operator_approval.source_doc_retirement_plan_hash_mismatch", joined)

    def test_replay_oracle_covers_doc_action_operator_approval_packets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            execution_plan = DocActionExecutionPlanStore(store).create(source_root=root, label="test-doc-action-execution")
            _create_ready_packet(store, root, execution_plan)

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("doc_action_operator_approval_packets", collections)


def _create_ready_packet(store: JsonStore, root: Path, execution_plan: dict[str, object]) -> dict[str, object]:
    return DocActionOperatorApprovalPacketStore(store).create(
        doc_action_execution_plan_id=str(execution_plan["doc_action_execution_plan_id"]),
        source_root=root,
        label="test-doc-action-operator-approval",
    )


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
    (root / "MILESTONE_57_DOC_ACTION_OPERATOR_APPROVAL.md").write_text(
        "# MILESTONE-57\n\nStatus: complete\nDate: 2026-06-13\n\n## Verification\n\nok\n\n## Next Risk\n\nNone.\n",
        encoding="utf-8",
    )
    return root


if __name__ == "__main__":
    unittest.main()
