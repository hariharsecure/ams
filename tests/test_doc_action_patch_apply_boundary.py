from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from ams.doc_action_patch_apply_boundary import (
    DocActionPatchApplyBoundaryPacketStore,
    _hash_without,
)
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.store import JsonStore

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_doc_action_patch_executor_preflight import _preflight_fixture
from test_doc_action_patch_preview import _minimal_repo


class DocActionPatchApplyBoundaryPacketTest(unittest.TestCase):
    def test_apply_boundary_consumes_preflight_without_applying(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _apply_boundary_fixture(store, root, Path(td) / "artifacts")
            packet = fixture["apply_boundary_packet"]

            self.assertEqual(packet["status"], "ready_for_operator_apply_acceptance")
            self.assertTrue(all(packet["required_gates"].values()))
            self.assertTrue(packet["approval_granted"])
            self.assertTrue(packet["preflight_ready"])
            self.assertTrue(packet["apply_boundary_ready"])
            self.assertFalse(packet["apply_allowed"])
            self.assertFalse(packet["live_execution_allowed"])
            self.assertFalse(packet["source_file_write_allowed"])
            self.assertFalse(packet["source_file_move_allowed"])
            self.assertFalse(packet["source_file_delete_allowed"])
            self.assertFalse(packet["archive_create_allowed"])
            self.assertFalse(packet["generated_surface_rewrite_allowed"])
            self.assertTrue(packet["apply_boundary_intent"]["artifact_hash_verified"])
            self.assertTrue(packet["apply_boundary_intent"]["source_hash_matches_preflight"])
            self.assertTrue(packet["apply_boundary_intent"]["source_hash_matches_approved_source"])
            self.assertTrue(packet["operator_apply_acceptance"]["operator_apply_acceptance_required"])
            self.assertFalse(packet["operator_apply_acceptance"]["operator_apply_acceptance_captured"])
            self.assertFalse(packet["operator_apply_acceptance"]["raw_acceptance_stored"])
            self.assertTrue(packet["rollback_plan"]["requires_source_backup_before_apply"])
            self.assertFalse(packet["rollback_plan"]["backup_written"])
            self.assertEqual(len(packet["apply_boundary_actions"]), 1)
            self.assertEqual(packet["execution_actions"], [])
            self.assertEqual(packet["source_write_actions"], [])
            self.assertFalse(packet["live_boundaries"]["source_file_rewritten"])
            self.assertFalse(packet["live_boundaries"]["terminal_injection_performed"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_apply_boundary_blocks_when_preflight_not_ready(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _preflight_fixture(store, root, Path(td) / "artifacts")
            state = store.load()
            preflight = state["doc_action_patch_executor_preflights"][
                fixture["executor_preflight"]["doc_action_patch_executor_preflight_id"]
            ]
            preflight["status"] = "blocked"
            preflight["preflight_ready"] = False
            preflight["preflight_actions"] = []
            preflight["live_boundaries"]["preflight_recorded"] = False
            preflight["doc_action_patch_executor_preflight_sha256"] = _hash_without(
                preflight,
                "doc_action_patch_executor_preflight_sha256",
            )
            store.save(state, validate=False)

            packet = DocActionPatchApplyBoundaryPacketStore(store).create(
                doc_action_patch_executor_preflight_id=preflight["doc_action_patch_executor_preflight_id"],
                source_root=root,
                label="test-doc-action-patch-apply-boundary-blocked",
            )

            self.assertEqual(packet["status"], "blocked")
            self.assertFalse(packet["preflight_ready"])
            self.assertFalse(packet["apply_boundary_ready"])
            self.assertEqual(packet["apply_boundary_actions"], [])

    def test_replay_catches_authority_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _apply_boundary_fixture(store, root, Path(td) / "artifacts")
            state = store.load()
            record = state["doc_action_patch_apply_boundary_packets"][
                fixture["apply_boundary_packet"]["doc_action_patch_apply_boundary_packet_id"]
            ]
            record["apply_allowed"] = True
            record["doc_action_patch_apply_boundary_packet_sha256"] = _hash_without(
                record,
                "doc_action_patch_apply_boundary_packet_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_apply_boundary.apply_allowed_not_false", "\n".join(replay["errors"]))

    def test_replay_catches_stale_preflight_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _apply_boundary_fixture(store, root, Path(td) / "artifacts")
            state = store.load()
            preflight = state["doc_action_patch_executor_preflights"][
                fixture["executor_preflight"]["doc_action_patch_executor_preflight_id"]
            ]
            preflight["label"] = "tampered-doc-action-patch-executor-preflight"
            preflight["doc_action_patch_executor_preflight_sha256"] = _hash_without(
                preflight,
                "doc_action_patch_executor_preflight_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_apply_boundary.executor_preflight_hash_mismatch", "\n".join(replay["errors"]))

    def test_replay_catches_source_drift_after_apply_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _apply_boundary_fixture(store, root, Path(td) / "artifacts")
            source_path = fixture["apply_boundary_packet"]["apply_boundary_intent"]["source_path"]
            (root / source_path).write_text("# Changed\n", encoding="utf-8")

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn(
                "doc_action_patch_apply_boundary.apply_boundary_intent_source_hash_matches_preflight_mismatch",
                "\n".join(replay["errors"]),
            )

    def test_replay_catches_artifact_tamper_after_apply_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _apply_boundary_fixture(store, root, Path(td) / "artifacts")
            artifact_path = Path(fixture["apply_boundary_packet"]["apply_boundary_intent"]["artifact_path"])
            artifact_path.write_text("tampered patch\n", encoding="utf-8")

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn(
                "doc_action_patch_apply_boundary.apply_boundary_intent_artifact_hash_verified_mismatch",
                "\n".join(replay["errors"]),
            )

    def test_replay_oracle_covers_doc_action_patch_apply_boundary_packets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            _apply_boundary_fixture(store, root, Path(td) / "artifacts")

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("doc_action_patch_apply_boundary_packets", collections)


def _apply_boundary_fixture(store: JsonStore, root: Path, artifact_root: Path) -> dict[str, dict]:
    fixture = _preflight_fixture(store, root, artifact_root)
    apply_boundary_packet = DocActionPatchApplyBoundaryPacketStore(store).create(
        doc_action_patch_executor_preflight_id=fixture["executor_preflight"][
            "doc_action_patch_executor_preflight_id"
        ],
        source_root=root,
        label="test-doc-action-patch-apply-boundary-ready",
    )
    return {**fixture, "apply_boundary_packet": apply_boundary_packet}


if __name__ == "__main__":
    unittest.main()
