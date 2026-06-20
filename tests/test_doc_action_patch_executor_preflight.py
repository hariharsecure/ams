from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from ams.doc_action_patch_executor_preflight import (
    DocActionPatchExecutorPreflightStore,
    _hash_without,
)
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.store import JsonStore

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_doc_action_patch_live_execution_approval import _live_approval_fixture
from test_doc_action_patch_preview import _minimal_repo


class DocActionPatchExecutorPreflightTest(unittest.TestCase):
    def test_executor_preflight_consumes_approval_without_applying(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _preflight_fixture(store, root, Path(td) / "artifacts")
            preflight = fixture["executor_preflight"]

            self.assertEqual(preflight["status"], "preflight_ready")
            self.assertTrue(all(preflight["required_gates"].values()))
            self.assertTrue(preflight["approval_granted"])
            self.assertTrue(preflight["preflight_ready"])
            self.assertFalse(preflight["apply_allowed"])
            self.assertFalse(preflight["live_execution_allowed"])
            self.assertFalse(preflight["source_file_write_allowed"])
            self.assertFalse(preflight["source_file_move_allowed"])
            self.assertFalse(preflight["source_file_delete_allowed"])
            self.assertFalse(preflight["archive_create_allowed"])
            self.assertFalse(preflight["generated_surface_rewrite_allowed"])
            self.assertTrue(preflight["apply_intent"]["artifact_hash_verified"])
            self.assertTrue(preflight["apply_intent"]["source_hash_verified"])
            self.assertTrue(preflight["apply_intent"]["approval_action_matches"])
            self.assertEqual(len(preflight["preflight_actions"]), 1)
            self.assertEqual(preflight["execution_actions"], [])
            self.assertEqual(preflight["source_write_actions"], [])
            self.assertFalse(preflight["live_boundaries"]["source_file_rewritten"])
            self.assertFalse(preflight["live_boundaries"]["terminal_injection_performed"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_preflight_blocks_when_approval_packet_not_ready(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _live_approval_fixture(store, root, Path(td) / "artifacts")
            state = store.load()
            approval = state["doc_action_patch_live_execution_approval_packets"][
                fixture["live_execution_approval_packet"]["doc_action_patch_live_execution_approval_packet_id"]
            ]
            approval["status"] = "blocked"
            approval["approval_granted"] = False
            approval["live_execution_approval_captured"] = False
            approval["approval_policy"]["approval_granted"] = False
            approval["live_boundaries"]["approval_granted"] = False
            approval["live_boundaries"]["live_execution_approval_captured"] = False
            approval["approval_actions"] = []
            approval["doc_action_patch_live_execution_approval_packet_sha256"] = _hash_without(
                approval,
                "doc_action_patch_live_execution_approval_packet_sha256",
            )
            store.save(state, validate=False)

            preflight = DocActionPatchExecutorPreflightStore(store).create(
                doc_action_patch_live_execution_approval_packet_id=approval[
                    "doc_action_patch_live_execution_approval_packet_id"
                ],
                label="test-doc-action-patch-executor-preflight-blocked",
            )

            self.assertEqual(preflight["status"], "blocked")
            self.assertFalse(preflight["preflight_ready"])
            self.assertFalse(preflight["approval_granted"])
            self.assertEqual(preflight["preflight_actions"], [])

    def test_replay_catches_authority_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _preflight_fixture(store, root, Path(td) / "artifacts")
            state = store.load()
            record = state["doc_action_patch_executor_preflights"][
                fixture["executor_preflight"]["doc_action_patch_executor_preflight_id"]
            ]
            record["apply_allowed"] = True
            record["doc_action_patch_executor_preflight_sha256"] = _hash_without(
                record,
                "doc_action_patch_executor_preflight_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_executor_preflight.apply_allowed_not_false", "\n".join(replay["errors"]))

    def test_replay_catches_source_drift_after_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _preflight_fixture(store, root, Path(td) / "artifacts")
            source_path = fixture["executor_preflight"]["apply_intent"]["source_path"]
            (root / source_path).write_text("# Changed\n", encoding="utf-8")

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_executor_preflight.apply_intent_source_hash_verified_mismatch", "\n".join(replay["errors"]))

    def test_replay_catches_artifact_tamper_after_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _preflight_fixture(store, root, Path(td) / "artifacts")
            artifact_path = Path(fixture["executor_preflight"]["apply_intent"]["artifact_path"])
            artifact_path.write_text("tampered patch\n", encoding="utf-8")

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_executor_preflight.apply_intent_artifact_hash_verified_mismatch", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_doc_action_patch_executor_preflights(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            _preflight_fixture(store, root, Path(td) / "artifacts")

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("doc_action_patch_executor_preflights", collections)


def _preflight_fixture(store: JsonStore, root: Path, artifact_root: Path) -> dict[str, dict]:
    fixture = _live_approval_fixture(store, root, artifact_root)
    executor_preflight = DocActionPatchExecutorPreflightStore(store).create(
        doc_action_patch_live_execution_approval_packet_id=fixture["live_execution_approval_packet"][
            "doc_action_patch_live_execution_approval_packet_id"
        ],
        source_root=root,
        label="test-doc-action-patch-executor-preflight-ready",
    )
    return {**fixture, "executor_preflight": executor_preflight}


if __name__ == "__main__":
    unittest.main()
