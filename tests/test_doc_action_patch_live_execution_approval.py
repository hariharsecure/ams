from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from ams.doc_action_patch_live_execution_approval import (
    REQUIRED_APPROVAL_PHRASES,
    DocActionPatchLiveExecutionApprovalPacketStore,
    _hash_without,
)
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.store import JsonStore

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_doc_action_patch_dry_run_readback import _readback_fixture
from test_doc_action_patch_preview import _minimal_repo


VALID_APPROVAL = (
    "I approve live doc action execution for this dry run. "
    "Dry run readback hash matches this approval packet. "
    "Artifact hash must be rechecked by the executor. "
    "Source hash must be rechecked by the executor. "
    "Only the listed source file action is in scope. "
    "This approval packet is not an executor. "
    "Generated surface rewrites remain disabled. "
    "Source deletes moves and archives remain disabled."
)


class DocActionPatchLiveExecutionApprovalPacketTest(unittest.TestCase):
    def test_live_execution_approval_packet_captures_approval_without_executing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _live_approval_fixture(store, root, Path(td) / "artifacts")
            packet = fixture["live_execution_approval_packet"]

            self.assertEqual(packet["status"], "approved_for_executor_review")
            self.assertTrue(all(packet["required_gates"].values()))
            self.assertEqual(packet["required_approval_phrases"], REQUIRED_APPROVAL_PHRASES)
            self.assertTrue(packet["approval"]["required_phrases_present"])
            self.assertFalse(packet["approval"]["raw_approval_stored"])
            self.assertTrue(packet["approval_granted"])
            self.assertTrue(packet["live_execution_approval_captured"])
            self.assertFalse(packet["live_execution_allowed"])
            self.assertFalse(packet["source_file_write_allowed"])
            self.assertFalse(packet["source_file_move_allowed"])
            self.assertFalse(packet["source_file_delete_allowed"])
            self.assertFalse(packet["archive_create_allowed"])
            self.assertFalse(packet["generated_surface_rewrite_allowed"])
            self.assertEqual(len(packet["approval_actions"]), 1)
            self.assertEqual(packet["execution_actions"], [])
            self.assertEqual(packet["source_write_actions"], [])
            self.assertFalse(packet["live_boundaries"]["source_file_rewritten"])
            self.assertFalse(packet["live_boundaries"]["discord_call_performed"])
            self.assertNotIn(VALID_APPROVAL, str(packet))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_missing_phrase_blocks_approval_without_breaking_replay(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _readback_fixture(store, root, Path(td) / "artifacts")

            packet = DocActionPatchLiveExecutionApprovalPacketStore(store).create(
                doc_action_patch_dry_run_readback_receipt_id=fixture["dry_run_readback_receipt"][
                    "doc_action_patch_dry_run_readback_receipt_id"
                ],
                approval_ref="local://tests/doc-action-patch-live-execution-approval-missing",
                approval_text="I approve live doc action execution for this dry run.",
                requested_by="test-operator",
                label="test-doc-action-patch-live-execution-approval-blocked",
            )

            self.assertEqual(packet["status"], "blocked")
            self.assertFalse(packet["approval_granted"])
            self.assertFalse(packet["live_execution_approval_captured"])
            self.assertEqual(packet["approval_actions"], [])
            self.assertTrue(packet["approval"]["missing_required_phrases"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_authority_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _live_approval_fixture(store, root, Path(td) / "artifacts")
            state = store.load()
            record = state["doc_action_patch_live_execution_approval_packets"][
                fixture["live_execution_approval_packet"]["doc_action_patch_live_execution_approval_packet_id"]
            ]
            record["source_file_write_allowed"] = True
            record["doc_action_patch_live_execution_approval_packet_sha256"] = _hash_without(
                record,
                "doc_action_patch_live_execution_approval_packet_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn(
                "doc_action_patch_live_execution_approval.source_file_write_allowed_not_false",
                "\n".join(replay["errors"]),
            )

    def test_replay_catches_stale_dry_run_readback_after_approval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _live_approval_fixture(store, root, Path(td) / "artifacts")
            state = store.load()
            receipt = state["doc_action_patch_dry_run_readback_receipts"][
                fixture["dry_run_readback_receipt"]["doc_action_patch_dry_run_readback_receipt_id"]
            ]
            receipt["label"] = "tampered-dry-run-readback"
            receipt["doc_action_patch_dry_run_readback_receipt_sha256"] = _hash_without(
                receipt,
                "doc_action_patch_dry_run_readback_receipt_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn(
                "doc_action_patch_live_execution_approval.dry_run_readback_hash_mismatch",
                "\n".join(replay["errors"]),
            )

    def test_replay_catches_source_drift_after_approval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _live_approval_fixture(store, root, Path(td) / "artifacts")
            source_path = fixture["live_execution_approval_packet"]["selected_execution_action"]["source_path"]
            (root / source_path).write_text("# Changed\n", encoding="utf-8")

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn(
                "doc_action_patch_live_execution_approval.selected_action_source_hash_matches_dry_run_mismatch",
                "\n".join(replay["errors"]),
            )

    def test_replay_catches_phrase_evidence_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _live_approval_fixture(store, root, Path(td) / "artifacts")
            state = store.load()
            record = state["doc_action_patch_live_execution_approval_packets"][
                fixture["live_execution_approval_packet"]["doc_action_patch_live_execution_approval_packet_id"]
            ]
            record["approval"]["phrase_results"][0]["evidence_sha256"] = "sha256:" + ("0" * 64)
            record["doc_action_patch_live_execution_approval_packet_sha256"] = _hash_without(
                record,
                "doc_action_patch_live_execution_approval_packet_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_live_execution_approval.phrase_evidence_mismatch", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_doc_action_patch_live_execution_approval_packets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            _live_approval_fixture(store, root, Path(td) / "artifacts")

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("doc_action_patch_live_execution_approval_packets", collections)


def _live_approval_fixture(store: JsonStore, root: Path, artifact_root: Path) -> dict[str, dict]:
    fixture = _readback_fixture(store, root, artifact_root)
    live_execution_approval_packet = DocActionPatchLiveExecutionApprovalPacketStore(store).create(
        doc_action_patch_dry_run_readback_receipt_id=fixture["dry_run_readback_receipt"][
            "doc_action_patch_dry_run_readback_receipt_id"
        ],
        approval_ref="local://tests/doc-action-patch-live-execution-approval-ready",
        approval_text=VALID_APPROVAL,
        requested_by="test-operator",
        label="test-doc-action-patch-live-execution-approval-ready",
    )
    return {**fixture, "live_execution_approval_packet": live_execution_approval_packet}


if __name__ == "__main__":
    unittest.main()
