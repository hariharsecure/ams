from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from ams_codex.doc_action_patch_artifact_approval import (
    DocActionPatchArtifactApprovalPacketStore,
    _hash_without,
)
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.store import JsonStore

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_doc_action_patch_artifact import _artifact_fixture
from test_doc_action_patch_preview import _minimal_repo


class DocActionPatchArtifactApprovalPacketTest(unittest.TestCase):
    def test_artifact_approval_packet_binds_selected_artifact_without_authority(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _approval_fixture(store, root, Path(td) / "artifacts")
            packet = fixture["approval_packet"]
            artifact = fixture["artifact_receipt"]["artifacts"][0]

            self.assertEqual(packet["status"], "ready_for_operator_review")
            self.assertTrue(all(packet["required_gates"].values()))
            self.assertEqual(packet["selected_artifact"]["action_id"], artifact["action_id"])
            self.assertEqual(packet["selected_artifact"]["artifact_sha256"], artifact["artifact_sha256"])
            self.assertTrue(packet["selected_artifact"]["artifact_hash_verified"])
            self.assertTrue(packet["selected_artifact"]["source_hash_matches_artifact_receipt"])
            self.assertFalse(packet["approval_granted"])
            self.assertFalse(packet["live_execution_allowed"])
            self.assertFalse(packet["source_file_write_allowed"])
            self.assertFalse(packet["live_boundaries"]["patch_artifact_written"])
            self.assertFalse(packet["live_boundaries"]["source_file_rewritten"])
            self.assertEqual(packet["approval_actions"], [])
            self.assertEqual(packet["execution_actions"], [])
            self.assertEqual(packet["source_write_actions"], [])
            self.assertNotIn("secret body", str(packet))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_artifact_file_tamper_after_approval_packet(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _approval_fixture(store, root, Path(td) / "artifacts")
            artifact_path = Path(fixture["approval_packet"]["selected_artifact"]["artifact_path"])
            artifact_path.write_text("tampered patch\n", encoding="utf-8")

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_artifact_approval.artifact_hash_mismatch", "\n".join(replay["errors"]))

    def test_create_defaults_to_artifact_receipt_source_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _artifact_fixture(store, root, Path(td) / "artifacts")

            packet = DocActionPatchArtifactApprovalPacketStore(store).create(
                doc_action_patch_artifact_receipt_id=fixture["artifact_receipt"][
                    "doc_action_patch_artifact_receipt_id"
                ],
                label="test-doc-action-patch-artifact-approval-default-root",
            )

            self.assertEqual(packet["source_root"], str(root.resolve(strict=False)))
            self.assertEqual(packet["status"], "ready_for_operator_review")
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_source_drift_after_approval_packet(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _approval_fixture(store, root, Path(td) / "artifacts")
            source_path = fixture["approval_packet"]["selected_artifact"]["source_path"]
            (root / source_path).write_text("# Changed\n", encoding="utf-8")

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_artifact_approval.source_ref_sha256_mismatch", "\n".join(replay["errors"]))

    def test_replay_catches_approval_authority_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _approval_fixture(store, root, Path(td) / "artifacts")
            state = store.load()
            record = state["doc_action_patch_artifact_approval_packets"][
                fixture["approval_packet"]["doc_action_patch_artifact_approval_packet_id"]
            ]
            record["live_execution_allowed"] = True
            record["doc_action_patch_artifact_approval_packet_sha256"] = _hash_without(
                record,
                "doc_action_patch_artifact_approval_packet_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_artifact_approval.live_execution_allowed_not_false", "\n".join(replay["errors"]))

    def test_replay_catches_artifact_receipt_hash_drift_after_approval_packet(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _approval_fixture(store, root, Path(td) / "artifacts")
            state = store.load()
            receipt = state["doc_action_patch_artifact_receipts"][
                fixture["artifact_receipt"]["doc_action_patch_artifact_receipt_id"]
            ]
            receipt["label"] = "tampered-artifact-receipt"
            receipt["doc_action_patch_artifact_receipt_sha256"] = _hash_without(
                receipt,
                "doc_action_patch_artifact_receipt_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_artifact_approval.artifact_receipt_hash_mismatch", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_doc_action_patch_artifact_approval_packets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            _approval_fixture(store, root, Path(td) / "artifacts")

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("doc_action_patch_artifact_approval_packets", collections)


def _approval_fixture(store: JsonStore, root: Path, artifact_root: Path) -> dict[str, dict]:
    fixture = _artifact_fixture(store, root, artifact_root)
    approval_packet = DocActionPatchArtifactApprovalPacketStore(store).create(
        doc_action_patch_artifact_receipt_id=fixture["artifact_receipt"]["doc_action_patch_artifact_receipt_id"],
        source_root=root,
        label="test-doc-action-patch-artifact-approval",
    )
    return {**fixture, "approval_packet": approval_packet}


if __name__ == "__main__":
    unittest.main()
