from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from ams.doc_action_patch_apply_acceptance import (
    DocActionPatchApplyAcceptancePacketStore,
    REQUIRED_ACCEPTANCE_PHRASES,
    _hash_without,
)
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.store import JsonStore

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_doc_action_patch_apply_boundary import _apply_boundary_fixture
from test_doc_action_patch_preview import _minimal_repo


VALID_ACCEPTANCE = (
    "I accept this doc action apply boundary. "
    "Apply boundary packet hash matches this acceptance packet. "
    "Preflight artifact and source hashes must be rechecked before write. "
    "Rollback preimage and backup evidence are required before write. "
    "Post apply readback is required before settlement. "
    "Only the listed source file action is in scope. "
    "This acceptance packet is not an executor. "
    "Generated surface rewrites remain disabled. "
    "Source deletes moves and archives remain disabled."
)


class DocActionPatchApplyAcceptancePacketTest(unittest.TestCase):
    def test_apply_acceptance_consumes_boundary_without_applying(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _apply_acceptance_fixture(store, root, Path(td) / "artifacts")
            packet = fixture["apply_acceptance_packet"]

            self.assertEqual(packet["status"], "accepted_for_backup_preimage_review")
            self.assertTrue(all(packet["required_gates"].values()))
            self.assertEqual(packet["required_acceptance_phrases"], REQUIRED_ACCEPTANCE_PHRASES)
            self.assertTrue(packet["operator_apply_acceptance_captured"])
            self.assertTrue(packet["accepted_for_backup_preimage_review"])
            self.assertFalse(packet["acceptance"]["raw_acceptance_stored"])
            self.assertTrue(packet["acceptance"]["required_phrases_present"])
            self.assertEqual(packet["acceptance"]["missing_required_phrases"], [])
            self.assertTrue(packet["accepted_apply_action"]["artifact_hash_verified"])
            self.assertTrue(packet["accepted_apply_action"]["source_hash_matches_boundary"])
            self.assertTrue(packet["accepted_apply_action"]["source_hash_matches_approved_source"])
            self.assertFalse(packet["accepted_apply_action"]["backup_evidence_captured"])
            self.assertFalse(packet["accepted_apply_action"]["post_apply_readback_captured"])
            self.assertFalse(packet["apply_allowed"])
            self.assertFalse(packet["live_execution_allowed"])
            self.assertFalse(packet["source_file_write_allowed"])
            self.assertFalse(packet["source_backup_write_allowed"])
            self.assertFalse(packet["archive_create_allowed"])
            self.assertFalse(packet["generated_surface_rewrite_allowed"])
            self.assertFalse(packet["provider_call_allowed"])
            self.assertFalse(packet["network_call_allowed"])
            self.assertEqual(len(packet["acceptance_actions"]), 1)
            self.assertEqual(packet["execution_actions"], [])
            self.assertEqual(packet["source_write_actions"], [])
            self.assertEqual(packet["backup_actions"], [])
            self.assertTrue(packet["live_boundaries"]["operator_apply_acceptance_captured"])
            self.assertFalse(packet["live_boundaries"]["source_file_rewritten"])
            self.assertFalse(packet["live_boundaries"]["terminal_injection_performed"])
            self.assertNotIn("I accept this doc action apply boundary", str(packet))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_apply_acceptance_blocks_when_required_phrase_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _apply_boundary_fixture(store, root, Path(td) / "artifacts")

            packet = DocActionPatchApplyAcceptancePacketStore(store).create(
                doc_action_patch_apply_boundary_packet_id=fixture["apply_boundary_packet"][
                    "doc_action_patch_apply_boundary_packet_id"
                ],
                acceptance_ref="local://test/incomplete",
                acceptance_text="I accept this doc action apply boundary.",
                requested_by="operator",
                source_root=root,
                label="test-doc-action-patch-apply-acceptance-blocked",
            )

            self.assertEqual(packet["status"], "blocked")
            self.assertFalse(packet["operator_apply_acceptance_captured"])
            self.assertFalse(packet["accepted_for_backup_preimage_review"])
            self.assertEqual(packet["acceptance_actions"], [])
            self.assertNotEqual(packet["acceptance"]["missing_required_phrases"], [])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_authority_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _apply_acceptance_fixture(store, root, Path(td) / "artifacts")
            state = store.load()
            record = state["doc_action_patch_apply_acceptance_packets"][
                fixture["apply_acceptance_packet"]["doc_action_patch_apply_acceptance_packet_id"]
            ]
            record["source_file_write_allowed"] = True
            record["doc_action_patch_apply_acceptance_packet_sha256"] = _hash_without(
                record,
                "doc_action_patch_apply_acceptance_packet_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_apply_acceptance.source_file_write_allowed_not_false", "\n".join(replay["errors"]))

    def test_replay_catches_stale_apply_boundary_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _apply_acceptance_fixture(store, root, Path(td) / "artifacts")
            state = store.load()
            boundary = state["doc_action_patch_apply_boundary_packets"][
                fixture["apply_boundary_packet"]["doc_action_patch_apply_boundary_packet_id"]
            ]
            boundary["label"] = "tampered-doc-action-patch-apply-boundary"
            boundary["doc_action_patch_apply_boundary_packet_sha256"] = _hash_without(
                boundary,
                "doc_action_patch_apply_boundary_packet_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_apply_acceptance.apply_boundary_packet_hash_mismatch", "\n".join(replay["errors"]))

    def test_replay_catches_source_drift_after_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _apply_acceptance_fixture(store, root, Path(td) / "artifacts")
            source_path = fixture["apply_acceptance_packet"]["accepted_apply_action"]["source_path"]
            (root / source_path).write_text("# Changed\n", encoding="utf-8")

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn(
                "doc_action_patch_apply_acceptance.accepted_action_source_hash_matches_boundary_mismatch",
                "\n".join(replay["errors"]),
            )

    def test_replay_catches_artifact_tamper_after_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _apply_acceptance_fixture(store, root, Path(td) / "artifacts")
            artifact_path = Path(fixture["apply_acceptance_packet"]["accepted_apply_action"]["artifact_path"])
            artifact_path.write_text("tampered patch\n", encoding="utf-8")

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn(
                "doc_action_patch_apply_acceptance.accepted_action_artifact_hash_verified_mismatch",
                "\n".join(replay["errors"]),
            )

    def test_replay_catches_phrase_evidence_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _apply_acceptance_fixture(store, root, Path(td) / "artifacts")
            state = store.load()
            record = state["doc_action_patch_apply_acceptance_packets"][
                fixture["apply_acceptance_packet"]["doc_action_patch_apply_acceptance_packet_id"]
            ]
            record["acceptance"]["phrase_results"][0]["evidence_sha256"] = "sha256:" + ("0" * 64)
            record["doc_action_patch_apply_acceptance_packet_sha256"] = _hash_without(
                record,
                "doc_action_patch_apply_acceptance_packet_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_apply_acceptance.phrase_evidence_mismatch", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_doc_action_patch_apply_acceptance_packets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            _apply_acceptance_fixture(store, root, Path(td) / "artifacts")

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("doc_action_patch_apply_acceptance_packets", collections)


def _apply_acceptance_fixture(store: JsonStore, root: Path, artifact_root: Path) -> dict[str, dict]:
    fixture = _apply_boundary_fixture(store, root, artifact_root)
    apply_acceptance_packet = DocActionPatchApplyAcceptancePacketStore(store).create(
        doc_action_patch_apply_boundary_packet_id=fixture["apply_boundary_packet"][
            "doc_action_patch_apply_boundary_packet_id"
        ],
        acceptance_ref="local://test/apply-acceptance",
        acceptance_text=VALID_ACCEPTANCE,
        requested_by="operator",
        source_root=root,
        label="test-doc-action-patch-apply-acceptance-ready",
    )
    return {**fixture, "apply_acceptance_packet": apply_acceptance_packet}


if __name__ == "__main__":
    unittest.main()
