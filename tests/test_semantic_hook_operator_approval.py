from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.semantic_hook_operator_approval import (
    REQUIRED_READBACK_PHRASES,
    REQUIRED_REVIEW_STEPS,
    SemanticHookOperatorApprovalPacketStore,
    _hash_without,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_semantic_hook_install_transaction import _create_ready_transaction
from test_semantic_hook_target_snapshot import SSH_KEYGEN, _create_ready_snapshot, _fixture_with_binding


@unittest.skipUnless(SSH_KEYGEN, "ssh-keygen required for semantic hook operator approval tests")
class SemanticHookOperatorApprovalPacketTest(unittest.TestCase):
    def test_ready_operator_packet_is_inert_and_requires_review(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _fixture_with_binding(root)
            snapshot = _create_ready_snapshot(fixture)
            transaction = _create_ready_transaction(fixture, snapshot)

            packet = SemanticHookOperatorApprovalPacketStore(fixture["store"]).create(
                semantic_hook_install_transaction_id=transaction["semantic_hook_install_transaction_id"],
                source_root=Path.cwd(),
                label="test-semantic-hook-operator-approval",
            )

            self.assertEqual(packet["status"], "ready_for_operator_review")
            self.assertTrue(all(packet["required_gates"].values()))
            self.assertFalse(packet["approval_granted"])
            self.assertFalse(packet["live_install_allowed"])
            self.assertFalse(packet["hook_file_write_allowed"])
            self.assertFalse(packet["hook_trust_allowed"])
            self.assertFalse(packet["provider_hook_execution_allowed"])
            self.assertEqual(packet["approval_actions"], [])
            self.assertEqual(packet["install_actions"], [])
            self.assertEqual(packet["trust_actions"], [])
            self.assertEqual(packet["start_actions"], [])
            self.assertEqual(packet["approval_request"]["required_review_steps"], REQUIRED_REVIEW_STEPS)
            self.assertEqual(packet["approval_request"]["required_readback_phrases"], REQUIRED_READBACK_PHRASES)
            self.assertFalse(packet["approval_request"]["operator_readback_captured"])
            self.assertFalse(packet["approval_request"]["raw_readback_stored"])
            self.assertEqual(packet["transaction_summary"]["target_count"], 3)
            self.assertEqual(packet["transaction_summary"]["payload_rendering_count"], 3)
            self.assertTrue(packet["transaction_summary"]["payload_hashes_match"])
            self.assertTrue(packet["provenance_summary"]["signed_package_verified"])
            self.assertTrue(packet["freshness"]["target_snapshot_hash_current"])
            self.assertTrue(ReplayChecker(fixture["store"]).check()["ok"])

    def test_replay_catches_packet_authority_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _fixture_with_binding(root)
            snapshot = _create_ready_snapshot(fixture)
            transaction = _create_ready_transaction(fixture, snapshot)
            packet = _create_ready_operator_packet(fixture, transaction)
            state = fixture["store"].load()
            record = state["semantic_hook_operator_approval_packets"][
                packet["semantic_hook_operator_approval_packet_id"]
            ]
            record["approval_granted"] = True
            record["semantic_hook_operator_approval_packet_sha256"] = _hash_without(
                record,
                "semantic_hook_operator_approval_packet_sha256",
            )
            fixture["store"].save(state, validate=False)

            replay = ReplayChecker(fixture["store"]).check()

            self.assertFalse(replay["ok"])
            self.assertIn(
                "semantic_hook_operator_approval.approval_granted_not_false",
                "\n".join(replay["errors"]),
            )

    def test_replay_catches_stale_transaction_after_packet(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _fixture_with_binding(root)
            snapshot = _create_ready_snapshot(fixture)
            transaction = _create_ready_transaction(fixture, snapshot)
            _create_ready_operator_packet(fixture, transaction)
            state = fixture["store"].load()
            record = state["semantic_hook_install_transactions"][transaction["semantic_hook_install_transaction_id"]]
            record["live_install_allowed"] = True
            record["semantic_hook_install_transaction_sha256"] = _hash_without(
                record,
                "semantic_hook_install_transaction_sha256",
            )
            fixture["store"].save(state, validate=False)

            replay = ReplayChecker(fixture["store"]).check()

            self.assertFalse(replay["ok"])
            joined = "\n".join(replay["errors"])
            self.assertIn("semantic_hook_operator_approval", joined)
            self.assertIn("install transaction hash mismatch", joined)
            self.assertIn("semantic_hook_install_transaction.live_install_allowed_not_false", joined)

    def test_replay_catches_summary_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _fixture_with_binding(root)
            snapshot = _create_ready_snapshot(fixture)
            transaction = _create_ready_transaction(fixture, snapshot)
            packet = _create_ready_operator_packet(fixture, transaction)
            state = fixture["store"].load()
            record = state["semantic_hook_operator_approval_packets"][
                packet["semantic_hook_operator_approval_packet_id"]
            ]
            record["provenance_summary"]["signed_package_verified"] = False
            record["semantic_hook_operator_approval_packet_sha256"] = _hash_without(
                record,
                "semantic_hook_operator_approval_packet_sha256",
            )
            fixture["store"].save(state, validate=False)

            replay = ReplayChecker(fixture["store"]).check()

            self.assertFalse(replay["ok"])
            self.assertIn(
                "semantic_hook_operator_approval.provenance_summary_mismatch",
                "\n".join(replay["errors"]),
            )

    def test_replay_oracle_covers_semantic_hook_operator_approval_packets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _fixture_with_binding(root)
            snapshot = _create_ready_snapshot(fixture)
            transaction = _create_ready_transaction(fixture, snapshot)
            _create_ready_operator_packet(fixture, transaction)

            result = ReplayOracle(fixture["store"]).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("semantic_hook_operator_approval_packets", collections)


def _create_ready_operator_packet(fixture: dict[str, object], transaction: dict[str, object]) -> dict[str, object]:
    return SemanticHookOperatorApprovalPacketStore(fixture["store"]).create(
        semantic_hook_install_transaction_id=transaction["semantic_hook_install_transaction_id"],
        source_root=Path.cwd(),
        label="test-semantic-hook-operator-approval-ready",
    )


if __name__ == "__main__":
    unittest.main()
