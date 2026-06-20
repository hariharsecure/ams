from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from ams.models import hash_without as _hash_without
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.semantic_hook_operator_approval import REQUIRED_READBACK_PHRASES
from ams.semantic_hook_operator_readback import SemanticHookOperatorReadbackReceiptStore

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_semantic_hook_install_transaction import _create_ready_transaction
from test_semantic_hook_operator_approval import _create_ready_operator_packet
from test_semantic_hook_target_snapshot import SSH_KEYGEN, _create_ready_snapshot, _fixture_with_binding


VALID_READBACK = (
    "I reviewed the semantic hook install transaction. "
    "Hook writes remain disabled. "
    "Hook trust remains disabled. "
    "Provider hook execution remains disabled. "
    "A later explicit approval is required."
)


@unittest.skipUnless(SSH_KEYGEN, "ssh-keygen required for semantic hook operator readback tests")
class SemanticHookOperatorReadbackReceiptTest(unittest.TestCase):
    def test_readback_receipt_verifies_phrases_but_grants_no_authority(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fixture, packet = _ready_fixture(Path(td))

            receipt = SemanticHookOperatorReadbackReceiptStore(fixture["store"]).create(
                semantic_hook_operator_approval_packet_id=packet["semantic_hook_operator_approval_packet_id"],
                readback_ref="local://tests/operator-readback",
                readback_text=VALID_READBACK,
                requested_by="test-operator",
                source_root=Path.cwd(),
                label="test-semantic-hook-operator-readback",
            )

            self.assertEqual(receipt["status"], "readback_verified")
            self.assertTrue(all(receipt["required_gates"].values()))
            self.assertEqual(receipt["required_readback_phrases"], REQUIRED_READBACK_PHRASES)
            self.assertFalse(receipt["readback"]["raw_readback_stored"])
            self.assertTrue(receipt["readback"]["required_phrases_present"])
            self.assertFalse(receipt["approval_granted"])
            self.assertFalse(receipt["live_install_allowed"])
            self.assertFalse(receipt["hook_file_write_allowed"])
            self.assertFalse(receipt["hook_trust_allowed"])
            self.assertFalse(receipt["provider_hook_execution_allowed"])
            self.assertEqual(receipt["approval_actions"], [])
            self.assertEqual(receipt["install_actions"], [])
            self.assertEqual(receipt["trust_actions"], [])
            self.assertEqual(receipt["start_actions"], [])
            self.assertTrue(ReplayChecker(fixture["store"]).check()["ok"])

    def test_missing_phrase_blocks_receipt_without_breaking_replay(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fixture, packet = _ready_fixture(Path(td))

            receipt = SemanticHookOperatorReadbackReceiptStore(fixture["store"]).create(
                semantic_hook_operator_approval_packet_id=packet["semantic_hook_operator_approval_packet_id"],
                readback_ref="local://tests/operator-readback-missing-phrase",
                readback_text="Hook writes remain disabled.",
                requested_by="test-operator",
                source_root=Path.cwd(),
                label="test-semantic-hook-operator-readback-blocked",
            )

            self.assertEqual(receipt["status"], "blocked")
            self.assertFalse(receipt["required_gates"]["required_phrases_present"])
            self.assertIn(
                "semantic_hook_operator_readback.required_phrases_present_missing",
                receipt["reason_codes"],
            )
            self.assertTrue(receipt["readback"]["missing_required_phrases"])
            self.assertTrue(ReplayChecker(fixture["store"]).check()["ok"])

    def test_replay_catches_receipt_authority_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fixture, packet = _ready_fixture(Path(td))
            receipt = _create_ready_readback(fixture, packet)
            state = fixture["store"].load()
            record = state["semantic_hook_operator_readback_receipts"][
                receipt["semantic_hook_operator_readback_receipt_id"]
            ]
            record["approval_granted"] = True
            record["semantic_hook_operator_readback_receipt_sha256"] = _hash_without(
                record,
                "semantic_hook_operator_readback_receipt_sha256",
            )
            fixture["store"].save(state, validate=False)

            replay = ReplayChecker(fixture["store"]).check()

            self.assertFalse(replay["ok"])
            self.assertIn(
                "semantic_hook_operator_readback.approval_granted_not_false",
                "\n".join(replay["errors"]),
            )

    def test_replay_catches_stale_operator_packet_hash_after_readback(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fixture, packet = _ready_fixture(Path(td))
            _create_ready_readback(fixture, packet)
            state = fixture["store"].load()
            packet_record = state["semantic_hook_operator_approval_packets"][
                packet["semantic_hook_operator_approval_packet_id"]
            ]
            packet_record["approval_granted"] = True
            packet_record["semantic_hook_operator_approval_packet_sha256"] = _hash_without(
                packet_record,
                "semantic_hook_operator_approval_packet_sha256",
            )
            fixture["store"].save(state, validate=False)

            replay = ReplayChecker(fixture["store"]).check()

            self.assertFalse(replay["ok"])
            joined = "\n".join(replay["errors"])
            self.assertIn("semantic_hook_operator_readback", joined)
            self.assertIn("operator packet hash mismatch", joined)
            self.assertIn("semantic_hook_operator_approval.approval_granted_not_false", joined)

    def test_replay_oracle_covers_semantic_hook_operator_readback_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fixture, packet = _ready_fixture(Path(td))
            _create_ready_readback(fixture, packet)

            result = ReplayOracle(fixture["store"]).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("semantic_hook_operator_readback_receipts", collections)


def _ready_fixture(root: Path) -> tuple[dict[str, object], dict[str, object]]:
    fixture = _fixture_with_binding(root)
    snapshot = _create_ready_snapshot(fixture)
    transaction = _create_ready_transaction(fixture, snapshot)
    packet = _create_ready_operator_packet(fixture, transaction)
    return fixture, packet


def _create_ready_readback(fixture: dict[str, object], packet: dict[str, object]) -> dict[str, object]:
    return SemanticHookOperatorReadbackReceiptStore(fixture["store"]).create(
        semantic_hook_operator_approval_packet_id=packet["semantic_hook_operator_approval_packet_id"],
        readback_ref="local://tests/operator-readback-ready",
        readback_text=VALID_READBACK,
        requested_by="test-operator",
        source_root=Path.cwd(),
        label="test-semantic-hook-operator-readback-ready",
    )


if __name__ == "__main__":
    unittest.main()
