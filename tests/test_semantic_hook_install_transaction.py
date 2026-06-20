from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.semantic_hook_install_transaction import (
    SemanticHookInstallTransactionStore,
    _hash_without,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_semantic_hook_target_snapshot import SSH_KEYGEN, _create_ready_snapshot, _fixture_with_binding


@unittest.skipUnless(SSH_KEYGEN, "ssh-keygen required for semantic hook install transaction tests")
class SemanticHookInstallTransactionTest(unittest.TestCase):
    def test_ready_install_transaction_is_hash_only_and_inert(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _fixture_with_binding(root)
            snapshot = _create_ready_snapshot(fixture)

            transaction = SemanticHookInstallTransactionStore(fixture["store"]).create(
                semantic_hook_target_snapshot_id=snapshot["semantic_hook_target_snapshot_id"],
                source_root=Path.cwd(),
                label="test-semantic-hook-install-transaction",
            )

            self.assertEqual(transaction["status"], "ready_for_operator_review")
            self.assertEqual(transaction["target_count"], 3)
            self.assertTrue(all(transaction["required_gates"].values()))
            self.assertFalse(transaction["approval_granted"])
            self.assertFalse(transaction["live_install_allowed"])
            self.assertFalse(transaction["hook_file_write_allowed"])
            self.assertFalse(transaction["hook_trust_allowed"])
            self.assertFalse(transaction["provider_hook_execution_allowed"])
            self.assertEqual(transaction["install_actions"], [])
            self.assertEqual(transaction["trust_actions"], [])
            self.assertEqual(transaction["start_actions"], [])
            self.assertTrue(all(payload["raw_payload_stored"] is False for payload in transaction["payload_renderings"]))
            self.assertTrue(all(payload["secret_stored"] is False for payload in transaction["payload_renderings"]))
            self.assertTrue(all(payload["write_performed"] is False for payload in transaction["payload_renderings"]))
            self.assertTrue(
                all(
                    payload["payload_sha256"] == payload["expected_config_sha256"]
                    for payload in transaction["payload_renderings"]
                )
            )
            self.assertTrue(
                all(step["write_performed"] is False for step in transaction["install_transaction_steps"])
            )
            self.assertTrue(
                all(step["provider_executed"] is False for step in transaction["install_transaction_steps"])
            )
            self.assertTrue(
                all(step["atomic_rename_required"] is True for step in transaction["install_transaction_steps"])
            )
            self.assertTrue(all(step["fsync_required"] is True for step in transaction["install_transaction_steps"]))
            self.assertTrue(
                all(step["restore_performed"] is False for step in transaction["rollback_transaction_steps"])
            )
            self.assertTrue(
                all(step["backup_file_written"] is False for step in transaction["rollback_transaction_steps"])
            )
            self.assertTrue(all(step["trusted"] is False for step in transaction["trust_review_steps"]))
            self.assertTrue(ReplayChecker(fixture["store"]).check()["ok"])

    def test_replay_catches_payload_hash_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _fixture_with_binding(root)
            snapshot = _create_ready_snapshot(fixture)
            transaction = _create_ready_transaction(fixture, snapshot)
            state = fixture["store"].load()
            record = state["semantic_hook_install_transactions"][transaction["semantic_hook_install_transaction_id"]]
            record["payload_renderings"][0]["payload_sha256"] = "sha256:" + ("0" * 64)
            record["semantic_hook_install_transaction_sha256"] = _hash_without(
                record,
                "semantic_hook_install_transaction_sha256",
            )
            fixture["store"].save(state, validate=False)

            replay = ReplayChecker(fixture["store"]).check()

            self.assertFalse(replay["ok"])
            joined = "\n".join(replay["errors"])
            self.assertIn("semantic_hook_install_transaction.payload_config_hash_mismatch", joined)
            self.assertIn("semantic_hook_install_transaction.payload_renderings_mismatch", joined)

    def test_replay_catches_stale_snapshot_after_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _fixture_with_binding(root)
            snapshot = _create_ready_snapshot(fixture)
            _create_ready_transaction(fixture, snapshot)
            state = fixture["store"].load()
            snapshot_record = state["semantic_hook_target_snapshots"][snapshot["semantic_hook_target_snapshot_id"]]
            snapshot_record["live_install_allowed"] = True
            snapshot_record["semantic_hook_target_snapshot_sha256"] = _hash_without(
                snapshot_record,
                "semantic_hook_target_snapshot_sha256",
            )
            fixture["store"].save(state, validate=False)

            replay = ReplayChecker(fixture["store"]).check()

            self.assertFalse(replay["ok"])
            joined = "\n".join(replay["errors"])
            self.assertIn("semantic_hook_install_transaction", joined)
            self.assertIn("target snapshot hash mismatch", joined)
            self.assertIn("semantic_hook_target_snapshot.live_install_allowed_not_false", joined)

    def test_replay_catches_authority_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _fixture_with_binding(root)
            snapshot = _create_ready_snapshot(fixture)
            transaction = _create_ready_transaction(fixture, snapshot)
            state = fixture["store"].load()
            record = state["semantic_hook_install_transactions"][transaction["semantic_hook_install_transaction_id"]]
            record["hook_file_write_allowed"] = True
            record["semantic_hook_install_transaction_sha256"] = _hash_without(
                record,
                "semantic_hook_install_transaction_sha256",
            )
            fixture["store"].save(state, validate=False)

            replay = ReplayChecker(fixture["store"]).check()

            self.assertFalse(replay["ok"])
            self.assertIn(
                "semantic_hook_install_transaction.hook_file_write_allowed_not_false",
                "\n".join(replay["errors"]),
            )

    def test_replay_oracle_covers_semantic_hook_install_transactions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _fixture_with_binding(root)
            snapshot = _create_ready_snapshot(fixture)
            _create_ready_transaction(fixture, snapshot)

            result = ReplayOracle(fixture["store"]).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("semantic_hook_install_transactions", collections)


def _create_ready_transaction(fixture: dict[str, object], snapshot: dict[str, object]) -> dict[str, object]:
    return SemanticHookInstallTransactionStore(fixture["store"]).create(
        semantic_hook_target_snapshot_id=snapshot["semantic_hook_target_snapshot_id"],
        source_root=Path.cwd(),
        label="test-semantic-hook-install-transaction-ready",
    )


if __name__ == "__main__":
    unittest.main()
