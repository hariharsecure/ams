from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from ams.backup_restore import StoreBackupDrillStore
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.runner_parity import RunnerDryRunParityStore
from ams.shadow_approval import ShadowApprovalPacketStore
from ams.shadow_runner import ShadowRunnerStore
from ams.workspace import workspace_root

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_runner_parity import SSH_KEYGEN, _live_preflight, _signed_manifest_dispatch_and_launch  # noqa: E402


READY_READBACK = (
    "No persistent process will start from this packet. "
    "Egress mode is none. "
    "Discord provider terminal injection remain disabled. "
    "Rollback is discard packet and restore from backup."
)


@unittest.skipUnless(SSH_KEYGEN, "ssh-keygen required for shadow approval tests")
class ShadowApprovalPacketTest(unittest.TestCase):
    def test_ready_shadow_approval_packet_is_replayable_and_inert(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _approval_fixture(root)

            packet = ShadowApprovalPacketStore(fixture["store"]).create(
                shadow_launch_plan_id=fixture["plan"]["shadow_launch_plan_id"],
                shadow_runner_transaction_id=fixture["transaction"]["shadow_runner_transaction_id"],
                runner_dry_run_parity_id=fixture["parity"]["runner_dry_run_parity_id"],
                store_backup_drill_id=fixture["drill"]["store_backup_drill_id"],
                requested_by="operator:test",
                readback_ref="local://shadow-approval/readback",
                readback_text=READY_READBACK,
            )

            self.assertEqual(packet["status"], "ready_for_operator_approval")
            self.assertEqual(packet["reason_codes"], ["shadow_approval.ready_for_operator_approval"])
            self.assertFalse(packet["approval_granted"])
            self.assertFalse(packet["live_start_allowed"])
            self.assertFalse(packet["process_start_allowed"])
            self.assertFalse(packet["network_egress_allowed"])
            self.assertEqual(packet["start_actions"], [])
            self.assertTrue(all(packet["required_gates"].values()))
            self.assertTrue(ReplayChecker(fixture["store"]).check()["ok"])

    def test_missing_operator_readback_phrase_blocks_packet(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _approval_fixture(root)

            packet = ShadowApprovalPacketStore(fixture["store"]).create(
                shadow_launch_plan_id=fixture["plan"]["shadow_launch_plan_id"],
                shadow_runner_transaction_id=fixture["transaction"]["shadow_runner_transaction_id"],
                runner_dry_run_parity_id=fixture["parity"]["runner_dry_run_parity_id"],
                store_backup_drill_id=fixture["drill"]["store_backup_drill_id"],
                requested_by="operator:test",
                readback_ref="local://shadow-approval/readback",
                readback_text="No persistent process will start from this packet. Egress mode is none.",
            )

            self.assertEqual(packet["status"], "blocked")
            self.assertFalse(packet["required_gates"]["operator_readback_required_phrases"])
            self.assertIn(
                "shadow_approval.operator_readback_required_phrases_missing",
                packet["reason_codes"],
            )
            self.assertTrue(
                any(reason.startswith("shadow_approval.readback_phrase_missing:") for reason in packet["reason_codes"])
            )
            self.assertTrue(ReplayChecker(fixture["store"]).check()["ok"])

    def test_replay_catches_shadow_approval_live_start_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _approval_fixture(root)
            packet = _create_ready_packet(fixture)
            state = fixture["store"].load()
            state["shadow_approval_packets"][packet["shadow_approval_packet_id"]]["live_start_allowed"] = True
            fixture["store"].save(state, validate=False)

            replay = ReplayChecker(fixture["store"]).check()

            self.assertFalse(replay["ok"])
            self.assertIn("shadow_approval.live_start_allowed_not_false", "\n".join(replay["errors"]))

    def test_replay_catches_stale_shadow_runner_prerequisite(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _approval_fixture(root)
            _create_ready_packet(fixture)
            state = fixture["store"].load()
            transaction_id = fixture["transaction"]["shadow_runner_transaction_id"]
            state["shadow_runner_transactions"][transaction_id]["process_start_allowed"] = True
            fixture["store"].save(state, validate=False)

            replay = ReplayChecker(fixture["store"]).check()

            self.assertFalse(replay["ok"])
            self.assertIn("shadow_approval.required_gates_mismatch", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_shadow_approval_packets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _approval_fixture(root)
            _create_ready_packet(fixture)

            result = ReplayOracle(fixture["store"]).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("shadow_approval_packets", collections)


def _approval_fixture(root: Path) -> dict:
    store, envelope, package = _signed_manifest_dispatch_and_launch(root)
    preflight = _live_preflight(store, envelope, package["launch_plan"])
    parity = RunnerDryRunParityStore(store).create(
        envelope=envelope,
        package_verification=package["verification"],
        package_manifest=package["manifest_json"],
        runner_preflight_result=preflight,
    )
    transaction = ShadowRunnerStore(store).create_transaction(
        runner_preflight=preflight,
        argv=["/bin/echo", "shadow-runner"],
        cwd=workspace_root(),
        requested_by="operator:test",
        approval_id="approval-shadow-approval-test",
        purpose="test no-egress shadow approval packet",
        env_names=["PATH"],
        redacted_env_names=["DISCORD_TOKEN"],
        abort_conditions=["approval packet becomes stale"],
        rollback_steps=["discard packet and restore from backup"],
    )
    drill = StoreBackupDrillStore(store).create(
        backup_path=root / "backup.json",
        restore_path=root / "restore.json",
        label="shadow-approval-drill",
    )
    return {
        "store": store,
        "plan": package["launch_plan"],
        "parity": parity,
        "transaction": transaction,
        "drill": drill,
    }


def _create_ready_packet(fixture: dict) -> dict:
    return ShadowApprovalPacketStore(fixture["store"]).create(
        shadow_launch_plan_id=fixture["plan"]["shadow_launch_plan_id"],
        shadow_runner_transaction_id=fixture["transaction"]["shadow_runner_transaction_id"],
        runner_dry_run_parity_id=fixture["parity"]["runner_dry_run_parity_id"],
        store_backup_drill_id=fixture["drill"]["store_backup_drill_id"],
        requested_by="operator:test",
        readback_ref="local://shadow-approval/readback",
        readback_text=READY_READBACK,
    )


if __name__ == "__main__":
    unittest.main()
