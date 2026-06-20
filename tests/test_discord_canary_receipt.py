from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from ams.discord_canary import DiscordCanarySendPlanStore
from ams.discord_canary_receipt import DiscordCanaryReceiptStore
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_discord_canary import _canary_fixture  # noqa: E402


class DiscordCanaryReceiptTest(unittest.TestCase):
    def test_records_external_observed_receipt_without_live_network(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fixture = _canary_fixture(Path(td))
            plan = _ready_plan(fixture)
            response_payload = {"message_id": "discord-msg-1", "nonce": plan["outbox_nonce"]}

            receipt = DiscordCanaryReceiptStore(fixture["store"]).create(
                discord_canary_send_plan_id=plan["discord_canary_send_plan_id"],
                response_payload=response_payload,
                readback_ref="discord://chan/discord-msg-1",
                observed_nonce=plan["outbox_nonce"],
            )

            self.assertEqual(receipt["status"], "recorded")
            self.assertEqual(receipt["reason_codes"], ["discord_canary_receipt.recorded"])
            self.assertEqual(receipt["provider_message_id"], "discord-msg-1")
            self.assertTrue(receipt["nonce_match"])
            self.assertFalse(receipt["network_call_performed"])
            self.assertFalse(receipt["token_stored"])
            self.assertFalse(receipt["raw_content_stored"])
            self.assertFalse(receipt["exactly_once_claimed"])

            state = fixture["store"].load()
            outbox = state["outbox_items"][fixture["outbox"]["outbox_id"]]
            self.assertEqual(outbox["state"], "readback_verified")
            self.assertEqual(outbox["last_receipt_id"], receipt["outbox_receipt_id"])
            promise = state["surface_promises"][fixture["promise"]["surface_promise_id"]]
            self.assertEqual(promise["surface_delivery_status"], "delivered_and_readback_verified")
            self.assertTrue(ReplayChecker(fixture["store"]).check()["ok"])

    def test_nonce_mismatch_blocks_without_receipt_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fixture = _canary_fixture(Path(td))
            plan = _ready_plan(fixture)

            receipt = DiscordCanaryReceiptStore(fixture["store"]).create(
                discord_canary_send_plan_id=plan["discord_canary_send_plan_id"],
                response_payload={"message_id": "discord-msg-2", "nonce": "wrong"},
                readback_ref="discord://chan/discord-msg-2",
                observed_nonce="wrong",
            )

            self.assertEqual(receipt["status"], "blocked")
            self.assertIn("discord_canary_receipt.nonce_matches_plan_missing", receipt["reason_codes"])
            state = fixture["store"].load()
            self.assertEqual(state["outbox_items"][fixture["outbox"]["outbox_id"]]["state"], "queued")
            self.assertEqual(state["outbox_receipts"], {})
            self.assertTrue(ReplayChecker(fixture["store"]).check()["ok"])

    def test_missing_provider_message_id_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fixture = _canary_fixture(Path(td))
            plan = _ready_plan(fixture)

            receipt = DiscordCanaryReceiptStore(fixture["store"]).create(
                discord_canary_send_plan_id=plan["discord_canary_send_plan_id"],
                response_payload={"nonce": plan["outbox_nonce"]},
                readback_ref="discord://chan/missing-provider-id",
                observed_nonce=plan["outbox_nonce"],
            )

            self.assertEqual(receipt["status"], "blocked")
            self.assertIn("discord_canary_receipt.provider_message_id_present_missing", receipt["reason_codes"])
            self.assertTrue(ReplayChecker(fixture["store"]).check()["ok"])

    def test_replay_catches_network_flag_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fixture = _canary_fixture(Path(td))
            plan = _ready_plan(fixture)
            receipt = _recorded_receipt(fixture, plan)
            state = fixture["store"].load()
            state["discord_canary_receipts"][receipt["discord_canary_receipt_id"]]["network_call_performed"] = True
            fixture["store"].save(state, validate=False)

            replay = ReplayChecker(fixture["store"]).check()

            self.assertFalse(replay["ok"])
            self.assertIn("discord_canary_receipt.network_call_performed_not_false", "\n".join(replay["errors"]))

    def test_replay_catches_outbox_receipt_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fixture = _canary_fixture(Path(td))
            plan = _ready_plan(fixture)
            receipt = _recorded_receipt(fixture, plan)
            state = fixture["store"].load()
            outbox_receipt = state["outbox_receipts"][receipt["outbox_receipt_id"]]
            outbox_receipt["response_payload"]["message_id"] = "discord-msg-changed"
            fixture["store"].save(state, validate=False)

            replay = ReplayChecker(fixture["store"]).check()

            self.assertFalse(replay["ok"])
            self.assertIn("discord_canary_receipt", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_discord_canary_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fixture = _canary_fixture(Path(td))
            plan = _ready_plan(fixture)
            _recorded_receipt(fixture, plan)

            result = ReplayOracle(fixture["store"]).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("discord_canary_receipts", collections)


def _ready_plan(fixture: dict) -> dict:
    return DiscordCanarySendPlanStore(fixture["store"]).create(
        outbox_id=fixture["outbox"]["outbox_id"],
        admission_review_id=fixture["admission"]["admission_review_id"],
        surface_promise_id=fixture["promise"]["surface_promise_id"],
        discord_source_packet_id=fixture["source"]["discord_source_packet_id"],
        operator_review_ref="local://milestone-27/operator-review",
    )


def _recorded_receipt(fixture: dict, plan: dict) -> dict:
    return DiscordCanaryReceiptStore(fixture["store"]).create(
        discord_canary_send_plan_id=plan["discord_canary_send_plan_id"],
        response_payload={"message_id": "discord-msg-1", "nonce": plan["outbox_nonce"]},
        readback_ref="discord://chan/discord-msg-1",
        observed_nonce=plan["outbox_nonce"],
    )


if __name__ == "__main__":
    unittest.main()
