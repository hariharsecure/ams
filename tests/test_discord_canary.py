from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.admission import AdmissionReviewStore
from ams.context import ContextStore
from ams.discord_canary import DiscordCanarySendPlanStore
from ams.discord_source import DiscordSourcePacketStore
from ams.outbox import OutboxStore
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.run_trace import RunTraceStore
from ams.session_registry import SessionRegistry
from ams.store import JsonStore
from ams.surface_promise import SurfacePromiseStore


class DiscordCanarySendPlanTest(unittest.TestCase):
    def test_ready_canary_send_plan_stays_inert(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fixture = _canary_fixture(Path(td))

            plan = DiscordCanarySendPlanStore(fixture["store"]).create(
                outbox_id=fixture["outbox"]["outbox_id"],
                admission_review_id=fixture["admission"]["admission_review_id"],
                surface_promise_id=fixture["promise"]["surface_promise_id"],
                discord_source_packet_id=fixture["source"]["discord_source_packet_id"],
                operator_review_ref="local://milestone-26/operator-review",
            )

            self.assertEqual(plan["status"], "ready_for_operator_approval")
            self.assertEqual(plan["reason_codes"], ["discord_canary.ready_for_operator_approval"])
            self.assertTrue(plan["canary_mode"])
            self.assertFalse(plan["network_call_allowed"])
            self.assertFalse(plan["send_performed"])
            self.assertFalse(plan["gateway_started"])
            self.assertFalse(plan["token_stored"])
            self.assertTrue(plan["readback_required"])
            self.assertEqual(plan["nonce_semantics"], "provider_validation_only")
            self.assertFalse(plan["exactly_once_claimed"])
            self.assertTrue(all(plan["required_gates"].values()))
            self.assertTrue(ReplayChecker(fixture["store"]).check()["ok"])

    def test_denied_admission_blocks_canary_plan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fixture = _canary_fixture(Path(td), admission_status="defer")

            plan = DiscordCanarySendPlanStore(fixture["store"]).create(
                outbox_id=fixture["outbox"]["outbox_id"],
                admission_review_id=fixture["admission"]["admission_review_id"],
            )

            self.assertEqual(plan["status"], "blocked")
            self.assertIn("discord_canary.admission_allows_canary_missing", plan["reason_codes"])
            self.assertTrue(ReplayChecker(fixture["store"]).check()["ok"])

    def test_replay_catches_canary_send_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fixture = _canary_fixture(Path(td))
            plan = DiscordCanarySendPlanStore(fixture["store"]).create(
                outbox_id=fixture["outbox"]["outbox_id"],
                admission_review_id=fixture["admission"]["admission_review_id"],
            )
            state = fixture["store"].load()
            state["discord_canary_send_plans"][plan["discord_canary_send_plan_id"]]["send_performed"] = True
            fixture["store"].save(state, validate=False)

            replay = ReplayChecker(fixture["store"]).check()

            self.assertFalse(replay["ok"])
            self.assertIn("discord_canary.send_performed_not_false", "\n".join(replay["errors"]))

    def test_replay_catches_exactly_once_claim_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fixture = _canary_fixture(Path(td))
            plan = DiscordCanarySendPlanStore(fixture["store"]).create(
                outbox_id=fixture["outbox"]["outbox_id"],
                admission_review_id=fixture["admission"]["admission_review_id"],
            )
            state = fixture["store"].load()
            state["discord_canary_send_plans"][plan["discord_canary_send_plan_id"]]["exactly_once_claimed"] = True
            fixture["store"].save(state, validate=False)

            replay = ReplayChecker(fixture["store"]).check()

            self.assertFalse(replay["ok"])
            self.assertIn("discord_canary.exactly_once_claimed_not_false", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_discord_canary_send_plans(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fixture = _canary_fixture(Path(td))
            DiscordCanarySendPlanStore(fixture["store"]).create(
                outbox_id=fixture["outbox"]["outbox_id"],
                admission_review_id=fixture["admission"]["admission_review_id"],
                surface_promise_id=fixture["promise"]["surface_promise_id"],
                discord_source_packet_id=fixture["source"]["discord_source_packet_id"],
            )

            result = ReplayOracle(fixture["store"]).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("discord_canary_send_plans", collections)


def _canary_fixture(root: Path, *, admission_status: str = "allow") -> dict:
    store = JsonStore(root / "store.json")
    event = {
        "channel_id": "chan",
        "message_id": "root",
        "content": "discord canary root",
        "attention_id": "attn-canary",
    }
    session, _ = SessionRegistry(store).ingest_event(event)
    context = ContextStore(store).create_for_event(session, event)
    task_run = RunTraceStore(store).create_run(
        session["session_id"],
        context["context_id"],
        provider="openai_codex",
        provider_surface="app-server",
        model="gpt-5.5",
        sandbox="workspace-write",
        tool_scope=["Read"],
    )
    outbox = OutboxStore(store).create_item(
        task_run["task_run_id"],
        target="discord",
        channel_id="chan",
        endpoint="/channels/chan/messages",
        method="POST",
        payload={"content": "canary dry run"},
    )
    admission = AdmissionReviewStore(store).create(
        subject_kind="outbox_item",
        subject_id=outbox["outbox_id"],
        operation="egress.discord.canary_send",
        request={"outbox_id": outbox["outbox_id"], "mode": "canary"},
        status=admission_status,
        reason_codes=[f"discord_canary.admission_{admission_status}"],
    )
    promise = SurfacePromiseStore(store).create(
        task_run["task_run_id"],
        promised_surfaces=[
            {
                "surface": "discord",
                "target": "discord",
                "channel_id": "chan",
                "outbox_id": outbox["outbox_id"],
                "required": True,
                "required_readback": True,
            }
        ],
        source_packet_ref="discord://chan/source-msg",
        promise_reason="discord_canary_send_plan_test",
    )
    source = DiscordSourcePacketStore(store).create(
        {
            "channel_id": "chan",
            "message_id": "source-msg",
            "content_sha256": "sha256:" + "6" * 64,
            "summary": "Discord canary source packet.",
        }
    )
    return {
        "store": store,
        "session": session,
        "context": context,
        "task_run": task_run,
        "outbox": outbox,
        "admission": admission,
        "promise": promise,
        "source": source,
    }


if __name__ == "__main__":
    unittest.main()
