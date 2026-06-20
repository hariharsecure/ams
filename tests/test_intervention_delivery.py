from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams_codex.attention_router import AttentionRouterStore
from ams_codex.context import ContextStore
from ams_codex.intervention_delivery import ManagerInterventionDeliveryStore
from ams_codex.manager_intervention import ManagerInterventionStore
from ams_codex.outbox import OutboxStore
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.run_trace import RunTraceStore
from ams_codex.session_registry import SessionRegistry
from ams_codex.store import JsonStore
from ams_codex.surface_promise import SurfacePromiseStore


CODEX_CLI_TARGET = {
    "agent_name": "codex",
    "provider": "openai_codex",
    "surface": "codex-cli",
}


def _intervention_store(path: Path) -> tuple[JsonStore, dict, dict, dict, dict, list[dict]]:
    store = JsonStore(path)
    event = {"channel_id": "chan", "message_id": "root", "content": "build"}
    session, _ = SessionRegistry(store).ingest_event(event)
    context = ContextStore(store).create_for_event(session, event)
    task_run = RunTraceStore(store).create_run(
        session["session_id"],
        context["context_id"],
        actor="agent_b",
        provider="openai_codex",
        provider_surface="app-server",
        action="implement_and_verify",
        model="gpt-5.5",
        tool_scope=["Read", "ApplyPatch", "Tests"],
        sandbox="workspace-write",
    )
    signal = AttentionRouterStore(store).ingest(
        {
            "source_surface": "manual",
            "source_ref": "manual://manager-delivery",
            "session_id": session["session_id"],
            "context_id": context["context_id"],
            "task_run_id": task_run["task_run_id"],
            "attention_id": task_run["attention_id"],
            "content": "Please update the AMS build state before the next dispatch.",
            "priority": "P2",
            "ack_required": True,
        }
    )
    interventions = ManagerInterventionStore(store).evaluate(
        target_agents=[CODEX_CLI_TARGET],
        task_run_id=task_run["task_run_id"],
    )["interventions"]
    return store, session, context, task_run, signal, interventions


class ManagerInterventionDeliveryTest(unittest.TestCase):
    def test_attach_delivery_creates_outbox_surface_promise_and_replays(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _, _, _, _, interventions = _intervention_store(Path(td) / "store.json")
            intervention = interventions[0]

            delivery = ManagerInterventionDeliveryStore(store).attach(
                intervention["manager_intervention_id"],
                target_agents=[CODEX_CLI_TARGET],
                surface="discord",
                target="discord",
                channel_id="chan",
                promise_reason="manager_attention_notification",
            )

            state = store.load()
            self.assertEqual(delivery["status"], "attached")
            self.assertEqual(len(delivery["outbox_ids"]), 1)
            outbox = state["outbox_items"][delivery["outbox_ids"][0]]
            self.assertEqual(outbox["state"], "queued")
            self.assertEqual(outbox["payload"]["manager_intervention_id"], intervention["manager_intervention_id"])
            promise = state["surface_promises"][delivery["surface_promise_id"]]
            self.assertEqual(promise["surface_delivery_status"], "pending")
            updated = state["manager_interventions"][intervention["manager_intervention_id"]]
            action_types = [action["type"] for action in updated["delivery_actions"]]
            self.assertIn("manager_intervention_delivery_attachment", action_types)
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_attach_delivery_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _, _, _, _, interventions = _intervention_store(Path(td) / "store.json")
            intervention = interventions[0]
            delivery_store = ManagerInterventionDeliveryStore(store)

            first = delivery_store.attach(
                intervention["manager_intervention_id"],
                target_agents=[CODEX_CLI_TARGET],
                surface="discord",
                target="discord",
                channel_id="chan",
                idempotency_key="delivery-once",
            )
            second = delivery_store.attach(
                intervention["manager_intervention_id"],
                target_agents=[CODEX_CLI_TARGET],
                surface="discord",
                target="discord",
                channel_id="chan",
                idempotency_key="delivery-once",
            )

            self.assertEqual(first["manager_intervention_delivery_id"], second["manager_intervention_delivery_id"])
            state = store.load()
            self.assertEqual(len(state["manager_intervention_deliveries"]), 1)
            self.assertEqual(len(state["outbox_items"]), 1)
            self.assertEqual(len(state["surface_promises"]), 1)

    def test_attach_delivery_rejects_conflicting_idempotency_key(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _, _, _, _, interventions = _intervention_store(Path(td) / "store.json")
            intervention = interventions[0]
            delivery_store = ManagerInterventionDeliveryStore(store)
            delivery_store.attach(
                intervention["manager_intervention_id"],
                target_agents=[CODEX_CLI_TARGET],
                surface="discord",
                target="discord",
                channel_id="chan",
                idempotency_key="same-key",
            )

            with self.assertRaises(ValueError):
                delivery_store.attach(
                    intervention["manager_intervention_id"],
                    target_agents=[CODEX_CLI_TARGET],
                    surface="discord",
                    target="discord",
                    channel_id="other-chan",
                    idempotency_key="same-key",
                )

    def test_readback_receipt_satisfies_attached_surface_promise(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _, _, _, _, interventions = _intervention_store(Path(td) / "store.json")
            intervention = interventions[0]
            delivery = ManagerInterventionDeliveryStore(store).attach(
                intervention["manager_intervention_id"],
                target_agents=[CODEX_CLI_TARGET],
                surface="discord",
                target="discord",
                channel_id="chan",
            )
            OutboxStore(store).record_receipt(
                delivery["outbox_ids"][0],
                status="readback_verified",
                response_payload={"message_id": "msg-1"},
                readback_ref="discord://chan/msg-1",
            )

            promise = SurfacePromiseStore(store).check(delivery["surface_promise_id"])

            self.assertEqual(promise["surface_delivery_status"], "delivered_and_readback_verified")
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_delivery_missing_outbox(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _, _, _, _, interventions = _intervention_store(Path(td) / "store.json")
            intervention = interventions[0]
            delivery = ManagerInterventionDeliveryStore(store).attach(
                intervention["manager_intervention_id"],
                target_agents=[CODEX_CLI_TARGET],
                surface="discord",
                target="discord",
                channel_id="chan",
            )
            state = store.load()
            state["outbox_items"].pop(delivery["outbox_ids"][0])
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("manager_intervention_delivery.outbox_missing", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_manager_intervention_deliveries(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _, _, _, _, interventions = _intervention_store(Path(td) / "store.json")
            intervention = interventions[0]
            ManagerInterventionDeliveryStore(store).attach(
                intervention["manager_intervention_id"],
                target_agents=[CODEX_CLI_TARGET],
                surface="discord",
                target="discord",
                channel_id="chan",
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("manager_intervention_deliveries", collections)


if __name__ == "__main__":
    unittest.main()
