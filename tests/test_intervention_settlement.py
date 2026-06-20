from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.admission import AdmissionReviewStore
from ams.attention_router import AttentionRouterStore
from ams.capability_policy import build_capability_request, evaluate_capability_request
from ams.codex_adapter import CodexDryRunAdapter
from ams.context import ContextStore
from ams.dispatch import dispatch
from ams.intervention_settlement import ManagerInterventionSettlementStore
from ams.manager_intervention import ManagerInterventionStore
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.resource_claim import ResourceClaimStore
from ams.run_trace import RunTraceStore
from ams.session_registry import SessionRegistry
from ams.store import JsonStore


CODEX_CLI_TARGET = {
    "agent_name": "codex",
    "provider": "openai_codex",
    "surface": "codex-cli",
}


def _dispatch_ready_store(path: Path) -> tuple[JsonStore, dict, dict, dict, dict]:
    store = JsonStore(path)
    event = {"channel_id": "chan", "message_id": "root", "content": "build"}
    session, _ = SessionRegistry(store).ingest_event(event)
    session = CodexDryRunAdapter(store).bind_thread(session["session_id"], "thread-1")
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
    request = build_capability_request(
        actor="agent:agent_b",
        tier="builder",
        action="write",
        paths=["tests/test_intervention_settlement.py"],
        tools=["Read", "ApplyPatch", "Tests"],
        egress_mode="ams_outbox",
    )
    verdict = evaluate_capability_request(request)
    AdmissionReviewStore(store).create(
        subject_kind="task_run",
        subject_id=task_run["task_run_id"],
        operation="capability.dispatch",
        request=request,
        verdict=verdict,
    )
    claim_result = ResourceClaimStore(store).reserve(task_run["task_run_id"])
    claim = ResourceClaimStore(store).transition(claim_result["claim"]["resource_claim_id"], "active")
    return store, event, session, context, task_run | {"resource_claim_id": claim["resource_claim_id"]}


def _create_task_interventions(store: JsonStore, session: dict, context: dict, task_run: dict) -> tuple[dict, list[dict]]:
    signal = AttentionRouterStore(store).ingest(
        {
            "source_surface": "manual",
            "source_ref": "manual://manager-settlement",
            "session_id": session["session_id"],
            "context_id": context["context_id"],
            "task_run_id": task_run["task_run_id"],
            "attention_id": task_run["attention_id"],
            "content": "Please update the AMS build state before the next dispatch.",
            "priority": "P2",
            "ack_required": True,
        }
    )
    result = ManagerInterventionStore(store).evaluate(task_run_id=task_run["task_run_id"])
    return signal, result["interventions"]


def _accepted_readback(intervention: dict, signal: dict) -> dict:
    return {
        "target_agent": CODEX_CLI_TARGET,
        "ack_status": "acknowledged",
        "readback_ref": "codex://thread-1/readback-1",
        "readback_summary": (
            "Used manual://manager-settlement. No P0/P1/P2 signals are deferred. "
            "Next action stays in unknown domain because this is a local test signal."
        ),
        "source_refs_used": list(intervention["source_refs"]),
        "priority_decision": "none_deferred",
        "deferred_signal_ids": [],
        "priority_reason": "No high-priority signal is deferred.",
        "next_domain": intervention["primary_domain"],
        "crosses_domains": False,
        "domain_reason": f"Continue in {intervention['primary_domain']} for {signal['attention_signal_id']}.",
    }


class ManagerInterventionSettlementTest(unittest.TestCase):
    def test_settlement_acknowledges_interventions_and_unblocks_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _, session, context, task_run = _dispatch_ready_store(Path(td) / "store.json")
            signal, interventions = _create_task_interventions(store, session, context, task_run)

            blocked = dispatch(store, task_run["task_run_id"])
            self.assertFalse(blocked["dispatched"])
            self.assertEqual(blocked["reason_code"], "dispatch.manager_intervention_unresolved")

            settlement_store = ManagerInterventionSettlementStore(store)
            settlements = [
                settlement_store.settle(
                    intervention["manager_intervention_id"],
                    **_accepted_readback(intervention, signal),
                )
                for intervention in interventions
            ]
            self.assertTrue(settlements)
            self.assertTrue(all(row["settlement_status"] == "accepted" for row in settlements))
            state = store.load()
            self.assertEqual(len(state["manager_intervention_settlements"]), len(interventions))
            self.assertTrue(all(row["ack_status"] == "acknowledged" for row in state["manager_interventions"].values()))
            self.assertEqual(state["attention_signals"][signal["attention_signal_id"]]["ack_status"], "acknowledged")
            self.assertEqual(state["attention_signals"][signal["attention_signal_id"]]["route_status"], "routed")

            dispatched = dispatch(store, task_run["task_run_id"])
            self.assertTrue(dispatched["dispatched"], dispatched)
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_deferred_settlement_is_durable_but_keeps_dispatch_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _, session, context, task_run = _dispatch_ready_store(Path(td) / "store.json")
            signal, interventions = _create_task_interventions(store, session, context, task_run)
            intervention = interventions[0]

            settlement = ManagerInterventionSettlementStore(store).settle(
                intervention["manager_intervention_id"],
                target_agent=CODEX_CLI_TARGET,
                ack_status="deferred",
                readback_ref="codex://thread-1/readback-defer",
                readback_summary="Used manual://manager-settlement, but deferred the P2 signal for a controlled test.",
                source_refs_used=list(intervention["source_refs"]),
                priority_decision="deferred",
                deferred_signal_ids=[signal["attention_signal_id"]],
                priority_reason="The test is verifying deferred settlement behavior.",
                next_domain=intervention["primary_domain"],
                crosses_domains=False,
                domain_reason=f"Stay in {intervention['primary_domain']} while deferred.",
            )

            self.assertEqual(settlement["settlement_status"], "accepted")
            state = store.load()
            updated = state["manager_interventions"][intervention["manager_intervention_id"]]
            self.assertEqual(updated["ack_status"], "deferred")
            self.assertEqual(updated["delivery_status"], "delivered")
            self.assertEqual(state["attention_signals"][signal["attention_signal_id"]]["ack_status"], "deferred")
            result = dispatch(store, task_run["task_run_id"])
            self.assertFalse(result["dispatched"])
            self.assertEqual(result["reason_code"], "dispatch.manager_intervention_unresolved")
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_rejected_settlement_does_not_mutate_intervention(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _, session, context, task_run = _dispatch_ready_store(Path(td) / "store.json")
            _, interventions = _create_task_interventions(store, session, context, task_run)
            intervention = interventions[0]

            settlement = ManagerInterventionSettlementStore(store).settle(
                intervention["manager_intervention_id"],
                target_agent=CODEX_CLI_TARGET,
                ack_status="acknowledged",
            )

            self.assertEqual(settlement["settlement_status"], "rejected")
            self.assertFalse(settlement["applied_to_intervention"])
            state = store.load()
            updated = state["manager_interventions"][intervention["manager_intervention_id"]]
            self.assertEqual(updated["ack_status"], "new")
            self.assertEqual(updated["delivery_status"], "planned")
            self.assertEqual(updated["delivery_actions"], [])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_idempotent_settlement_returns_existing_record(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _, session, context, task_run = _dispatch_ready_store(Path(td) / "store.json")
            signal, interventions = _create_task_interventions(store, session, context, task_run)
            intervention = interventions[0]
            payload = _accepted_readback(intervention, signal) | {"idempotency_key": "settle-once"}
            settlement_store = ManagerInterventionSettlementStore(store)

            first = settlement_store.settle(intervention["manager_intervention_id"], **payload)
            second = settlement_store.settle(intervention["manager_intervention_id"], **payload)

            self.assertEqual(first["manager_intervention_settlement_id"], second["manager_intervention_settlement_id"])
            self.assertEqual(len(store.load()["manager_intervention_settlements"]), 1)

    def test_replay_catches_settlement_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _, session, context, task_run = _dispatch_ready_store(Path(td) / "store.json")
            signal, interventions = _create_task_interventions(store, session, context, task_run)
            intervention = interventions[0]
            settlement = ManagerInterventionSettlementStore(store).settle(
                intervention["manager_intervention_id"],
                **_accepted_readback(intervention, signal),
            )
            state = store.load()
            state["manager_intervention_settlements"][settlement["manager_intervention_settlement_id"]][
                "ack_status"
            ] = "deferred"
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("manager_intervention_settlement.hash_mismatch", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_manager_intervention_settlements(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            signal = AttentionRouterStore(store).ingest(
                {
                    "source_surface": "manual",
                    "source_ref": "manual://manager-settlement-oracle",
                    "content": "Please update AMS status before continuing.",
                    "priority": "P2",
                    "ack_required": True,
                }
            )
            interventions = ManagerInterventionStore(store).evaluate()["interventions"]
            intervention = interventions[0]
            ManagerInterventionSettlementStore(store).settle(
                intervention["manager_intervention_id"],
                **_accepted_readback(intervention, signal),
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("manager_intervention_settlements", collections)


if __name__ == "__main__":
    unittest.main()
