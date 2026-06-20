from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams_codex.attention_router import AttentionRouterStore
from ams_codex.codex_adapter import CodexDryRunAdapter
from ams_codex.context import ContextStore
from ams_codex.dispatch import dispatch
from ams_codex.manager_intervention import ManagerInterventionStore
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.run_trace import RunTraceStore
from ams_codex.session_registry import SessionRegistry
from ams_codex.store import JsonStore


class ManagerInterventionTest(unittest.TestCase):
    def test_evaluate_builds_cross_agent_interventions_from_attention_signals(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            signal = AttentionRouterStore(store).ingest(
                {
                    "source_surface": "claude_code",
                    "source_ref": "claude://session-a305/15413",
                    "content": (
                        "Track-A training failed and SIGUSR1 caused a durable checkpoint "
                        "broken pipe; Codex and Claude must not forget the RCA."
                    ),
                }
            )

            result = ManagerInterventionStore(store).evaluate()

            self.assertGreaterEqual(result["created"], 2)
            intervention_types = {row["intervention_type"] for row in result["interventions"]}
            self.assertIn("ack_escalation", intervention_types)
            self.assertIn("cross_domain_bridge", intervention_types)
            for row in result["interventions"]:
                self.assertIn(signal["attention_signal_id"], row["source_attention_signal_ids"])
                self.assertEqual(row["delivery_status"], "planned")
                self.assertEqual(row["delivery_actions"], [])
                self.assertTrue(row["target_agents"])
                self.assertIn("ams_attention_training_ops", row["payload"]["vector_query"]["collections"])
                self.assertTrue(row["manager_intervention_sha256"].startswith("sha256:"))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_manager_intervention_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            AttentionRouterStore(store).ingest(
                {
                    "source_surface": "manual",
                    "source_ref": "manual://manager-tamper",
                    "content": "Codex attention missed a security token cleanup task.",
                }
            )
            ManagerInterventionStore(store).evaluate()
            state = store.load()
            intervention = next(iter(state["manager_interventions"].values()))
            intervention["priority"] = "P4"
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("manager_intervention.hash_mismatch", "\n".join(replay["errors"]))

    def test_replay_catches_missing_source_attention_signal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            signal = AttentionRouterStore(store).ingest(
                {
                    "source_surface": "manual",
                    "source_ref": "manual://manager-missing-source",
                    "content": "Discord gateway.disconnect needs RCA and update.",
                }
            )
            ManagerInterventionStore(store).evaluate()
            state = store.load()
            state["attention_signals"].pop(signal["attention_signal_id"])
            state["indexes"]["attention_signal_ids"].pop(signal["attention_signal_id"])
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("manager_intervention.attention_signal_missing", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_manager_interventions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            AttentionRouterStore(store).ingest(
                {
                    "source_surface": "manual",
                    "source_ref": "manual://manager-oracle",
                    "content": "AMS replay gate status update please.",
                }
            )
            ManagerInterventionStore(store).evaluate()

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("manager_interventions", collections)

    def test_dispatch_refuses_unresolved_manager_intervention_for_task_run(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            event = {"channel_id": "chan", "message_id": "root", "content": "build"}
            session, _ = SessionRegistry(store).ingest_event(event)
            session = CodexDryRunAdapter(store).bind_thread(session["session_id"], "thread-1")
            context = ContextStore(store).create_for_event(session, event)
            task_run = RunTraceStore(store).create_run(session["session_id"], context["context_id"])
            AttentionRouterStore(store).ingest(
                {
                    "source_surface": "manual",
                    "source_ref": "manual://manager-dispatch-block",
                    "session_id": session["session_id"],
                    "context_id": context["context_id"],
                    "task_run_id": task_run["task_run_id"],
                    "attention_id": task_run["attention_id"],
                    "content": "P1 Codex session missed security followup; require acknowledgement before dispatch.",
                    "priority": "P1",
                }
            )
            manager = ManagerInterventionStore(store).evaluate(task_run_id=task_run["task_run_id"])
            self.assertGreater(manager["created"], 0)

            result = dispatch(store, task_run["task_run_id"])

            self.assertFalse(result["dispatched"])
            self.assertEqual(result["reason_code"], "dispatch.manager_intervention_unresolved")
            self.assertTrue(result["manager_intervention_ids"])


if __name__ == "__main__":
    unittest.main()
