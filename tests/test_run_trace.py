from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.admission import AdmissionReviewStore
from ams.capability_policy import build_capability_request, evaluate_capability_request
from ams.checkpoint import CheckpointStore
from ams.codex_adapter import CodexDryRunAdapter
from ams.context import ContextStore
from ams.dispatch import dispatch
from ams.replay import ReplayChecker
from ams.resource_claim import ResourceClaimStore
from ams.run_trace import RunTraceStore
from ams.session_registry import SessionRegistry
from ams.store import JsonStore


class RunTraceTest(unittest.TestCase):
    def test_create_run_and_append_hash_chained_event(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            event = {"channel_id": "chan", "message_id": "root", "content": "build"}
            session, _ = SessionRegistry(store).ingest_event(event)
            context = ContextStore(store).create_for_event(session, event)
            session = CodexDryRunAdapter(store).bind_thread(session["session_id"], "thread-1")
            context = ContextStore(store).create_for_event(session, event)

            trace = RunTraceStore(store)
            task_run = trace.create_run(
                session["session_id"],
                context["context_id"],
                model="gpt-5.5",
                tool_scope=["Read", "Edit"],
            )
            self.assertEqual(task_run["state"], "planned")
            self.assertEqual(task_run["provider_session_id"], "thread-1")
            self.assertEqual(task_run["initial_event"]["sequence"], 1)
            self.assertEqual(task_run["initial_event"]["to_state"], "planned")
            claim_result = ResourceClaimStore(store).reserve(task_run["task_run_id"])
            self.assertTrue(claim_result["reserved"])
            ResourceClaimStore(store).transition(claim_result["claim"]["resource_claim_id"], "active")
            request = build_capability_request(
                action="write",
                paths=["tests/test_run_trace.py"],
                tools=["Read", "Edit"],
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

            result = dispatch(store, task_run["task_run_id"])
            self.assertTrue(result["dispatched"], result)
            intent = result["events"][0]
            self.assertEqual(intent["to_state"], "dispatching")

            dispatched = result["events"][1]
            self.assertEqual(dispatched["sequence"], 3)
            self.assertEqual(dispatched["previous_event_sha256"], intent["event_sha256"])
            self.assertEqual(dispatched["from_state"], "dispatching")
            self.assertEqual(dispatched["to_state"], "in_flight")

            updated = trace.get_run(task_run["task_run_id"])
            self.assertIsNotNone(updated)
            assert updated is not None
            self.assertEqual(updated["state"], "in_flight")
            self.assertTrue(str(updated["provider_request_id"]).startswith("preq_"))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_create_run_rejects_stale_context(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            event = {"channel_id": "chan", "message_id": "root", "content": "build"}
            session, _ = SessionRegistry(store).ingest_event(event)
            context = ContextStore(store).create_for_event(session, event)
            CheckpointStore(store).create(
                session["session_id"],
                trigger="turn_completed",
                state_summary="newer state exists",
                next_action="refresh context",
            )

            with self.assertRaises(ValueError):
                RunTraceStore(store).create_run(session["session_id"], context["context_id"])

    def test_replay_detects_tampered_run_event(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            event = {"channel_id": "chan", "message_id": "root", "content": "build"}
            session, _ = SessionRegistry(store).ingest_event(event)
            context = ContextStore(store).create_for_event(session, event)
            task_run = RunTraceStore(store).create_run(session["session_id"], context["context_id"])

            state = store.load()
            run_event_id = task_run["initial_event"]["run_event_id"]
            state["run_events"][run_event_id]["payload"]["state"] = "tampered"
            store.save(state)

            result = ReplayChecker(store).check()
            self.assertFalse(result["ok"])
            self.assertIn("sha256 mismatch", "\n".join(result["errors"]))


if __name__ == "__main__":
    unittest.main()
