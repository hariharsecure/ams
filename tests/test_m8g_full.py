from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams_codex.admission import AdmissionReviewStore
from ams_codex.capability_policy import build_capability_request, evaluate_capability_request
from ams_codex.codex_adapter import CodexDryRunAdapter
from ams_codex.context import ContextStore
from ams_codex.dispatch import dispatch
from ams_codex.replay import ReplayChecker
from ams_codex.run_trace import RunTraceStore
from ams_codex.session_registry import SessionRegistry
from ams_codex.simulation import run_full_simulation
from ams_codex.store import JsonStore


class M8GFullSliceTest(unittest.TestCase):
    def test_simulate_full_completes_and_replays(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            result = run_full_simulation(
                {"channel_id": "chan", "message_id": "root", "content": "build m8g"},
                store,
            )
            self.assertEqual(result["final_state"], "completed")
            self.assertTrue(result["dispatch"]["dispatched"], result["dispatch"])
            self.assertTrue(result["predicate"]["passed"], result["predicate"])
            self.assertTrue(result["replay"]["ok"], result["replay"]["errors"])
            state = store.load()
            self.assertEqual(len(state["provider_results"]), 1)
            self.assertEqual(len(state["resource_claims"]), 1)
            claim = next(iter(state["resource_claims"].values()))
            self.assertEqual(claim["state"], "released")

    def test_dispatch_refuses_without_active_claim(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            event = {"channel_id": "chan", "message_id": "root", "content": "build"}
            session, _ = SessionRegistry(store).ingest_event(event)
            session = CodexDryRunAdapter(store).bind_thread(session["session_id"], "thread-1")
            context = ContextStore(store).create_for_event(session, event)
            task_run = RunTraceStore(store).create_run(session["session_id"], context["context_id"])
            request = build_capability_request(
                action="write",
                paths=["tests/test_m8g_full.py"],
                tools=["ApplyPatch"],
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
            self.assertFalse(result["dispatched"])
            self.assertEqual(result["reason_code"], "dispatch.claim_not_active")

    def test_dispatch_requires_capability_for_run_tool_scope(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            event = {"channel_id": "chan", "message_id": "root", "content": "build"}
            session, _ = SessionRegistry(store).ingest_event(event)
            session = CodexDryRunAdapter(store).bind_thread(session["session_id"], "thread-1")
            context = ContextStore(store).create_for_event(session, event)
            task_run = RunTraceStore(store).create_run(
                session["session_id"],
                context["context_id"],
                tool_scope=["ApplyPatch"],
            )
            request = build_capability_request(
                action="read",
                paths=["tests/test_m8g_full.py"],
                tools=["Read"],
            )
            verdict = evaluate_capability_request(request)
            self.assertEqual(verdict["status"], "allow")
            AdmissionReviewStore(store).create(
                subject_kind="task_run",
                subject_id=task_run["task_run_id"],
                operation="capability.dispatch",
                request=request,
                verdict=verdict,
            )
            result = dispatch(store, task_run["task_run_id"])
            self.assertFalse(result["dispatched"])
            self.assertEqual(result["reason_code"], "dispatch.capability_not_allowed")

    def test_replay_fails_when_provider_result_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            run_full_simulation({"channel_id": "chan", "message_id": "root", "content": "build"}, store)
            state = store.load()
            state["provider_results"] = {}
            store.save(state)
            result = ReplayChecker(store).check()
            self.assertFalse(result["ok"])
            self.assertIn("missing provider_result", "\n".join(result["errors"]))

    def test_replay_fails_when_provider_result_mutated(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            run_full_simulation({"channel_id": "chan", "message_id": "root", "content": "build"}, store)
            state = store.load()
            provider_result = next(iter(state["provider_results"].values()))
            provider_result["status"] = "error"
            store.save(state)
            result = ReplayChecker(store).check()
            self.assertFalse(result["ok"])
            self.assertIn("provider_result", "\n".join(result["errors"]))
            self.assertIn("sha256 mismatch", "\n".join(result["errors"]))


if __name__ == "__main__":
    unittest.main()
