from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.checkpoint import CheckpointStore
from ams.codex_adapter import CodexDryRunAdapter
from ams.context import ContextStore
from ams.session_registry import SessionRegistry
from ams.store import JsonStore


class CodexAdapterTest(unittest.TestCase):
    def test_request_starts_thread_then_turn_after_bind(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            event = {"channel_id": "chan", "message_id": "root", "content": "build"}
            session, _ = SessionRegistry(store).ingest_event(event)
            context = ContextStore(store).create_for_event(session, event)
            adapter = CodexDryRunAdapter(store)

            start = adapter.prepare_request(session["session_id"], context["context_id"])
            self.assertEqual(start["method"], "thread/start")

            session = adapter.bind_thread(session["session_id"], "thread-123")
            context = ContextStore(store).create_for_event(session, event)
            turn = adapter.prepare_request(session["session_id"], context["context_id"])
            self.assertEqual(turn["method"], "turn/start")
            self.assertEqual(turn["params"]["threadId"], "thread-123")
            resume = adapter.prepare_resume_request(session["session_id"])
            self.assertEqual(resume["method"], "thread/resume")
            self.assertEqual(resume["params"]["threadId"], "thread-123")

    def test_rejects_stale_context_after_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            event = {"channel_id": "chan", "message_id": "root", "content": "build"}
            session, _ = SessionRegistry(store).ingest_event(event)
            context = ContextStore(store).create_for_event(session, event)
            CheckpointStore(store).create(
                session["session_id"],
                trigger="pre_compact",
                state_summary="new checkpoint",
                next_action="refresh context",
            )
            with self.assertRaisesRegex(ValueError, "stale context"):
                CodexDryRunAdapter(store).prepare_request(session["session_id"], context["context_id"])


if __name__ == "__main__":
    unittest.main()
