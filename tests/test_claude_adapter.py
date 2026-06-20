from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams_codex.claude_adapter import ClaudeDryRunAdapter
from ams_codex.context import ContextStore
from ams_codex.session_registry import SessionRegistry
from ams_codex.store import JsonStore


class ClaudeAdapterTest(unittest.TestCase):
    def test_request_adds_resume_after_bind(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            event = {"channel_id": "chan", "message_id": "root", "content": "verify"}
            session, _ = SessionRegistry(store).ingest_event(event)
            context = ContextStore(store).create_for_event(session, event)
            adapter = ClaudeDryRunAdapter(store)

            start = adapter.prepare_request(session["session_id"], context["context_id"])
            self.assertNotIn("resume", start["options"])
            self.assertIn("PreCompact", start["options"]["hooks"])

            session = adapter.bind_session(session["session_id"], "claude-session-123", claude_agent_id="agent-123")
            context = ContextStore(store).create_for_event(session, event)
            resume = adapter.prepare_request(session["session_id"], context["context_id"])
            self.assertEqual(resume["options"]["resume"], "claude-session-123")
            updated = SessionRegistry(store).get(session["session_id"])
            self.assertEqual(updated["provider_sessions"][0]["provider"], "anthropic_claude")


if __name__ == "__main__":
    unittest.main()
