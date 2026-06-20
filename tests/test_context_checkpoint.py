from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.checkpoint import CheckpointStore
from ams.codex_adapter import CodexDryRunAdapter
from ams.context import ContextStore
from ams.session_registry import SessionRegistry
from ams.store import JsonStore


class ContextCheckpointTest(unittest.TestCase):
    def test_context_and_checkpoint_update_session(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            event = {
                "channel_id": "chan",
                "message_id": "root",
                "content": "build registry",
                "priority": "P1",
                "requested_action": "plan",
            }
            session, _ = SessionRegistry(store).ingest_event(event)
            context = ContextStore(store).create_for_event(session, event)
            self.assertEqual(context["session_id"], session["session_id"])
            self.assertEqual(context["target"]["id"], "root")
            self.assertEqual(context["compaction_epoch"], 0)
            checkpoint = CheckpointStore(store).create(
                session["session_id"],
                trigger="pre_compact",
                state_summary="Registry created and context built.",
                next_action="Run dry-run CLI.",
                decisions=["Use JSON store for M1"],
            )
            self.assertTrue(checkpoint["checkpoint_sha256"].startswith("sha256:"))
            updated = SessionRegistry(store).get(session["session_id"])
            self.assertIsNotNone(updated)
            self.assertEqual(updated["last_summary_checkpoint_id"], checkpoint["summary_checkpoint_id"])

    def test_checkpoint_advances_provider_binding(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            event = {"channel_id": "chan", "message_id": "root", "content": "build registry"}
            session, _ = SessionRegistry(store).ingest_event(event)
            CodexDryRunAdapter(store).bind_thread(session["session_id"], "thread-123")
            checkpoint = CheckpointStore(store).create(
                session["session_id"],
                trigger="post_compact",
                state_summary="compacted after turn",
                next_action="resume with fresh context",
            )
            updated = SessionRegistry(store).get(session["session_id"])
            self.assertIsNotNone(updated)
            binding = updated["provider_sessions"][0]
            self.assertEqual(binding["last_checkpoint_id"], checkpoint["summary_checkpoint_id"])
            self.assertEqual(binding["compaction_epoch"], 1)


if __name__ == "__main__":
    unittest.main()
