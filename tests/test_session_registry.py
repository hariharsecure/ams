from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams_codex.session_registry import SessionRegistry
from ams_codex.store import JsonStore


class SessionRegistryTest(unittest.TestCase):
    def test_ingest_creates_then_reuses_by_reply(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            registry = SessionRegistry(JsonStore(Path(td) / "store.json"))
            root = {
                "channel_id": "chan",
                "message_id": "root",
                "content": "please build x",
                "priority": "P0",
            }
            session, created = registry.ingest_event(root)
            self.assertTrue(created)
            self.assertEqual(session["discord_root_message_id"], "root")
            reply = {
                "channel_id": "chan",
                "message_id": "reply-1",
                "reply_to_message_id": "root",
                "content": "follow up",
            }
            session2, created2 = registry.ingest_event(reply)
            self.assertFalse(created2)
            self.assertEqual(session2["session_id"], session["session_id"])
            self.assertIn("reply-1", session2["message_ids"])

    def test_reuses_by_thread_id(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            registry = SessionRegistry(JsonStore(Path(td) / "store.json"))
            session, created = registry.ingest_event({
                "channel_id": "chan",
                "message_id": "root",
                "discord_thread_id": "thread-a",
                "content": "root",
            })
            self.assertTrue(created)
            session2, created2 = registry.ingest_event({
                "channel_id": "chan",
                "message_id": "thread-msg",
                "discord_thread_id": "thread-a",
                "content": "thread follow up",
            })
            self.assertFalse(created2)
            self.assertEqual(session2["session_id"], session["session_id"])

    def test_duplicate_event_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            registry = SessionRegistry(JsonStore(Path(td) / "store.json"))
            event = {
                "event_id": "evt-1",
                "channel_id": "chan",
                "message_id": "root",
                "content": "same request",
            }
            session, created = registry.ingest_event(event)
            session2, created2 = registry.ingest_event(event)
            self.assertTrue(created)
            self.assertFalse(created2)
            self.assertEqual(session2["session_id"], session["session_id"])
            self.assertEqual(session2["event_ids"], ["evt-1"])
            self.assertEqual(session2["message_ids"], ["root"])

    def test_same_content_different_root_creates_new_session(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            registry = SessionRegistry(JsonStore(Path(td) / "store.json"))
            first, created = registry.ingest_event({
                "channel_id": "chan",
                "message_id": "root-a",
                "content": "repeatable request text",
            })
            second, created2 = registry.ingest_event({
                "channel_id": "chan",
                "message_id": "root-b",
                "content": "repeatable request text",
            })
            self.assertTrue(created)
            self.assertTrue(created2)
            self.assertNotEqual(second["session_id"], first["session_id"])


if __name__ == "__main__":
    unittest.main()
