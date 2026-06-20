from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.checkpoint import CheckpointStore
from ams.context import ContextStore
from ams.replay import ReplayChecker
from ams.session_registry import SessionRegistry
from ams.store import JsonStore


class ReplayTest(unittest.TestCase):
    def test_replay_check_ok(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            event = {"channel_id": "chan", "message_id": "root", "content": "build"}
            session, _ = SessionRegistry(store).ingest_event(event)
            ContextStore(store).create_for_event(session, event)
            CheckpointStore(store).create(
                session["session_id"],
                trigger="turn_completed",
                state_summary="done",
                next_action="next",
            )
            result = ReplayChecker(store).check()
            self.assertTrue(result["ok"], result["errors"])


if __name__ == "__main__":
    unittest.main()
