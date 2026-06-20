from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams_codex.codex_adapter import CodexDryRunAdapter
from ams_codex.context import ContextStore
from ams_codex.models import canonical_json, sha256_text
from ams_codex.replay import ReplayChecker
from ams_codex.session_registry import SessionRegistry
from ams_codex.simulation import run_full_simulation
from ams_codex.store import JsonStore


def _rehash_record(record: dict, hash_field: str) -> None:
    material = dict(record)
    material.pop(hash_field, None)
    record[hash_field] = sha256_text(canonical_json(material))


def _rehash_run_chain(state: dict, task_run_id: str) -> None:
    previous_hash = None
    events = sorted(
        [
            event for event in state["run_events"].values()
            if event.get("task_run_id") == task_run_id
        ],
        key=lambda event: int(event.get("sequence", 0) or 0),
    )
    for event in events:
        event["previous_event_sha256"] = previous_hash
        _rehash_record(event, "event_sha256")
        previous_hash = event["event_sha256"]


class M8HReplayClosureTest(unittest.TestCase):
    def test_replay_rejects_rehashed_illegal_semantic_transition(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            result = run_full_simulation({"channel_id": "chan", "message_id": "root", "content": "build"}, store)
            state = store.load()
            task_run_id = result["task_run_id"]
            event = next(
                item for item in state["run_events"].values()
                if item.get("task_run_id") == task_run_id and item.get("sequence") == 3
            )
            event["event_type"] = "verify.passed"
            event["from_state"] = "dispatching"
            event["to_state"] = "verified"
            _rehash_run_chain(state, task_run_id)
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("illegal semantic transition", "\n".join(replay["errors"]))

    def test_replay_rejects_context_overwrite_after_run_creation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            result = run_full_simulation({"channel_id": "chan", "message_id": "root", "content": "build"}, store)
            state = store.load()
            context = state["contexts"][result["context_id"]]
            context["requested_action"] = "tampered_after_run_creation"
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("input context sha256 mismatch", "\n".join(replay["errors"]))

    def test_replay_rejects_terminal_run_with_active_claim(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            result = run_full_simulation({"channel_id": "chan", "message_id": "root", "content": "build"}, store)
            state = store.load()
            claim_id = result["resource_claim_id"]
            claim = state["resource_claims"][claim_id]
            claim["state"] = "active"
            claim["released_at"] = None
            _rehash_record(claim, "claim_sha256")
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("terminal with active resource_claim", "\n".join(replay["errors"]))

    def test_context_id_changes_after_session_revision_changes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            event = {"channel_id": "chan", "message_id": "root", "content": "build"}
            session, _ = SessionRegistry(store).ingest_event(event)
            first = ContextStore(store).create_for_event(session, event)
            session = CodexDryRunAdapter(store).bind_thread(session["session_id"], "thread-1")
            second = ContextStore(store).create_for_event(session, event)

            self.assertNotEqual(first["context_id"], second["context_id"])
            self.assertLess(first["session_revision"], second["session_revision"])


if __name__ == "__main__":
    unittest.main()
