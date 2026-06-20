from __future__ import annotations

from copy import deepcopy
import tempfile
import unittest
from pathlib import Path

from ams_codex.epoch import EpochCloser
from ams_codex.models import canonical_json
from ams_codex.replay import ReplayChecker
from ams_codex.simulation import run_full_simulation, run_incident_simulation
from ams_codex.store import JsonStore


class M8HEpochCloseTest(unittest.TestCase):
    def test_close_epoch_on_completed_run_writes_attestation_event(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            run_full_simulation({"channel_id": "chan", "message_id": "root", "content": "build"}, store)

            result = EpochCloser(store).close(label="m8h-c-completed")

            self.assertTrue(result["closed"], result["report"]["errors"])
            self.assertTrue(result["replay_after"]["ok"], result["replay_after"]["errors"])
            event = result["epoch_event"]
            self.assertEqual(event["type"], "ams.ams_codex.epoch.closed")
            self.assertEqual(event["data"]["label"], "m8h-c-completed")
            state = store.load()
            self.assertIn(event["id"], state["ams_events"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_close_epoch_on_incident_run_writes_second_ams_event(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            run_incident_simulation({"channel_id": "chan", "message_id": "root", "content": "fail"}, store)

            result = EpochCloser(store).close(label="m8h-c-incident")

            self.assertTrue(result["closed"], result["report"]["errors"])
            state = store.load()
            event_types = [event["type"] for event in state["ams_events"].values()]
            self.assertIn("ams.ams_codex.incident.opened", event_types)
            self.assertIn("ams.ams_codex.epoch.closed", event_types)
            self.assertTrue(result["replay_after"]["ok"], result["replay_after"]["errors"])

    def test_close_epoch_refuses_future_context_revision_without_commit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            run_full_simulation({"channel_id": "chan", "message_id": "root", "content": "build"}, store)
            state = store.load()
            context = next(iter(state["contexts"].values()))
            context["session_revision"] = 999
            store.save(state, validate=False)
            before = deepcopy(store.load())

            result = EpochCloser(store).close(label="bad-future-context")

            self.assertFalse(result["closed"])
            self.assertIn("future session_revision", "\n".join(result["report"]["errors"]))
            self.assertEqual(canonical_json(store.load()), canonical_json(before))


if __name__ == "__main__":
    unittest.main()
