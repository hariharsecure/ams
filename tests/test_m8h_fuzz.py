from __future__ import annotations

from copy import deepcopy
import tempfile
import unittest
from pathlib import Path

from ams.models import canonical_json
from ams.replay import replay_check
from ams.replay_oracle import ReplayOracle
from ams.simulation import run_full_simulation, run_incident_simulation
from ams.store import JsonStore


class M8HFuzzTest(unittest.TestCase):
    def test_replay_oracle_is_non_destructive_across_happy_and_incident_stores(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            happy = JsonStore(Path(td) / "happy.json")
            incident = JsonStore(Path(td) / "incident.json")
            run_full_simulation({"channel_id": "chan", "message_id": "happy", "content": "build"}, happy)
            run_incident_simulation({"channel_id": "chan", "message_id": "incident", "content": "fail"}, incident)

            for store in (happy, incident):
                before = canonical_json(store.load())
                result = ReplayOracle(store).check()
                self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
                self.assertTrue(result["ok"], result["misses"])
                self.assertEqual(canonical_json(store.load()), before)

    def test_seeded_delete_each_record_faults_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            run_incident_simulation({"channel_id": "chan", "message_id": "root", "content": "fail"}, store)
            state = store.load()
            checked = 0
            for collection in (
                "sessions",
                "events",
                "contexts",
                "task_runs",
                "run_events",
                "ams_events",
                "admission_reviews",
                "resource_claims",
                "provider_results",
                "incident_packets",
            ):
                records = state.get(collection) or {}
                for record_id in sorted(records)[:2]:
                    mutated = deepcopy(state)
                    mutated[collection].pop(record_id)
                    result = replay_check(mutated)
                    self.assertFalse(result["ok"], f"{collection}/{record_id} was not detected")
                    checked += 1
            self.assertGreaterEqual(checked, 10)


if __name__ == "__main__":
    unittest.main()
