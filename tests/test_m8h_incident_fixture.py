from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.simulation import run_incident_simulation
from ams_codex.store import JsonStore


class M8HIncidentFixtureTest(unittest.TestCase):
    def test_incident_simulation_blocks_and_replays(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            result = run_incident_simulation(
                {"channel_id": "chan", "message_id": "root", "content": "simulate provider error"},
                store,
            )

            self.assertEqual(result["final_state"], "blocked")
            self.assertTrue(result["dispatch"]["dispatched"], result["dispatch"])
            self.assertTrue(result["incident_packet_id"])
            self.assertTrue(result["ams_event_id"])
            self.assertTrue(result["replay"]["ok"], result["replay"]["errors"])

            state = store.load()
            self.assertEqual(len(state["incident_packets"]), 1)
            self.assertGreaterEqual(len(state["ams_events"]), 1)
            claim = next(iter(state["resource_claims"].values()))
            self.assertEqual(claim["state"], "released")

    def test_replay_rejects_missing_incident_packet(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            run_incident_simulation({"channel_id": "chan", "message_id": "root", "content": "fail"}, store)
            state = store.load()
            state["incident_packets"] = {}
            store.save(state)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("references missing incident_packet", "\n".join(replay["errors"]))

    def test_replay_rejects_missing_incident_ams_event(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            run_incident_simulation({"channel_id": "chan", "message_id": "root", "content": "fail"}, store)
            state = store.load()
            state["ams_events"] = {}
            store.save(state)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("references missing ams_event", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_incident_records(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            run_incident_simulation({"channel_id": "chan", "message_id": "root", "content": "fail"}, store)

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            skipped_empty = {
                row["collection"] for row in result["skipped"]
                if row.get("reason") == "empty"
            }
            self.assertNotIn("ams_events", skipped_empty)
            self.assertNotIn("incident_packets", skipped_empty)


if __name__ == "__main__":
    unittest.main()
