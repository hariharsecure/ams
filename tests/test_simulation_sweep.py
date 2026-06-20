from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.simulation_sweep import SimulationSweepStore, _hash_without
from ams.store import JsonStore


class SimulationSweepTest(unittest.TestCase):
    def test_simulation_sweep_records_1000_plus_scenarios_without_live_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")

            sweep = SimulationSweepStore(store).create(
                source_root=Path.cwd(),
                simulation_area=root / "sim",
                scenario_count=1370,
                label="test-sweep",
            )

            self.assertEqual(sweep["scenario_count"], 1370)
            self.assertEqual(sweep["scenario_matrix"]["available_scenario_count"], 1370)
            self.assertEqual(sweep["status"], "defer")
            self.assertIn("simulation_sweep.weaknesses_found", sweep["reason_codes"])
            self.assertFalse(sweep["live_boundaries"]["network_call_performed"])
            self.assertFalse(sweep["live_boundaries"]["provider_call_performed"])
            self.assertEqual(sweep["metrics"]["live_boundary_leak_count"], 0)
            self.assertEqual(sweep["metrics"]["raw_material_leak_count"], 0)
            self.assertGreater(sweep["metrics"]["strong_scenario_rate"], 0)
            self.assertGreater(sweep["weakness_summary"]["weak_scenario_count"], 0)
            self.assertTrue(sweep["innovation_backlog"])
            for artifact in sweep["artifacts"]:
                self.assertTrue(Path(artifact["path"]).exists())
                self.assertTrue(artifact["sha256"].startswith("sha256:"))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_rejects_under_1000_scenario_claim(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            sweep = SimulationSweepStore(store).create(
                source_root=Path.cwd(),
                simulation_area=root / "sim",
                scenario_count=10,
                label="test-small-sweep",
            )

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("simulation_sweep.scenario_count_below_1000", "\n".join(replay["errors"]))
            self.assertEqual(sweep["scenario_count"], 10)

    def test_replay_oracle_covers_simulation_sweeps(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            SimulationSweepStore(store).create(
                source_root=Path.cwd(),
                simulation_area=root / "sim",
                scenario_count=1370,
                label="test-oracle-sweep",
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("simulation_sweeps", collections)

    def test_replay_catches_sweep_hash_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            sweep = SimulationSweepStore(store).create(
                source_root=Path.cwd(),
                simulation_area=root / "sim",
                scenario_count=1370,
                label="test-tamper-sweep",
            )
            state = store.load()
            record = state["simulation_sweeps"][sweep["simulation_sweep_id"]]
            record["live_boundaries"]["network_call_performed"] = True
            record["simulation_sweep_sha256"] = _hash_without(record, "simulation_sweep_sha256")
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("simulation_sweep.network_call_performed_not_false", "\n".join(replay["errors"]))


if __name__ == "__main__":
    unittest.main()
