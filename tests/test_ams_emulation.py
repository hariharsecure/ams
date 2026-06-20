from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ams.ams_emulation import AmsEmulationTrialStore, _hash_without
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.store import JsonStore


class AmsEmulationTrialTest(unittest.TestCase):
    def test_emulation_trial_runs_real_subprocess_agents_without_live_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")

            trial = AmsEmulationTrialStore(store).create(
                source_root=Path.cwd(),
                emulation_area=root / "emu",
                label="test-ams-emulation",
                timeout_seconds=1,
            )

            self.assertEqual(trial["mode"], "subprocess_sandbox_emulation")
            self.assertEqual(trial["scenario_count"], 9)
            self.assertEqual(trial["agent_count"], 4)
            self.assertEqual(trial["invocation_count"], 36)
            self.assertEqual(trial["metrics"]["failed_invocations"], 0)
            self.assertEqual(trial["metrics"]["live_boundary_leak_count"], 0)
            self.assertEqual(trial["metrics"]["timeout_count"], 1)
            self.assertEqual(trial["metrics"]["contained_escape_attempt_count"], 1)
            self.assertEqual(trial["status"], "defer")
            self.assertIn("ams_emulation.completed_with_limitations", trial["reason_codes"])
            self.assertFalse(trial["live_boundaries"]["discord_call_performed"])
            self.assertFalse(trial["sandbox_model"]["host_secrets_forwarded"])
            self.assertTrue(Path(trial["artifacts"][0]["path"]).exists())
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_external_agent_command_file_requires_explicit_allow(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            command_file = root / "agents.json"
            command_file.write_text(
                json.dumps({"agents": [{"agent_name": "probe", "argv": ["echo", "{}"]}]}),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "allow_external_agents"):
                AmsEmulationTrialStore(JsonStore(root / "store.json")).create(
                    source_root=Path.cwd(),
                    emulation_area=root / "emu",
                    agent_command_file=command_file,
                )

    def test_replay_catches_emulation_trial_hash_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            trial = AmsEmulationTrialStore(store).create(
                source_root=Path.cwd(),
                emulation_area=root / "emu",
                timeout_seconds=1,
            )
            state = store.load()
            record = state["ams_emulation_trials"][trial["ams_emulation_trial_id"]]
            record["metrics"]["live_boundary_leak_count"] = 1
            record["ams_emulation_trial_sha256"] = _hash_without(record, "ams_emulation_trial_sha256")
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("ams_emulation_trial.live_boundary_leak", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_emulation_trials(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            AmsEmulationTrialStore(store).create(
                source_root=Path.cwd(),
                emulation_area=root / "emu",
                timeout_seconds=1,
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("ams_emulation_trials", collections)


if __name__ == "__main__":
    unittest.main()
