from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams_codex.agent_memory_sim import init_agent_sim_runtime, run_default_agent_memory_trial
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.store import JsonStore


class AgentMemorySimTest(unittest.TestCase):
    def test_init_creates_isolated_capsules_and_optional_venvs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            manifest = init_agent_sim_runtime(Path(td) / "runtime", create_venvs=True)

            self.assertEqual(len(manifest["capsules"]), 2)
            self.assertEqual(manifest["launch_actions"], [])
            self.assertEqual(manifest["egress_actions"], [])
            for capsule in manifest["capsules"]:
                self.assertFalse(capsule["launch_allowed"])
                self.assertTrue(Path(capsule["workspace"]).exists())
                self.assertTrue(Path(capsule["venv_path"], "pyvenv.cfg").exists())

    def test_fake_discord_agent_memory_trial_records_forgetting_delta(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            runtime_root = Path(td) / "runtime"

            trial = run_default_agent_memory_trial(store, runtime_root=runtime_root)

            self.assertEqual(len(trial["agents"]), 2)
            self.assertEqual(trial["launch_actions"], [])
            self.assertEqual(trial["egress_actions"], [])
            self.assertGreater(trial["metrics"]["total_raw_forget_count"], 0)
            self.assertEqual(trial["metrics"]["total_ams_forget_count"], 0)
            self.assertEqual(len(trial["attention_signal_ids"]), 5)
            self.assertTrue(Path(trial["discord_sim"]["input_ref"]).exists())
            self.assertTrue(Path(trial["discord_sim"]["output_ref"]).exists())
            self.assertTrue((runtime_root / "trial_record.json").exists())
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_trial_referencing_missing_attention_signal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            trial = run_default_agent_memory_trial(store, runtime_root=Path(td) / "runtime")
            state = store.load()
            missing_signal_id = trial["attention_signal_ids"][0]
            state["attention_signals"].pop(missing_signal_id)
            state["indexes"]["attention_signal_ids"].pop(missing_signal_id)
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("agent_memory_trial.attention_signal_missing", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_agent_memory_trials(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            run_default_agent_memory_trial(store, runtime_root=Path(td) / "runtime")

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("agent_memory_trials", collections)


if __name__ == "__main__":
    unittest.main()
