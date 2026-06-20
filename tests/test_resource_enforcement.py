from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

from ams.models import hash_without as _hash_without
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.resource_enforcement import ResourceEnforcementTrialStore

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_resource_telemetry import _store_run_claim


class ResourceEnforcementTrialTest(unittest.TestCase):
    def test_within_budget_trial_writes_telemetry_and_releases_claim(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _, claim = _store_run_claim(Path(td))

            trial = ResourceEnforcementTrialStore(store).create(
                resource_claim_id=claim["resource_claim_id"],
                mode="within_budget",
                timeout_seconds=2.0,
                source_root=Path.cwd(),
                label="test-resource-enforcement-within",
            )

            state = store.load()
            released = state["resource_claims"][claim["resource_claim_id"]]
            telemetry = state["resource_telemetry_samples"][trial["resource_telemetry_id"]]
            self.assertEqual(trial["status"], "within_budget")
            self.assertEqual(trial["reason_codes"], ["resource_enforcement.within_budget"])
            self.assertFalse(trial["subprocess"]["timed_out"])
            self.assertFalse(trial["subprocess"]["killed"])
            self.assertFalse(trial["subprocess"]["raw_output_stored"])
            self.assertFalse(trial["subprocess"]["shell_used"])
            self.assertEqual(released["state"], "released")
            self.assertEqual(telemetry["source_type"], "runner_summary")
            self.assertEqual(telemetry["source_ref"]["kind"], "resource_enforcement_trial")
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_timeout_trial_kills_owned_subprocess_and_releases_claim(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _, claim = _store_run_claim(Path(td))

            trial = ResourceEnforcementTrialStore(store).create(
                resource_claim_id=claim["resource_claim_id"],
                mode="timeout_kill",
                timeout_seconds=0.05,
                source_root=Path.cwd(),
                label="test-resource-enforcement-timeout",
            )

            state = store.load()
            released = state["resource_claims"][claim["resource_claim_id"]]
            self.assertEqual(trial["status"], "killed_over_budget")
            self.assertEqual(trial["reason_codes"], ["resource_enforcement.timeout_killed"])
            self.assertTrue(trial["subprocess"]["timed_out"])
            self.assertTrue(trial["subprocess"]["killed"])
            self.assertEqual(released["state"], "released")
            self.assertFalse(trial["live_boundaries"]["external_process_inspection_performed"])
            self.assertFalse(trial["live_boundaries"]["network_call_performed"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_enforcement_boundary_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _, claim = _store_run_claim(Path(td))
            trial = ResourceEnforcementTrialStore(store).create(
                resource_claim_id=claim["resource_claim_id"],
                mode="within_budget",
                timeout_seconds=2.0,
                source_root=Path.cwd(),
                label="test-resource-enforcement-tamper",
            )
            state = store.load()
            record = state["resource_enforcement_trials"][trial["resource_enforcement_trial_id"]]
            record["live_boundaries"]["network_call_performed"] = True
            record["resource_enforcement_trial_sha256"] = _hash_without(
                record,
                "resource_enforcement_trial_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn(
                "resource_enforcement.network_call_performed_not_false",
                "\n".join(replay["errors"]),
            )

    def test_replay_oracle_covers_resource_enforcement_trials(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _, claim = _store_run_claim(Path(td))
            ResourceEnforcementTrialStore(store).create(
                resource_claim_id=claim["resource_claim_id"],
                mode="within_budget",
                timeout_seconds=2.0,
                source_root=Path.cwd(),
                label="test-resource-enforcement-oracle",
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("resource_enforcement_trials", collections)


if __name__ == "__main__":
    unittest.main()
