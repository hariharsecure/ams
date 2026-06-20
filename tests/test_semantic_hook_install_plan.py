from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.semantic_hook_install_plan import SemanticHookInstallPlanStore, _hash_without
from ams.semantic_hook_run import SemanticHookRunStore
from ams.semantic_oracle_review import SemanticOracleReviewStore
from ams.simulation_sweep import SimulationSweepStore
from ams.store import JsonStore


class SemanticHookInstallPlanTest(unittest.TestCase):
    def _hook_run_store(self, root: Path) -> tuple[JsonStore, dict[str, object]]:
        store = JsonStore(root / "store.json")
        sweep = SimulationSweepStore(store).create(
            source_root=Path.cwd(),
            simulation_area=root / "sim",
            scenario_count=1370,
            label="semantic-install-source",
        )
        review = SemanticOracleReviewStore(store).create(
            simulation_sweep_id=sweep["simulation_sweep_id"],
            source_root=Path.cwd(),
            label="semantic-install-review",
        )
        hook_run = SemanticHookRunStore(store).create(
            semantic_oracle_review_id=str(review["semantic_oracle_review_id"]),
            source_root=Path.cwd(),
            label="semantic-install-hook-run",
        )
        return store, hook_run

    def test_install_plan_is_ready_but_installs_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store, hook_run = self._hook_run_store(root)

            plan = SemanticHookInstallPlanStore(store).create(
                semantic_hook_run_id=str(hook_run["semantic_hook_run_id"]),
                source_root=Path.cwd(),
                label="test-install-plan",
            )

            self.assertEqual(plan["status"], "ready_for_operator_review")
            self.assertEqual(plan["semantic_gap_remaining_count"], 0)
            self.assertEqual(plan["semantic_hook_record_count"], 11)
            self.assertFalse(plan["operator_approval"]["approval_granted"])
            self.assertFalse(plan["signing_requirements"]["verified_signed_package_present"])
            self.assertFalse(plan["live_boundaries"]["hook_installed"])
            self.assertTrue(all(target["installed"] is False for target in plan["install_targets"]))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_missing_hook_run(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store, hook_run = self._hook_run_store(root)
            plan = SemanticHookInstallPlanStore(store).create(
                semantic_hook_run_id=str(hook_run["semantic_hook_run_id"]),
                source_root=Path.cwd(),
                label="test-missing-hook-run",
            )
            state = store.load()
            del state["semantic_hook_runs"][hook_run["semantic_hook_run_id"]]
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn(
                f"semantic_hook_install_plan references missing semantic_hook_run {plan['semantic_hook_run_id']}",
                "\n".join(replay["errors"]),
            )

    def test_replay_catches_installed_target_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store, hook_run = self._hook_run_store(root)
            plan = SemanticHookInstallPlanStore(store).create(
                semantic_hook_run_id=str(hook_run["semantic_hook_run_id"]),
                source_root=Path.cwd(),
                label="test-install-tamper",
            )
            state = store.load()
            record = state["semantic_hook_install_plans"][plan["semantic_hook_install_plan_id"]]
            record["install_targets"][0]["installed"] = True
            record["semantic_hook_install_plan_sha256"] = _hash_without(
                record,
                "semantic_hook_install_plan_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("semantic_hook_install_plan.target_installed_not_false", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_install_plans(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store, hook_run = self._hook_run_store(root)
            SemanticHookInstallPlanStore(store).create(
                semantic_hook_run_id=str(hook_run["semantic_hook_run_id"]),
                source_root=Path.cwd(),
                label="test-install-oracle",
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("semantic_hook_install_plans", collections)


if __name__ == "__main__":
    unittest.main()
