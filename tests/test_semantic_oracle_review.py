from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.semantic_oracle_review import SemanticOracleReviewStore, _hash_without
from ams_codex.simulation_sweep import SimulationSweepStore
from ams_codex.store import JsonStore


class SemanticOracleReviewTest(unittest.TestCase):
    def test_semantic_oracle_review_finds_sweep_gaps_and_hook_contract(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            sweep = SimulationSweepStore(store).create(
                source_root=Path.cwd(),
                simulation_area=root / "sim",
                scenario_count=1370,
                label="semantic-review-source",
            )

            review = SemanticOracleReviewStore(store).create(
                simulation_sweep_id=sweep["simulation_sweep_id"],
                source_root=Path.cwd(),
                label="test-semantic-review",
            )

            self.assertEqual(review["status"], "defer")
            self.assertIn("semantic_oracle_review.semantic_gaps_found", review["reason_codes"])
            self.assertEqual(review["reviewed_scenario_count"], 1370)
            self.assertGreater(review["metrics"]["semantic_gap_count"], 0)
            self.assertFalse(review["hook_shim_contract"]["live_installed"])
            self.assertEqual(review["hook_shim_contract"]["enforcement_mode"], "contract_only")
            self.assertIn("PreCompact", review["hook_shim_contract"]["required_hooks"])
            self.assertIn("work_mode_decision", review["hook_shim_contract"]["required_records"])
            self.assertFalse(review["live_boundaries"]["hook_installed"])
            self.assertTrue(Path(review["artifacts"][0]["path"]).exists())
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_missing_sweep_reference(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            sweep = SimulationSweepStore(store).create(
                source_root=Path.cwd(),
                simulation_area=root / "sim",
                scenario_count=1370,
                label="semantic-review-missing-source",
            )
            review = SemanticOracleReviewStore(store).create(
                simulation_sweep_id=sweep["simulation_sweep_id"],
                source_root=Path.cwd(),
                label="test-missing-sweep",
            )
            state = store.load()
            del state["simulation_sweeps"][sweep["simulation_sweep_id"]]
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn(
                f"semantic_oracle_review references missing simulation_sweep {sweep['simulation_sweep_id']}",
                "\n".join(replay["errors"]),
            )
            self.assertIn(review["semantic_oracle_review_id"], state["semantic_oracle_reviews"])

    def test_replay_oracle_covers_semantic_oracle_reviews(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            sweep = SimulationSweepStore(store).create(
                source_root=Path.cwd(),
                simulation_area=root / "sim",
                scenario_count=1370,
                label="semantic-review-oracle-source",
            )
            SemanticOracleReviewStore(store).create(
                simulation_sweep_id=sweep["simulation_sweep_id"],
                source_root=Path.cwd(),
                label="test-oracle-review",
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("semantic_oracle_reviews", collections)

    def test_replay_catches_semantic_review_live_boundary_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            sweep = SimulationSweepStore(store).create(
                source_root=Path.cwd(),
                simulation_area=root / "sim",
                scenario_count=1370,
                label="semantic-review-tamper-source",
            )
            review = SemanticOracleReviewStore(store).create(
                simulation_sweep_id=sweep["simulation_sweep_id"],
                source_root=Path.cwd(),
                label="test-tamper-review",
            )
            state = store.load()
            record = state["semantic_oracle_reviews"][review["semantic_oracle_review_id"]]
            record["live_boundaries"]["hook_installed"] = True
            record["semantic_oracle_review_sha256"] = _hash_without(record, "semantic_oracle_review_sha256")
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("semantic_oracle_review.hook_installed_not_false", "\n".join(replay["errors"]))


if __name__ == "__main__":
    unittest.main()
