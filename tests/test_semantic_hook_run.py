from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.semantic_hook_run import SemanticHookRunStore, _hash_without
from ams_codex.semantic_oracle_review import SemanticOracleReviewStore
from ams_codex.simulation_sweep import SimulationSweepStore
from ams_codex.store import JsonStore


class SemanticHookRunTest(unittest.TestCase):
    def _review_store(self, root: Path) -> tuple[JsonStore, dict[str, object]]:
        store = JsonStore(root / "store.json")
        sweep = SimulationSweepStore(store).create(
            source_root=Path.cwd(),
            simulation_area=root / "sim",
            scenario_count=1370,
            label="semantic-hook-source",
        )
        review = SemanticOracleReviewStore(store).create(
            simulation_sweep_id=sweep["simulation_sweep_id"],
            source_root=Path.cwd(),
            label="semantic-hook-review",
        )
        return store, review

    def test_semantic_hook_run_records_first_class_hook_records(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store, review = self._review_store(root)

            run = SemanticHookRunStore(store).create(
                semantic_oracle_review_id=str(review["semantic_oracle_review_id"]),
                source_root=Path.cwd(),
                label="test-hook-run",
            )
            state = store.load()

            self.assertEqual(run["status"], "allow")
            self.assertEqual(run["coverage"]["semantic_gap_input_count"], 685)
            self.assertEqual(run["coverage"]["semantic_gap_remaining_count"], 0)
            self.assertEqual(run["coverage"]["covered_hook_count"], 5)
            self.assertEqual(run["coverage"]["covered_record_family_count"], 11)
            self.assertFalse(run["live_boundaries"]["hook_installed"])
            self.assertEqual(len(state["semantic_hook_records"]), 11)
            for receipt in run["record_family_receipts"]:
                record_id = receipt["semantic_hook_record_id"]
                self.assertIn(record_id, state["semantic_hook_records"])
                self.assertEqual(
                    receipt["semantic_hook_record_sha256"],
                    state["semantic_hook_records"][record_id]["semantic_hook_record_sha256"],
                )
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_missing_hook_record_reference(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store, review = self._review_store(root)
            run = SemanticHookRunStore(store).create(
                semantic_oracle_review_id=str(review["semantic_oracle_review_id"]),
                source_root=Path.cwd(),
                label="test-missing-hook-record",
            )
            state = store.load()
            record_id = run["record_family_receipts"][0]["semantic_hook_record_id"]
            del state["semantic_hook_records"][record_id]
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn(
                f"semantic_hook_run {run['semantic_hook_run_id']} references missing semantic_hook_record {record_id}",
                "\n".join(replay["errors"]),
            )

    def test_replay_catches_hook_record_live_boundary_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store, review = self._review_store(root)
            SemanticHookRunStore(store).create(
                semantic_oracle_review_id=str(review["semantic_oracle_review_id"]),
                source_root=Path.cwd(),
                label="test-hook-record-tamper",
            )
            state = store.load()
            record = next(iter(state["semantic_hook_records"].values()))
            record["live_boundaries"]["hook_installed"] = True
            record["semantic_hook_record_sha256"] = _hash_without(record, "semantic_hook_record_sha256")
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("semantic_hook_record.hook_installed_not_false", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_semantic_hook_run_collections(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store, review = self._review_store(root)
            SemanticHookRunStore(store).create(
                semantic_oracle_review_id=str(review["semantic_oracle_review_id"]),
                source_root=Path.cwd(),
                label="test-hook-oracle",
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("semantic_hook_records", collections)
            self.assertIn("semantic_hook_runs", collections)


if __name__ == "__main__":
    unittest.main()
