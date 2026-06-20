from __future__ import annotations

from copy import deepcopy
from contextlib import redirect_stdout
from io import StringIO
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ams.cli import cmd_replay_oracle
from ams.models import canonical_json
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.simulation import run_full_simulation
from ams.store import JsonStore


class ReplayOracleTest(unittest.TestCase):
    def test_oracle_detects_delete_and_mutate_faults(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            run_full_simulation({"channel_id": "chan", "message_id": "root", "content": "build"}, store)
            before = canonical_json(store.load())

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            self.assertGreaterEqual(result["summary"]["cases"], 20)
            self.assertEqual(result["summary"]["missed"], 0)
            self.assertEqual(canonical_json(store.load()), before)

    def test_replay_detects_missing_source_event(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            run_full_simulation({"channel_id": "chan", "message_id": "root", "content": "build"}, store)
            state = store.load()
            state["events"] = {}
            store.save(state)

            result = ReplayChecker(store).check()

            self.assertFalse(result["ok"])
            self.assertIn("references missing event", "\n".join(result["errors"]))

    def test_oracle_reports_miss_for_unprotected_copy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            run_full_simulation({"channel_id": "chan", "message_id": "root", "content": "build"}, store)
            state = deepcopy(store.load())
            run_event_id = next(iter(state["run_events"]))
            state["run_events"][run_event_id]["event_sha256"] = "sha256:" + "0" * 64
            store.save(state, validate=False)

            result = ReplayOracle(store).check()

            self.assertFalse(result["ok"])
            self.assertFalse(result["baseline"]["ok"])
            self.assertIn("sha256 mismatch", "\n".join(result["baseline"]["errors"]))

    def test_cli_replay_oracle_default_output_is_compact(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            run_full_simulation({"channel_id": "chan", "message_id": "root", "content": "build"}, store)
            args = SimpleNamespace(store=str(store.path), full_output=False)
            stdout = StringIO()

            with redirect_stdout(stdout):
                code = cmd_replay_oracle(args)

            self.assertEqual(code, 0)
            text = stdout.getvalue()
            self.assertIn('"summary"', text)
            self.assertIn('"skipped_count"', text)
            self.assertNotIn('"attack"', text)
            self.assertNotIn('"record_id"', text)


if __name__ == "__main__":
    unittest.main()
