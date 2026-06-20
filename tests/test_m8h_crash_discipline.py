from __future__ import annotations

import json
import multiprocessing
import os
import tempfile
import time
import unittest
from pathlib import Path
from queue import Empty

from ams_codex.models import canonical_json
from ams_codex.schema_validation import SchemaValidationError
from ams_codex.store import JsonStore, empty_state


class FailingBeforeReplaceStore(JsonStore):
    def _save_unlocked(self, state: dict) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        raise RuntimeError("simulated crash before replace")


def _hold_store_lock(store_path: str, queue: multiprocessing.Queue) -> None:
    store = JsonStore(store_path)
    with store._lock_file():
        queue.put("locked")
        time.sleep(60)


class M8HCrashDisciplineTest(unittest.TestCase):
    def test_interrupted_write_before_replace_preserves_previous_store(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "store.json"
            store = JsonStore(path)
            initial = empty_state()
            store.save(initial, check_revision=False)
            before = canonical_json(store.load())

            failing = FailingBeforeReplaceStore(path)
            state = failing.load()
            state["schema"] = "tampered"
            with self.assertRaises(RuntimeError):
                failing.save(state)

            self.assertEqual(canonical_json(store.load()), before)
            self.assertTrue(path.with_suffix(path.suffix + ".tmp").exists())

    def test_orphan_tmp_file_is_ignored_on_load(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "store.json"
            store = JsonStore(path)
            store.save(empty_state(), check_revision=False)
            before = canonical_json(store.load())
            path.with_suffix(path.suffix + ".tmp").write_text("{not json", encoding="utf-8")

            self.assertEqual(canonical_json(store.load()), before)

    def test_exception_inside_locked_block_does_not_commit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            store.save(empty_state(), check_revision=False)
            before = canonical_json(store.load())

            with self.assertRaises(RuntimeError):
                with store.locked() as state:
                    state["schema"] = "changed inside failed transaction"
                    raise RuntimeError("abort locked update")

            self.assertEqual(canonical_json(store.load()), before)

    def test_validation_failure_inside_locked_block_does_not_commit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            store.save(empty_state(), check_revision=False)
            before = canonical_json(store.load())

            with self.assertRaises(SchemaValidationError):
                with store.locked() as state:
                    state["task_runs"]["bad-run"] = {
                        "schema_version": "ams.ams_codex.task_run.v0",
                        "task_run_id": "bad-run",
                        "state": "invalid",
                    }

            self.assertEqual(canonical_json(store.load()), before)

    def test_preexisting_lock_file_does_not_block_future_writes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "store.json"
            store = JsonStore(path)
            store.lock_path.parent.mkdir(parents=True, exist_ok=True)
            store.lock_path.write_text("stale lock file from dead process", encoding="utf-8")

            store.save(empty_state(), check_revision=False)

            self.assertEqual(store.load()["revision"], 1)

    def test_killed_lock_holder_releases_future_writes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "store.json"
            store = JsonStore(path)
            ctx = multiprocessing.get_context("spawn")
            queue = ctx.Queue()
            process = ctx.Process(target=_hold_store_lock, args=(str(path), queue))
            process.start()
            try:
                self.assertEqual(queue.get(timeout=5), "locked")
            except Empty:
                self.fail("lock holder did not report readiness")

            process.terminate()
            process.join(timeout=5)
            self.assertFalse(process.is_alive())

            store.save(empty_state(), check_revision=False)
            self.assertEqual(store.load()["revision"], 1)

    def test_corrupt_main_store_fails_loud(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "store.json"
            path.write_text("{not json", encoding="utf-8")

            with self.assertRaises(json.JSONDecodeError):
                JsonStore(path).load()


if __name__ == "__main__":
    unittest.main()
