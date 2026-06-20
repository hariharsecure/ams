from __future__ import annotations

import multiprocessing
import tempfile
import unittest
from pathlib import Path
from queue import Empty

from ams.context import ContextStore
from ams.replay import ReplayChecker
from ams.resource_claim import ResourceClaimStore
from ams.run_trace import RunTraceStore
from ams.schema_validation import SchemaValidationError
from ams.session_registry import SessionRegistry
from ams.store import JsonStore, StoreRevisionError, empty_state


def _append_event_worker(store_path: str, task_run_id: str, worker_id: int, queue: multiprocessing.Queue) -> None:
    try:
        event = RunTraceStore(JsonStore(store_path)).append_event(
            task_run_id,
            "worker.progress",
            payload={"worker_id": worker_id},
        )
        queue.put({"ok": True, "sequence": event["sequence"]})
    except Exception as exc:  # pragma: no cover - reported to parent process
        queue.put({"ok": False, "error": repr(exc)})


def _create_run(store: JsonStore) -> dict:
    raw_event = {"channel_id": "chan", "message_id": "root", "content": "build"}
    session, _ = SessionRegistry(store).ingest_event(raw_event)
    context = ContextStore(store).create_for_event(session, raw_event)
    task_run = RunTraceStore(store).create_run(
        session["session_id"],
        context["context_id"],
        tool_scope=["Read"],
    )
    ResourceClaimStore(store).reserve(task_run["task_run_id"])
    return task_run


class StoreHardeningTest(unittest.TestCase):
    def test_save_rejects_stale_revision(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            first = store.load()
            second = store.load()
            first["events"]["evt-1"] = {"message_id": "evt-1"}
            store.save(first)

            second["events"]["evt-2"] = {"message_id": "evt-2"}
            with self.assertRaises(StoreRevisionError):
                store.save(second)

    def test_store_boundary_rejects_invalid_schema_record(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            state = empty_state()
            state["task_runs"]["bad-run"] = {
                "schema_version": "ams.ams.task_run.v0",
                "task_run_id": "bad-run",
                "state": "invalid",
            }

            with self.assertRaises(SchemaValidationError):
                store.save(state, check_revision=False)

    def test_multiprocess_run_event_append_preserves_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store_path = str(Path(td) / "store.json")
            store = JsonStore(store_path)
            task_run = _create_run(store)
            ctx = multiprocessing.get_context("spawn")
            queue = ctx.Queue()
            processes = [
                ctx.Process(target=_append_event_worker, args=(store_path, task_run["task_run_id"], index, queue))
                for index in range(8)
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(timeout=10)
                self.assertEqual(process.exitcode, 0)

            results = []
            for _ in processes:
                try:
                    results.append(queue.get(timeout=2))
                except Empty:
                    self.fail("worker did not report result")
            self.assertTrue(all(result.get("ok") for result in results), results)

            state = store.load()
            run_events = [
                event for event in state["run_events"].values()
                if event.get("task_run_id") == task_run["task_run_id"]
            ]
            self.assertEqual(len(run_events), 1 + len(processes))
            self.assertEqual(
                sorted(event["sequence"] for event in run_events),
                list(range(1, len(processes) + 2)),
            )
            self.assertTrue(ReplayChecker(store).check()["ok"])


if __name__ == "__main__":
    unittest.main()
