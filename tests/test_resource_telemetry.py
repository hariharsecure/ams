from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.context import ContextStore
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.resource_claim import ResourceClaimStore
from ams.resource_telemetry import ResourceTelemetryStore
from ams.run_trace import RunTraceStore
from ams.session_registry import SessionRegistry
from ams.store import JsonStore


def _store_run_claim(root: Path) -> tuple[JsonStore, dict, dict]:
    store = JsonStore(root / "store.json")
    event = {"channel_id": "chan", "message_id": "root", "content": "build"}
    session, _ = SessionRegistry(store).ingest_event(event)
    context = ContextStore(store).create_for_event(session, event)
    task_run = RunTraceStore(store).create_run(
        session["session_id"],
        context["context_id"],
        model="gpt-5.5",
        tool_scope=["Read"],
    )
    claim = ResourceClaimStore(store).reserve(task_run["task_run_id"])["claim"]
    return store, task_run, claim


class ResourceTelemetryTest(unittest.TestCase):
    def test_resource_telemetry_within_limits_replays(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _, claim = _store_run_claim(Path(td))

            telemetry = ResourceTelemetryStore(store).record(
                claim["resource_claim_id"],
                observed={
                    "input_tokens": 1200,
                    "output_tokens": 300,
                    "runtime_ms": 4500,
                    "cost_microusd": 1250,
                    "cpu_core_ms": 900,
                    "peak_memory_mb": 256,
                },
                source_ref={"kind": "manual", "ref": "local://test/resource-telemetry"},
            )

            self.assertEqual(telemetry["settlement_status"], "within_limits")
            self.assertEqual(telemetry["reason_codes"], ["resource_telemetry.within_limits"])
            self.assertEqual(telemetry["observed"]["total_tokens"], 1500)
            self.assertFalse(telemetry["live_boundaries"]["listener_started"])
            self.assertFalse(telemetry["live_boundaries"]["provider_poll_performed"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_resource_telemetry_over_limit_records_reasons_without_listener(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _, claim = _store_run_claim(Path(td))

            telemetry = ResourceTelemetryStore(store).record(
                claim["resource_claim_id"],
                observed={
                    "input_tokens": 60000,
                    "output_tokens": 13000,
                    "runtime_ms": 3_700_000,
                    "peak_memory_mb": 4096,
                },
                source_ref={"kind": "synthetic", "ref": "local://test/resource-telemetry-over-limit"},
                source_type="synthetic",
            )

            self.assertEqual(telemetry["settlement_status"], "over_limit")
            self.assertIn("resource_telemetry.input_tokens_over_reserved", telemetry["reason_codes"])
            self.assertIn("resource_telemetry.output_tokens_over_reserved", telemetry["reason_codes"])
            self.assertIn("resource_telemetry.runtime_over_reserved", telemetry["reason_codes"])
            self.assertIn("resource_telemetry.memory_over_reserved", telemetry["reason_codes"])
            self.assertFalse(telemetry["live_boundaries"]["network_call_performed"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_rejects_tampered_resource_telemetry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _, claim = _store_run_claim(Path(td))
            telemetry = ResourceTelemetryStore(store).record(
                claim["resource_claim_id"],
                observed={"input_tokens": 1, "output_tokens": 1},
            )
            state = store.load()
            state["resource_telemetry_samples"][telemetry["resource_telemetry_id"]]["live_boundaries"][
                "provider_poll_performed"
            ] = True
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("resource_telemetry.provider_poll_performed_not_false", "\n".join(replay["errors"]))

    def test_replay_rejects_invalid_numeric_resource_telemetry_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _, claim = _store_run_claim(Path(td))
            telemetry = ResourceTelemetryStore(store).record(
                claim["resource_claim_id"],
                observed={"input_tokens": 1, "output_tokens": 1},
            )
            state = store.load()
            state["resource_telemetry_samples"][telemetry["resource_telemetry_id"]]["observed"]["input_tokens"] = -1
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("resource_telemetry.numeric_value_invalid", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_resource_telemetry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _, claim = _store_run_claim(Path(td))
            ResourceTelemetryStore(store).record(
                claim["resource_claim_id"],
                observed={"input_tokens": 1, "output_tokens": 1},
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("resource_telemetry_samples", collections)


if __name__ == "__main__":
    unittest.main()
