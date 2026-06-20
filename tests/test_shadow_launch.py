from __future__ import annotations

from copy import deepcopy
import tempfile
import unittest
from pathlib import Path

from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.schema_validation import SchemaValidationError
from ams_codex.shadow_launch import ShadowLaunchStore
from ams_codex.simulation import run_full_simulation
from ams_codex.store import JsonStore
from ams_codex.surface_bindings import SurfaceBindingStore, _record_sha
from ams_codex.surface_promise import SurfacePromiseStore


PACKAGE_SHA = "sha256:" + "1" * 64
OTHER_PACKAGE_SHA = "sha256:" + "2" * 64
READY_INSTALL = {
    "schema_version": "ams.ams_codex.install_preflight.v0",
    "ready_for_live": True,
    "status": "pass",
    "checks": [],
    "summary": {"pass": 4, "defer": 0, "fail": 0},
}
VERIFIED_PACKAGE = {
    "allowed": True,
    "status": "allow",
    "reason_code": "package.verified",
    "reason_codes": ["package.verified"],
    "manifest_sha256": PACKAGE_SHA,
}


class ShadowLaunchTest(unittest.TestCase):
    def test_ready_no_egress_shadow_plan_is_replayable_and_inert(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            ids = _ready_inputs(store)

            plan = _create_plan(store, ids)

            self.assertTrue(plan["ready_to_launch"], plan)
            self.assertEqual(plan["status"], "allow")
            self.assertEqual(plan["launch_actions"], [])
            self.assertEqual(plan["downstream_consumers"], [])
            self.assertEqual(plan["runtime_surface_ids"], [ids["runtime_surface_id"]])
            self.assertEqual(plan["surface_binding_ids"], [ids["surface_binding_id"]])
            self.assertEqual(plan["surface_promise_ids"], [ids["surface_promise_id"]])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_install_not_ready_defers_launch_plan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            ids = _ready_inputs(store)

            plan = _create_plan(
                store,
                ids,
                install_preflight={**READY_INSTALL, "ready_for_live": False, "status": "defer"},
            )

            self.assertFalse(plan["ready_to_launch"])
            self.assertEqual(plan["status"], "defer")
            self.assertIn("shadow.install_preflight_not_ready", plan["reason_codes"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_direct_egress_denies_launch_plan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            ids = _ready_inputs(store)

            plan = _create_plan(store, ids, egress_mode="ams_outbox")

            self.assertFalse(plan["ready_to_launch"])
            self.assertEqual(plan["status"], "deny")
            self.assertIn("shadow.egress_must_be_none", plan["reason_codes"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_runtime_surface_egress_denies_launch_plan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            ids = _ready_inputs(store, runtime_egress_modes=["ams_outbox"])

            plan = _create_plan(store, ids)

            self.assertFalse(plan["ready_to_launch"])
            self.assertEqual(plan["status"], "deny")
            self.assertIn(
                f"shadow_launch.runtime_surface_egress_not_none:{ids['runtime_surface_id']}",
                plan["reason_codes"],
            )
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_stale_runtime_rollout_after_plan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            ids = _ready_inputs(store)
            _create_plan(store, ids)
            state = store.load()
            surface = state["runtime_surfaces"][ids["runtime_surface_id"]]
            surface["rollout_mode"] = "dry_run"
            surface["runtime_surface_sha256"] = _record_sha(surface, "runtime_surface_sha256")
            store.save(state)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("shadow_launch_plan.ready_to_launch_stale", "\n".join(replay["errors"]))

    def test_replay_catches_stale_package_pin_after_plan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            ids = _ready_inputs(store)
            _create_plan(store, ids)
            state = store.load()
            surface = state["runtime_surfaces"][ids["runtime_surface_id"]]
            surface["package_manifest_sha256"] = OTHER_PACKAGE_SHA
            surface["runtime_surface_sha256"] = _record_sha(surface, "runtime_surface_sha256")
            store.save(state)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("shadow_launch_plan.ready_to_launch_stale", "\n".join(replay["errors"]))

    def test_store_schema_rejects_malformed_launch_plan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            ids = _ready_inputs(store)
            plan = _create_plan(store, ids)
            state = store.load()
            bad = deepcopy(plan)
            bad.pop("surface_binding_ids")
            state["shadow_launch_plans"]["shadowlaunch_bad"] = bad

            with self.assertRaises(SchemaValidationError):
                store.save(state)

    def test_replay_oracle_covers_shadow_launch_plan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            ids = _ready_inputs(store)
            _create_plan(store, ids)

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("shadow_launch_plans", collections)


def _ready_inputs(
    store: JsonStore,
    *,
    runtime_egress_modes: list[str] | None = None,
) -> dict[str, str]:
    result = run_full_simulation(
        {"channel_id": "chan", "message_id": "root", "content": "build"},
        store,
    )
    surface = SurfaceBindingStore(store).declare_surface(
        provider="openai_codex",
        surface="app-server",
        runtime_name="studio-codex-app-server",
        transport="stdio",
        rollout_mode="shadow",
        session_semantics="persistent_thread",
        capability_tier="builder",
        egress_modes=runtime_egress_modes or ["none"],
        package_manifest_sha256=PACKAGE_SHA,
    )
    binding = SurfaceBindingStore(store).bind_surface(
        runtime_surface_id=surface["runtime_surface_id"],
        session_id=result["session_id"],
        provider_session_id="sim-codex-thread-m8g",
    )
    promise = SurfacePromiseStore(store).create(
        result["task_run_id"],
        promised_surfaces=[
            {
                "surface": "discord",
                "target": "discord",
                "channel_id": "chan",
                "outbox_id": result["outbox_id"],
                "required": True,
                "required_readback": True,
            }
        ],
        source_packet_ref="source-packet://shadow-launch-test",
        promise_reason="launch_packet_surface_gate",
    )
    return {
        "runtime_surface_id": surface["runtime_surface_id"],
        "surface_binding_id": binding["surface_binding_id"],
        "surface_promise_id": promise["surface_promise_id"],
    }


def _create_plan(
    store: JsonStore,
    ids: dict[str, str],
    *,
    install_preflight: dict | None = None,
    package_verification: dict | None = None,
    egress_mode: str = "none",
) -> dict:
    return ShadowLaunchStore(store).create_plan(
        install_preflight=install_preflight or READY_INSTALL,
        package_verification=package_verification or VERIFIED_PACKAGE,
        approval_id="approval-local-shadow-test",
        egress_mode=egress_mode,
        runtime_surface_ids=[ids["runtime_surface_id"]],
        surface_binding_ids=[ids["surface_binding_id"]],
        surface_promise_ids=[ids["surface_promise_id"]],
    )


if __name__ == "__main__":
    unittest.main()
