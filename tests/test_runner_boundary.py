from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.admission import AdmissionReviewStore
from ams.capability_policy import build_capability_request, evaluate_capability_request
from ams.codex_adapter import CodexDryRunAdapter
from ams.context import ContextStore
from ams.dispatch import dispatch
from ams.outbox import OutboxStore
from ams.resource_claim import ResourceClaimStore
from ams.runner_boundary import runner_preflight
from ams.run_trace import RunTraceStore
from ams.session_registry import SessionRegistry
from ams.shadow_launch import ShadowLaunchStore
from ams.store import JsonStore
from ams.surface_bindings import SurfaceBindingStore, _record_sha
from ams.surface_promise import SurfacePromiseStore


PACKAGE_SHA = "sha256:" + "1" * 64
OTHER_PACKAGE_SHA = "sha256:" + "2" * 64
READY_INSTALL = {
    "schema_version": "ams.ams.install_preflight.v0",
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


class RunnerBoundaryTest(unittest.TestCase):
    def test_dispatch_envelope_preflights_as_dry_run_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, envelope = _dispatched_envelope(Path(td))

            result = runner_preflight(envelope, store)

            self.assertTrue(result["allowed"], result)
            invocation = result["invocation"]
            self.assertTrue(invocation["dry_run_only"])
            self.assertEqual(invocation["task_run_id"], envelope["task_run_id"])
            self.assertEqual(invocation["provider_request_id"], envelope["provider_request_id"])

    def test_direct_codex_adapter_request_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _ = _dispatched_envelope(Path(td))
            state = store.load()
            session = next(iter(state["sessions"].values()))
            context = next(iter(state["contexts"].values()))
            direct = CodexDryRunAdapter(store).prepare_request(session["session_id"], context["context_id"])

            result = runner_preflight(direct, store)

            self.assertFalse(result["allowed"])
            self.assertIn("runner.not_dispatch_envelope", result["reason_codes"])

    def test_tampered_dispatch_envelope_hash_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, envelope = _dispatched_envelope(Path(td))
            envelope["model"] = "tampered-model"

            result = runner_preflight(envelope, store)

            self.assertFalse(result["allowed"])
            self.assertEqual(result["reason_code"], "runner.envelope_hash_mismatch")

    def test_live_runner_mode_requires_launch_plan_reference(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, envelope = _dispatched_envelope(Path(td))

            result = runner_preflight(envelope, store, live=True)

            self.assertFalse(result["allowed"])
            self.assertEqual(result["reason_code"], "runner.shadow_launch_plan_id_missing")
            self.assertIn("runner.shadow_launch_plan_sha256_missing", result["reason_codes"])

    def test_live_runner_preflights_with_matching_shadow_launch_plan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, envelope = _dispatched_envelope(Path(td))
            plan = _shadow_launch_plan_for_envelope(store, envelope)

            result = runner_preflight(
                envelope,
                store,
                live=True,
                shadow_launch_plan_id=plan["shadow_launch_plan_id"],
                shadow_launch_plan_sha256=plan["shadow_launch_plan_sha256"],
            )

            self.assertTrue(result["allowed"], result)
            self.assertEqual(result["reason_code"], "runner.live_shadow_preflight_ok")
            invocation = result["invocation"]
            self.assertTrue(invocation["dry_run_only"])
            self.assertTrue(invocation["preflight_only"])
            self.assertTrue(invocation["live_requested"])
            self.assertEqual(invocation["launch_mode"], "shadow")
            self.assertEqual(invocation["shadow_launch_plan_id"], plan["shadow_launch_plan_id"])

    def test_live_runner_rejects_launch_plan_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, envelope = _dispatched_envelope(Path(td))
            plan = _shadow_launch_plan_for_envelope(store, envelope)

            result = runner_preflight(
                envelope,
                store,
                live=True,
                shadow_launch_plan_id=plan["shadow_launch_plan_id"],
                shadow_launch_plan_sha256="sha256:" + "0" * 64,
            )

            self.assertFalse(result["allowed"])
            self.assertIn("runner.shadow_launch_plan_hash_mismatch", result["reason_codes"])

    def test_live_runner_rejects_stale_shadow_launch_plan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, envelope = _dispatched_envelope(Path(td))
            plan = _shadow_launch_plan_for_envelope(store, envelope)
            state = store.load()
            surface_id = plan["runtime_surface_ids"][0]
            surface = state["runtime_surfaces"][surface_id]
            surface["package_manifest_sha256"] = OTHER_PACKAGE_SHA
            surface["runtime_surface_sha256"] = _record_sha(surface, "runtime_surface_sha256")
            store.save(state)

            result = runner_preflight(
                envelope,
                store,
                live=True,
                shadow_launch_plan_id=plan["shadow_launch_plan_id"],
                shadow_launch_plan_sha256=plan["shadow_launch_plan_sha256"],
            )

            self.assertFalse(result["allowed"])
            self.assertIn("shadow_launch_plan.ready_to_launch_stale", "\n".join(result["reason_codes"]))


def _dispatched_envelope(root: Path) -> tuple[JsonStore, dict]:
    store = JsonStore(root / "store.json")
    event = {"channel_id": "chan", "message_id": "root", "content": "build"}
    session, _ = SessionRegistry(store).ingest_event(event)
    session = CodexDryRunAdapter(store).bind_thread(session["session_id"], "thread-1")
    context = ContextStore(store).create_for_event(session, event)
    task_run = RunTraceStore(store).create_run(
        session["session_id"],
        context["context_id"],
        model="gpt-5.5",
        sandbox="workspace-write",
        tool_scope=["Read", "ApplyPatch", "Tests"],
    )
    request = build_capability_request(
        action="write",
        paths=["tests/test_runner_boundary.py"],
        tools=["Read", "ApplyPatch", "Tests"],
        egress_mode="ams_outbox",
    )
    verdict = evaluate_capability_request(request)
    AdmissionReviewStore(store).create(
        subject_kind="task_run",
        subject_id=task_run["task_run_id"],
        operation="capability.dispatch",
        request=request,
        verdict=verdict,
    )
    claim = ResourceClaimStore(store).reserve(task_run["task_run_id"])["claim"]
    assert claim is not None
    ResourceClaimStore(store).transition(claim["resource_claim_id"], "active")
    result = dispatch(store, task_run["task_run_id"])
    assert result["dispatched"], result
    return store, result["envelope"]


def _shadow_launch_plan_for_envelope(store: JsonStore, envelope: dict) -> dict:
    surface = SurfaceBindingStore(store).declare_surface(
        provider=envelope["provider"],
        surface=envelope["surface"],
        runtime_name="runner-test-codex-app-server",
        transport="stdio",
        rollout_mode="shadow",
        session_semantics="persistent_thread",
        capability_tier="builder",
        egress_modes=["none"],
        package_manifest_sha256=PACKAGE_SHA,
    )
    binding = SurfaceBindingStore(store).bind_surface(
        runtime_surface_id=surface["runtime_surface_id"],
        session_id=envelope["session_id"],
        provider_session_id=envelope.get("provider_session_id"),
        task_run_id=envelope["task_run_id"],
    )
    outbox = OutboxStore(store).create_item(
        envelope["task_run_id"],
        target="discord",
        channel_id="chan",
        endpoint="/channels/chan/messages",
        payload={"content": "runner live-shadow preflight test"},
    )
    OutboxStore(store).record_receipt(
        outbox["outbox_id"],
        status="readback_verified",
        response_payload={"message_id": "runner-preflight-msg"},
        readback_ref="discord://chan/runner-preflight-msg",
    )
    promise = SurfacePromiseStore(store).create(
        envelope["task_run_id"],
        promised_surfaces=[
            {
                "surface": "discord",
                "target": "discord",
                "channel_id": "chan",
                "outbox_id": outbox["outbox_id"],
                "required": True,
                "required_readback": True,
            }
        ],
        source_packet_ref="source-packet://runner-live-shadow-test",
        promise_reason="runner_preflight_surface_gate",
    )
    return ShadowLaunchStore(store).create_plan(
        install_preflight=READY_INSTALL,
        package_verification=VERIFIED_PACKAGE,
        approval_id="approval-runner-live-shadow-test",
        egress_mode="none",
        runtime_surface_ids=[surface["runtime_surface_id"]],
        surface_binding_ids=[binding["surface_binding_id"]],
        surface_promise_ids=[promise["surface_promise_id"]],
    )


if __name__ == "__main__":
    unittest.main()
