from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams_codex.admission import AdmissionReviewStore
from ams_codex.capability_policy import build_capability_request, evaluate_capability_request
from ams_codex.codex_adapter import CodexDryRunAdapter
from ams_codex.context import ContextStore
from ams_codex.dispatch import dispatch
from ams_codex.outbox import OutboxStore
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.resource_claim import ResourceClaimStore
from ams_codex.runner_boundary import runner_preflight
from ams_codex.run_trace import RunTraceStore
from ams_codex.session_registry import SessionRegistry
from ams_codex.shadow_launch import ShadowLaunchStore
from ams_codex.shadow_runner import ShadowRunnerStore
from ams_codex.store import JsonStore
from ams_codex.surface_bindings import SurfaceBindingStore, _record_sha
from ams_codex.surface_promise import SurfacePromiseStore
from ams_codex.workspace import workspace_root


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


class ShadowRunnerTransactionTest(unittest.TestCase):
    def test_ready_shadow_runner_transaction_is_replayable_and_inert(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, preflight, _plan = _live_shadow_preflight(Path(td))

            transaction = _create_transaction(store, preflight)

            self.assertEqual(transaction["status"], "allow")
            self.assertTrue(transaction["ready_for_operator_review"])
            self.assertFalse(transaction["process_start_allowed"])
            self.assertEqual(transaction["start_actions"], [])
            self.assertEqual(transaction["command"]["argv"], ["/bin/echo", "shadow-runner"])
            self.assertEqual(transaction["environment"]["allowed_names"], ["PATH"])
            self.assertEqual(transaction["environment"]["redacted_names"], ["DISCORD_TOKEN"])
            self.assertEqual(transaction["environment"]["stored_values"], {})
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_denies_non_live_shadow_runner_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, _preflight, envelope = _live_shadow_preflight(Path(td))
            dry_run_preflight = runner_preflight(envelope, store)

            transaction = _create_transaction(store, dry_run_preflight)

            self.assertEqual(transaction["status"], "deny")
            self.assertIn("shadow_runner.runner_preflight_not_live_shadow", transaction["reason_codes"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_secret_env_name_in_allowed_env_denies_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, preflight, _plan = _live_shadow_preflight(Path(td))

            transaction = _create_transaction(store, preflight, env_names=["DISCORD_TOKEN"])

            self.assertEqual(transaction["status"], "deny")
            self.assertIn("shadow_runner.environment_secret_name_allowed", transaction["reason_codes"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_missing_abort_or_rollback_defers_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, preflight, _plan = _live_shadow_preflight(Path(td))

            transaction = _create_transaction(store, preflight, abort_conditions=[], rollback_steps=[])

            self.assertEqual(transaction["status"], "defer")
            self.assertIn("shadow_runner.abort_conditions_missing", transaction["reason_codes"])
            self.assertIn("shadow_runner.rollback_steps_missing", transaction["reason_codes"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_stale_launch_plan_after_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, preflight, plan = _live_shadow_preflight(Path(td))
            _create_transaction(store, preflight)
            state = store.load()
            surface = state["runtime_surfaces"][plan["runtime_surface_ids"][0]]
            surface["package_manifest_sha256"] = OTHER_PACKAGE_SHA
            surface["runtime_surface_sha256"] = _record_sha(surface, "runtime_surface_sha256")
            store.save(state)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("shadow_runner_transaction.status_stale", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_shadow_runner_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, preflight, _plan = _live_shadow_preflight(Path(td))
            _create_transaction(store, preflight)

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("shadow_runner_transactions", collections)


def _live_shadow_preflight(root: Path) -> tuple[JsonStore, dict, dict]:
    store, envelope = _dispatched_envelope(root)
    plan = _shadow_launch_plan_for_envelope(store, envelope)
    preflight = runner_preflight(
        envelope,
        store,
        live=True,
        shadow_launch_plan_id=plan["shadow_launch_plan_id"],
        shadow_launch_plan_sha256=plan["shadow_launch_plan_sha256"],
    )
    assert preflight["allowed"], preflight
    return store, preflight, plan


def _create_transaction(
    store: JsonStore,
    preflight: dict,
    *,
    env_names: list[str] | None = None,
    abort_conditions: list[str] | None = None,
    rollback_steps: list[str] | None = None,
) -> dict:
    return ShadowRunnerStore(store).create_transaction(
        runner_preflight=preflight,
        argv=["/bin/echo", "shadow-runner"],
        cwd=workspace_root(),
        requested_by="operator:test",
        approval_id="approval-shadow-runner-test",
        purpose="test no-egress shadow runner transaction",
        env_names=["PATH"] if env_names is None else env_names,
        redacted_env_names=["DISCORD_TOKEN"],
        abort_conditions=["runner preflight becomes stale"] if abort_conditions is None else abort_conditions,
        rollback_steps=["do not start process; discard transaction"] if rollback_steps is None else rollback_steps,
    )


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
        paths=["tests/test_shadow_runner.py"],
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
        runtime_name="shadow-runner-test-codex-app-server",
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
        payload={"content": "shadow runner transaction test"},
    )
    OutboxStore(store).record_receipt(
        outbox["outbox_id"],
        status="readback_verified",
        response_payload={"message_id": "shadow-runner-msg"},
        readback_ref="discord://chan/shadow-runner-msg",
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
        source_packet_ref="source-packet://shadow-runner-test",
        promise_reason="shadow_runner_surface_gate",
    )
    return ShadowLaunchStore(store).create_plan(
        install_preflight=READY_INSTALL,
        package_verification=VERIFIED_PACKAGE,
        approval_id="approval-shadow-runner-test",
        egress_mode="none",
        runtime_surface_ids=[surface["runtime_surface_id"]],
        surface_binding_ids=[binding["surface_binding_id"]],
        surface_promise_ids=[promise["surface_promise_id"]],
    )


if __name__ == "__main__":
    unittest.main()
