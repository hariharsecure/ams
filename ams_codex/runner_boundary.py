from __future__ import annotations

from typing import Any

from .models import canonical_json, sha256_text
from .shadow_launch import validate_shadow_launch_plan_record
from .store import JsonStore


DISPATCH_ENVELOPE_SCHEMA = "ams.ams_codex.dispatch_envelope.v0"
SHADOW_LAUNCH_MODE = "shadow"


def runner_preflight(
    envelope: dict[str, Any],
    store: JsonStore,
    *,
    live: bool = False,
    shadow_launch_plan_id: str | None = None,
    shadow_launch_plan_sha256: str | None = None,
) -> dict[str, Any]:
    shape = _validate_envelope_shape(envelope)
    if not shape["ok"]:
        return _deny_many(shape["reason_codes"])
    expected_hash = envelope.get("sha256")
    material = dict(envelope)
    material.pop("sha256", None)
    if expected_hash != sha256_text(canonical_json(material)):
        return _deny("runner.envelope_hash_mismatch")

    state = store.load()
    task_run = (state.get("task_runs") or {}).get(envelope.get("task_run_id"))
    if not task_run:
        return _deny("runner.task_run_missing")
    checks = _validate_against_task_run(envelope, task_run, state)
    if not checks["ok"]:
        return _deny_many(checks["reason_codes"])
    live_checks: dict[str, Any] = {"ok": True, "reason_codes": [], "plan": None}
    if live:
        live_checks = _validate_live_shadow_launch(
            envelope,
            state,
            shadow_launch_plan_id=shadow_launch_plan_id,
            shadow_launch_plan_sha256=shadow_launch_plan_sha256,
        )
        if not live_checks["ok"]:
            return _deny_many(live_checks["reason_codes"])

    invocation = {
        "schema_version": "ams.ams_codex.runner_invocation.v0",
        "dry_run_only": True,
        "preflight_only": True,
        "live_requested": bool(live),
        "launch_mode": SHADOW_LAUNCH_MODE if live else "dry_run",
        "shadow_launch_plan_id": shadow_launch_plan_id if live else None,
        "shadow_launch_plan_sha256": shadow_launch_plan_sha256 if live else None,
        "dispatch_envelope_id": envelope["dispatch_envelope_id"],
        "task_run_id": envelope["task_run_id"],
        "session_id": envelope["session_id"],
        "provider": envelope["provider"],
        "surface": envelope["surface"],
        "provider_session_id": envelope.get("provider_session_id"),
        "provider_request_id": envelope["provider_request_id"],
        "method": envelope["method"],
        "model": envelope.get("model"),
        "cwd": envelope.get("cwd"),
        "sandbox": envelope.get("sandbox"),
        "tool_scope": list(envelope.get("tool_scope") or []),
        "trace_id": envelope.get("trace_id"),
        "parent_span_id": envelope.get("parent_span_id"),
        "definition_snapshot_sha256": envelope.get("definition_snapshot_sha256"),
        "resource_claim_id": envelope.get("resource_claim_id"),
    }
    invocation["sha256"] = sha256_text(canonical_json(invocation))
    return {
        "allowed": True,
        "status": "allow",
        "reason_code": "runner.live_shadow_preflight_ok" if live else "runner.preflight_ok",
        "reason_codes": ["runner.live_shadow_preflight_ok"] if live else ["runner.preflight_ok"],
        "invocation": invocation,
    }


def _validate_envelope_shape(envelope: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    if envelope.get("schema_version") != DISPATCH_ENVELOPE_SCHEMA:
        reason_codes.append("runner.not_dispatch_envelope")
    for field in (
        "dispatch_envelope_id",
        "task_run_id",
        "session_id",
        "context_id",
        "provider",
        "surface",
        "provider_request_id",
        "method",
        "idempotency_key",
        "definition_snapshot_sha256",
        "resource_claim_id",
        "sha256",
    ):
        if not envelope.get(field):
            reason_codes.append(f"runner.envelope_missing:{field}")
    return {"ok": not reason_codes, "reason_codes": reason_codes}


def _validate_against_task_run(
    envelope: dict[str, Any],
    task_run: dict[str, Any],
    state: dict[str, Any],
) -> dict[str, Any]:
    reason_codes: list[str] = []
    task_run_id = envelope.get("task_run_id")
    if task_run.get("state") != "in_flight":
        reason_codes.append(f"runner.task_run_not_in_flight:{task_run.get('state')}")
    for envelope_field, task_field in (
        ("session_id", "session_id"),
        ("context_id", "context_id"),
        ("provider", "provider"),
        ("surface", "provider_surface"),
        ("method", "method"),
        ("idempotency_key", "idempotency_key"),
        ("definition_snapshot_sha256", "definition_snapshot_sha256"),
    ):
        if envelope.get(envelope_field) != task_run.get(task_field):
            reason_codes.append(f"runner.task_run_mismatch:{envelope_field}")
    if envelope.get("tool_scope") != task_run.get("tool_scope"):
        reason_codes.append("runner.task_run_mismatch:tool_scope")
    if envelope.get("tool_definition_refs") != task_run.get("tool_definition_refs"):
        reason_codes.append("runner.task_run_mismatch:tool_definition_refs")
    if envelope.get("surface_definition_ref") != task_run.get("surface_definition_ref"):
        reason_codes.append("runner.task_run_mismatch:surface_definition_ref")

    claim = (state.get("resource_claims") or {}).get(envelope.get("resource_claim_id"))
    if not claim or claim.get("task_run_id") != task_run_id:
        reason_codes.append("runner.resource_claim_missing")
    elif claim.get("state") != "active":
        reason_codes.append(f"runner.resource_claim_not_active:{claim.get('state')}")
    session = (state.get("sessions") or {}).get(envelope.get("session_id")) or {}
    matched = [
        binding for binding in session.get("provider_sessions") or []
        if binding.get("provider") == envelope.get("provider")
        and binding.get("surface") == envelope.get("surface")
        and binding.get("provider_session_id") == envelope.get("provider_session_id")
    ]
    if not matched:
        reason_codes.append("runner.provider_binding_missing")
    return {"ok": not reason_codes, "reason_codes": reason_codes}


def _validate_live_shadow_launch(
    envelope: dict[str, Any],
    state: dict[str, Any],
    *,
    shadow_launch_plan_id: str | None,
    shadow_launch_plan_sha256: str | None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    if not shadow_launch_plan_id:
        reason_codes.append("runner.shadow_launch_plan_id_missing")
    if not shadow_launch_plan_sha256:
        reason_codes.append("runner.shadow_launch_plan_sha256_missing")
    if reason_codes:
        return {"ok": False, "reason_codes": reason_codes, "plan": None}

    plan = (state.get("shadow_launch_plans") or {}).get(shadow_launch_plan_id)
    if not plan:
        return {
            "ok": False,
            "reason_codes": [f"runner.shadow_launch_plan_missing:{shadow_launch_plan_id}"],
            "plan": None,
        }
    if plan.get("shadow_launch_plan_sha256") != shadow_launch_plan_sha256:
        reason_codes.append("runner.shadow_launch_plan_hash_mismatch")

    validation = validate_shadow_launch_plan_record(plan, state=state)
    if not validation["ok"]:
        reason_codes.extend(validation["reason_codes"])
    if plan.get("ready_to_launch") is not True or plan.get("status") != "allow":
        reason_codes.append(f"runner.shadow_launch_plan_not_allowed:{plan.get('status')}")
    if plan.get("mode") != SHADOW_LAUNCH_MODE:
        reason_codes.append(f"runner.shadow_launch_plan_mode_invalid:{plan.get('mode')}")
    if plan.get("egress_mode") != "none":
        reason_codes.append("runner.shadow_launch_plan_egress_not_none")

    binding_match = _launch_plan_has_matching_binding(plan, envelope, state)
    if not binding_match:
        reason_codes.append("runner.shadow_launch_plan_binding_missing")
    promise_match = _launch_plan_has_matching_promise(plan, envelope, state)
    if not promise_match:
        reason_codes.append("runner.shadow_launch_plan_promise_missing")
    return {"ok": not reason_codes, "reason_codes": reason_codes, "plan": plan}


def _launch_plan_has_matching_binding(
    plan: dict[str, Any],
    envelope: dict[str, Any],
    state: dict[str, Any],
) -> bool:
    for binding_id in plan.get("surface_binding_ids") or []:
        binding = (state.get("surface_bindings") or {}).get(binding_id) or {}
        if binding.get("session_id") != envelope.get("session_id"):
            continue
        if binding.get("provider") != envelope.get("provider"):
            continue
        if binding.get("surface") != envelope.get("surface"):
            continue
        if binding.get("provider_session_id") != envelope.get("provider_session_id"):
            continue
        task_run_id = binding.get("task_run_id")
        if task_run_id and task_run_id != envelope.get("task_run_id"):
            continue
        return True
    return False


def _launch_plan_has_matching_promise(
    plan: dict[str, Any],
    envelope: dict[str, Any],
    state: dict[str, Any],
) -> bool:
    for promise_id in plan.get("surface_promise_ids") or []:
        promise = (state.get("surface_promises") or {}).get(promise_id) or {}
        if promise.get("task_run_id") == envelope.get("task_run_id"):
            return True
    return False


def _deny(reason_code: str) -> dict[str, Any]:
    return {
        "allowed": False,
        "status": "deny",
        "reason_code": reason_code,
        "reason_codes": [reason_code],
    }


def _deny_many(reason_codes: list[str]) -> dict[str, Any]:
    reason_codes = list(reason_codes)
    return {
        "allowed": False,
        "status": "deny",
        "reason_code": reason_codes[0] if reason_codes else "runner.denied",
        "reason_codes": reason_codes or ["runner.denied"],
    }
