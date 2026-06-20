from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .shadow_readiness import evaluate_shadow_readiness
from .store import JsonStore
from .surface_bindings import validate_runtime_surface_record, validate_surface_binding_record
from .surface_promise import ACCEPTABLE_DELIVERY_STATUSES, validate_surface_promise_record


NO_LAUNCH_ACTIONS: list[dict[str, Any]] = []
NO_DOWNSTREAM_CONSUMERS: list[dict[str, Any]] = []



def _snapshot_hash(snapshot: dict[str, Any]) -> str:
    return sha256_text(canonical_json(snapshot))


def evaluate_shadow_launch_plan(
    state: dict[str, Any],
    *,
    install_preflight: dict[str, Any],
    package_verification: dict[str, Any],
    approval_id: str | None,
    egress_mode: str,
    runtime_surface_ids: list[str],
    surface_binding_ids: list[str],
    surface_promise_ids: list[str],
) -> dict[str, Any]:
    shadow_readiness = evaluate_shadow_readiness(
        install_preflight=install_preflight,
        package_verification=package_verification,
        approval_id=approval_id,
        egress_mode=egress_mode,
    )
    reason_codes: list[str] = []
    if not shadow_readiness["allowed"]:
        reason_codes.extend(shadow_readiness["reason_codes"])

    runtime_gate = _evaluate_runtime_surfaces(
        state,
        package_manifest_sha256=package_verification.get("manifest_sha256"),
        runtime_surface_ids=runtime_surface_ids,
        surface_binding_ids=surface_binding_ids,
    )
    reason_codes.extend(runtime_gate["reason_codes"])
    promise_gate = _evaluate_surface_promises(state, surface_promise_ids)
    reason_codes.extend(promise_gate["reason_codes"])

    status = _status_for(reason_codes)
    ready = status == "allow"
    return {
        "ready_to_launch": ready,
        "status": status,
        "reason_code": "shadow_launch.ready" if ready else reason_codes[0],
        "reason_codes": ["shadow_launch.ready"] if ready else reason_codes,
        "shadow_readiness": shadow_readiness,
        "required_gates": {
            "install_preflight_ready": bool(install_preflight.get("ready_for_live")),
            "package_verified": package_verification.get("allowed") is True,
            "explicit_approval": bool(approval_id),
            "egress_none": egress_mode == "none",
            **runtime_gate["required_gates"],
            **promise_gate["required_gates"],
        },
    }


def build_shadow_launch_plan(
    state: dict[str, Any],
    *,
    install_preflight: dict[str, Any],
    package_verification: dict[str, Any],
    approval_id: str | None,
    egress_mode: str = "none",
    runtime_surface_ids: list[str] | None = None,
    surface_binding_ids: list[str] | None = None,
    surface_promise_ids: list[str] | None = None,
    source_refs: dict[str, Any] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    runtime_surface_ids = list(runtime_surface_ids or [])
    surface_binding_ids = list(surface_binding_ids or [])
    surface_promise_ids = list(surface_promise_ids or [])
    install_snapshot = deepcopy(install_preflight)
    package_snapshot = deepcopy(package_verification)
    evaluation = evaluate_shadow_launch_plan(
        state,
        install_preflight=install_snapshot,
        package_verification=package_snapshot,
        approval_id=approval_id,
        egress_mode=egress_mode,
        runtime_surface_ids=runtime_surface_ids,
        surface_binding_ids=surface_binding_ids,
        surface_promise_ids=surface_promise_ids,
    )
    input_hashes = {
        "install_preflight_sha256": _snapshot_hash(install_snapshot),
        "package_verification_sha256": _snapshot_hash(package_snapshot),
        "shadow_readiness_sha256": _snapshot_hash(evaluation["shadow_readiness"]),
    }
    record = {
        "schema_version": "ams.ams_codex.shadow_launch_plan.v0",
        "shadow_launch_plan_id": stable_id(
            "shadowlaunch",
            input_hashes,
            approval_id,
            egress_mode,
            runtime_surface_ids,
            surface_binding_ids,
            surface_promise_ids,
        ),
        "mode": "shadow",
        "egress_mode": egress_mode,
        "approval_id": approval_id,
        "ready_to_launch": evaluation["ready_to_launch"],
        "status": evaluation["status"],
        "reason_code": evaluation["reason_code"],
        "reason_codes": evaluation["reason_codes"],
        "runtime_surface_ids": runtime_surface_ids,
        "surface_binding_ids": surface_binding_ids,
        "surface_promise_ids": surface_promise_ids,
        "input_hashes": input_hashes,
        "gate_snapshots": {
            "install_preflight": install_snapshot,
            "package_verification": package_snapshot,
            "shadow_readiness": evaluation["shadow_readiness"],
        },
        "required_gates": evaluation["required_gates"],
        "launch_actions": deepcopy(NO_LAUNCH_ACTIONS),
        "downstream_consumers": deepcopy(NO_DOWNSTREAM_CONSUMERS),
        "source_refs": source_refs or {},
        "created_at": now,
        "updated_at": now,
    }
    record["shadow_launch_plan_sha256"] = _hash_without(record, "shadow_launch_plan_sha256")
    return record


def validate_shadow_launch_plan_record(
    record: dict[str, Any],
    *,
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    expected_hash = record.get("shadow_launch_plan_sha256")
    if expected_hash and expected_hash != _hash_without(record, "shadow_launch_plan_sha256"):
        reason_codes.append("shadow_launch_plan.hash_mismatch")

    if record.get("launch_actions") != []:
        reason_codes.append("shadow_launch_plan.launch_actions_not_empty")
    if record.get("downstream_consumers") != []:
        reason_codes.append("shadow_launch_plan.downstream_consumers_not_empty")

    snapshots = record.get("gate_snapshots") or {}
    input_hashes = record.get("input_hashes") or {}
    install_preflight = snapshots.get("install_preflight") or {}
    package_verification = snapshots.get("package_verification") or {}
    expected_input_hashes = {
        "install_preflight_sha256": _snapshot_hash(install_preflight),
        "package_verification_sha256": _snapshot_hash(package_verification),
    }
    for key, value in expected_input_hashes.items():
        if input_hashes.get(key) != value:
            reason_codes.append(f"shadow_launch_plan.input_hash_mismatch:{key}")

    shadow_readiness = evaluate_shadow_readiness(
        install_preflight=install_preflight,
        package_verification=package_verification,
        approval_id=record.get("approval_id"),
        egress_mode=str(record.get("egress_mode") or ""),
    )
    if input_hashes.get("shadow_readiness_sha256") != _snapshot_hash(shadow_readiness):
        reason_codes.append("shadow_launch_plan.input_hash_mismatch:shadow_readiness_sha256")
    if snapshots.get("shadow_readiness") != shadow_readiness:
        reason_codes.append("shadow_launch_plan.shadow_readiness_stale")

    if state is not None:
        current = evaluate_shadow_launch_plan(
            state,
            install_preflight=install_preflight,
            package_verification=package_verification,
            approval_id=record.get("approval_id"),
            egress_mode=str(record.get("egress_mode") or ""),
            runtime_surface_ids=list(record.get("runtime_surface_ids") or []),
            surface_binding_ids=list(record.get("surface_binding_ids") or []),
            surface_promise_ids=list(record.get("surface_promise_ids") or []),
        )
        for key in ("ready_to_launch", "status", "reason_code", "reason_codes", "required_gates"):
            if record.get(key) != current[key]:
                reason_codes.append(f"shadow_launch_plan.{key}_stale")
        if snapshots.get("shadow_readiness") != current["shadow_readiness"]:
            reason_codes.append("shadow_launch_plan.shadow_readiness_stale")
    return {"ok": not reason_codes, "reason_codes": reason_codes}


class ShadowLaunchStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create_plan(
        self,
        *,
        install_preflight: dict[str, Any],
        package_verification: dict[str, Any],
        approval_id: str | None,
        egress_mode: str = "none",
        runtime_surface_ids: list[str] | None = None,
        surface_binding_ids: list[str] | None = None,
        surface_promise_ids: list[str] | None = None,
        source_refs: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            record = build_shadow_launch_plan(
                state,
                install_preflight=install_preflight,
                package_verification=package_verification,
                approval_id=approval_id,
                egress_mode=egress_mode,
                runtime_surface_ids=runtime_surface_ids,
                surface_binding_ids=surface_binding_ids,
                surface_promise_ids=surface_promise_ids,
                source_refs=source_refs,
            )
            state.setdefault("shadow_launch_plans", {})[record["shadow_launch_plan_id"]] = record
            state.setdefault("indexes", {}).setdefault("shadow_launch_plan_ids", {})[
                record["shadow_launch_plan_id"]
            ] = record["shadow_launch_plan_id"]
            return deepcopy(record)


def _evaluate_runtime_surfaces(
    state: dict[str, Any],
    *,
    package_manifest_sha256: str | None,
    runtime_surface_ids: list[str],
    surface_binding_ids: list[str],
) -> dict[str, Any]:
    reason_codes: list[str] = []
    seen: set[str] = set()
    present = bool(runtime_surface_ids)
    valid = True
    shadow_rollout = True
    no_egress = True
    package_pins_match = True

    if not runtime_surface_ids:
        reason_codes.append("shadow_launch.runtime_surfaces_missing")
    if not package_manifest_sha256:
        package_pins_match = False
        reason_codes.append("shadow_launch.package_manifest_sha256_missing")
    for runtime_surface_id in runtime_surface_ids:
        if runtime_surface_id in seen:
            reason_codes.append(f"shadow_launch.runtime_surface_duplicate:{runtime_surface_id}")
            valid = False
            continue
        seen.add(runtime_surface_id)
        runtime_surface = (state.get("runtime_surfaces") or {}).get(runtime_surface_id)
        if not runtime_surface:
            reason_codes.append(f"shadow_launch.runtime_surface_missing:{runtime_surface_id}")
            valid = False
            continue
        validation = validate_runtime_surface_record(runtime_surface, state=state)
        if not validation["ok"]:
            valid = False
            reason_codes.extend(validation["reason_codes"])
        if runtime_surface.get("rollout_mode") != "shadow":
            shadow_rollout = False
            reason_codes.append(f"shadow_launch.runtime_surface_not_shadow_rollout:{runtime_surface_id}")
        if runtime_surface.get("status") == "disabled":
            valid = False
            reason_codes.append(f"shadow_launch.runtime_surface_disabled:{runtime_surface_id}")
        egress_modes = runtime_surface.get("egress_modes") or []
        if egress_modes != ["none"]:
            no_egress = False
            reason_codes.append(f"shadow_launch.runtime_surface_egress_not_none:{runtime_surface_id}")
        if runtime_surface.get("package_manifest_sha256") != package_manifest_sha256:
            package_pins_match = False
            reason_codes.append(f"shadow_launch.runtime_surface_package_pin_mismatch:{runtime_surface_id}")

    binding_gate = _evaluate_surface_bindings(state, surface_binding_ids, runtime_surface_ids)
    reason_codes.extend(binding_gate["reason_codes"])

    return {
        "reason_codes": reason_codes,
        "required_gates": {
            "runtime_surfaces_present": present,
            "runtime_surfaces_valid": valid,
            "runtime_surfaces_shadow_rollout": shadow_rollout,
            "runtime_surfaces_no_egress": no_egress,
            "runtime_surface_package_pins_match": package_pins_match,
            **binding_gate["required_gates"],
        },
    }


def _evaluate_surface_bindings(
    state: dict[str, Any],
    surface_binding_ids: list[str],
    runtime_surface_ids: list[str],
) -> dict[str, Any]:
    reason_codes: list[str] = []
    seen: set[str] = set()
    present = bool(surface_binding_ids)
    valid = True
    bound = True
    no_egress_queue = True
    runtime_set = set(runtime_surface_ids)

    if not surface_binding_ids:
        reason_codes.append("shadow_launch.surface_bindings_missing")
    for surface_binding_id in surface_binding_ids:
        if surface_binding_id in seen:
            reason_codes.append(f"shadow_launch.surface_binding_duplicate:{surface_binding_id}")
            valid = False
            continue
        seen.add(surface_binding_id)
        binding = (state.get("surface_bindings") or {}).get(surface_binding_id)
        if not binding:
            reason_codes.append(f"shadow_launch.surface_binding_missing:{surface_binding_id}")
            valid = False
            continue
        validation = validate_surface_binding_record(binding, state=state)
        if not validation["ok"]:
            valid = False
            reason_codes.extend(validation["reason_codes"])
        if binding.get("runtime_surface_id") not in runtime_set:
            valid = False
            reason_codes.append(f"shadow_launch.surface_binding_unplanned_runtime:{surface_binding_id}")
        if binding.get("status") != "bound":
            bound = False
            reason_codes.append(f"shadow_launch.surface_binding_not_bound:{surface_binding_id}")
        if binding.get("binding_role") == "egress_queue":
            no_egress_queue = False
            reason_codes.append(f"shadow_launch.surface_binding_egress_queue_denied:{surface_binding_id}")

    return {
        "reason_codes": reason_codes,
        "required_gates": {
            "surface_bindings_present": present,
            "surface_bindings_valid": valid,
            "surface_bindings_bound": bound,
            "surface_bindings_no_egress_queue": no_egress_queue,
        },
    }


def _evaluate_surface_promises(state: dict[str, Any], surface_promise_ids: list[str]) -> dict[str, Any]:
    reason_codes: list[str] = []
    seen: set[str] = set()
    present = bool(surface_promise_ids)
    terminal = True

    if not surface_promise_ids:
        reason_codes.append("shadow_launch.surface_promises_missing")
    for surface_promise_id in surface_promise_ids:
        if surface_promise_id in seen:
            reason_codes.append(f"shadow_launch.surface_promise_duplicate:{surface_promise_id}")
            terminal = False
            continue
        seen.add(surface_promise_id)
        promise = (state.get("surface_promises") or {}).get(surface_promise_id)
        if not promise:
            reason_codes.append(f"shadow_launch.surface_promise_missing:{surface_promise_id}")
            terminal = False
            continue
        validation = validate_surface_promise_record(promise, state=state)
        if not validation["ok"]:
            terminal = False
            reason_codes.extend(validation["reason_codes"])
        status = promise.get("surface_delivery_status")
        if status not in ACCEPTABLE_DELIVERY_STATUSES:
            terminal = False
            reason_codes.append(f"shadow_launch.surface_promise_not_terminal:{surface_promise_id}:{status}")

    return {
        "reason_codes": reason_codes,
        "required_gates": {
            "surface_promises_present": present,
            "surface_promises_terminal": terminal,
        },
    }


def _status_for(reason_codes: list[str]) -> str:
    if not reason_codes:
        return "allow"
    deny_fragments = (
        "shadow.egress_must_be_none",
        "surface.runtime_direct_egress_denied",
        "surface.runtime_terminal_injection_denied",
        "surface.runtime_live_rollout_requires_approval",
        "shadow_launch.runtime_surface_egress_not_none",
        "shadow_launch.surface_binding_egress_queue_denied",
        "shadow_launch_plan.launch_actions_not_empty",
        "shadow_launch_plan.downstream_consumers_not_empty",
    )
    if any(any(fragment in reason for fragment in deny_fragments) for reason in reason_codes):
        return "deny"
    return "defer"
