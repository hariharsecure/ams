from __future__ import annotations

from copy import deepcopy
from typing import Any

from .definition_registry import definition_snapshot_sha256
from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .package_manifest import compare_registry_to_manifest, validate_package_manifest
from .runner_boundary import runner_preflight
from .store import JsonStore


SCHEMA_VERSION = "ams.ams.runner_dry_run_parity.v0"
STATUSES = {"ready_for_operator_review", "blocked"}


class RunnerDryRunParityStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        envelope: dict[str, Any],
        package_verification: dict[str, Any],
        package_manifest: dict[str, Any],
        runner_preflight_result: dict[str, Any] | None = None,
        live: bool = True,
        shadow_launch_plan_id: str | None = None,
        shadow_launch_plan_sha256: str | None = None,
    ) -> dict[str, Any]:
        preflight = runner_preflight_result or runner_preflight(
            envelope,
            self.store,
            live=live,
            shadow_launch_plan_id=shadow_launch_plan_id,
            shadow_launch_plan_sha256=shadow_launch_plan_sha256,
        )
        with self.store.locked() as state:
            record = build_runner_dry_run_parity(
                state=state,
                envelope=envelope,
                package_verification=package_verification,
                package_manifest=package_manifest,
                runner_preflight_result=preflight,
            )
            validation = validate_runner_dry_run_parity_record(record, state=state)
            if not validation["ok"]:
                raise ValueError("; ".join(validation["reason_codes"]))
            parity_id = record["runner_dry_run_parity_id"]
            state.setdefault("runner_dry_run_parities", {})[parity_id] = record
            state.setdefault("indexes", {}).setdefault("runner_dry_run_parity_ids", {})[parity_id] = parity_id
        return deepcopy(record)


def build_runner_dry_run_parity(
    *,
    state: dict[str, Any],
    envelope: dict[str, Any],
    package_verification: dict[str, Any],
    package_manifest: dict[str, Any],
    runner_preflight_result: dict[str, Any],
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    evaluation = _evaluate(
        state=state,
        envelope=envelope,
        package_verification=package_verification,
        package_manifest=package_manifest,
        runner_preflight_result=runner_preflight_result,
    )
    manifest_summary = {
        "package_manifest_id": package_manifest.get("package_manifest_id"),
        "name": package_manifest.get("name"),
        "version": package_manifest.get("version"),
        "package_mode": package_manifest.get("package_mode"),
    }
    record = {
        "schema_version": SCHEMA_VERSION,
        "runner_dry_run_parity_id": stable_id(
            "runparity",
            envelope.get("dispatch_envelope_id"),
            envelope.get("sha256"),
            package_manifest.get("manifest_sha256"),
            _snapshot_hash(package_verification),
            _snapshot_hash(runner_preflight_result),
            now,
        ),
        "dispatch_envelope": deepcopy(envelope),
        "dispatch_envelope_id": envelope.get("dispatch_envelope_id"),
        "dispatch_envelope_sha256": envelope.get("sha256"),
        "task_run_id": envelope.get("task_run_id"),
        "session_id": envelope.get("session_id"),
        "provider": envelope.get("provider"),
        "surface": envelope.get("surface"),
        "runner_mode": evaluation["runner_mode"],
        "shadow_launch_plan_id": evaluation["shadow_launch_plan_id"],
        "shadow_launch_plan_sha256": evaluation["shadow_launch_plan_sha256"],
        "package_manifest": deepcopy(package_manifest),
        "package_manifest_summary": manifest_summary,
        "package_manifest_sha256": package_manifest.get("manifest_sha256"),
        "package_verification": deepcopy(package_verification),
        "package_verification_sha256": _snapshot_hash(package_verification),
        "runner_preflight": deepcopy(runner_preflight_result),
        "runner_preflight_sha256": _snapshot_hash(runner_preflight_result),
        "definition_snapshot_sha256": envelope.get("definition_snapshot_sha256"),
        "tool_definition_refs": deepcopy(envelope.get("tool_definition_refs") or []),
        "surface_definition_ref": deepcopy(envelope.get("surface_definition_ref")),
        "parity_checks": evaluation["checks"],
        "process_start_allowed": False,
        "network_egress_allowed": False,
        "start_actions": [],
        "status": evaluation["status"],
        "reason_codes": evaluation["reason_codes"],
        "created_at": now,
    }
    record["parity_sha256"] = _hash_without(record, "parity_sha256")
    return deepcopy(record)


def validate_runner_dry_run_parity_record(record: dict[str, Any], *, state: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("runner_parity.schema_version_invalid")
    expected_hash = record.get("parity_sha256")
    if expected_hash and expected_hash != _hash_without(record, "parity_sha256"):
        reason_codes.append("runner_parity.hash_mismatch")
    if record.get("status") not in STATUSES:
        reason_codes.append("runner_parity.status_invalid")
    if record.get("process_start_allowed") is not False:
        reason_codes.append("runner_parity.process_start_allowed_not_false")
    if record.get("network_egress_allowed") is not False:
        reason_codes.append("runner_parity.network_egress_allowed_not_false")
    if record.get("start_actions") != []:
        reason_codes.append("runner_parity.start_actions_not_empty")

    envelope = _envelope_from_record(record)
    package_manifest = record.get("package_manifest") or {}
    package_verification = record.get("package_verification") or {}
    runner_result = record.get("runner_preflight") or {}
    if record.get("dispatch_envelope_sha256") != envelope.get("sha256"):
        reason_codes.append("runner_parity.envelope_hash_mismatch")
    material = dict(envelope)
    material.pop("sha256", None)
    if envelope.get("sha256") != _snapshot_hash(material):
        reason_codes.append("runner_parity.dispatch_envelope_hash_mismatch")
    if record.get("package_manifest_sha256") != package_manifest.get("manifest_sha256"):
        reason_codes.append("runner_parity.package_manifest_hash_mismatch")
    if record.get("package_verification_sha256") != _snapshot_hash(package_verification):
        reason_codes.append("runner_parity.package_verification_hash_mismatch")
    if record.get("runner_preflight_sha256") != _snapshot_hash(runner_result):
        reason_codes.append("runner_parity.runner_preflight_hash_mismatch")
    if record.get("definition_snapshot_sha256") != envelope.get("definition_snapshot_sha256"):
        reason_codes.append("runner_parity.definition_snapshot_hash_mismatch")

    evaluation = _evaluate(
        state=state,
        envelope=envelope,
        package_verification=package_verification,
        package_manifest=package_manifest,
        runner_preflight_result=runner_result,
    )
    if record.get("status") != evaluation["status"]:
        reason_codes.append("runner_parity.status_reason_mismatch")
    if sorted(record.get("reason_codes") or []) != sorted(evaluation["reason_codes"]):
        reason_codes.append("runner_parity.reason_codes_mismatch")
    if record.get("parity_checks") != evaluation["checks"]:
        reason_codes.append("runner_parity.checks_mismatch")
    if record.get("runner_mode") != evaluation["runner_mode"]:
        reason_codes.append("runner_parity.runner_mode_mismatch")
    if record.get("shadow_launch_plan_id") != evaluation["shadow_launch_plan_id"]:
        reason_codes.append("runner_parity.shadow_launch_plan_id_mismatch")
    if record.get("shadow_launch_plan_sha256") != evaluation["shadow_launch_plan_sha256"]:
        reason_codes.append("runner_parity.shadow_launch_plan_sha256_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _evaluate(
    *,
    state: dict[str, Any],
    envelope: dict[str, Any],
    package_verification: dict[str, Any],
    package_manifest: dict[str, Any],
    runner_preflight_result: dict[str, Any],
) -> dict[str, Any]:
    manifest_check = validate_package_manifest(package_manifest)
    registry_check = compare_registry_to_manifest(state, package_manifest)
    definition_result = _definitions_present_in_manifest(envelope, package_manifest)
    snapshot_result = _definition_snapshot_matches(envelope)
    invocation = runner_preflight_result.get("invocation") or {}
    invocation_hash_ok = invocation.get("sha256") == _snapshot_hash(
        {key: value for key, value in invocation.items() if key != "sha256"}
    )
    runner_inert = (
        invocation.get("dry_run_only") is True
        and invocation.get("preflight_only") is True
        and invocation_hash_ok
    )
    runner_live_shadow = (
        runner_preflight_result.get("allowed") is True
        and runner_preflight_result.get("reason_code") == "runner.live_shadow_preflight_ok"
        and invocation.get("live_requested") is True
        and invocation.get("launch_mode") == "shadow"
        and bool(invocation.get("shadow_launch_plan_id"))
        and bool(invocation.get("shadow_launch_plan_sha256"))
    )
    checks = {
        "package_verified": package_verification.get("allowed") is True
        and package_verification.get("reason_code") == "package.verified",
        "package_manifest_hash_match": package_verification.get("manifest_sha256")
        == package_manifest.get("manifest_sha256"),
        "package_manifest_valid": manifest_check["ok"],
        "registry_matches_manifest": registry_check["ok"],
        "envelope_definitions_in_manifest": definition_result["ok"],
        "definition_snapshot_match": snapshot_result["ok"],
        "runner_preflight_allowed": runner_preflight_result.get("allowed") is True
        and runner_preflight_result.get("reason_code") in {"runner.preflight_ok", "runner.live_shadow_preflight_ok"},
        "runner_preflight_live_shadow": runner_live_shadow,
        "runner_preflight_inert": runner_inert,
        "runner_invocation_matches_envelope": _runner_invocation_matches_envelope(invocation, envelope),
        "process_start_allowed_false": True,
        "network_egress_allowed_false": True,
    }
    reason_codes = _reason_codes(
        checks,
        manifest_reasons=manifest_check["reason_codes"],
        registry_reasons=registry_check["reason_codes"],
        definition_reasons=definition_result["reason_codes"],
        snapshot_reasons=snapshot_result["reason_codes"],
        runner_reasons=runner_preflight_result.get("reason_codes") or [],
    )
    status = "ready_for_operator_review" if reason_codes == ["runner_parity.ready"] else "blocked"
    return {
        "status": status,
        "reason_codes": reason_codes,
        "checks": checks,
        "runner_mode": "live_shadow_preflight" if runner_live_shadow else "dry_run",
        "shadow_launch_plan_id": invocation.get("shadow_launch_plan_id"),
        "shadow_launch_plan_sha256": invocation.get("shadow_launch_plan_sha256"),
    }


def _reason_codes(
    checks: dict[str, bool],
    *,
    manifest_reasons: list[str],
    registry_reasons: list[str],
    definition_reasons: list[str],
    snapshot_reasons: list[str],
    runner_reasons: list[str],
) -> list[str]:
    reasons: list[str] = []
    if not checks["package_verified"]:
        reasons.append("runner_parity.package_not_verified")
    if not checks["package_manifest_hash_match"]:
        reasons.append("runner_parity.package_manifest_hash_mismatch")
    if not checks["package_manifest_valid"]:
        reasons.append("runner_parity.package_manifest_invalid")
    if not checks["registry_matches_manifest"]:
        reasons.append("runner_parity.registry_mismatch")
    if not checks["envelope_definitions_in_manifest"]:
        reasons.append("runner_parity.envelope_definitions_not_manifested")
    if not checks["definition_snapshot_match"]:
        reasons.append("runner_parity.definition_snapshot_mismatch")
    if not checks["runner_preflight_allowed"]:
        reasons.append("runner_parity.runner_preflight_not_allowed")
    if not checks["runner_preflight_live_shadow"]:
        reasons.append("runner_parity.runner_preflight_not_live_shadow")
    if not checks["runner_preflight_inert"]:
        reasons.append("runner_parity.runner_preflight_not_inert")
    if not checks["runner_invocation_matches_envelope"]:
        reasons.append("runner_parity.runner_invocation_mismatch")
    detailed_reasons = [
        ("runner_parity.package_manifest", manifest_reasons),
        ("runner_parity.registry", registry_reasons),
        ("runner_parity.definitions", definition_reasons),
        ("runner_parity.snapshot", snapshot_reasons),
    ]
    if not checks["runner_preflight_allowed"]:
        detailed_reasons.append(("runner_parity.runner", runner_reasons))
    for prefix, details in detailed_reasons:
        reasons.extend(f"{prefix}:{reason}" for reason in details)
    return sorted(set(reasons)) or ["runner_parity.ready"]


def _definitions_present_in_manifest(envelope: dict[str, Any], package_manifest: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    registry = package_manifest.get("registry") or {}
    tools = {
        item.get("definition_id"): item
        for item in registry.get("tool_definitions") or []
    }
    surfaces = {
        item.get("definition_id"): item
        for item in registry.get("surface_definitions") or []
    }
    for ref in envelope.get("tool_definition_refs") or []:
        manifest_tool = tools.get(ref.get("definition_id"))
        name = ref.get("name") or ref.get("definition_id")
        if not manifest_tool:
            reason_codes.append(f"tool_missing:{name}")
            continue
        if manifest_tool.get("definition_sha256") != ref.get("definition_sha256"):
            reason_codes.append(f"tool_hash_mismatch:{name}")
        if manifest_tool.get("status") != "active":
            reason_codes.append(f"tool_not_active:{name}")
    surface_ref = envelope.get("surface_definition_ref") or {}
    if surface_ref:
        manifest_surface = surfaces.get(surface_ref.get("definition_id"))
        label = f"{surface_ref.get('provider')}/{surface_ref.get('surface')}"
        if not manifest_surface:
            reason_codes.append(f"surface_missing:{label}")
        elif manifest_surface.get("definition_sha256") != surface_ref.get("definition_sha256"):
            reason_codes.append(f"surface_hash_mismatch:{label}")
        elif manifest_surface.get("status") != "active":
            reason_codes.append(f"surface_not_active:{label}")
    else:
        reason_codes.append("surface_ref_missing")
    return {"ok": not reason_codes, "reason_codes": reason_codes}


def _definition_snapshot_matches(envelope: dict[str, Any]) -> dict[str, Any]:
    expected = definition_snapshot_sha256(
        tool_refs=list(envelope.get("tool_definition_refs") or []),
        surface_ref=envelope.get("surface_definition_ref"),
    )
    ok = envelope.get("definition_snapshot_sha256") == expected
    return {
        "ok": ok,
        "reason_codes": [] if ok else ["definition_snapshot_hash_mismatch"],
    }


def _runner_invocation_matches_envelope(invocation: dict[str, Any], envelope: dict[str, Any]) -> bool:
    for invocation_field, envelope_field in (
        ("dispatch_envelope_id", "dispatch_envelope_id"),
        ("task_run_id", "task_run_id"),
        ("session_id", "session_id"),
        ("provider", "provider"),
        ("surface", "surface"),
        ("provider_session_id", "provider_session_id"),
        ("provider_request_id", "provider_request_id"),
        ("method", "method"),
        ("model", "model"),
        ("cwd", "cwd"),
        ("sandbox", "sandbox"),
        ("definition_snapshot_sha256", "definition_snapshot_sha256"),
        ("resource_claim_id", "resource_claim_id"),
    ):
        if invocation.get(invocation_field) != envelope.get(envelope_field):
            return False
    if list(invocation.get("tool_scope") or []) != list(envelope.get("tool_scope") or []):
        return False
    return True


def _envelope_from_record(record: dict[str, Any]) -> dict[str, Any]:
    if isinstance(record.get("dispatch_envelope"), dict):
        return deepcopy(record["dispatch_envelope"])
    envelope = {
        "dispatch_envelope_id": record.get("dispatch_envelope_id"),
        "task_run_id": record.get("task_run_id"),
        "session_id": record.get("session_id"),
        "provider": record.get("provider"),
        "surface": record.get("surface"),
        "definition_snapshot_sha256": record.get("definition_snapshot_sha256"),
        "tool_definition_refs": deepcopy(record.get("tool_definition_refs") or []),
        "surface_definition_ref": deepcopy(record.get("surface_definition_ref")),
        "sha256": record.get("dispatch_envelope_sha256"),
    }
    invocation = (record.get("runner_preflight") or {}).get("invocation") or {}
    for key in (
        "context_id",
        "provider_session_id",
        "provider_request_id",
        "method",
        "model",
        "cwd",
        "sandbox",
        "tool_scope",
        "resource_claim_id",
    ):
        if invocation.get(key) is not None:
            envelope[key] = deepcopy(invocation.get(key))
    return envelope


def _snapshot_hash(snapshot: dict[str, Any]) -> str:
    return sha256_text(canonical_json(snapshot))
