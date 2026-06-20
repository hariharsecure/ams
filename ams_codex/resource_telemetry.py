from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import canonical_json, sha256_text, stable_id, utc_now
from .store import JsonStore


SCHEMA_VERSION = "ams.ams_codex.resource_telemetry.v0"
STATUSES = {"within_limits", "over_limit"}
SOURCE_TYPES = {"manual_local", "provider_result_summary", "runner_summary", "synthetic"}
LIVE_BOUNDARY_FLAGS = {
    "listener_started": False,
    "provider_poll_performed": False,
    "network_call_performed": False,
    "process_inspection_performed": False,
    "terminal_capture_performed": False,
    "token_log_read_performed": False,
    "raw_usage_log_stored": False,
    "token_stored": False,
}


class ResourceTelemetryStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def record(
        self,
        resource_claim_id: str,
        *,
        observed: dict[str, Any] | None = None,
        source_type: str = "manual_local",
        source_ref: dict[str, Any] | None = None,
        provider_result_id: str | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            claim = (state.get("resource_claims") or {}).get(resource_claim_id)
            if not claim:
                raise KeyError(f"unknown resource_claim_id: {resource_claim_id}")
            task_run = (state.get("task_runs") or {}).get(claim.get("task_run_id"))
            if not task_run:
                raise KeyError(f"resource_claim {resource_claim_id} references missing task_run")
            provider_result = None
            if provider_result_id:
                provider_result = (state.get("provider_results") or {}).get(provider_result_id)
                if not provider_result:
                    raise KeyError(f"unknown provider_result_id: {provider_result_id}")
            record = build_resource_telemetry_record(
                task_run=task_run,
                claim=claim,
                observed=observed or {},
                source_type=source_type,
                source_ref=source_ref or {},
                provider_result=provider_result,
            )
            telemetry_id = record["resource_telemetry_id"]
            state.setdefault("resource_telemetry_samples", {})[telemetry_id] = record
            indexes = state.setdefault("indexes", {})
            indexes.setdefault("resource_telemetry_ids", {})[telemetry_id] = telemetry_id
            indexes.setdefault("resource_claim_to_telemetry", {})[resource_claim_id] = telemetry_id
        return deepcopy(record)


def build_resource_telemetry_record(
    *,
    task_run: dict[str, Any],
    claim: dict[str, Any],
    observed: dict[str, Any],
    source_type: str = "manual_local",
    source_ref: dict[str, Any] | None = None,
    provider_result: dict[str, Any] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    if source_type not in SOURCE_TYPES:
        raise ValueError(f"invalid source_type: {source_type}")
    now = now or utc_now()
    normalized_observed = _observed(observed)
    reserved = _reserved_snapshot(claim)
    reason_codes = _reason_codes(normalized_observed, reserved)
    status = "within_limits" if reason_codes == ["resource_telemetry.within_limits"] else "over_limit"
    source = _source_ref(source_ref or {})
    record = {
        "schema_version": SCHEMA_VERSION,
        "resource_telemetry_id": stable_id(
            "restelem",
            claim.get("resource_claim_id"),
            task_run.get("task_run_id"),
            provider_result.get("provider_result_id") if provider_result else None,
            canonical_json(normalized_observed),
            canonical_json(source),
            now,
        ),
        "task_run_id": task_run.get("task_run_id"),
        "session_id": task_run.get("session_id"),
        "resource_claim_id": claim.get("resource_claim_id"),
        "provider_result_id": provider_result.get("provider_result_id") if provider_result else None,
        "source_type": source_type,
        "source_ref": source,
        "observed": normalized_observed,
        "reserved_snapshot": reserved,
        "claim_state_at_record": claim.get("state"),
        "policy_id": claim.get("policy_id"),
        "policy_sha256": claim.get("policy_sha256"),
        "provider_profile_id": claim.get("provider_profile_id"),
        "live_boundaries": dict(LIVE_BOUNDARY_FLAGS),
        "settlement_status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["telemetry_sha256"] = _telemetry_hash(record)
    return deepcopy(record)


def validate_resource_telemetry_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("resource_telemetry.schema_version_invalid")
    if record.get("settlement_status") not in STATUSES:
        reason_codes.append("resource_telemetry.status_invalid")
    if record.get("source_type") not in SOURCE_TYPES:
        reason_codes.append("resource_telemetry.source_type_invalid")
    expected_hash = record.get("telemetry_sha256")
    if expected_hash and expected_hash != _telemetry_hash(record):
        reason_codes.append("resource_telemetry.hash_mismatch")
    for key, expected in LIVE_BOUNDARY_FLAGS.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"resource_telemetry.{key}_not_false")

    observed = record.get("observed") or {}
    try:
        if _nonnegative_int(observed.get("total_tokens")) != _nonnegative_int(observed.get("input_tokens")) + _nonnegative_int(
            observed.get("output_tokens")
        ):
            reason_codes.append("resource_telemetry.total_tokens_mismatch")
        expected_reasons = _reason_codes(observed, record.get("reserved_snapshot") or {})
        expected_status = "within_limits" if expected_reasons == ["resource_telemetry.within_limits"] else "over_limit"
        if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
            reason_codes.append("resource_telemetry.reason_codes_mismatch")
        if record.get("settlement_status") != expected_status:
            reason_codes.append("resource_telemetry.status_reason_mismatch")
    except (TypeError, ValueError):
        reason_codes.append("resource_telemetry.numeric_value_invalid")
    source_ref = record.get("source_ref") or {}
    if source_ref.get("ref_sha256") != sha256_text(str(source_ref.get("ref") or "")):
        reason_codes.append("resource_telemetry.source_ref_hash_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _observed(values: dict[str, Any]) -> dict[str, int]:
    input_tokens = _nonnegative_int(values.get("input_tokens"))
    output_tokens = _nonnegative_int(values.get("output_tokens"))
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "runtime_ms": _nonnegative_int(values.get("runtime_ms")),
        "cost_microusd": _nonnegative_int(values.get("cost_microusd")),
        "cpu_core_ms": _nonnegative_int(values.get("cpu_core_ms")),
        "peak_memory_mb": _nonnegative_int(values.get("peak_memory_mb")),
        "peak_gpu_memory_mb": _nonnegative_int(values.get("peak_gpu_memory_mb")),
        "network_bytes": _nonnegative_int(values.get("network_bytes")),
        "disk_read_bytes": _nonnegative_int(values.get("disk_read_bytes")),
        "disk_write_bytes": _nonnegative_int(values.get("disk_write_bytes")),
    }


def _reserved_snapshot(claim: dict[str, Any]) -> dict[str, int]:
    reserved = claim.get("reserved") or {}
    return {
        "cpu_cores": _nonnegative_int(reserved.get("cpu_cores")),
        "memory_mb": _nonnegative_int(reserved.get("memory_mb")),
        "gpu_memory_mb": _nonnegative_int(reserved.get("gpu_memory_mb")),
        "max_input_tokens": _nonnegative_int(reserved.get("max_input_tokens")),
        "max_output_tokens": _nonnegative_int(reserved.get("max_output_tokens")),
        "max_runtime_seconds": _nonnegative_int(reserved.get("max_runtime_seconds")),
        "concurrency_units": _nonnegative_int(reserved.get("concurrency_units")),
    }


def _source_ref(source_ref: dict[str, Any]) -> dict[str, str]:
    kind = str(source_ref.get("kind") or "manual")
    ref = str(source_ref.get("ref") or "local://manual/resource-telemetry")
    return {
        "kind": kind,
        "ref": ref,
        "ref_sha256": sha256_text(ref),
        "artifact_sha256": str(source_ref.get("artifact_sha256") or sha256_text("")),
    }


def _reason_codes(observed: dict[str, Any], reserved: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if _nonnegative_int(observed.get("input_tokens")) > _nonnegative_int(reserved.get("max_input_tokens")):
        reasons.append("resource_telemetry.input_tokens_over_reserved")
    if _nonnegative_int(observed.get("output_tokens")) > _nonnegative_int(reserved.get("max_output_tokens")):
        reasons.append("resource_telemetry.output_tokens_over_reserved")
    max_runtime_ms = _nonnegative_int(reserved.get("max_runtime_seconds")) * 1000
    if max_runtime_ms and _nonnegative_int(observed.get("runtime_ms")) > max_runtime_ms:
        reasons.append("resource_telemetry.runtime_over_reserved")
    if _nonnegative_int(reserved.get("memory_mb")) and _nonnegative_int(observed.get("peak_memory_mb")) > _nonnegative_int(
        reserved.get("memory_mb")
    ):
        reasons.append("resource_telemetry.memory_over_reserved")
    if _nonnegative_int(reserved.get("gpu_memory_mb")) and _nonnegative_int(observed.get("peak_gpu_memory_mb")) > _nonnegative_int(
        reserved.get("gpu_memory_mb")
    ):
        reasons.append("resource_telemetry.gpu_memory_over_reserved")
    return reasons or ["resource_telemetry.within_limits"]


def _nonnegative_int(value: Any) -> int:
    parsed = int(value or 0)
    if parsed < 0:
        raise ValueError("resource telemetry values must be nonnegative")
    return parsed


def _telemetry_hash(record: dict[str, Any]) -> str:
    material = deepcopy(record)
    material.pop("telemetry_sha256", None)
    return sha256_text(canonical_json(material))
