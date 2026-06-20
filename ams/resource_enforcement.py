from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .resource_claim import transition_resource_claim
from .resource_telemetry import build_resource_telemetry_record, validate_resource_telemetry_record
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore
from .workspace import repo_root


SCHEMA_VERSION = "ams.ams.resource_enforcement_trial.v0"
STATUSES = {"within_budget", "killed_over_budget"}
MODES = {"within_budget", "timeout_kill"}
LIVE_BOUNDARIES = {
    "external_process_inspection_performed": False,
    "persistent_process_started": False,
    "network_call_performed": False,
    "provider_call_performed": False,
    "discord_call_performed": False,
    "terminal_capture_performed": False,
    "terminal_injection_performed": False,
    "raw_stdout_stored": False,
    "raw_stderr_stored": False,
    "secret_stored": False,
}


class ResourceEnforcementTrialStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        resource_claim_id: str,
        mode: str = "within_budget",
        timeout_seconds: float = 1.0,
        source_root: str | Path | None = None,
        label: str = "manual-resource-enforcement-trial",
    ) -> dict[str, Any]:
        if mode not in MODES:
            raise ValueError(f"invalid resource enforcement mode: {mode}")
        timeout_seconds = max(float(timeout_seconds), 0.05)
        with self.store.locked() as state:
            claim = (state.get("resource_claims") or {}).get(resource_claim_id)
            if not claim:
                raise KeyError(f"unknown resource_claim_id: {resource_claim_id}")
            if claim.get("state") not in {"reserved", "active"}:
                raise ValueError(f"resource claim is not enforceable in state: {claim.get('state')}")
            task_run = (state.get("task_runs") or {}).get(claim.get("task_run_id"))
            if not task_run:
                raise KeyError(f"resource_claim {resource_claim_id} references missing task_run")
            claim_before = deepcopy(claim)
            active_claim = transition_resource_claim(claim, "active")
            state.setdefault("resource_claims", {})[resource_claim_id] = active_claim

        process_result = _run_owned_subprocess(mode=mode, timeout_seconds=timeout_seconds)
        observed = {
            "input_tokens": 0,
            "output_tokens": 0,
            "runtime_ms": process_result["runtime_ms"],
            "cpu_core_ms": 0,
            "peak_memory_mb": 0,
            "network_bytes": 0,
            "disk_read_bytes": 0,
            "disk_write_bytes": 0,
        }
        with self.store.locked() as state:
            active_claim = (state.get("resource_claims") or {}).get(resource_claim_id)
            if not active_claim:
                raise KeyError(f"resource claim disappeared during enforcement: {resource_claim_id}")
            task_run = (state.get("task_runs") or {}).get(active_claim.get("task_run_id"))
            if not task_run:
                raise KeyError(f"resource_claim {resource_claim_id} references missing task_run")
            telemetry = build_resource_telemetry_record(
                task_run=task_run,
                claim=active_claim,
                observed=observed,
                source_type="runner_summary",
                source_ref={
                    "kind": "resource_enforcement_trial",
                    "ref": f"local://resource-enforcement/{label}/{mode}",
                    "artifact_sha256": process_result["combined_output_sha256"],
                },
            )
            telemetry_id = telemetry["resource_telemetry_id"]
            state.setdefault("resource_telemetry_samples", {})[telemetry_id] = telemetry
            indexes = state.setdefault("indexes", {})
            indexes.setdefault("resource_telemetry_ids", {})[telemetry_id] = telemetry_id
            indexes.setdefault("resource_claim_to_telemetry", {})[resource_claim_id] = telemetry_id
            released_claim = transition_resource_claim(active_claim, "released")
            state.setdefault("resource_claims", {})[resource_claim_id] = released_claim
            record = build_resource_enforcement_trial_record(
                task_run=task_run,
                claim_before=claim_before,
                active_claim=active_claim,
                released_claim=released_claim,
                telemetry=telemetry,
                process_result=process_result,
                mode=mode,
                timeout_seconds=timeout_seconds,
                source_root=source_root,
                label=label,
            )
            trial_id = record["resource_enforcement_trial_id"]
            state.setdefault("resource_enforcement_trials", {})[trial_id] = record
            indexes.setdefault("resource_enforcement_trial_ids", {})[trial_id] = trial_id
            return deepcopy(record)


def build_resource_enforcement_trial_record(
    *,
    task_run: dict[str, Any],
    claim_before: dict[str, Any],
    active_claim: dict[str, Any],
    released_claim: dict[str, Any],
    telemetry: dict[str, Any],
    process_result: dict[str, Any],
    mode: str,
    timeout_seconds: float,
    source_root: str | Path | None = None,
    label: str = "manual-resource-enforcement-trial",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False) if source_root else repo_root()
    status = "killed_over_budget" if process_result["timed_out"] else "within_budget"
    gates = _required_gates(
        mode=mode,
        process_result=process_result,
        released_claim=released_claim,
        telemetry=telemetry,
    )
    reason_codes = _reason_codes(status=status, gates=gates)
    record = {
        "schema_version": SCHEMA_VERSION,
        "resource_enforcement_trial_id": stable_id(
            "resenforce",
            label,
            task_run.get("task_run_id"),
            claim_before.get("resource_claim_id"),
            telemetry.get("resource_telemetry_id"),
            process_result.get("combined_output_sha256"),
            now,
        ),
        "label": label,
        "source_root": str(root),
        "task_run_id": task_run.get("task_run_id"),
        "session_id": task_run.get("session_id"),
        "resource_claim_id": claim_before.get("resource_claim_id"),
        "resource_claim_sha256_before": claim_before.get("claim_sha256"),
        "resource_claim_sha256_active": active_claim.get("claim_sha256"),
        "resource_claim_sha256_released": released_claim.get("claim_sha256"),
        "resource_telemetry_id": telemetry.get("resource_telemetry_id"),
        "resource_telemetry_sha256": telemetry.get("telemetry_sha256"),
        "mode": mode,
        "budget": {
            "timeout_seconds": timeout_seconds,
            "kill_on_timeout": True,
            "shell_allowed": False,
            "network_allowed": False,
            "external_process_inspection_allowed": False,
        },
        "subprocess": process_result,
        "settlement": {
            "claim_state_before": claim_before.get("state"),
            "claim_state_during": active_claim.get("state"),
            "claim_state_after": released_claim.get("state"),
            "telemetry_settlement_status": telemetry.get("settlement_status"),
        },
        "required_gates": gates,
        "live_boundaries": dict(LIVE_BOUNDARIES),
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["resource_enforcement_trial_sha256"] = _hash_without(record, "resource_enforcement_trial_sha256")
    return deepcopy(record)


def validate_resource_enforcement_trial_record(
    record: dict[str, Any],
    *,
    claim: dict[str, Any] | None = None,
    telemetry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record(
            "resource_enforcement_trial.schema.json",
            record,
            location="resource_enforcement_trial",
        )
    except SchemaValidationError:
        reason_codes.append("resource_enforcement.schema_invalid")
    expected_hash = record.get("resource_enforcement_trial_sha256")
    if expected_hash and expected_hash != _hash_without(record, "resource_enforcement_trial_sha256"):
        reason_codes.append("resource_enforcement.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("resource_enforcement.schema_version_invalid")
    if record.get("mode") not in MODES:
        reason_codes.append("resource_enforcement.mode_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("resource_enforcement.status_invalid")
    for key, expected in LIVE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"resource_enforcement.{key}_not_false")
    budget = record.get("budget") or {}
    if budget.get("kill_on_timeout") is not True:
        reason_codes.append("resource_enforcement.kill_on_timeout_not_true")
    for key in ("shell_allowed", "network_allowed", "external_process_inspection_allowed"):
        if budget.get(key) is not False:
            reason_codes.append(f"resource_enforcement.{key}_not_false")
    process = record.get("subprocess") or {}
    if process.get("shell_used") is not False:
        reason_codes.append("resource_enforcement.shell_used_not_false")
    if process.get("raw_output_stored") is not False:
        reason_codes.append("resource_enforcement.raw_output_stored_not_false")
    expected_status = "killed_over_budget" if process.get("timed_out") is True else "within_budget"
    if record.get("status") != expected_status:
        reason_codes.append("resource_enforcement.status_process_mismatch")
    if process.get("timed_out") is True and process.get("killed") is not True:
        reason_codes.append("resource_enforcement.timeout_without_kill")
    if (record.get("settlement") or {}).get("claim_state_before") not in {"reserved", "active"}:
        reason_codes.append("resource_enforcement.claim_state_before_invalid")
    if record.get("mode") == "timeout_kill" and process.get("timed_out") is not True:
        reason_codes.append("resource_enforcement.timeout_mode_without_timeout")
    if record.get("mode") == "within_budget" and process.get("timed_out") is True:
        reason_codes.append("resource_enforcement.within_budget_mode_timed_out")
    if claim is not None:
        if record.get("resource_claim_sha256_released") != claim.get("claim_sha256"):
            reason_codes.append("resource_enforcement.claim_hash_mismatch")
        if claim.get("state") != "released":
            reason_codes.append("resource_enforcement.claim_not_released")
    if telemetry is not None:
        if record.get("resource_telemetry_sha256") != telemetry.get("telemetry_sha256"):
            reason_codes.append("resource_enforcement.telemetry_hash_mismatch")
        telemetry_validation = validate_resource_telemetry_record(telemetry)
        if not telemetry_validation["ok"]:
            reason_codes.extend(
                f"resource_enforcement.telemetry:{reason}"
                for reason in telemetry_validation["reason_codes"]
            )
    gates = _required_gates(
        mode=str(record.get("mode") or ""),
        process_result=process,
        released_claim=claim or {"state": (record.get("settlement") or {}).get("claim_state_after")},
        telemetry=telemetry or {"resource_telemetry_id": record.get("resource_telemetry_id")},
    )
    if record.get("required_gates") != gates:
        reason_codes.append("resource_enforcement.required_gates_mismatch")
    expected_reasons = _reason_codes(status=expected_status, gates=gates)
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("resource_enforcement.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _run_owned_subprocess(*, mode: str, timeout_seconds: float) -> dict[str, Any]:
    if mode == "timeout_kill":
        code = f"import time; time.sleep({timeout_seconds + 1.0!r})"
    else:
        code = "print('ams-resource-ok')"
    argv = [sys.executable, "-c", code]
    start = time.monotonic()
    process = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
    )
    timed_out = False
    killed = False
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        process.kill()
        killed = True
        stdout, stderr = process.communicate()
        stdout = stdout or (exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout or "")
        stderr = stderr or (exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr or "")
    runtime_ms = max(0, int((time.monotonic() - start) * 1000))
    stdout = stdout or ""
    stderr = stderr or ""
    stdout_sha = sha256_text(stdout)
    stderr_sha = sha256_text(stderr)
    combined_sha = sha256_text(canonical_json({"stdout_sha256": stdout_sha, "stderr_sha256": stderr_sha}))
    return {
        "owned_subprocess_started": True,
        "command_family": "python_timeout_probe",
        "argv_sha256": sha256_text(canonical_json(argv)),
        "shell_used": False,
        "timeout_seconds": timeout_seconds,
        "runtime_ms": runtime_ms,
        "return_code": process.returncode,
        "timed_out": timed_out,
        "killed": killed,
        "stdout_sha256": stdout_sha,
        "stderr_sha256": stderr_sha,
        "combined_output_sha256": combined_sha,
        "stdout_bytes": len(stdout.encode("utf-8")),
        "stderr_bytes": len(stderr.encode("utf-8")),
        "raw_output_stored": False,
    }


def _required_gates(
    *,
    mode: str,
    process_result: dict[str, Any],
    released_claim: dict[str, Any],
    telemetry: dict[str, Any],
) -> dict[str, bool]:
    return {
        "claim_released": released_claim.get("state") == "released",
        "telemetry_written": bool(telemetry.get("resource_telemetry_id")),
        "owned_subprocess_started": process_result.get("owned_subprocess_started") is True,
        "shell_not_used": process_result.get("shell_used") is False,
        "raw_output_not_stored": process_result.get("raw_output_stored") is False,
        "mode_result_consistent": (
            (mode == "timeout_kill" and process_result.get("timed_out") is True and process_result.get("killed") is True)
            or (mode == "within_budget" and process_result.get("timed_out") is False)
        ),
    }


def _reason_codes(*, status: str, gates: dict[str, bool]) -> list[str]:
    missing = [f"resource_enforcement.{key}_missing" for key, ok in gates.items() if not ok]
    if missing:
        return sorted(set(missing))
    if status == "killed_over_budget":
        return ["resource_enforcement.timeout_killed"]
    return ["resource_enforcement.within_budget"]
