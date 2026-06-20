from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .shadow_launch import validate_shadow_launch_plan_record
from .store import JsonStore
from .workspace import workspace_root


SECRET_ENV_MARKERS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PRIVATE",
    "CREDENTIAL",
    "COOKIE",
    "SESSION",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "DISCORD_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
)



def _snapshot_hash(snapshot: dict[str, Any]) -> str:
    return sha256_text(canonical_json(snapshot))


def build_shadow_runner_transaction(
    state: dict[str, Any],
    *,
    runner_preflight: dict[str, Any],
    argv: list[str],
    cwd: str | None = None,
    requested_by: str = "operator",
    approval_id: str | None = None,
    purpose: str = "no-egress live shadow",
    env_names: list[str] | None = None,
    redacted_env_names: list[str] | None = None,
    abort_conditions: list[str] | None = None,
    rollback_steps: list[str] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    command = _build_command(argv, cwd or workspace_root())
    environment = _build_environment(env_names or [], redacted_env_names or [])
    operator_intent = {
        "requested_by": requested_by,
        "approval_id": approval_id,
        "purpose": purpose,
        "created_at": now,
    }
    runner_snapshot = deepcopy(runner_preflight)
    evaluation = evaluate_shadow_runner_transaction(
        state,
        runner_preflight=runner_snapshot,
        command=command,
        environment=environment,
        operator_intent=operator_intent,
        abort_conditions=list(abort_conditions or []),
        rollback_steps=list(rollback_steps or []),
    )
    invocation = runner_snapshot.get("invocation") or {}
    record = {
        "schema_version": "ams.ams_codex.shadow_runner_transaction.v0",
        "shadow_runner_transaction_id": stable_id(
            "shadowrun",
            _snapshot_hash(runner_snapshot),
            command["command_sha256"],
            environment["environment_sha256"],
            operator_intent,
            abort_conditions or [],
            rollback_steps or [],
        ),
        "mode": "shadow",
        "egress_mode": "none",
        "status": evaluation["status"],
        "reason_code": evaluation["reason_code"],
        "reason_codes": evaluation["reason_codes"],
        "ready_for_operator_review": evaluation["ready_for_operator_review"],
        "process_start_allowed": False,
        "runner_preflight": runner_snapshot,
        "runner_preflight_sha256": _snapshot_hash(runner_snapshot),
        "shadow_launch_plan_id": invocation.get("shadow_launch_plan_id"),
        "shadow_launch_plan_sha256": invocation.get("shadow_launch_plan_sha256"),
        "dispatch_envelope_id": invocation.get("dispatch_envelope_id"),
        "task_run_id": invocation.get("task_run_id"),
        "session_id": invocation.get("session_id"),
        "provider": invocation.get("provider"),
        "surface": invocation.get("surface"),
        "provider_session_id": invocation.get("provider_session_id"),
        "command": command,
        "environment": environment,
        "operator_intent": operator_intent,
        "abort_conditions": list(abort_conditions or []),
        "rollback_steps": list(rollback_steps or []),
        "required_gates": evaluation["required_gates"],
        "start_actions": [],
        "created_at": now,
        "updated_at": now,
    }
    record["shadow_runner_transaction_sha256"] = _hash_without(
        record,
        "shadow_runner_transaction_sha256",
    )
    return record


def evaluate_shadow_runner_transaction(
    state: dict[str, Any],
    *,
    runner_preflight: dict[str, Any],
    command: dict[str, Any],
    environment: dict[str, Any],
    operator_intent: dict[str, Any],
    abort_conditions: list[str],
    rollback_steps: list[str],
) -> dict[str, Any]:
    reason_codes: list[str] = []
    invocation = runner_preflight.get("invocation") or {}

    if runner_preflight.get("allowed") is not True:
        reason_codes.append("shadow_runner.runner_preflight_not_allowed")
    if runner_preflight.get("reason_code") != "runner.live_shadow_preflight_ok":
        reason_codes.append("shadow_runner.runner_preflight_not_live_shadow")
    if invocation.get("dry_run_only") is not True or invocation.get("preflight_only") is not True:
        reason_codes.append("shadow_runner.runner_preflight_not_inert")
    if invocation.get("live_requested") is not True or invocation.get("launch_mode") != "shadow":
        reason_codes.append("shadow_runner.runner_preflight_mode_mismatch")

    plan = (state.get("shadow_launch_plans") or {}).get(invocation.get("shadow_launch_plan_id"))
    if not plan:
        reason_codes.append("shadow_runner.shadow_launch_plan_missing")
    else:
        if plan.get("shadow_launch_plan_sha256") != invocation.get("shadow_launch_plan_sha256"):
            reason_codes.append("shadow_runner.shadow_launch_plan_hash_mismatch")
        validation = validate_shadow_launch_plan_record(plan, state=state)
        if not validation["ok"]:
            reason_codes.extend(validation["reason_codes"])
        if plan.get("ready_to_launch") is not True or plan.get("status") != "allow":
            reason_codes.append(f"shadow_runner.shadow_launch_plan_not_allowed:{plan.get('status')}")

    command_validation = _validate_command(command)
    reason_codes.extend(command_validation["reason_codes"])
    environment_validation = _validate_environment(environment)
    reason_codes.extend(environment_validation["reason_codes"])

    if not operator_intent.get("approval_id"):
        reason_codes.append("shadow_runner.operator_approval_missing")
    if not operator_intent.get("purpose"):
        reason_codes.append("shadow_runner.operator_purpose_missing")
    if not abort_conditions:
        reason_codes.append("shadow_runner.abort_conditions_missing")
    if not rollback_steps:
        reason_codes.append("shadow_runner.rollback_steps_missing")

    status = _status_for(reason_codes)
    ready = status == "allow"
    return {
        "status": status,
        "reason_code": "shadow_runner.transaction_ready" if ready else reason_codes[0],
        "reason_codes": ["shadow_runner.transaction_ready"] if ready else reason_codes,
        "ready_for_operator_review": ready,
        "required_gates": {
            "runner_preflight_allowed": runner_preflight.get("allowed") is True,
            "runner_preflight_live_shadow": runner_preflight.get("reason_code") == "runner.live_shadow_preflight_ok",
            "runner_preflight_inert": invocation.get("dry_run_only") is True
            and invocation.get("preflight_only") is True,
            "shadow_launch_plan_valid": bool(plan)
            and plan.get("ready_to_launch") is True
            and plan.get("status") == "allow"
            and not validate_shadow_launch_plan_record(plan, state=state)["reason_codes"],
            "command_argv_sequence": command_validation["checks"]["argv_sequence"],
            "command_absolute_executable": command_validation["checks"]["absolute_executable"],
            "command_shell_disabled": command_validation["checks"]["shell_disabled"],
            "command_cwd_under_workspace": command_validation["checks"]["cwd_under_workspace"],
            "environment_inherit_disabled": environment_validation["checks"]["inherit_disabled"],
            "environment_secret_values_not_stored": environment_validation["checks"]["secret_values_not_stored"],
            "operator_approval_present": bool(operator_intent.get("approval_id")),
            "abort_conditions_present": bool(abort_conditions),
            "rollback_steps_present": bool(rollback_steps),
            "process_start_allowed_false": True,
        },
    }


def validate_shadow_runner_transaction_record(
    record: dict[str, Any],
    *,
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    expected_hash = record.get("shadow_runner_transaction_sha256")
    if expected_hash and expected_hash != _hash_without(record, "shadow_runner_transaction_sha256"):
        reason_codes.append("shadow_runner_transaction.hash_mismatch")

    runner_preflight = record.get("runner_preflight") or {}
    if record.get("runner_preflight_sha256") != _snapshot_hash(runner_preflight):
        reason_codes.append("shadow_runner_transaction.runner_preflight_hash_mismatch")
    command = record.get("command") or {}
    expected_command_hash = _snapshot_hash(_command_hash_material(command))
    if command.get("command_sha256") != expected_command_hash:
        reason_codes.append("shadow_runner_transaction.command_hash_mismatch")
    environment = record.get("environment") or {}
    expected_environment_hash = _snapshot_hash(_environment_hash_material(environment))
    if environment.get("environment_sha256") != expected_environment_hash:
        reason_codes.append("shadow_runner_transaction.environment_hash_mismatch")
    if record.get("process_start_allowed") is not False:
        reason_codes.append("shadow_runner_transaction.process_start_allowed_not_false")
    if record.get("start_actions") != []:
        reason_codes.append("shadow_runner_transaction.start_actions_not_empty")

    if state is not None:
        current = evaluate_shadow_runner_transaction(
            state,
            runner_preflight=runner_preflight,
            command=command,
            environment=environment,
            operator_intent=record.get("operator_intent") or {},
            abort_conditions=list(record.get("abort_conditions") or []),
            rollback_steps=list(record.get("rollback_steps") or []),
        )
        for key in ("status", "reason_code", "reason_codes", "ready_for_operator_review", "required_gates"):
            if record.get(key) != current[key]:
                reason_codes.append(f"shadow_runner_transaction.{key}_stale")
    return {"ok": not reason_codes, "reason_codes": reason_codes}


class ShadowRunnerStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create_transaction(
        self,
        *,
        runner_preflight: dict[str, Any],
        argv: list[str],
        cwd: str | None = None,
        requested_by: str = "operator",
        approval_id: str | None = None,
        purpose: str = "no-egress live shadow",
        env_names: list[str] | None = None,
        redacted_env_names: list[str] | None = None,
        abort_conditions: list[str] | None = None,
        rollback_steps: list[str] | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            record = build_shadow_runner_transaction(
                state,
                runner_preflight=runner_preflight,
                argv=argv,
                cwd=cwd,
                requested_by=requested_by,
                approval_id=approval_id,
                purpose=purpose,
                env_names=env_names,
                redacted_env_names=redacted_env_names,
                abort_conditions=abort_conditions,
                rollback_steps=rollback_steps,
            )
            state.setdefault("shadow_runner_transactions", {})[
                record["shadow_runner_transaction_id"]
            ] = record
            state.setdefault("indexes", {}).setdefault("shadow_runner_transaction_ids", {})[
                record["shadow_runner_transaction_id"]
            ] = record["shadow_runner_transaction_id"]
            return deepcopy(record)


def _build_command(argv: list[str], cwd: str) -> dict[str, Any]:
    command = {
        "argv": list(argv),
        "executable": argv[0] if argv else None,
        "cwd": str(Path(cwd).expanduser().resolve(strict=False)),
        "shell": False,
    }
    command["command_sha256"] = _snapshot_hash(_command_hash_material(command))
    return command


def _build_environment(env_names: list[str], redacted_env_names: list[str]) -> dict[str, Any]:
    allowed = _unique(env_names)
    redacted = _unique(redacted_env_names)
    blocked = [name for name in allowed if _is_secret_env_name(name)]
    environment = {
        "inherit": False,
        "redaction_policy": "names_only_hash_values",
        "allowed_names": allowed,
        "redacted_names": redacted,
        "blocked_secret_names": blocked,
        "stored_values": {},
    }
    environment["environment_sha256"] = _snapshot_hash(_environment_hash_material(environment))
    return environment


def _validate_command(command: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    argv = command.get("argv") or []
    executable = command.get("executable")
    cwd = command.get("cwd")
    checks = {
        "argv_sequence": isinstance(argv, list) and bool(argv) and all(isinstance(item, str) and item for item in argv),
        "absolute_executable": isinstance(executable, str) and Path(executable).is_absolute(),
        "shell_disabled": command.get("shell") is False,
        "cwd_under_workspace": _path_under_workspace(str(cwd or "")),
    }
    if not checks["argv_sequence"]:
        reason_codes.append("shadow_runner.command_argv_invalid")
    if not checks["absolute_executable"]:
        reason_codes.append("shadow_runner.command_executable_not_absolute")
    if not checks["shell_disabled"]:
        reason_codes.append("shadow_runner.command_shell_not_allowed")
    if not checks["cwd_under_workspace"]:
        reason_codes.append("shadow_runner.command_cwd_outside_workspace")
    return {"ok": not reason_codes, "reason_codes": reason_codes, "checks": checks}


def _validate_environment(environment: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    stored_values = environment.get("stored_values") or {}
    blocked_secret_names = list(environment.get("blocked_secret_names") or [])
    checks = {
        "inherit_disabled": environment.get("inherit") is False,
        "secret_values_not_stored": not stored_values and not blocked_secret_names,
    }
    if not checks["inherit_disabled"]:
        reason_codes.append("shadow_runner.environment_inherit_denied")
    if stored_values:
        reason_codes.append("shadow_runner.environment_values_stored")
    if blocked_secret_names:
        reason_codes.append("shadow_runner.environment_secret_name_allowed")
    return {"ok": not reason_codes, "reason_codes": reason_codes, "checks": checks}


def _command_hash_material(command: dict[str, Any]) -> dict[str, Any]:
    return {
        "argv": list(command.get("argv") or []),
        "executable": command.get("executable"),
        "cwd": command.get("cwd"),
        "shell": command.get("shell"),
    }


def _environment_hash_material(environment: dict[str, Any]) -> dict[str, Any]:
    return {
        "inherit": environment.get("inherit"),
        "redaction_policy": environment.get("redaction_policy"),
        "allowed_names": list(environment.get("allowed_names") or []),
        "redacted_names": list(environment.get("redacted_names") or []),
        "blocked_secret_names": list(environment.get("blocked_secret_names") or []),
        "stored_values": environment.get("stored_values") or {},
    }


def _path_under_workspace(path: str) -> bool:
    try:
        Path(path).expanduser().resolve(strict=False).relative_to(Path(workspace_root()).resolve(strict=False))
    except ValueError:
        return False
    return True


def _is_secret_env_name(name: str) -> bool:
    upper = name.upper()
    return any(marker in upper for marker in SECRET_ENV_MARKERS)


def _unique(values: list[str]) -> list[str]:
    return sorted({str(value) for value in values if str(value)})


def _status_for(reason_codes: list[str]) -> str:
    if not reason_codes:
        return "allow"
    deny_fragments = (
        "runner_preflight_not_allowed",
        "runner_preflight_not_live_shadow",
        "runner_preflight_not_inert",
        "shadow_launch_plan",
        "command_",
        "environment_",
    )
    if any(any(fragment in reason for fragment in deny_fragments) for reason in reason_codes):
        return "deny"
    return "defer"
