from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .semantic_hook_approval import validate_semantic_hook_approval_binding_record
from .semantic_hook_install_plan import validate_semantic_hook_install_plan_record
from .semantic_hook_run import validate_semantic_hook_run_record
from .semantic_hook_target_snapshot import validate_semantic_hook_target_snapshot_record
from .store import JsonStore
from .workspace import repo_root


SCHEMA_VERSION = "ams.ams.semantic_hook_install_transaction.v0"
STATUSES = {"ready_for_operator_review", "blocked"}

LIVE_BOUNDARIES = {
    "hook_file_written": False,
    "hook_installed": False,
    "hook_trusted": False,
    "provider_hook_executed": False,
    "backup_file_written": False,
    "restore_performed": False,
    "discord_call_performed": False,
    "terminal_attach_performed": False,
    "terminal_capture_performed": False,
    "terminal_injection_performed": False,
    "persistent_process_started": False,
    "provider_call_performed": False,
    "network_call_performed": False,
    "raw_payload_stored": False,
    "secret_stored": False,
}


class SemanticHookInstallTransactionStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        semantic_hook_target_snapshot_id: str,
        source_root: str | Path | None = None,
        label: str = "manual-semantic-hook-install-transaction",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            snapshot = (state.get("semantic_hook_target_snapshots") or {}).get(semantic_hook_target_snapshot_id)
            if not snapshot:
                raise KeyError(f"semantic hook target snapshot not found: {semantic_hook_target_snapshot_id}")
            binding = (state.get("semantic_hook_approval_bindings") or {}).get(
                snapshot.get("semantic_hook_approval_binding_id")
            )
            if not binding:
                raise KeyError(f"semantic hook approval binding not found: {snapshot.get('semantic_hook_approval_binding_id')}")
            install_plan = (state.get("semantic_hook_install_plans") or {}).get(binding.get("semantic_hook_install_plan_id"))
            if not install_plan:
                raise KeyError(f"semantic hook install plan not found: {binding.get('semantic_hook_install_plan_id')}")
            hook_run = (state.get("semantic_hook_runs") or {}).get(install_plan.get("semantic_hook_run_id"))
            if not hook_run:
                raise KeyError(f"semantic hook run not found: {install_plan.get('semantic_hook_run_id')}")
            record = build_semantic_hook_install_transaction(
                target_snapshot=snapshot,
                binding=binding,
                install_plan=install_plan,
                hook_run=hook_run,
                source_root=source_root,
                label=label,
            )
            transaction_id = record["semantic_hook_install_transaction_id"]
            state.setdefault("semantic_hook_install_transactions", {})[transaction_id] = record
            state.setdefault("indexes", {}).setdefault("semantic_hook_install_transaction_ids", {})[
                transaction_id
            ] = transaction_id
            return deepcopy(record)


def build_semantic_hook_install_transaction(
    *,
    target_snapshot: dict[str, Any],
    binding: dict[str, Any],
    install_plan: dict[str, Any],
    hook_run: dict[str, Any],
    source_root: str | Path | None = None,
    label: str = "manual-semantic-hook-install-transaction",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False) if source_root else repo_root()
    payloads = _payload_renderings(
        install_plan=install_plan,
        hook_run=hook_run,
        target_snapshot=target_snapshot,
    )
    install_steps = _install_transaction_steps(payloads)
    rollback_steps = _rollback_transaction_steps(target_snapshot)
    trust_steps = _trust_review_steps(install_plan)
    required_gates = _required_gates(
        target_snapshot=target_snapshot,
        binding=binding,
        install_plan=install_plan,
        hook_run=hook_run,
        payloads=payloads,
        install_steps=install_steps,
        rollback_steps=rollback_steps,
        trust_steps=trust_steps,
    )
    reason_codes = _reason_codes(required_gates, payloads)
    status = (
        "ready_for_operator_review"
        if reason_codes == ["semantic_hook_install_transaction.ready_for_operator_review"]
        else "blocked"
    )
    record = {
        "schema_version": SCHEMA_VERSION,
        "semantic_hook_install_transaction_id": stable_id(
            "semhooktxn",
            label,
            target_snapshot.get("semantic_hook_target_snapshot_id"),
            target_snapshot.get("semantic_hook_target_snapshot_sha256"),
            binding.get("semantic_hook_approval_binding_id"),
            binding.get("semantic_hook_approval_binding_sha256"),
            install_plan.get("semantic_hook_install_plan_id"),
            install_plan.get("semantic_hook_install_plan_sha256"),
            hook_run.get("semantic_hook_run_id"),
            hook_run.get("semantic_hook_run_sha256"),
            payloads,
            now,
        ),
        "label": label,
        "source_root": str(root),
        "semantic_hook_target_snapshot_id": target_snapshot.get("semantic_hook_target_snapshot_id"),
        "semantic_hook_target_snapshot_sha256": target_snapshot.get("semantic_hook_target_snapshot_sha256"),
        "semantic_hook_approval_binding_id": binding.get("semantic_hook_approval_binding_id"),
        "semantic_hook_approval_binding_sha256": binding.get("semantic_hook_approval_binding_sha256"),
        "semantic_hook_install_plan_id": install_plan.get("semantic_hook_install_plan_id"),
        "semantic_hook_install_plan_sha256": install_plan.get("semantic_hook_install_plan_sha256"),
        "semantic_hook_run_id": hook_run.get("semantic_hook_run_id"),
        "semantic_hook_run_sha256": hook_run.get("semantic_hook_run_sha256"),
        "target_count": len(payloads),
        "payload_renderings": payloads,
        "install_transaction_steps": install_steps,
        "rollback_transaction_steps": rollback_steps,
        "trust_review_steps": trust_steps,
        "required_gates": required_gates,
        "approval_granted": False,
        "live_install_allowed": False,
        "hook_file_write_allowed": False,
        "hook_trust_allowed": False,
        "provider_hook_execution_allowed": False,
        "backup_write_allowed": False,
        "restore_allowed": False,
        "install_actions": [],
        "trust_actions": [],
        "start_actions": [],
        "live_boundaries": dict(LIVE_BOUNDARIES),
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["semantic_hook_install_transaction_sha256"] = _hash_without(
        record,
        "semantic_hook_install_transaction_sha256",
    )
    return deepcopy(record)


def validate_semantic_hook_install_transaction_record(
    record: dict[str, Any],
    *,
    target_snapshot: dict[str, Any] | None = None,
    binding: dict[str, Any] | None = None,
    install_plan: dict[str, Any] | None = None,
    hook_run: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record(
            "semantic_hook_install_transaction.schema.json",
            record,
            location="semantic_hook_install_transaction",
        )
    except SchemaValidationError:
        reason_codes.append("semantic_hook_install_transaction.schema_invalid")
    expected_hash = record.get("semantic_hook_install_transaction_sha256")
    if expected_hash and expected_hash != _hash_without(record, "semantic_hook_install_transaction_sha256"):
        reason_codes.append("semantic_hook_install_transaction.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("semantic_hook_install_transaction.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("semantic_hook_install_transaction.status_invalid")
    for key, expected in LIVE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"semantic_hook_install_transaction.{key}_not_false")
    for key in (
        "approval_granted",
        "live_install_allowed",
        "hook_file_write_allowed",
        "hook_trust_allowed",
        "provider_hook_execution_allowed",
        "backup_write_allowed",
        "restore_allowed",
    ):
        if record.get(key) is not False:
            reason_codes.append(f"semantic_hook_install_transaction.{key}_not_false")
    for key in ("install_actions", "trust_actions", "start_actions"):
        if record.get(key) != []:
            reason_codes.append(f"semantic_hook_install_transaction.{key}_not_empty")
    for payload in record.get("payload_renderings") or []:
        if payload.get("raw_payload_stored") is not False:
            reason_codes.append("semantic_hook_install_transaction.raw_payload_stored_not_false")
        if payload.get("secret_stored") is not False:
            reason_codes.append("semantic_hook_install_transaction.secret_stored_not_false")
        if payload.get("write_performed") is not False:
            reason_codes.append("semantic_hook_install_transaction.payload_write_performed_not_false")
        if payload.get("payload_sha256") != payload.get("expected_config_sha256"):
            reason_codes.append("semantic_hook_install_transaction.payload_config_hash_mismatch")
    for step in record.get("install_transaction_steps") or []:
        if step.get("write_performed") is not False:
            reason_codes.append("semantic_hook_install_transaction.install_step_write_performed_not_false")
        if step.get("provider_executed") is not False:
            reason_codes.append("semantic_hook_install_transaction.install_step_provider_executed_not_false")
    for step in record.get("rollback_transaction_steps") or []:
        if step.get("restore_performed") is not False:
            reason_codes.append("semantic_hook_install_transaction.rollback_step_restore_performed_not_false")
        if step.get("backup_file_written") is not False:
            reason_codes.append("semantic_hook_install_transaction.rollback_step_backup_written_not_false")
    for step in record.get("trust_review_steps") or []:
        if step.get("trusted") is not False:
            reason_codes.append("semantic_hook_install_transaction.trust_step_trusted_not_false")
    if target_snapshot is not None:
        if record.get("semantic_hook_target_snapshot_sha256") != target_snapshot.get("semantic_hook_target_snapshot_sha256"):
            reason_codes.append("semantic_hook_install_transaction.target_snapshot_hash_mismatch")
        snapshot_validation = validate_semantic_hook_target_snapshot_record(
            target_snapshot,
            binding=binding,
            install_plan=install_plan,
        )
        if not snapshot_validation["ok"]:
            reason_codes.extend(
                f"semantic_hook_install_transaction.target_snapshot:{reason}"
                for reason in snapshot_validation["reason_codes"]
            )
    if binding is not None:
        if record.get("semantic_hook_approval_binding_sha256") != binding.get("semantic_hook_approval_binding_sha256"):
            reason_codes.append("semantic_hook_install_transaction.approval_binding_hash_mismatch")
        binding_validation = validate_semantic_hook_approval_binding_record(binding, install_plan=install_plan)
        if not binding_validation["ok"]:
            reason_codes.extend(
                f"semantic_hook_install_transaction.binding:{reason}" for reason in binding_validation["reason_codes"]
            )
    if install_plan is not None:
        if record.get("semantic_hook_install_plan_sha256") != install_plan.get("semantic_hook_install_plan_sha256"):
            reason_codes.append("semantic_hook_install_transaction.install_plan_hash_mismatch")
        install_validation = validate_semantic_hook_install_plan_record(install_plan)
        if not install_validation["ok"]:
            reason_codes.extend(
                f"semantic_hook_install_transaction.install_plan:{reason}"
                for reason in install_validation["reason_codes"]
            )
    if hook_run is not None:
        if record.get("semantic_hook_run_sha256") != hook_run.get("semantic_hook_run_sha256"):
            reason_codes.append("semantic_hook_install_transaction.hook_run_hash_mismatch")
        hook_run_validation = validate_semantic_hook_run_record(hook_run)
        if not hook_run_validation["ok"]:
            reason_codes.extend(
                f"semantic_hook_install_transaction.hook_run:{reason}" for reason in hook_run_validation["reason_codes"]
            )
    if target_snapshot is not None and binding is not None and install_plan is not None and hook_run is not None:
        expected_payloads = _payload_renderings(
            install_plan=install_plan,
            hook_run=hook_run,
            target_snapshot=target_snapshot,
        )
        if record.get("payload_renderings") != expected_payloads:
            reason_codes.append("semantic_hook_install_transaction.payload_renderings_mismatch")
        expected_install_steps = _install_transaction_steps(expected_payloads)
        expected_rollback_steps = _rollback_transaction_steps(target_snapshot)
        expected_trust_steps = _trust_review_steps(install_plan)
        if record.get("install_transaction_steps") != expected_install_steps:
            reason_codes.append("semantic_hook_install_transaction.install_steps_mismatch")
        if record.get("rollback_transaction_steps") != expected_rollback_steps:
            reason_codes.append("semantic_hook_install_transaction.rollback_steps_mismatch")
        if record.get("trust_review_steps") != expected_trust_steps:
            reason_codes.append("semantic_hook_install_transaction.trust_steps_mismatch")
        expected_gates = _required_gates(
            target_snapshot=target_snapshot,
            binding=binding,
            install_plan=install_plan,
            hook_run=hook_run,
            payloads=record.get("payload_renderings") or [],
            install_steps=record.get("install_transaction_steps") or [],
            rollback_steps=record.get("rollback_transaction_steps") or [],
            trust_steps=record.get("trust_review_steps") or [],
        )
        if record.get("required_gates") != expected_gates:
            reason_codes.append("semantic_hook_install_transaction.required_gates_mismatch")
        expected_reasons = _reason_codes(expected_gates, record.get("payload_renderings") or [])
        expected_status = (
            "ready_for_operator_review"
            if expected_reasons == ["semantic_hook_install_transaction.ready_for_operator_review"]
            else "blocked"
        )
        if record.get("status") != expected_status:
            reason_codes.append("semantic_hook_install_transaction.status_reason_mismatch")
        if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
            reason_codes.append("semantic_hook_install_transaction.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _payload_renderings(
    *,
    install_plan: dict[str, Any],
    hook_run: dict[str, Any],
    target_snapshot: dict[str, Any],
) -> list[dict[str, Any]]:
    snapshot_by_target = {item.get("target"): item for item in target_snapshot.get("target_snapshots") or []}
    payloads: list[dict[str, Any]] = []
    for target in install_plan.get("install_targets") or []:
        target_name = target.get("target")
        source = "claude_hook_contract_preview" if target_name == "claude_hook_contract" else "codex_hook_config_preview"
        preview = hook_run.get(source) or {}
        rendered = canonical_json(preview)
        snapshot = snapshot_by_target.get(target_name) or {}
        payloads.append(
            {
                "target": target_name,
                "payload_source": source,
                "declared_path": target.get("path"),
                "resolved_path": snapshot.get("resolved_path"),
                "expected_config_sha256": target.get("config_sha256"),
                "payload_sha256": sha256_text(rendered),
                "payload_size_bytes": len(rendered.encode("utf-8")),
                "raw_payload_stored": False,
                "secret_stored": False,
                "write_performed": False,
                "target_safe_for_no_write_drill": snapshot.get("safe_for_no_write_drill") is True,
            }
        )
    return payloads


def _install_transaction_steps(payloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for payload in payloads:
        resolved = payload.get("resolved_path") or payload.get("declared_path") or ""
        steps.append(
            {
                "target": payload.get("target"),
                "payload_sha256": payload.get("payload_sha256"),
                "target_path": resolved,
                "temp_path_pattern": f"{resolved}.ams-new-*",
                "step_order": [
                    "verify_current_snapshot_hash",
                    "write_temp_file",
                    "fsync_temp_file",
                    "atomic_rename",
                    "fsync_parent_directory",
                    "verify_written_hash",
                ],
                "atomic_rename_required": True,
                "fsync_required": True,
                "trust_after_write": False,
                "write_performed": False,
                "provider_executed": False,
            }
        )
    return steps


def _rollback_transaction_steps(target_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for snapshot in target_snapshot.get("target_snapshots") or []:
        steps.append(
            {
                "target": snapshot.get("target"),
                "target_path": snapshot.get("resolved_path"),
                "restore_action": snapshot.get("restore_action"),
                "previous_exists": snapshot.get("exists"),
                "previous_sha256": snapshot.get("current_sha256"),
                "delete_if_created": snapshot.get("restore_action") == "delete_created_file",
                "restore_performed": False,
                "backup_file_written": False,
            }
        )
    return steps


def _trust_review_steps(install_plan: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "surface": step.get("surface"),
            "review_command": step.get("review_command"),
            "config_sha256": step.get("config_sha256"),
            "trusted": False,
            "provider_hook_execution_allowed": False,
        }
        for step in install_plan.get("trust_review_plan") or []
    ]


def _required_gates(
    *,
    target_snapshot: dict[str, Any],
    binding: dict[str, Any],
    install_plan: dict[str, Any],
    hook_run: dict[str, Any],
    payloads: list[dict[str, Any]],
    install_steps: list[dict[str, Any]],
    rollback_steps: list[dict[str, Any]],
    trust_steps: list[dict[str, Any]],
) -> dict[str, bool]:
    payload_hashes_match = all(
        payload.get("payload_sha256") == payload.get("expected_config_sha256")
        for payload in payloads
    )
    return {
        "target_snapshot_ready": target_snapshot.get("status") == "ready_for_operator_review",
        "target_snapshot_inert": _snapshot_inert(target_snapshot),
        "approval_binding_ready": binding.get("status") == "ready_for_operator_approval",
        "approval_binding_inert": _binding_inert(binding),
        "install_plan_ready": install_plan.get("status") == "ready_for_operator_review",
        "hook_run_allow": hook_run.get("status") == "allow",
        "target_count_matches": len(payloads) == target_snapshot.get("target_count") == len(install_plan.get("install_targets") or []),
        "payload_hashes_match_install_plan": payload_hashes_match,
        "payloads_hash_only": all(
            payload.get("raw_payload_stored") is False
            and payload.get("secret_stored") is False
            and payload.get("write_performed") is False
            for payload in payloads
        ),
        "install_steps_no_write": all(
            step.get("write_performed") is False and step.get("provider_executed") is False
            for step in install_steps
        ),
        "install_steps_atomic": all(
            step.get("atomic_rename_required") is True and step.get("fsync_required") is True
            for step in install_steps
        ),
        "rollback_steps_no_restore": all(
            step.get("restore_performed") is False and step.get("backup_file_written") is False
            for step in rollback_steps
        ),
        "trust_steps_not_trusted": all(
            step.get("trusted") is False and step.get("provider_hook_execution_allowed") is False
            for step in trust_steps
        ),
        "approval_granted_false": True,
        "live_install_allowed_false": True,
    }


def _snapshot_inert(snapshot: dict[str, Any]) -> bool:
    if any((snapshot.get("live_boundaries") or {}).values()):
        return False
    for key in (
        "approval_granted",
        "live_install_allowed",
        "hook_file_write_allowed",
        "hook_trust_allowed",
        "provider_hook_execution_allowed",
        "backup_write_allowed",
        "restore_allowed",
    ):
        if snapshot.get(key) is not False:
            return False
    return snapshot.get("install_actions") == [] and snapshot.get("trust_actions") == [] and snapshot.get("start_actions") == []


def _binding_inert(binding: dict[str, Any]) -> bool:
    if any((binding.get("live_boundaries") or {}).values()):
        return False
    for key in (
        "approval_granted",
        "live_install_allowed",
        "hook_file_write_allowed",
        "hook_trust_allowed",
        "provider_hook_execution_allowed",
    ):
        if binding.get(key) is not False:
            return False
    return binding.get("start_actions") == []


def _reason_codes(gates: dict[str, bool], payloads: list[dict[str, Any]]) -> list[str]:
    reasons = [f"semantic_hook_install_transaction.{key}_missing" for key, ok in gates.items() if not ok]
    for payload in payloads:
        target = payload.get("target") or "unknown"
        if payload.get("payload_sha256") != payload.get("expected_config_sha256"):
            reasons.append(f"semantic_hook_install_transaction.payload_hash_mismatch:{target}")
        if payload.get("target_safe_for_no_write_drill") is not True:
            reasons.append(f"semantic_hook_install_transaction.target_not_safe:{target}")
    return sorted(set(reasons)) or ["semantic_hook_install_transaction.ready_for_operator_review"]
