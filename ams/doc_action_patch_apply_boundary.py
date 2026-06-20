from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any

from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore
from .workspace import path_is_under, repo_root


SCHEMA_VERSION = "ams.ams.doc_action_patch_apply_boundary_packet.v0"
STATUSES = {"ready_for_operator_apply_acceptance", "blocked"}

NON_APPLY_BOUNDARIES = {
    "source_file_rewritten": False,
    "source_file_deleted": False,
    "source_file_moved": False,
    "archive_created": False,
    "generated_surface_rewritten": False,
    "patch_artifact_written": False,
    "raw_patch_stored_in_ams_state": False,
    "raw_source_markdown_stored_in_ams_state": False,
    "raw_approval_stored_in_ams_state": False,
    "raw_operator_apply_acceptance_stored_in_ams_state": False,
    "raw_executor_output_stored_in_ams_state": False,
    "discord_call_performed": False,
    "terminal_attach_performed": False,
    "terminal_capture_performed": False,
    "terminal_injection_performed": False,
    "persistent_process_started": False,
    "provider_call_performed": False,
    "network_call_performed": False,
    "secret_stored": False,
}


class DocActionPatchApplyBoundaryPacketStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        doc_action_patch_executor_preflight_id: str,
        source_root: str | Path | None = None,
        label: str = "manual-doc-action-patch-apply-boundary",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            preflight = (state.get("doc_action_patch_executor_preflights") or {}).get(
                doc_action_patch_executor_preflight_id
            )
            if not preflight:
                raise KeyError(
                    "doc action patch executor preflight not found: "
                    f"{doc_action_patch_executor_preflight_id}"
                )
            record = build_doc_action_patch_apply_boundary_packet(
                executor_preflight=preflight,
                source_root=source_root,
                label=label,
            )
            packet_id = record["doc_action_patch_apply_boundary_packet_id"]
            state.setdefault("doc_action_patch_apply_boundary_packets", {})[packet_id] = record
            state.setdefault("indexes", {}).setdefault("doc_action_patch_apply_boundary_packet_ids", {})[
                packet_id
            ] = packet_id
            return deepcopy(record)


def build_doc_action_patch_apply_boundary_packet(
    *,
    executor_preflight: dict[str, Any],
    source_root: str | Path | None = None,
    label: str = "manual-doc-action-patch-apply-boundary",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root_value = source_root or executor_preflight.get("source_root") or repo_root()
    root = Path(root_value).expanduser().resolve(strict=False)
    apply_boundary_intent = _apply_boundary_intent(root=root, executor_preflight=executor_preflight)
    rollback_plan = _rollback_plan(apply_boundary_intent)
    operator_apply_acceptance = _operator_apply_acceptance(now=now)
    required_gates = _required_gates(
        executor_preflight=executor_preflight,
        apply_boundary_intent=apply_boundary_intent,
        rollback_plan=rollback_plan,
        operator_apply_acceptance=operator_apply_acceptance,
    )
    status = _status(required_gates)
    ready = status == "ready_for_operator_apply_acceptance"
    record = {
        "schema_version": SCHEMA_VERSION,
        "doc_action_patch_apply_boundary_packet_id": stable_id(
            "docpatchapplyboundary",
            label,
            executor_preflight.get("doc_action_patch_executor_preflight_id"),
            executor_preflight.get("doc_action_patch_executor_preflight_sha256"),
            apply_boundary_intent,
            now,
        ),
        "label": label,
        "source_root": str(root),
        "doc_action_patch_executor_preflight_id": executor_preflight.get(
            "doc_action_patch_executor_preflight_id"
        ),
        "doc_action_patch_executor_preflight_sha256": executor_preflight.get(
            "doc_action_patch_executor_preflight_sha256"
        ),
        "doc_action_patch_live_execution_approval_packet_id": executor_preflight.get(
            "doc_action_patch_live_execution_approval_packet_id"
        ),
        "doc_action_patch_live_execution_approval_packet_sha256": executor_preflight.get(
            "doc_action_patch_live_execution_approval_packet_sha256"
        ),
        "doc_action_patch_dry_run_readback_receipt_id": executor_preflight.get(
            "doc_action_patch_dry_run_readback_receipt_id"
        ),
        "doc_action_patch_dry_run_readback_receipt_sha256": executor_preflight.get(
            "doc_action_patch_dry_run_readback_receipt_sha256"
        ),
        "doc_action_patch_dry_run_plan_id": executor_preflight.get("doc_action_patch_dry_run_plan_id"),
        "doc_action_patch_dry_run_plan_sha256": executor_preflight.get(
            "doc_action_patch_dry_run_plan_sha256"
        ),
        "doc_action_patch_artifact_approval_packet_id": executor_preflight.get(
            "doc_action_patch_artifact_approval_packet_id"
        ),
        "doc_action_patch_artifact_approval_packet_sha256": executor_preflight.get(
            "doc_action_patch_artifact_approval_packet_sha256"
        ),
        "doc_action_patch_artifact_receipt_id": executor_preflight.get(
            "doc_action_patch_artifact_receipt_id"
        ),
        "doc_action_patch_artifact_receipt_sha256": executor_preflight.get(
            "doc_action_patch_artifact_receipt_sha256"
        ),
        "doc_action_patch_readback_receipt_id": executor_preflight.get("doc_action_patch_readback_receipt_id"),
        "doc_action_patch_readback_receipt_sha256": executor_preflight.get(
            "doc_action_patch_readback_receipt_sha256"
        ),
        "doc_action_patch_preview_id": executor_preflight.get("doc_action_patch_preview_id"),
        "doc_action_patch_preview_sha256": executor_preflight.get("doc_action_patch_preview_sha256"),
        "doc_action_operator_approval_packet_id": executor_preflight.get(
            "doc_action_operator_approval_packet_id"
        ),
        "doc_action_operator_approval_packet_sha256": executor_preflight.get(
            "doc_action_operator_approval_packet_sha256"
        ),
        "doc_action_execution_plan_id": executor_preflight.get("doc_action_execution_plan_id"),
        "doc_action_execution_plan_sha256": executor_preflight.get("doc_action_execution_plan_sha256"),
        "source_doc_retirement_plan_id": executor_preflight.get("source_doc_retirement_plan_id"),
        "source_doc_retirement_plan_sha256": executor_preflight.get(
            "source_doc_retirement_plan_sha256"
        ),
        "apply_boundary_policy": {
            "apply_boundary_only": True,
            "requires_executor_preflight": True,
            "requires_source_hash_recheck": True,
            "requires_artifact_hash_recheck": True,
            "requires_operator_apply_acceptance": True,
            "requires_rollback_plan": True,
            "requires_post_apply_readback": True,
            "apply_allowed": False,
            "live_execution_allowed": False,
            "source_file_write_allowed": False,
            "source_file_move_allowed": False,
            "source_file_delete_allowed": False,
            "archive_create_allowed": False,
            "generated_surface_rewrite_allowed": False,
            "raw_patch_stored_in_ams_state": False,
            "raw_source_markdown_stored_in_ams_state": False,
            "raw_operator_apply_acceptance_stored_in_ams_state": False,
            "raw_executor_output_stored_in_ams_state": False,
        },
        "apply_boundary_intent": apply_boundary_intent,
        "rollback_plan": rollback_plan,
        "operator_apply_acceptance": operator_apply_acceptance,
        "required_gates": required_gates,
        "approval_granted": executor_preflight.get("approval_granted") is True,
        "preflight_ready": executor_preflight.get("preflight_ready") is True,
        "apply_boundary_ready": ready,
        "apply_allowed": False,
        "live_execution_allowed": False,
        "source_file_write_allowed": False,
        "source_file_move_allowed": False,
        "source_file_delete_allowed": False,
        "archive_create_allowed": False,
        "generated_surface_rewrite_allowed": False,
        "patch_artifact_write_allowed": False,
        "provider_call_allowed": False,
        "network_call_allowed": False,
        "apply_boundary_actions": _apply_boundary_actions(apply_boundary_intent) if ready else [],
        "execution_actions": [],
        "source_write_actions": [],
        "live_boundaries": {
            "approval_granted": executor_preflight.get("approval_granted") is True,
            "preflight_recorded": executor_preflight.get("preflight_ready") is True,
            "apply_boundary_recorded": ready,
            "operator_apply_acceptance_captured": False,
            **NON_APPLY_BOUNDARIES,
        },
        "status": status,
        "reason_codes": _reason_codes(required_gates, status),
        "created_at": now,
    }
    record["doc_action_patch_apply_boundary_packet_sha256"] = _hash_without(
        record,
        "doc_action_patch_apply_boundary_packet_sha256",
    )
    return deepcopy(record)


def validate_doc_action_patch_apply_boundary_packet_record(
    record: dict[str, Any],
    *,
    executor_preflight: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record(
            "doc_action_patch_apply_boundary_packet.schema.json",
            record,
            location="doc_action_patch_apply_boundary_packet",
        )
    except SchemaValidationError:
        reason_codes.append("doc_action_patch_apply_boundary.schema_invalid")
    expected_hash = record.get("doc_action_patch_apply_boundary_packet_sha256")
    if expected_hash and expected_hash != _hash_without(record, "doc_action_patch_apply_boundary_packet_sha256"):
        reason_codes.append("doc_action_patch_apply_boundary.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("doc_action_patch_apply_boundary.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("doc_action_patch_apply_boundary.status_invalid")
    if executor_preflight is None:
        reason_codes.append("doc_action_patch_apply_boundary.executor_preflight_missing")
    else:
        _validate_executor_preflight_ref(record, executor_preflight, reason_codes)
    apply_boundary_intent = record.get("apply_boundary_intent") or {}
    _validate_apply_boundary_intent(record, executor_preflight, apply_boundary_intent, reason_codes)
    rollback_plan = record.get("rollback_plan") or {}
    _validate_rollback_plan(apply_boundary_intent, rollback_plan, reason_codes)
    operator_apply_acceptance = record.get("operator_apply_acceptance") or {}
    _validate_operator_apply_acceptance(operator_apply_acceptance, reason_codes)
    expected_gates = _required_gates(
        executor_preflight=executor_preflight or {},
        apply_boundary_intent=apply_boundary_intent,
        rollback_plan=rollback_plan,
        operator_apply_acceptance=operator_apply_acceptance,
    )
    if record.get("required_gates") != expected_gates:
        reason_codes.append("doc_action_patch_apply_boundary.required_gates_mismatch")
    expected_status = _status(expected_gates)
    if record.get("status") != expected_status:
        reason_codes.append("doc_action_patch_apply_boundary.status_mismatch")
    expected_reasons = _reason_codes(expected_gates, expected_status)
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("doc_action_patch_apply_boundary.reason_codes_mismatch")
    _validate_authority(record, executor_preflight or {}, expected_status, apply_boundary_intent, reason_codes)
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _apply_boundary_intent(*, root: Path, executor_preflight: dict[str, Any]) -> dict[str, Any]:
    preflight_intent = executor_preflight.get("apply_intent") or {}
    artifact_path = Path(str(preflight_intent.get("artifact_path") or "")).expanduser().resolve(strict=False)
    artifact_exists = artifact_path.is_file()
    current_source_ref = _source_ref(root, str(preflight_intent.get("source_path") or ""))
    preflight_current_source_ref = deepcopy(preflight_intent.get("current_source_ref") or {})
    approved_source_ref = deepcopy(preflight_intent.get("source_ref") or {})
    intent = {
        "action_id": preflight_intent.get("action_id"),
        "source_path": preflight_intent.get("source_path"),
        "planned_operation": preflight_intent.get("planned_operation"),
        "patch_kind": preflight_intent.get("patch_kind"),
        "target_surface": preflight_intent.get("target_surface"),
        "artifact_path": str(artifact_path),
        "artifact_exists": artifact_exists,
        "artifact_path_under_source_root": path_is_under(artifact_path, root),
        "artifact_sha256": preflight_intent.get("artifact_sha256"),
        "artifact_sha256_current": _file_sha256(artifact_path) if artifact_exists else None,
        "artifact_hash_verified": artifact_exists
        and _file_sha256(artifact_path) == preflight_intent.get("artifact_sha256"),
        "approved_source_ref": approved_source_ref,
        "preflight_current_source_ref": preflight_current_source_ref,
        "current_source_ref": current_source_ref,
        "source_hash_matches_preflight": _source_refs_match(preflight_current_source_ref, current_source_ref),
        "source_hash_matches_approved_source": _source_refs_match(approved_source_ref, current_source_ref),
        "preflight_apply_intent_sha256": preflight_intent.get("apply_intent_sha256"),
        "patch_hunk_count": preflight_intent.get("patch_hunk_count", 0),
        "patch_addition_count": preflight_intent.get("patch_addition_count", 0),
        "patch_deletion_count": preflight_intent.get("patch_deletion_count", 0),
        "apply_boundary_only": True,
        "operator_apply_acceptance_required": True,
        "operator_apply_acceptance_captured": False,
        "rollback_plan_required": True,
        "post_apply_readback_required": True,
        "apply_allowed": False,
        "source_write_performed": False,
        "source_file_rewritten": False,
        "source_file_deleted": False,
        "source_file_moved": False,
        "archive_created": False,
        "generated_surface_rewritten": False,
        "raw_patch_stored_in_ams_state": False,
        "raw_source_markdown_stored_in_ams_state": False,
    }
    intent["apply_boundary_intent_sha256"] = sha256_text(canonical_json(intent))
    return intent


def _rollback_plan(apply_boundary_intent: dict[str, Any]) -> dict[str, Any]:
    current_source_ref = deepcopy(apply_boundary_intent.get("current_source_ref") or {})
    artifact_ref = {
        "path": apply_boundary_intent.get("artifact_path"),
        "sha256": apply_boundary_intent.get("artifact_sha256"),
        "sha256_current": apply_boundary_intent.get("artifact_sha256_current"),
    }
    plan = {
        "rollback_plan_required": True,
        "requires_source_backup_before_apply": True,
        "requires_post_apply_readback": True,
        "requires_source_hash_preimage": True,
        "source_path": apply_boundary_intent.get("source_path"),
        "pre_apply_source_ref": current_source_ref,
        "artifact_ref": artifact_ref,
        "backup_path": "",
        "backup_written": False,
        "rollback_executed": False,
        "rollback_action_sha256": sha256_text(
            canonical_json(
                {
                    "source_path": apply_boundary_intent.get("source_path"),
                    "pre_apply_source_ref": current_source_ref,
                    "artifact_ref": artifact_ref,
                    "backup_written": False,
                    "rollback_executed": False,
                }
            )
        ),
    }
    plan["rollback_plan_sha256"] = sha256_text(canonical_json(plan))
    return plan


def _operator_apply_acceptance(*, now: str) -> dict[str, Any]:
    acceptance = {
        "operator_apply_acceptance_required": True,
        "operator_apply_acceptance_captured": False,
        "acceptance_ref": "",
        "acceptance_text_sha256": "",
        "raw_acceptance_stored": False,
        "created_at": now,
    }
    acceptance["operator_apply_acceptance_sha256"] = sha256_text(canonical_json(acceptance))
    return acceptance


def _apply_boundary_actions(apply_boundary_intent: dict[str, Any]) -> list[dict[str, Any]]:
    action = {
        "action_id": apply_boundary_intent.get("action_id"),
        "source_path": apply_boundary_intent.get("source_path"),
        "artifact_sha256": apply_boundary_intent.get("artifact_sha256"),
        "pre_apply_source_ref_sha256": (apply_boundary_intent.get("current_source_ref") or {}).get("sha256"),
        "apply_boundary_intent_sha256": apply_boundary_intent.get("apply_boundary_intent_sha256"),
        "operator_apply_acceptance_required": True,
        "rollback_plan_required": True,
        "post_apply_readback_required": True,
        "apply_boundary_only": True,
        "apply_allowed": False,
        "source_write_performed": False,
    }
    action["apply_boundary_action_sha256"] = sha256_text(canonical_json(action))
    return [action]


def _validate_executor_preflight_ref(
    record: dict[str, Any],
    executor_preflight: dict[str, Any],
    reason_codes: list[str],
) -> None:
    if record.get("doc_action_patch_executor_preflight_id") != executor_preflight.get(
        "doc_action_patch_executor_preflight_id"
    ):
        reason_codes.append("doc_action_patch_apply_boundary.executor_preflight_id_mismatch")
    if record.get("doc_action_patch_executor_preflight_sha256") != executor_preflight.get(
        "doc_action_patch_executor_preflight_sha256"
    ):
        reason_codes.append("doc_action_patch_apply_boundary.executor_preflight_hash_mismatch")
    if executor_preflight.get("doc_action_patch_executor_preflight_sha256") != _hash_without(
        executor_preflight,
        "doc_action_patch_executor_preflight_sha256",
    ):
        reason_codes.append("doc_action_patch_apply_boundary.executor_preflight_hash_not_current")
    if executor_preflight.get("status") != "preflight_ready":
        reason_codes.append("doc_action_patch_apply_boundary.executor_preflight_not_ready")
    for key in (
        "doc_action_patch_live_execution_approval_packet_id",
        "doc_action_patch_live_execution_approval_packet_sha256",
        "doc_action_patch_dry_run_readback_receipt_id",
        "doc_action_patch_dry_run_readback_receipt_sha256",
        "doc_action_patch_dry_run_plan_id",
        "doc_action_patch_dry_run_plan_sha256",
        "doc_action_patch_artifact_approval_packet_id",
        "doc_action_patch_artifact_approval_packet_sha256",
        "doc_action_patch_artifact_receipt_id",
        "doc_action_patch_artifact_receipt_sha256",
        "doc_action_patch_readback_receipt_id",
        "doc_action_patch_readback_receipt_sha256",
        "doc_action_patch_preview_id",
        "doc_action_patch_preview_sha256",
        "doc_action_operator_approval_packet_id",
        "doc_action_operator_approval_packet_sha256",
        "doc_action_execution_plan_id",
        "doc_action_execution_plan_sha256",
        "source_doc_retirement_plan_id",
        "source_doc_retirement_plan_sha256",
    ):
        if record.get(key) != executor_preflight.get(key):
            reason_codes.append(f"doc_action_patch_apply_boundary.{key}_mismatch")


def _validate_apply_boundary_intent(
    record: dict[str, Any],
    executor_preflight: dict[str, Any] | None,
    apply_boundary_intent: dict[str, Any],
    reason_codes: list[str],
) -> None:
    if executor_preflight is None:
        return
    expected = _apply_boundary_intent(
        root=Path(str(record.get("source_root") or repo_root())).expanduser().resolve(strict=False),
        executor_preflight=executor_preflight,
    )
    for key, expected_value in expected.items():
        if apply_boundary_intent.get(key) != expected_value:
            reason_codes.append(f"doc_action_patch_apply_boundary.apply_boundary_intent_{key}_mismatch")


def _validate_rollback_plan(
    apply_boundary_intent: dict[str, Any],
    rollback_plan: dict[str, Any],
    reason_codes: list[str],
) -> None:
    expected = _rollback_plan(apply_boundary_intent)
    if rollback_plan != expected:
        reason_codes.append("doc_action_patch_apply_boundary.rollback_plan_mismatch")
    for key in (
        "rollback_plan_required",
        "requires_source_backup_before_apply",
        "requires_post_apply_readback",
        "requires_source_hash_preimage",
    ):
        if rollback_plan.get(key) is not True:
            reason_codes.append(f"doc_action_patch_apply_boundary.rollback_{key}_not_true")
    for key in ("backup_written", "rollback_executed"):
        if rollback_plan.get(key) is not False:
            reason_codes.append(f"doc_action_patch_apply_boundary.rollback_{key}_not_false")


def _validate_operator_apply_acceptance(
    operator_apply_acceptance: dict[str, Any],
    reason_codes: list[str],
) -> None:
    if operator_apply_acceptance.get("operator_apply_acceptance_required") is not True:
        reason_codes.append("doc_action_patch_apply_boundary.operator_apply_acceptance_required_not_true")
    if operator_apply_acceptance.get("operator_apply_acceptance_captured") is not False:
        reason_codes.append("doc_action_patch_apply_boundary.operator_apply_acceptance_captured_not_false")
    if operator_apply_acceptance.get("raw_acceptance_stored") is not False:
        reason_codes.append("doc_action_patch_apply_boundary.raw_acceptance_stored_not_false")
    if operator_apply_acceptance.get("acceptance_ref") != "":
        reason_codes.append("doc_action_patch_apply_boundary.acceptance_ref_not_empty")
    if operator_apply_acceptance.get("acceptance_text_sha256") != "":
        reason_codes.append("doc_action_patch_apply_boundary.acceptance_hash_not_empty")
    expected = deepcopy(operator_apply_acceptance)
    expected_hash = expected.pop("operator_apply_acceptance_sha256", None)
    if expected_hash != sha256_text(canonical_json(expected)):
        reason_codes.append("doc_action_patch_apply_boundary.operator_apply_acceptance_hash_mismatch")


def _validate_authority(
    record: dict[str, Any],
    executor_preflight: dict[str, Any],
    expected_status: str,
    apply_boundary_intent: dict[str, Any],
    reason_codes: list[str],
) -> None:
    ready = expected_status == "ready_for_operator_apply_acceptance"
    policy = record.get("apply_boundary_policy") or {}
    for key in (
        "apply_boundary_only",
        "requires_executor_preflight",
        "requires_source_hash_recheck",
        "requires_artifact_hash_recheck",
        "requires_operator_apply_acceptance",
        "requires_rollback_plan",
        "requires_post_apply_readback",
    ):
        if policy.get(key) is not True:
            reason_codes.append(f"doc_action_patch_apply_boundary.policy_{key}_not_true")
    for key in (
        "apply_allowed",
        "live_execution_allowed",
        "source_file_write_allowed",
        "source_file_move_allowed",
        "source_file_delete_allowed",
        "archive_create_allowed",
        "generated_surface_rewrite_allowed",
        "raw_patch_stored_in_ams_state",
        "raw_source_markdown_stored_in_ams_state",
        "raw_operator_apply_acceptance_stored_in_ams_state",
        "raw_executor_output_stored_in_ams_state",
    ):
        if policy.get(key) is not False:
            reason_codes.append(f"doc_action_patch_apply_boundary.policy_{key}_not_false")
    if record.get("approval_granted") is not (executor_preflight.get("approval_granted") is True):
        reason_codes.append("doc_action_patch_apply_boundary.approval_granted_mismatch")
    if record.get("preflight_ready") is not (executor_preflight.get("preflight_ready") is True):
        reason_codes.append("doc_action_patch_apply_boundary.preflight_ready_mismatch")
    if record.get("apply_boundary_ready") is not ready:
        reason_codes.append("doc_action_patch_apply_boundary.apply_boundary_ready_mismatch")
    for key in (
        "apply_allowed",
        "live_execution_allowed",
        "source_file_write_allowed",
        "source_file_move_allowed",
        "source_file_delete_allowed",
        "archive_create_allowed",
        "generated_surface_rewrite_allowed",
        "patch_artifact_write_allowed",
        "provider_call_allowed",
        "network_call_allowed",
    ):
        if record.get(key) is not False:
            reason_codes.append(f"doc_action_patch_apply_boundary.{key}_not_false")
    boundaries = record.get("live_boundaries") or {}
    if boundaries.get("approval_granted") is not (executor_preflight.get("approval_granted") is True):
        reason_codes.append("doc_action_patch_apply_boundary.approval_granted_boundary_mismatch")
    if boundaries.get("preflight_recorded") is not (executor_preflight.get("preflight_ready") is True):
        reason_codes.append("doc_action_patch_apply_boundary.preflight_recorded_boundary_mismatch")
    if boundaries.get("apply_boundary_recorded") is not ready:
        reason_codes.append("doc_action_patch_apply_boundary.apply_boundary_recorded_boundary_mismatch")
    if boundaries.get("operator_apply_acceptance_captured") is not False:
        reason_codes.append("doc_action_patch_apply_boundary.operator_apply_acceptance_boundary_mismatch")
    for key, expected in NON_APPLY_BOUNDARIES.items():
        if boundaries.get(key) is not expected:
            reason_codes.append(f"doc_action_patch_apply_boundary.{key}_boundary_mismatch")
    expected_actions = _apply_boundary_actions(apply_boundary_intent) if ready else []
    if record.get("apply_boundary_actions") != expected_actions:
        reason_codes.append("doc_action_patch_apply_boundary.apply_boundary_actions_mismatch")
    if record.get("execution_actions") != []:
        reason_codes.append("doc_action_patch_apply_boundary.execution_actions_not_empty")
    if record.get("source_write_actions") != []:
        reason_codes.append("doc_action_patch_apply_boundary.source_write_actions_not_empty")


def _required_gates(
    *,
    executor_preflight: dict[str, Any],
    apply_boundary_intent: dict[str, Any],
    rollback_plan: dict[str, Any],
    operator_apply_acceptance: dict[str, Any],
) -> dict[str, bool]:
    return {
        "executor_preflight_present": bool(executor_preflight.get("doc_action_patch_executor_preflight_id")),
        "executor_preflight_ready": executor_preflight.get("status") == "preflight_ready",
        "executor_preflight_hash_current": bool(executor_preflight)
        and executor_preflight.get("doc_action_patch_executor_preflight_sha256")
        == _hash_without(executor_preflight, "doc_action_patch_executor_preflight_sha256"),
        "preflight_grants_no_apply_authority": _preflight_grants_no_apply_authority(executor_preflight),
        "artifact_exists": apply_boundary_intent.get("artifact_exists") is True,
        "artifact_hash_verified": apply_boundary_intent.get("artifact_hash_verified") is True,
        "source_exists": (apply_boundary_intent.get("current_source_ref") or {}).get("exists") is True,
        "source_under_root": (apply_boundary_intent.get("current_source_ref") or {}).get("under_source_root") is True,
        "source_hash_matches_preflight": apply_boundary_intent.get("source_hash_matches_preflight") is True,
        "source_hash_matches_approved_source": apply_boundary_intent.get("source_hash_matches_approved_source")
        is True,
        "operator_apply_acceptance_required": operator_apply_acceptance.get(
            "operator_apply_acceptance_required"
        )
        is True,
        "operator_apply_acceptance_not_captured": operator_apply_acceptance.get(
            "operator_apply_acceptance_captured"
        )
        is False,
        "rollback_plan_required": rollback_plan.get("rollback_plan_required") is True,
        "rollback_backup_not_written": rollback_plan.get("backup_written") is False,
        "post_apply_readback_required": apply_boundary_intent.get("post_apply_readback_required") is True,
        "apply_boundary_only": apply_boundary_intent.get("apply_boundary_only") is True,
        "apply_not_allowed": apply_boundary_intent.get("apply_allowed") is False,
    }


def _preflight_grants_no_apply_authority(executor_preflight: dict[str, Any]) -> bool:
    return (
        executor_preflight.get("preflight_ready") is True
        and executor_preflight.get("apply_allowed") is False
        and executor_preflight.get("live_execution_allowed") is False
        and executor_preflight.get("source_file_write_allowed") is False
        and executor_preflight.get("source_file_move_allowed") is False
        and executor_preflight.get("source_file_delete_allowed") is False
        and executor_preflight.get("archive_create_allowed") is False
        and executor_preflight.get("generated_surface_rewrite_allowed") is False
        and executor_preflight.get("patch_artifact_write_allowed") is False
        and executor_preflight.get("execution_actions") == []
        and executor_preflight.get("source_write_actions") == []
    )


def _status(required_gates: dict[str, bool]) -> str:
    return "ready_for_operator_apply_acceptance" if required_gates and all(required_gates.values()) else "blocked"


def _reason_codes(required_gates: dict[str, bool], status: str) -> list[str]:
    if status == "ready_for_operator_apply_acceptance":
        return ["doc_action_patch_apply_boundary.ready_for_operator_apply_acceptance"]
    missing = [key for key, value in sorted(required_gates.items()) if value is not True]
    return [f"doc_action_patch_apply_boundary.gate_failed:{key}" for key in missing] or [
        "doc_action_patch_apply_boundary.blocked"
    ]


def _source_ref(root: Path, source_path: str) -> dict[str, Any]:
    source = (root / source_path).resolve(strict=False)
    exists = source.is_file()
    return {
        "path": source_path,
        "absolute_path": str(source),
        "exists": exists,
        "under_source_root": path_is_under(source, root),
        "sha256": _file_sha256(source) if exists else None,
        "size_bytes": source.stat().st_size if exists else 0,
    }


def _source_refs_match(expected: dict[str, Any], current: dict[str, Any]) -> bool:
    return (
        bool(expected)
        and expected.get("path") == current.get("path")
        and expected.get("exists") is True
        and current.get("exists") is True
        and expected.get("sha256") == current.get("sha256")
        and expected.get("size_bytes") == current.get("size_bytes")
    )


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()
