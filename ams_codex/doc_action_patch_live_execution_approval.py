from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any

from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore
from .workspace import path_is_under, repo_root


SCHEMA_VERSION = "ams.ams_codex.doc_action_patch_live_execution_approval_packet.v0"
STATUSES = {"approved_for_executor_review", "blocked"}

REQUIRED_APPROVAL_PHRASES = [
    "i approve live doc action execution for this dry run",
    "dry run readback hash matches this approval packet",
    "artifact hash must be rechecked by the executor",
    "source hash must be rechecked by the executor",
    "only the listed source file action is in scope",
    "this approval packet is not an executor",
    "generated surface rewrites remain disabled",
    "source deletes moves and archives remain disabled",
]

NON_EXECUTION_BOUNDARIES = {
    "source_file_rewritten": False,
    "source_file_deleted": False,
    "source_file_moved": False,
    "archive_created": False,
    "generated_surface_rewritten": False,
    "patch_artifact_written": False,
    "raw_patch_stored_in_ams_state": False,
    "raw_source_markdown_stored_in_ams_state": False,
    "raw_readback_stored_in_ams_state": False,
    "raw_approval_stored_in_ams_state": False,
    "discord_call_performed": False,
    "terminal_attach_performed": False,
    "terminal_capture_performed": False,
    "terminal_injection_performed": False,
    "persistent_process_started": False,
    "provider_call_performed": False,
    "network_call_performed": False,
    "secret_stored": False,
}


class DocActionPatchLiveExecutionApprovalPacketStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        doc_action_patch_dry_run_readback_receipt_id: str,
        approval_ref: str,
        approval_text: str,
        requested_by: str = "operator",
        source_root: str | Path | None = None,
        label: str = "manual-doc-action-patch-live-execution-approval",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            receipt = (state.get("doc_action_patch_dry_run_readback_receipts") or {}).get(
                doc_action_patch_dry_run_readback_receipt_id
            )
            if not receipt:
                raise KeyError(
                    "doc action patch dry-run readback receipt not found: "
                    f"{doc_action_patch_dry_run_readback_receipt_id}"
                )
            dry_run_plan_id = receipt.get("doc_action_patch_dry_run_plan_id")
            dry_run_plan = (state.get("doc_action_patch_dry_run_plans") or {}).get(dry_run_plan_id)
            if not dry_run_plan:
                raise KeyError(f"doc action patch dry-run plan not found: {dry_run_plan_id}")
            record = build_doc_action_patch_live_execution_approval_packet(
                dry_run_readback_receipt=receipt,
                dry_run_plan=dry_run_plan,
                approval_ref=approval_ref,
                approval_text=approval_text,
                requested_by=requested_by,
                source_root=source_root,
                label=label,
            )
            packet_id = record["doc_action_patch_live_execution_approval_packet_id"]
            state.setdefault("doc_action_patch_live_execution_approval_packets", {})[packet_id] = record
            state.setdefault("indexes", {}).setdefault("doc_action_patch_live_execution_approval_packet_ids", {})[
                packet_id
            ] = packet_id
            return deepcopy(record)


def build_doc_action_patch_live_execution_approval_packet(
    *,
    dry_run_readback_receipt: dict[str, Any],
    dry_run_plan: dict[str, Any],
    approval_ref: str,
    approval_text: str,
    requested_by: str = "operator",
    source_root: str | Path | None = None,
    label: str = "manual-doc-action-patch-live-execution-approval",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root_value = source_root or dry_run_readback_receipt.get("source_root") or dry_run_plan.get("source_root") or repo_root()
    root = Path(root_value).expanduser().resolve(strict=False)
    approval = _approval(
        approval_ref=approval_ref,
        approval_text=approval_text,
        requested_by=requested_by,
        now=now,
    )
    selected_action = _selected_action(root=root, dry_run_plan=dry_run_plan)
    required_gates = _required_gates(
        dry_run_readback_receipt=dry_run_readback_receipt,
        dry_run_plan=dry_run_plan,
        selected_action=selected_action,
        approval=approval,
    )
    status = _status(required_gates)
    approval_captured = status == "approved_for_executor_review"
    approval_actions = _approval_actions(selected_action) if approval_captured else []
    reason_codes = _reason_codes(required_gates, status)
    record = {
        "schema_version": SCHEMA_VERSION,
        "doc_action_patch_live_execution_approval_packet_id": stable_id(
            "docpatchliveapproval",
            label,
            dry_run_readback_receipt.get("doc_action_patch_dry_run_readback_receipt_id"),
            dry_run_readback_receipt.get("doc_action_patch_dry_run_readback_receipt_sha256"),
            approval.get("approval_text_sha256"),
            now,
        ),
        "label": label,
        "source_root": str(root),
        "doc_action_patch_dry_run_readback_receipt_id": dry_run_readback_receipt.get(
            "doc_action_patch_dry_run_readback_receipt_id"
        ),
        "doc_action_patch_dry_run_readback_receipt_sha256": dry_run_readback_receipt.get(
            "doc_action_patch_dry_run_readback_receipt_sha256"
        ),
        "doc_action_patch_dry_run_plan_id": dry_run_readback_receipt.get("doc_action_patch_dry_run_plan_id"),
        "doc_action_patch_dry_run_plan_sha256": dry_run_readback_receipt.get(
            "doc_action_patch_dry_run_plan_sha256"
        ),
        "doc_action_patch_artifact_approval_packet_id": dry_run_readback_receipt.get(
            "doc_action_patch_artifact_approval_packet_id"
        ),
        "doc_action_patch_artifact_approval_packet_sha256": dry_run_readback_receipt.get(
            "doc_action_patch_artifact_approval_packet_sha256"
        ),
        "doc_action_patch_artifact_receipt_id": dry_run_readback_receipt.get(
            "doc_action_patch_artifact_receipt_id"
        ),
        "doc_action_patch_artifact_receipt_sha256": dry_run_readback_receipt.get(
            "doc_action_patch_artifact_receipt_sha256"
        ),
        "doc_action_patch_readback_receipt_id": dry_run_readback_receipt.get(
            "doc_action_patch_readback_receipt_id"
        ),
        "doc_action_patch_readback_receipt_sha256": dry_run_readback_receipt.get(
            "doc_action_patch_readback_receipt_sha256"
        ),
        "doc_action_patch_preview_id": dry_run_readback_receipt.get("doc_action_patch_preview_id"),
        "doc_action_patch_preview_sha256": dry_run_readback_receipt.get("doc_action_patch_preview_sha256"),
        "doc_action_operator_approval_packet_id": dry_run_readback_receipt.get(
            "doc_action_operator_approval_packet_id"
        ),
        "doc_action_operator_approval_packet_sha256": dry_run_readback_receipt.get(
            "doc_action_operator_approval_packet_sha256"
        ),
        "doc_action_execution_plan_id": dry_run_readback_receipt.get("doc_action_execution_plan_id"),
        "doc_action_execution_plan_sha256": dry_run_readback_receipt.get("doc_action_execution_plan_sha256"),
        "source_doc_retirement_plan_id": dry_run_readback_receipt.get("source_doc_retirement_plan_id"),
        "source_doc_retirement_plan_sha256": dry_run_readback_receipt.get(
            "source_doc_retirement_plan_sha256"
        ),
        "dry_run_summary": deepcopy(dry_run_readback_receipt.get("dry_run_summary") or {}),
        "selected_execution_action": selected_action,
        "approval": approval,
        "required_approval_phrases": list(REQUIRED_APPROVAL_PHRASES),
        "required_gates": required_gates,
        "approval_policy": {
            "approval_packet_only": True,
            "requires_dry_run_readback_receipt": True,
            "requires_executor_source_hash_recheck": True,
            "requires_executor_artifact_hash_recheck": True,
            "executor_required_for_source_writes": True,
            "approval_granted": approval_captured,
            "live_execution_allowed_by_packet": False,
            "source_file_write_allowed_by_packet": False,
            "source_file_move_allowed_by_packet": False,
            "source_file_delete_allowed_by_packet": False,
            "archive_create_allowed_by_packet": False,
            "generated_surface_rewrite_allowed_by_packet": False,
            "raw_patch_stored_in_ams_state": False,
            "raw_source_markdown_stored_in_ams_state": False,
            "raw_approval_stored_in_ams_state": False,
        },
        "approval_granted": approval_captured,
        "live_execution_approval_captured": approval_captured,
        "live_execution_allowed": False,
        "source_file_write_allowed": False,
        "source_file_move_allowed": False,
        "source_file_delete_allowed": False,
        "archive_create_allowed": False,
        "generated_surface_rewrite_allowed": False,
        "patch_artifact_write_allowed": False,
        "provider_call_allowed": False,
        "network_call_allowed": False,
        "approval_actions": approval_actions,
        "execution_actions": [],
        "source_write_actions": [],
        "live_boundaries": {
            "approval_granted": approval_captured,
            "live_execution_approval_captured": approval_captured,
            **NON_EXECUTION_BOUNDARIES,
        },
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["doc_action_patch_live_execution_approval_packet_sha256"] = _hash_without(
        record,
        "doc_action_patch_live_execution_approval_packet_sha256",
    )
    return deepcopy(record)


def validate_doc_action_patch_live_execution_approval_packet_record(
    record: dict[str, Any],
    *,
    dry_run_readback_receipt: dict[str, Any] | None = None,
    dry_run_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record(
            "doc_action_patch_live_execution_approval_packet.schema.json",
            record,
            location="doc_action_patch_live_execution_approval_packet",
        )
    except SchemaValidationError:
        reason_codes.append("doc_action_patch_live_execution_approval.schema_invalid")
    expected_hash = record.get("doc_action_patch_live_execution_approval_packet_sha256")
    if expected_hash and expected_hash != _hash_without(
        record,
        "doc_action_patch_live_execution_approval_packet_sha256",
    ):
        reason_codes.append("doc_action_patch_live_execution_approval.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("doc_action_patch_live_execution_approval.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("doc_action_patch_live_execution_approval.status_invalid")
    if dry_run_readback_receipt is None:
        reason_codes.append("doc_action_patch_live_execution_approval.dry_run_readback_missing")
    else:
        _validate_dry_run_readback_ref(record, dry_run_readback_receipt, reason_codes)
    if dry_run_plan is None:
        reason_codes.append("doc_action_patch_live_execution_approval.dry_run_plan_missing")
    else:
        _validate_dry_run_plan_ref(record, dry_run_plan, reason_codes)
    selected_action = record.get("selected_execution_action") or {}
    _validate_selected_action(record, selected_action, reason_codes)
    _validate_approval(record, reason_codes)
    expected_gates = _required_gates(
        dry_run_readback_receipt=dry_run_readback_receipt or {},
        dry_run_plan=dry_run_plan or {},
        selected_action=selected_action,
        approval=record.get("approval") or {},
    )
    if record.get("required_gates") != expected_gates:
        reason_codes.append("doc_action_patch_live_execution_approval.required_gates_mismatch")
    expected_status = _status(expected_gates)
    if record.get("status") != expected_status:
        reason_codes.append("doc_action_patch_live_execution_approval.status_mismatch")
    expected_reasons = _reason_codes(expected_gates, expected_status)
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("doc_action_patch_live_execution_approval.reason_codes_mismatch")
    _validate_authority(record, expected_status, selected_action, reason_codes)
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _approval(*, approval_ref: str, approval_text: str, requested_by: str, now: str) -> dict[str, Any]:
    normalized = _normalize(approval_text)
    phrase_results = [
        {
            "phrase": phrase,
            "present": phrase in normalized,
            "evidence_sha256": sha256_text(phrase if phrase in normalized else ""),
        }
        for phrase in REQUIRED_APPROVAL_PHRASES
    ]
    missing = [row["phrase"] for row in phrase_results if not row["present"]]
    return {
        "requested_by": requested_by,
        "approval_ref": approval_ref,
        "approval_present": bool(approval_ref and approval_text),
        "approval_text_sha256": sha256_text(normalized),
        "normalized_approval_sha256": sha256_text(normalized),
        "raw_approval_stored": False,
        "phrase_results": phrase_results,
        "required_phrases_present": not missing,
        "missing_required_phrases": missing,
        "created_at": now,
    }


def _selected_action(*, root: Path, dry_run_plan: dict[str, Any]) -> dict[str, Any]:
    actions = [action for action in dry_run_plan.get("dry_run_actions") or [] if isinstance(action, dict)]
    action = actions[0] if actions else {}
    artifact_path = Path(str(action.get("artifact_path") or "")).expanduser().resolve(strict=False)
    artifact_exists = artifact_path.is_file()
    current_source_ref = _source_ref(root, str(action.get("source_path") or ""))
    source_ref = deepcopy(action.get("source_ref") or {})
    return {
        "action_id": action.get("action_id"),
        "source_path": action.get("source_path"),
        "target_surface": action.get("target_surface"),
        "planned_operation": action.get("planned_operation"),
        "patch_kind": action.get("patch_kind"),
        "artifact_path": str(artifact_path),
        "artifact_path_under_source_root": path_is_under(artifact_path, root),
        "artifact_sha256": action.get("artifact_sha256"),
        "artifact_exists": artifact_exists,
        "artifact_hash_verified": artifact_exists and _file_sha256(artifact_path) == action.get("artifact_sha256"),
        "source_ref": source_ref,
        "current_source_ref": current_source_ref,
        "source_hash_matches_dry_run": _source_refs_match(source_ref, current_source_ref),
        "source_file_exists": current_source_ref.get("exists") is True,
        "source_file_under_source_root": current_source_ref.get("under_source_root") is True,
        "patch_hunk_count": action.get("patch_hunk_count", 0),
        "patch_addition_count": action.get("patch_addition_count", 0),
        "patch_deletion_count": action.get("patch_deletion_count", 0),
        "dry_run_only_input": action.get("dry_run_only") is True,
        "approval_only": True,
        "executor_source_hash_recheck_required": True,
        "executor_artifact_hash_recheck_required": True,
        "source_file_rewritten": False,
        "source_file_deleted": False,
        "source_file_moved": False,
        "archive_created": False,
        "generated_surface_rewritten": False,
    }


def _approval_actions(selected_action: dict[str, Any]) -> list[dict[str, Any]]:
    action = {
        "action_id": selected_action.get("action_id"),
        "source_path": selected_action.get("source_path"),
        "planned_operation": selected_action.get("planned_operation"),
        "artifact_sha256": selected_action.get("artifact_sha256"),
        "source_ref_sha256": (selected_action.get("source_ref") or {}).get("sha256"),
        "executor_source_hash_recheck_required": True,
        "executor_artifact_hash_recheck_required": True,
        "approval_only": True,
        "source_write_performed": False,
    }
    action["approval_action_sha256"] = sha256_text(canonical_json(action))
    return [action]


def _validate_dry_run_readback_ref(
    record: dict[str, Any],
    receipt: dict[str, Any],
    reason_codes: list[str],
) -> None:
    if record.get("doc_action_patch_dry_run_readback_receipt_id") != receipt.get(
        "doc_action_patch_dry_run_readback_receipt_id"
    ):
        reason_codes.append("doc_action_patch_live_execution_approval.dry_run_readback_id_mismatch")
    if record.get("doc_action_patch_dry_run_readback_receipt_sha256") != receipt.get(
        "doc_action_patch_dry_run_readback_receipt_sha256"
    ):
        reason_codes.append("doc_action_patch_live_execution_approval.dry_run_readback_hash_mismatch")
    if receipt.get("doc_action_patch_dry_run_readback_receipt_sha256") != _hash_without(
        receipt,
        "doc_action_patch_dry_run_readback_receipt_sha256",
    ):
        reason_codes.append("doc_action_patch_live_execution_approval.dry_run_readback_hash_not_current")
    if receipt.get("status") != "readback_verified":
        reason_codes.append("doc_action_patch_live_execution_approval.dry_run_readback_not_verified")
    for key in (
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
        if record.get(key) != receipt.get(key):
            reason_codes.append(f"doc_action_patch_live_execution_approval.{key}_mismatch")
    if record.get("dry_run_summary") != (receipt.get("dry_run_summary") or {}):
        reason_codes.append("doc_action_patch_live_execution_approval.dry_run_summary_mismatch")


def _validate_dry_run_plan_ref(record: dict[str, Any], dry_run_plan: dict[str, Any], reason_codes: list[str]) -> None:
    if record.get("doc_action_patch_dry_run_plan_id") != dry_run_plan.get("doc_action_patch_dry_run_plan_id"):
        reason_codes.append("doc_action_patch_live_execution_approval.dry_run_plan_id_mismatch")
    if record.get("doc_action_patch_dry_run_plan_sha256") != dry_run_plan.get("doc_action_patch_dry_run_plan_sha256"):
        reason_codes.append("doc_action_patch_live_execution_approval.dry_run_plan_hash_mismatch")
    if dry_run_plan.get("doc_action_patch_dry_run_plan_sha256") != _hash_without(
        dry_run_plan,
        "doc_action_patch_dry_run_plan_sha256",
    ):
        reason_codes.append("doc_action_patch_live_execution_approval.dry_run_plan_hash_not_current")
    if dry_run_plan.get("status") != "dry_run_ready":
        reason_codes.append("doc_action_patch_live_execution_approval.dry_run_plan_not_ready")
    dry_run_source_root = str(dry_run_plan.get("source_root") or "")
    if dry_run_source_root and record.get("source_root") != str(Path(dry_run_source_root).resolve(strict=False)):
        reason_codes.append("doc_action_patch_live_execution_approval.source_root_mismatch")


def _validate_selected_action(record: dict[str, Any], selected_action: dict[str, Any], reason_codes: list[str]) -> None:
    expected = _selected_action(
        root=Path(str(record.get("source_root") or repo_root())).expanduser().resolve(strict=False),
        dry_run_plan={
            "dry_run_actions": [
                {
                    "action_id": selected_action.get("action_id"),
                    "source_path": selected_action.get("source_path"),
                    "target_surface": selected_action.get("target_surface"),
                    "planned_operation": selected_action.get("planned_operation"),
                    "patch_kind": selected_action.get("patch_kind"),
                    "artifact_path": selected_action.get("artifact_path"),
                    "artifact_sha256": selected_action.get("artifact_sha256"),
                    "source_ref": selected_action.get("source_ref") or {},
                    "patch_hunk_count": selected_action.get("patch_hunk_count", 0),
                    "patch_addition_count": selected_action.get("patch_addition_count", 0),
                    "patch_deletion_count": selected_action.get("patch_deletion_count", 0),
                    "dry_run_only": selected_action.get("dry_run_only_input") is True,
                }
            ]
        },
    )
    for key in (
        "artifact_hash_verified",
        "source_hash_matches_dry_run",
        "source_file_exists",
        "source_file_under_source_root",
        "dry_run_only_input",
        "approval_only",
        "executor_source_hash_recheck_required",
        "executor_artifact_hash_recheck_required",
        "source_file_rewritten",
        "source_file_deleted",
        "source_file_moved",
        "archive_created",
        "generated_surface_rewritten",
    ):
        if selected_action.get(key) != expected.get(key):
            reason_codes.append(f"doc_action_patch_live_execution_approval.selected_action_{key}_mismatch")
    if selected_action.get("current_source_ref") != expected.get("current_source_ref"):
        reason_codes.append("doc_action_patch_live_execution_approval.current_source_ref_mismatch")


def _validate_approval(record: dict[str, Any], reason_codes: list[str]) -> None:
    approval = record.get("approval") or {}
    if approval.get("raw_approval_stored") is not False:
        reason_codes.append("doc_action_patch_live_execution_approval.raw_approval_stored_not_false")
    if approval.get("approval_text_sha256") != approval.get("normalized_approval_sha256"):
        reason_codes.append("doc_action_patch_live_execution_approval.approval_hash_mismatch")
    if record.get("required_approval_phrases") != REQUIRED_APPROVAL_PHRASES:
        reason_codes.append("doc_action_patch_live_execution_approval.required_approval_phrases_mismatch")
    phrase_results = approval.get("phrase_results") or []
    if len(phrase_results) != len(REQUIRED_APPROVAL_PHRASES):
        reason_codes.append("doc_action_patch_live_execution_approval.phrase_results_count_mismatch")
    present_by_phrase: dict[str, bool] = {}
    for phrase in REQUIRED_APPROVAL_PHRASES:
        matches = [row for row in phrase_results if isinstance(row, dict) and row.get("phrase") == phrase]
        if len(matches) != 1:
            reason_codes.append(f"doc_action_patch_live_execution_approval.phrase_result_missing:{phrase}")
            continue
        row = matches[0]
        present = row.get("present")
        if not isinstance(present, bool):
            reason_codes.append(f"doc_action_patch_live_execution_approval.phrase_present_invalid:{phrase}")
            continue
        present_by_phrase[phrase] = present
        expected_evidence = sha256_text(phrase if present else "")
        if row.get("evidence_sha256") != expected_evidence:
            reason_codes.append(f"doc_action_patch_live_execution_approval.phrase_evidence_mismatch:{phrase}")
    missing = [phrase for phrase in REQUIRED_APPROVAL_PHRASES if present_by_phrase.get(phrase) is not True]
    if missing != approval.get("missing_required_phrases"):
        reason_codes.append("doc_action_patch_live_execution_approval.missing_required_phrases_mismatch")
    if approval.get("required_phrases_present") is not (not missing):
        reason_codes.append("doc_action_patch_live_execution_approval.required_phrases_present_mismatch")


def _validate_authority(
    record: dict[str, Any],
    expected_status: str,
    selected_action: dict[str, Any],
    reason_codes: list[str],
) -> None:
    approval_captured = expected_status == "approved_for_executor_review"
    policy = record.get("approval_policy") or {}
    for key in (
        "approval_packet_only",
        "requires_dry_run_readback_receipt",
        "requires_executor_source_hash_recheck",
        "requires_executor_artifact_hash_recheck",
        "executor_required_for_source_writes",
    ):
        if policy.get(key) is not True:
            reason_codes.append(f"doc_action_patch_live_execution_approval.policy_{key}_not_true")
    for key in (
        "live_execution_allowed_by_packet",
        "source_file_write_allowed_by_packet",
        "source_file_move_allowed_by_packet",
        "source_file_delete_allowed_by_packet",
        "archive_create_allowed_by_packet",
        "generated_surface_rewrite_allowed_by_packet",
        "raw_patch_stored_in_ams_state",
        "raw_source_markdown_stored_in_ams_state",
        "raw_approval_stored_in_ams_state",
    ):
        if policy.get(key) is not False:
            reason_codes.append(f"doc_action_patch_live_execution_approval.policy_{key}_not_false")
    if policy.get("approval_granted") is not approval_captured:
        reason_codes.append("doc_action_patch_live_execution_approval.policy_approval_granted_mismatch")
    for key in (
        "approval_granted",
        "live_execution_approval_captured",
    ):
        if record.get(key) is not approval_captured:
            reason_codes.append(f"doc_action_patch_live_execution_approval.{key}_mismatch")
    for key in (
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
            reason_codes.append(f"doc_action_patch_live_execution_approval.{key}_not_false")
    for key, expected in NON_EXECUTION_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"doc_action_patch_live_execution_approval.{key}_boundary_mismatch")
    for key in ("approval_granted", "live_execution_approval_captured"):
        if (record.get("live_boundaries") or {}).get(key) is not approval_captured:
            reason_codes.append(f"doc_action_patch_live_execution_approval.{key}_boundary_mismatch")
    expected_approval_actions = _approval_actions(selected_action) if approval_captured else []
    if record.get("approval_actions") != expected_approval_actions:
        reason_codes.append("doc_action_patch_live_execution_approval.approval_actions_mismatch")
    if record.get("execution_actions") != []:
        reason_codes.append("doc_action_patch_live_execution_approval.execution_actions_not_empty")
    if record.get("source_write_actions") != []:
        reason_codes.append("doc_action_patch_live_execution_approval.source_write_actions_not_empty")


def _required_gates(
    *,
    dry_run_readback_receipt: dict[str, Any],
    dry_run_plan: dict[str, Any],
    selected_action: dict[str, Any],
    approval: dict[str, Any],
) -> dict[str, bool]:
    return {
        "dry_run_readback_present": bool(
            dry_run_readback_receipt.get("doc_action_patch_dry_run_readback_receipt_id")
        ),
        "dry_run_readback_verified": dry_run_readback_receipt.get("status") == "readback_verified",
        "dry_run_readback_hash_current": bool(dry_run_readback_receipt)
        and dry_run_readback_receipt.get("doc_action_patch_dry_run_readback_receipt_sha256")
        == _hash_without(dry_run_readback_receipt, "doc_action_patch_dry_run_readback_receipt_sha256"),
        "dry_run_plan_present": bool(dry_run_plan.get("doc_action_patch_dry_run_plan_id")),
        "dry_run_plan_ready": dry_run_plan.get("status") == "dry_run_ready",
        "dry_run_plan_hash_current": bool(dry_run_plan)
        and dry_run_plan.get("doc_action_patch_dry_run_plan_sha256")
        == _hash_without(dry_run_plan, "doc_action_patch_dry_run_plan_sha256"),
        "dry_run_grants_no_authority": _dry_run_grants_no_authority(dry_run_plan),
        "artifact_hash_current": selected_action.get("artifact_hash_verified") is True,
        "source_hash_current": selected_action.get("source_hash_matches_dry_run") is True,
        "approval_ref_present": bool(approval.get("approval_ref")),
        "approval_present": approval.get("approval_present") is True,
        "required_phrases_present": approval.get("required_phrases_present") is True,
        "raw_approval_not_stored": approval.get("raw_approval_stored") is False,
        "approval_packet_executes_nothing": True,
    }


def _dry_run_grants_no_authority(dry_run_plan: dict[str, Any]) -> bool:
    summary = dry_run_plan.get("dry_run_summary") or {}
    return (
        dry_run_plan.get("approval_granted") is False
        and dry_run_plan.get("live_execution_allowed") is False
        and dry_run_plan.get("source_file_write_allowed") is False
        and dry_run_plan.get("source_file_move_allowed") is False
        and dry_run_plan.get("source_file_delete_allowed") is False
        and dry_run_plan.get("archive_create_allowed") is False
        and dry_run_plan.get("generated_surface_rewrite_allowed") is False
        and dry_run_plan.get("patch_artifact_write_allowed") is False
        and summary.get("dry_run_only") is True
        and summary.get("raw_patch_stored_in_ams_state") is False
        and summary.get("source_files_modified") is False
    )


def _status(required_gates: dict[str, bool]) -> str:
    return "approved_for_executor_review" if required_gates and all(required_gates.values()) else "blocked"


def _reason_codes(required_gates: dict[str, bool], status: str) -> list[str]:
    if status == "approved_for_executor_review":
        return ["doc_action_patch_live_execution_approval.approved_for_executor_review"]
    missing = [key for key, value in sorted(required_gates.items()) if value is not True]
    return [f"doc_action_patch_live_execution_approval.gate_failed:{key}" for key in missing] or [
        "doc_action_patch_live_execution_approval.blocked"
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


def _normalize(text: str) -> str:
    return " ".join(text.lower().replace(",", " ").replace(";", " ").replace(".", " ").split())
