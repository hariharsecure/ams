from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any

from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore
from .workspace import path_is_under, repo_root


SCHEMA_VERSION = "ams.ams_codex.doc_action_patch_apply_acceptance_packet.v0"
STATUSES = {"accepted_for_backup_preimage_review", "blocked"}

REQUIRED_ACCEPTANCE_PHRASES = [
    "i accept this doc action apply boundary",
    "apply boundary packet hash matches this acceptance packet",
    "preflight artifact and source hashes must be rechecked before write",
    "rollback preimage and backup evidence are required before write",
    "post apply readback is required before settlement",
    "only the listed source file action is in scope",
    "this acceptance packet is not an executor",
    "generated surface rewrites remain disabled",
    "source deletes moves and archives remain disabled",
]

NON_EXECUTION_BOUNDARIES = {
    "source_file_rewritten": False,
    "source_file_deleted": False,
    "source_file_moved": False,
    "source_backup_written": False,
    "rollback_executed": False,
    "archive_created": False,
    "generated_surface_rewritten": False,
    "patch_artifact_written": False,
    "raw_patch_stored_in_ams_state": False,
    "raw_source_markdown_stored_in_ams_state": False,
    "raw_operator_acceptance_stored_in_ams_state": False,
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


class DocActionPatchApplyAcceptancePacketStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        doc_action_patch_apply_boundary_packet_id: str,
        acceptance_ref: str,
        acceptance_text: str,
        requested_by: str = "operator",
        source_root: str | Path | None = None,
        label: str = "manual-doc-action-patch-apply-acceptance",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            boundary_packet = (state.get("doc_action_patch_apply_boundary_packets") or {}).get(
                doc_action_patch_apply_boundary_packet_id
            )
            if not boundary_packet:
                raise KeyError(
                    "doc action patch apply boundary packet not found: "
                    f"{doc_action_patch_apply_boundary_packet_id}"
                )
            record = build_doc_action_patch_apply_acceptance_packet(
                apply_boundary_packet=boundary_packet,
                acceptance_ref=acceptance_ref,
                acceptance_text=acceptance_text,
                requested_by=requested_by,
                source_root=source_root,
                label=label,
            )
            packet_id = record["doc_action_patch_apply_acceptance_packet_id"]
            state.setdefault("doc_action_patch_apply_acceptance_packets", {})[packet_id] = record
            state.setdefault("indexes", {}).setdefault("doc_action_patch_apply_acceptance_packet_ids", {})[
                packet_id
            ] = packet_id
            return deepcopy(record)


def build_doc_action_patch_apply_acceptance_packet(
    *,
    apply_boundary_packet: dict[str, Any],
    acceptance_ref: str,
    acceptance_text: str,
    requested_by: str = "operator",
    source_root: str | Path | None = None,
    label: str = "manual-doc-action-patch-apply-acceptance",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root_value = source_root or apply_boundary_packet.get("source_root") or repo_root()
    root = Path(root_value).expanduser().resolve(strict=False)
    acceptance = _acceptance(
        acceptance_ref=acceptance_ref,
        acceptance_text=acceptance_text,
        requested_by=requested_by,
        now=now,
    )
    accepted_action = _accepted_action(root=root, apply_boundary_packet=apply_boundary_packet)
    required_gates = _required_gates(
        apply_boundary_packet=apply_boundary_packet,
        accepted_action=accepted_action,
        acceptance=acceptance,
    )
    status = _status(required_gates)
    accepted = status == "accepted_for_backup_preimage_review"
    record = {
        "schema_version": SCHEMA_VERSION,
        "doc_action_patch_apply_acceptance_packet_id": stable_id(
            "docpatchapplyacceptance",
            label,
            apply_boundary_packet.get("doc_action_patch_apply_boundary_packet_id"),
            apply_boundary_packet.get("doc_action_patch_apply_boundary_packet_sha256"),
            acceptance.get("acceptance_text_sha256"),
            accepted_action,
            now,
        ),
        "label": label,
        "source_root": str(root),
        "doc_action_patch_apply_boundary_packet_id": apply_boundary_packet.get(
            "doc_action_patch_apply_boundary_packet_id"
        ),
        "doc_action_patch_apply_boundary_packet_sha256": apply_boundary_packet.get(
            "doc_action_patch_apply_boundary_packet_sha256"
        ),
        "doc_action_patch_executor_preflight_id": apply_boundary_packet.get(
            "doc_action_patch_executor_preflight_id"
        ),
        "doc_action_patch_executor_preflight_sha256": apply_boundary_packet.get(
            "doc_action_patch_executor_preflight_sha256"
        ),
        "doc_action_patch_live_execution_approval_packet_id": apply_boundary_packet.get(
            "doc_action_patch_live_execution_approval_packet_id"
        ),
        "doc_action_patch_live_execution_approval_packet_sha256": apply_boundary_packet.get(
            "doc_action_patch_live_execution_approval_packet_sha256"
        ),
        "doc_action_patch_dry_run_readback_receipt_id": apply_boundary_packet.get(
            "doc_action_patch_dry_run_readback_receipt_id"
        ),
        "doc_action_patch_dry_run_readback_receipt_sha256": apply_boundary_packet.get(
            "doc_action_patch_dry_run_readback_receipt_sha256"
        ),
        "doc_action_patch_dry_run_plan_id": apply_boundary_packet.get("doc_action_patch_dry_run_plan_id"),
        "doc_action_patch_dry_run_plan_sha256": apply_boundary_packet.get(
            "doc_action_patch_dry_run_plan_sha256"
        ),
        "doc_action_patch_artifact_approval_packet_id": apply_boundary_packet.get(
            "doc_action_patch_artifact_approval_packet_id"
        ),
        "doc_action_patch_artifact_approval_packet_sha256": apply_boundary_packet.get(
            "doc_action_patch_artifact_approval_packet_sha256"
        ),
        "doc_action_patch_artifact_receipt_id": apply_boundary_packet.get(
            "doc_action_patch_artifact_receipt_id"
        ),
        "doc_action_patch_artifact_receipt_sha256": apply_boundary_packet.get(
            "doc_action_patch_artifact_receipt_sha256"
        ),
        "doc_action_patch_readback_receipt_id": apply_boundary_packet.get("doc_action_patch_readback_receipt_id"),
        "doc_action_patch_readback_receipt_sha256": apply_boundary_packet.get(
            "doc_action_patch_readback_receipt_sha256"
        ),
        "doc_action_patch_preview_id": apply_boundary_packet.get("doc_action_patch_preview_id"),
        "doc_action_patch_preview_sha256": apply_boundary_packet.get("doc_action_patch_preview_sha256"),
        "doc_action_operator_approval_packet_id": apply_boundary_packet.get(
            "doc_action_operator_approval_packet_id"
        ),
        "doc_action_operator_approval_packet_sha256": apply_boundary_packet.get(
            "doc_action_operator_approval_packet_sha256"
        ),
        "doc_action_execution_plan_id": apply_boundary_packet.get("doc_action_execution_plan_id"),
        "doc_action_execution_plan_sha256": apply_boundary_packet.get("doc_action_execution_plan_sha256"),
        "source_doc_retirement_plan_id": apply_boundary_packet.get("source_doc_retirement_plan_id"),
        "source_doc_retirement_plan_sha256": apply_boundary_packet.get(
            "source_doc_retirement_plan_sha256"
        ),
        "accepted_apply_action": accepted_action,
        "acceptance": acceptance,
        "required_acceptance_phrases": list(REQUIRED_ACCEPTANCE_PHRASES),
        "required_gates": required_gates,
        "acceptance_policy": {
            "acceptance_packet_only": True,
            "requires_apply_boundary_packet": True,
            "requires_artifact_hash_recheck": True,
            "requires_source_hash_recheck": True,
            "requires_backup_preimage_evidence": True,
            "requires_source_backup_before_apply": True,
            "requires_post_apply_readback": True,
            "accepted_for_backup_preimage_review": accepted,
            "apply_allowed_by_packet": False,
            "live_execution_allowed_by_packet": False,
            "source_file_write_allowed_by_packet": False,
            "source_file_move_allowed_by_packet": False,
            "source_file_delete_allowed_by_packet": False,
            "archive_create_allowed_by_packet": False,
            "generated_surface_rewrite_allowed_by_packet": False,
            "raw_patch_stored_in_ams_state": False,
            "raw_source_markdown_stored_in_ams_state": False,
            "raw_operator_acceptance_stored_in_ams_state": False,
            "raw_executor_output_stored_in_ams_state": False,
        },
        "approval_granted": apply_boundary_packet.get("approval_granted") is True,
        "preflight_ready": apply_boundary_packet.get("preflight_ready") is True,
        "apply_boundary_ready": apply_boundary_packet.get("apply_boundary_ready") is True,
        "operator_apply_acceptance_captured": accepted,
        "accepted_for_backup_preimage_review": accepted,
        "apply_allowed": False,
        "live_execution_allowed": False,
        "source_file_write_allowed": False,
        "source_file_move_allowed": False,
        "source_file_delete_allowed": False,
        "source_backup_write_allowed": False,
        "archive_create_allowed": False,
        "generated_surface_rewrite_allowed": False,
        "patch_artifact_write_allowed": False,
        "provider_call_allowed": False,
        "network_call_allowed": False,
        "acceptance_actions": _acceptance_actions(accepted_action, acceptance) if accepted else [],
        "execution_actions": [],
        "source_write_actions": [],
        "backup_actions": [],
        "live_boundaries": {
            "approval_granted": apply_boundary_packet.get("approval_granted") is True,
            "preflight_recorded": apply_boundary_packet.get("preflight_ready") is True,
            "apply_boundary_recorded": apply_boundary_packet.get("apply_boundary_ready") is True,
            "operator_apply_acceptance_captured": accepted,
            **NON_EXECUTION_BOUNDARIES,
        },
        "status": status,
        "reason_codes": _reason_codes(required_gates, status),
        "created_at": now,
    }
    record["doc_action_patch_apply_acceptance_packet_sha256"] = _hash_without(
        record,
        "doc_action_patch_apply_acceptance_packet_sha256",
    )
    return deepcopy(record)


def validate_doc_action_patch_apply_acceptance_packet_record(
    record: dict[str, Any],
    *,
    apply_boundary_packet: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record(
            "doc_action_patch_apply_acceptance_packet.schema.json",
            record,
            location="doc_action_patch_apply_acceptance_packet",
        )
    except SchemaValidationError:
        reason_codes.append("doc_action_patch_apply_acceptance.schema_invalid")
    expected_hash = record.get("doc_action_patch_apply_acceptance_packet_sha256")
    if expected_hash and expected_hash != _hash_without(
        record,
        "doc_action_patch_apply_acceptance_packet_sha256",
    ):
        reason_codes.append("doc_action_patch_apply_acceptance.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("doc_action_patch_apply_acceptance.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("doc_action_patch_apply_acceptance.status_invalid")
    if apply_boundary_packet is None:
        reason_codes.append("doc_action_patch_apply_acceptance.apply_boundary_packet_missing")
    else:
        _validate_apply_boundary_ref(record, apply_boundary_packet, reason_codes)
    accepted_action = record.get("accepted_apply_action") or {}
    _validate_accepted_action(record, apply_boundary_packet, accepted_action, reason_codes)
    _validate_acceptance(record, reason_codes)
    expected_gates = _required_gates(
        apply_boundary_packet=apply_boundary_packet or {},
        accepted_action=accepted_action,
        acceptance=record.get("acceptance") or {},
    )
    if record.get("required_gates") != expected_gates:
        reason_codes.append("doc_action_patch_apply_acceptance.required_gates_mismatch")
    expected_status = _status(expected_gates)
    if record.get("status") != expected_status:
        reason_codes.append("doc_action_patch_apply_acceptance.status_mismatch")
    expected_reasons = _reason_codes(expected_gates, expected_status)
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("doc_action_patch_apply_acceptance.reason_codes_mismatch")
    _validate_authority(record, apply_boundary_packet or {}, expected_status, accepted_action, reason_codes)
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _acceptance(*, acceptance_ref: str, acceptance_text: str, requested_by: str, now: str) -> dict[str, Any]:
    normalized = _normalize(acceptance_text)
    phrase_results = [
        {
            "phrase": phrase,
            "present": phrase in normalized,
            "evidence_sha256": sha256_text(phrase if phrase in normalized else ""),
        }
        for phrase in REQUIRED_ACCEPTANCE_PHRASES
    ]
    missing = [row["phrase"] for row in phrase_results if not row["present"]]
    return {
        "requested_by": requested_by,
        "acceptance_ref": acceptance_ref,
        "acceptance_present": bool(acceptance_ref and acceptance_text),
        "acceptance_text_sha256": sha256_text(normalized),
        "normalized_acceptance_sha256": sha256_text(normalized),
        "raw_acceptance_stored": False,
        "phrase_results": phrase_results,
        "required_phrases_present": not missing,
        "missing_required_phrases": missing,
        "created_at": now,
    }


def _accepted_action(*, root: Path, apply_boundary_packet: dict[str, Any]) -> dict[str, Any]:
    boundary_intent = apply_boundary_packet.get("apply_boundary_intent") or {}
    rollback_plan = apply_boundary_packet.get("rollback_plan") or {}
    artifact_path = Path(str(boundary_intent.get("artifact_path") or "")).expanduser().resolve(strict=False)
    artifact_exists = artifact_path.is_file()
    current_source_ref = _source_ref(root, str(boundary_intent.get("source_path") or ""))
    boundary_source_ref = deepcopy(boundary_intent.get("current_source_ref") or {})
    approved_source_ref = deepcopy(boundary_intent.get("approved_source_ref") or {})
    return {
        "action_id": boundary_intent.get("action_id"),
        "source_path": boundary_intent.get("source_path"),
        "target_surface": boundary_intent.get("target_surface"),
        "planned_operation": boundary_intent.get("planned_operation"),
        "patch_kind": boundary_intent.get("patch_kind"),
        "artifact_path": str(artifact_path),
        "artifact_sha256": boundary_intent.get("artifact_sha256"),
        "artifact_exists": artifact_exists,
        "artifact_hash_verified": artifact_exists
        and _file_sha256(artifact_path) == boundary_intent.get("artifact_sha256"),
        "source_ref": boundary_source_ref,
        "approved_source_ref": approved_source_ref,
        "current_source_ref": current_source_ref,
        "source_hash_matches_boundary": _source_refs_match(boundary_source_ref, current_source_ref),
        "source_hash_matches_approved_source": _source_refs_match(approved_source_ref, current_source_ref),
        "apply_boundary_intent_sha256": boundary_intent.get("apply_boundary_intent_sha256"),
        "rollback_plan_sha256": rollback_plan.get("rollback_plan_sha256"),
        "rollback_plan_required": rollback_plan.get("rollback_plan_required") is True,
        "requires_source_backup_before_apply": rollback_plan.get("requires_source_backup_before_apply") is True,
        "backup_written": rollback_plan.get("backup_written") is True,
        "backup_evidence_required": True,
        "backup_evidence_captured": False,
        "post_apply_readback_required": boundary_intent.get("post_apply_readback_required") is True,
        "post_apply_readback_captured": False,
        "patch_hunk_count": boundary_intent.get("patch_hunk_count", 0),
        "patch_addition_count": boundary_intent.get("patch_addition_count", 0),
        "patch_deletion_count": boundary_intent.get("patch_deletion_count", 0),
        "acceptance_only": True,
        "apply_allowed": False,
        "source_write_performed": False,
        "source_file_rewritten": False,
        "source_file_deleted": False,
        "source_file_moved": False,
        "source_backup_written": False,
        "archive_created": False,
        "generated_surface_rewritten": False,
    }


def _acceptance_actions(accepted_action: dict[str, Any], acceptance: dict[str, Any]) -> list[dict[str, Any]]:
    action = {
        "action_id": accepted_action.get("action_id"),
        "source_path": accepted_action.get("source_path"),
        "artifact_sha256": accepted_action.get("artifact_sha256"),
        "source_ref_sha256": (accepted_action.get("source_ref") or {}).get("sha256"),
        "apply_boundary_intent_sha256": accepted_action.get("apply_boundary_intent_sha256"),
        "rollback_plan_sha256": accepted_action.get("rollback_plan_sha256"),
        "acceptance_text_sha256": acceptance.get("acceptance_text_sha256"),
        "backup_preimage_evidence_required": True,
        "source_backup_before_apply_required": True,
        "post_apply_readback_required": True,
        "acceptance_only": True,
        "apply_allowed": False,
        "source_write_performed": False,
    }
    action["acceptance_action_sha256"] = sha256_text(canonical_json(action))
    return [action]


def _validate_apply_boundary_ref(
    record: dict[str, Any],
    apply_boundary_packet: dict[str, Any],
    reason_codes: list[str],
) -> None:
    if record.get("doc_action_patch_apply_boundary_packet_id") != apply_boundary_packet.get(
        "doc_action_patch_apply_boundary_packet_id"
    ):
        reason_codes.append("doc_action_patch_apply_acceptance.apply_boundary_packet_id_mismatch")
    if record.get("doc_action_patch_apply_boundary_packet_sha256") != apply_boundary_packet.get(
        "doc_action_patch_apply_boundary_packet_sha256"
    ):
        reason_codes.append("doc_action_patch_apply_acceptance.apply_boundary_packet_hash_mismatch")
    if apply_boundary_packet.get("doc_action_patch_apply_boundary_packet_sha256") != _hash_without(
        apply_boundary_packet,
        "doc_action_patch_apply_boundary_packet_sha256",
    ):
        reason_codes.append("doc_action_patch_apply_acceptance.apply_boundary_packet_hash_not_current")
    if apply_boundary_packet.get("status") != "ready_for_operator_apply_acceptance":
        reason_codes.append("doc_action_patch_apply_acceptance.apply_boundary_not_ready")
    for key in (
        "doc_action_patch_executor_preflight_id",
        "doc_action_patch_executor_preflight_sha256",
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
        if record.get(key) != apply_boundary_packet.get(key):
            reason_codes.append(f"doc_action_patch_apply_acceptance.{key}_mismatch")


def _validate_accepted_action(
    record: dict[str, Any],
    apply_boundary_packet: dict[str, Any] | None,
    accepted_action: dict[str, Any],
    reason_codes: list[str],
) -> None:
    if apply_boundary_packet is None:
        return
    expected = _accepted_action(
        root=Path(str(record.get("source_root") or repo_root())).expanduser().resolve(strict=False),
        apply_boundary_packet=apply_boundary_packet,
    )
    for key, expected_value in expected.items():
        if accepted_action.get(key) != expected_value:
            reason_codes.append(f"doc_action_patch_apply_acceptance.accepted_action_{key}_mismatch")


def _validate_acceptance(record: dict[str, Any], reason_codes: list[str]) -> None:
    acceptance = record.get("acceptance") or {}
    if acceptance.get("raw_acceptance_stored") is not False:
        reason_codes.append("doc_action_patch_apply_acceptance.raw_acceptance_stored_not_false")
    if acceptance.get("acceptance_text_sha256") != acceptance.get("normalized_acceptance_sha256"):
        reason_codes.append("doc_action_patch_apply_acceptance.acceptance_hash_mismatch")
    if record.get("required_acceptance_phrases") != REQUIRED_ACCEPTANCE_PHRASES:
        reason_codes.append("doc_action_patch_apply_acceptance.required_acceptance_phrases_mismatch")
    phrase_results = acceptance.get("phrase_results") or []
    if len(phrase_results) != len(REQUIRED_ACCEPTANCE_PHRASES):
        reason_codes.append("doc_action_patch_apply_acceptance.phrase_results_count_mismatch")
    present_by_phrase: dict[str, bool] = {}
    for phrase in REQUIRED_ACCEPTANCE_PHRASES:
        matches = [row for row in phrase_results if isinstance(row, dict) and row.get("phrase") == phrase]
        if len(matches) != 1:
            reason_codes.append(f"doc_action_patch_apply_acceptance.phrase_result_missing:{phrase}")
            continue
        row = matches[0]
        present = row.get("present")
        if not isinstance(present, bool):
            reason_codes.append(f"doc_action_patch_apply_acceptance.phrase_present_invalid:{phrase}")
            continue
        present_by_phrase[phrase] = present
        expected_evidence = sha256_text(phrase if present else "")
        if row.get("evidence_sha256") != expected_evidence:
            reason_codes.append(f"doc_action_patch_apply_acceptance.phrase_evidence_mismatch:{phrase}")
    missing = [phrase for phrase in REQUIRED_ACCEPTANCE_PHRASES if present_by_phrase.get(phrase) is not True]
    if missing != acceptance.get("missing_required_phrases"):
        reason_codes.append("doc_action_patch_apply_acceptance.missing_required_phrases_mismatch")
    if acceptance.get("required_phrases_present") is not (not missing):
        reason_codes.append("doc_action_patch_apply_acceptance.required_phrases_present_mismatch")


def _validate_authority(
    record: dict[str, Any],
    apply_boundary_packet: dict[str, Any],
    expected_status: str,
    accepted_action: dict[str, Any],
    reason_codes: list[str],
) -> None:
    accepted = expected_status == "accepted_for_backup_preimage_review"
    policy = record.get("acceptance_policy") or {}
    for key in (
        "acceptance_packet_only",
        "requires_apply_boundary_packet",
        "requires_artifact_hash_recheck",
        "requires_source_hash_recheck",
        "requires_backup_preimage_evidence",
        "requires_source_backup_before_apply",
        "requires_post_apply_readback",
    ):
        if policy.get(key) is not True:
            reason_codes.append(f"doc_action_patch_apply_acceptance.policy_{key}_not_true")
    for key in (
        "apply_allowed_by_packet",
        "live_execution_allowed_by_packet",
        "source_file_write_allowed_by_packet",
        "source_file_move_allowed_by_packet",
        "source_file_delete_allowed_by_packet",
        "archive_create_allowed_by_packet",
        "generated_surface_rewrite_allowed_by_packet",
        "raw_patch_stored_in_ams_state",
        "raw_source_markdown_stored_in_ams_state",
        "raw_operator_acceptance_stored_in_ams_state",
        "raw_executor_output_stored_in_ams_state",
    ):
        if policy.get(key) is not False:
            reason_codes.append(f"doc_action_patch_apply_acceptance.policy_{key}_not_false")
    if policy.get("accepted_for_backup_preimage_review") is not accepted:
        reason_codes.append("doc_action_patch_apply_acceptance.policy_accepted_mismatch")
    for key in (
        "approval_granted",
        "preflight_ready",
        "apply_boundary_ready",
    ):
        if record.get(key) is not (apply_boundary_packet.get(key) is True):
            reason_codes.append(f"doc_action_patch_apply_acceptance.{key}_mismatch")
    if record.get("operator_apply_acceptance_captured") is not accepted:
        reason_codes.append("doc_action_patch_apply_acceptance.operator_apply_acceptance_captured_mismatch")
    if record.get("accepted_for_backup_preimage_review") is not accepted:
        reason_codes.append("doc_action_patch_apply_acceptance.accepted_for_backup_preimage_review_mismatch")
    for key in (
        "apply_allowed",
        "live_execution_allowed",
        "source_file_write_allowed",
        "source_file_move_allowed",
        "source_file_delete_allowed",
        "source_backup_write_allowed",
        "archive_create_allowed",
        "generated_surface_rewrite_allowed",
        "patch_artifact_write_allowed",
        "provider_call_allowed",
        "network_call_allowed",
    ):
        if record.get(key) is not False:
            reason_codes.append(f"doc_action_patch_apply_acceptance.{key}_not_false")
    boundaries = record.get("live_boundaries") or {}
    for key in ("approval_granted", "preflight_recorded", "apply_boundary_recorded"):
        boundary_expected = {
            "approval_granted": apply_boundary_packet.get("approval_granted") is True,
            "preflight_recorded": apply_boundary_packet.get("preflight_ready") is True,
            "apply_boundary_recorded": apply_boundary_packet.get("apply_boundary_ready") is True,
        }[key]
        if boundaries.get(key) is not boundary_expected:
            reason_codes.append(f"doc_action_patch_apply_acceptance.{key}_boundary_mismatch")
    if boundaries.get("operator_apply_acceptance_captured") is not accepted:
        reason_codes.append("doc_action_patch_apply_acceptance.operator_apply_acceptance_boundary_mismatch")
    for key, expected in NON_EXECUTION_BOUNDARIES.items():
        if boundaries.get(key) is not expected:
            reason_codes.append(f"doc_action_patch_apply_acceptance.{key}_boundary_mismatch")
    expected_actions = _acceptance_actions(accepted_action, record.get("acceptance") or {}) if accepted else []
    if record.get("acceptance_actions") != expected_actions:
        reason_codes.append("doc_action_patch_apply_acceptance.acceptance_actions_mismatch")
    for key in ("execution_actions", "source_write_actions", "backup_actions"):
        if record.get(key) != []:
            reason_codes.append(f"doc_action_patch_apply_acceptance.{key}_not_empty")


def _required_gates(
    *,
    apply_boundary_packet: dict[str, Any],
    accepted_action: dict[str, Any],
    acceptance: dict[str, Any],
) -> dict[str, bool]:
    return {
        "apply_boundary_present": bool(apply_boundary_packet.get("doc_action_patch_apply_boundary_packet_id")),
        "apply_boundary_ready": apply_boundary_packet.get("status") == "ready_for_operator_apply_acceptance",
        "apply_boundary_hash_current": bool(apply_boundary_packet)
        and apply_boundary_packet.get("doc_action_patch_apply_boundary_packet_sha256")
        == _hash_without(apply_boundary_packet, "doc_action_patch_apply_boundary_packet_sha256"),
        "apply_boundary_grants_no_authority": _apply_boundary_grants_no_authority(apply_boundary_packet),
        "artifact_hash_current": accepted_action.get("artifact_hash_verified") is True,
        "source_exists": (accepted_action.get("current_source_ref") or {}).get("exists") is True,
        "source_under_root": (accepted_action.get("current_source_ref") or {}).get("under_source_root") is True,
        "source_hash_matches_boundary": accepted_action.get("source_hash_matches_boundary") is True,
        "source_hash_matches_approved_source": accepted_action.get("source_hash_matches_approved_source") is True,
        "rollback_plan_required": accepted_action.get("rollback_plan_required") is True,
        "source_backup_required": accepted_action.get("requires_source_backup_before_apply") is True,
        "backup_evidence_not_captured": accepted_action.get("backup_evidence_captured") is False,
        "post_apply_readback_required": accepted_action.get("post_apply_readback_required") is True,
        "post_apply_readback_not_captured": accepted_action.get("post_apply_readback_captured") is False,
        "acceptance_ref_present": bool(acceptance.get("acceptance_ref")),
        "acceptance_present": acceptance.get("acceptance_present") is True,
        "required_phrases_present": acceptance.get("required_phrases_present") is True,
        "raw_acceptance_not_stored": acceptance.get("raw_acceptance_stored") is False,
        "acceptance_packet_executes_nothing": True,
    }


def _apply_boundary_grants_no_authority(apply_boundary_packet: dict[str, Any]) -> bool:
    return (
        apply_boundary_packet.get("apply_allowed") is False
        and apply_boundary_packet.get("live_execution_allowed") is False
        and apply_boundary_packet.get("source_file_write_allowed") is False
        and apply_boundary_packet.get("source_file_move_allowed") is False
        and apply_boundary_packet.get("source_file_delete_allowed") is False
        and apply_boundary_packet.get("archive_create_allowed") is False
        and apply_boundary_packet.get("generated_surface_rewrite_allowed") is False
        and apply_boundary_packet.get("patch_artifact_write_allowed") is False
        and apply_boundary_packet.get("execution_actions") == []
        and apply_boundary_packet.get("source_write_actions") == []
    )


def _status(required_gates: dict[str, bool]) -> str:
    return "accepted_for_backup_preimage_review" if required_gates and all(required_gates.values()) else "blocked"


def _reason_codes(required_gates: dict[str, bool], status: str) -> list[str]:
    if status == "accepted_for_backup_preimage_review":
        return ["doc_action_patch_apply_acceptance.accepted_for_backup_preimage_review"]
    missing = [key for key, value in sorted(required_gates.items()) if value is not True]
    return [f"doc_action_patch_apply_acceptance.gate_failed:{key}" for key in missing] or [
        "doc_action_patch_apply_acceptance.blocked"
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
