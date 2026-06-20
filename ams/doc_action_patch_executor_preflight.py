from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any

from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore
from .workspace import path_is_under, repo_root


SCHEMA_VERSION = "ams.ams.doc_action_patch_executor_preflight.v0"
STATUSES = {"preflight_ready", "blocked"}

NON_WRITE_BOUNDARIES = {
    "source_file_rewritten": False,
    "source_file_deleted": False,
    "source_file_moved": False,
    "archive_created": False,
    "generated_surface_rewritten": False,
    "patch_artifact_written": False,
    "raw_patch_stored_in_ams_state": False,
    "raw_source_markdown_stored_in_ams_state": False,
    "raw_approval_stored_in_ams_state": False,
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


class DocActionPatchExecutorPreflightStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        doc_action_patch_live_execution_approval_packet_id: str,
        source_root: str | Path | None = None,
        label: str = "manual-doc-action-patch-executor-preflight",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            approval_packet = (state.get("doc_action_patch_live_execution_approval_packets") or {}).get(
                doc_action_patch_live_execution_approval_packet_id
            )
            if not approval_packet:
                raise KeyError(
                    "doc action patch live-execution approval packet not found: "
                    f"{doc_action_patch_live_execution_approval_packet_id}"
                )
            record = build_doc_action_patch_executor_preflight(
                approval_packet=approval_packet,
                source_root=source_root,
                label=label,
            )
            preflight_id = record["doc_action_patch_executor_preflight_id"]
            state.setdefault("doc_action_patch_executor_preflights", {})[preflight_id] = record
            state.setdefault("indexes", {}).setdefault("doc_action_patch_executor_preflight_ids", {})[
                preflight_id
            ] = preflight_id
            return deepcopy(record)


def build_doc_action_patch_executor_preflight(
    *,
    approval_packet: dict[str, Any],
    source_root: str | Path | None = None,
    label: str = "manual-doc-action-patch-executor-preflight",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root_value = source_root or approval_packet.get("source_root") or repo_root()
    root = Path(root_value).expanduser().resolve(strict=False)
    apply_intent = _apply_intent(root=root, approval_packet=approval_packet)
    required_gates = _required_gates(approval_packet=approval_packet, apply_intent=apply_intent)
    status = _status(required_gates)
    preflight_ready = status == "preflight_ready"
    record = {
        "schema_version": SCHEMA_VERSION,
        "doc_action_patch_executor_preflight_id": stable_id(
            "docpatchpreflight",
            label,
            approval_packet.get("doc_action_patch_live_execution_approval_packet_id"),
            approval_packet.get("doc_action_patch_live_execution_approval_packet_sha256"),
            apply_intent,
            now,
        ),
        "label": label,
        "source_root": str(root),
        "doc_action_patch_live_execution_approval_packet_id": approval_packet.get(
            "doc_action_patch_live_execution_approval_packet_id"
        ),
        "doc_action_patch_live_execution_approval_packet_sha256": approval_packet.get(
            "doc_action_patch_live_execution_approval_packet_sha256"
        ),
        "doc_action_patch_dry_run_readback_receipt_id": approval_packet.get(
            "doc_action_patch_dry_run_readback_receipt_id"
        ),
        "doc_action_patch_dry_run_readback_receipt_sha256": approval_packet.get(
            "doc_action_patch_dry_run_readback_receipt_sha256"
        ),
        "doc_action_patch_dry_run_plan_id": approval_packet.get("doc_action_patch_dry_run_plan_id"),
        "doc_action_patch_dry_run_plan_sha256": approval_packet.get("doc_action_patch_dry_run_plan_sha256"),
        "doc_action_patch_artifact_approval_packet_id": approval_packet.get(
            "doc_action_patch_artifact_approval_packet_id"
        ),
        "doc_action_patch_artifact_approval_packet_sha256": approval_packet.get(
            "doc_action_patch_artifact_approval_packet_sha256"
        ),
        "doc_action_patch_artifact_receipt_id": approval_packet.get("doc_action_patch_artifact_receipt_id"),
        "doc_action_patch_artifact_receipt_sha256": approval_packet.get(
            "doc_action_patch_artifact_receipt_sha256"
        ),
        "doc_action_patch_readback_receipt_id": approval_packet.get("doc_action_patch_readback_receipt_id"),
        "doc_action_patch_readback_receipt_sha256": approval_packet.get(
            "doc_action_patch_readback_receipt_sha256"
        ),
        "doc_action_patch_preview_id": approval_packet.get("doc_action_patch_preview_id"),
        "doc_action_patch_preview_sha256": approval_packet.get("doc_action_patch_preview_sha256"),
        "doc_action_operator_approval_packet_id": approval_packet.get("doc_action_operator_approval_packet_id"),
        "doc_action_operator_approval_packet_sha256": approval_packet.get(
            "doc_action_operator_approval_packet_sha256"
        ),
        "doc_action_execution_plan_id": approval_packet.get("doc_action_execution_plan_id"),
        "doc_action_execution_plan_sha256": approval_packet.get("doc_action_execution_plan_sha256"),
        "source_doc_retirement_plan_id": approval_packet.get("source_doc_retirement_plan_id"),
        "source_doc_retirement_plan_sha256": approval_packet.get("source_doc_retirement_plan_sha256"),
        "preflight_policy": {
            "preflight_only": True,
            "requires_live_execution_approval_packet": True,
            "requires_source_hash_recheck": True,
            "requires_artifact_hash_recheck": True,
            "requires_separate_apply_boundary": True,
            "approval_granted": approval_packet.get("approval_granted") is True,
            "apply_allowed": False,
            "source_file_write_allowed": False,
            "source_file_move_allowed": False,
            "source_file_delete_allowed": False,
            "archive_create_allowed": False,
            "generated_surface_rewrite_allowed": False,
            "raw_patch_stored_in_ams_state": False,
            "raw_source_markdown_stored_in_ams_state": False,
            "raw_executor_output_stored_in_ams_state": False,
        },
        "apply_intent": apply_intent,
        "required_gates": required_gates,
        "approval_granted": approval_packet.get("approval_granted") is True,
        "preflight_ready": preflight_ready,
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
        "approval_actions": deepcopy(approval_packet.get("approval_actions") or []),
        "preflight_actions": _preflight_actions(apply_intent) if preflight_ready else [],
        "execution_actions": [],
        "source_write_actions": [],
        "live_boundaries": {
            "approval_granted": approval_packet.get("approval_granted") is True,
            "preflight_recorded": preflight_ready,
            **NON_WRITE_BOUNDARIES,
        },
        "status": status,
        "reason_codes": _reason_codes(required_gates, status),
        "created_at": now,
    }
    record["doc_action_patch_executor_preflight_sha256"] = _hash_without(
        record,
        "doc_action_patch_executor_preflight_sha256",
    )
    return deepcopy(record)


def validate_doc_action_patch_executor_preflight_record(
    record: dict[str, Any],
    *,
    approval_packet: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record(
            "doc_action_patch_executor_preflight.schema.json",
            record,
            location="doc_action_patch_executor_preflight",
        )
    except SchemaValidationError:
        reason_codes.append("doc_action_patch_executor_preflight.schema_invalid")
    expected_hash = record.get("doc_action_patch_executor_preflight_sha256")
    if expected_hash and expected_hash != _hash_without(record, "doc_action_patch_executor_preflight_sha256"):
        reason_codes.append("doc_action_patch_executor_preflight.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("doc_action_patch_executor_preflight.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("doc_action_patch_executor_preflight.status_invalid")
    if approval_packet is None:
        reason_codes.append("doc_action_patch_executor_preflight.approval_packet_missing")
    else:
        _validate_approval_packet_ref(record, approval_packet, reason_codes)
    apply_intent = record.get("apply_intent") or {}
    _validate_apply_intent(record, apply_intent, reason_codes)
    expected_gates = _required_gates(approval_packet=approval_packet or {}, apply_intent=apply_intent)
    if record.get("required_gates") != expected_gates:
        reason_codes.append("doc_action_patch_executor_preflight.required_gates_mismatch")
    expected_status = _status(expected_gates)
    if record.get("status") != expected_status:
        reason_codes.append("doc_action_patch_executor_preflight.status_mismatch")
    expected_reasons = _reason_codes(expected_gates, expected_status)
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("doc_action_patch_executor_preflight.reason_codes_mismatch")
    _validate_authority(record, approval_packet or {}, expected_status, apply_intent, reason_codes)
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _apply_intent(*, root: Path, approval_packet: dict[str, Any]) -> dict[str, Any]:
    selected = approval_packet.get("selected_execution_action") or {}
    artifact_path = Path(str(selected.get("artifact_path") or "")).expanduser().resolve(strict=False)
    artifact_exists = artifact_path.is_file()
    current_source_ref = _source_ref(root, str(selected.get("source_path") or ""))
    approved_source_ref = deepcopy(selected.get("source_ref") or {})
    approval_actions = [row for row in approval_packet.get("approval_actions") or [] if isinstance(row, dict)]
    approval_action = approval_actions[0] if approval_actions else {}
    intent = {
        "action_id": selected.get("action_id"),
        "source_path": selected.get("source_path"),
        "planned_operation": selected.get("planned_operation"),
        "patch_kind": selected.get("patch_kind"),
        "target_surface": selected.get("target_surface"),
        "artifact_path": str(artifact_path),
        "artifact_exists": artifact_exists,
        "artifact_path_under_source_root": path_is_under(artifact_path, root),
        "artifact_sha256": selected.get("artifact_sha256"),
        "artifact_sha256_current": _file_sha256(artifact_path) if artifact_exists else None,
        "artifact_hash_verified": artifact_exists and _file_sha256(artifact_path) == selected.get("artifact_sha256"),
        "source_ref": approved_source_ref,
        "current_source_ref": current_source_ref,
        "source_hash_verified": _source_refs_match(approved_source_ref, current_source_ref),
        "approval_action_sha256": approval_action.get("approval_action_sha256"),
        "approval_action_matches": _approval_action_matches(approval_action, selected),
        "patch_hunk_count": selected.get("patch_hunk_count", 0),
        "patch_addition_count": selected.get("patch_addition_count", 0),
        "patch_deletion_count": selected.get("patch_deletion_count", 0),
        "preflight_only": True,
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
    intent["apply_intent_sha256"] = sha256_text(canonical_json(intent))
    return intent


def _preflight_actions(apply_intent: dict[str, Any]) -> list[dict[str, Any]]:
    action = {
        "action_id": apply_intent.get("action_id"),
        "source_path": apply_intent.get("source_path"),
        "artifact_sha256": apply_intent.get("artifact_sha256"),
        "source_ref_sha256": (apply_intent.get("source_ref") or {}).get("sha256"),
        "apply_intent_sha256": apply_intent.get("apply_intent_sha256"),
        "preflight_only": True,
        "apply_allowed": False,
        "source_write_performed": False,
    }
    action["preflight_action_sha256"] = sha256_text(canonical_json(action))
    return [action]


def _validate_approval_packet_ref(
    record: dict[str, Any],
    approval_packet: dict[str, Any],
    reason_codes: list[str],
) -> None:
    if record.get("doc_action_patch_live_execution_approval_packet_id") != approval_packet.get(
        "doc_action_patch_live_execution_approval_packet_id"
    ):
        reason_codes.append("doc_action_patch_executor_preflight.approval_packet_id_mismatch")
    if record.get("doc_action_patch_live_execution_approval_packet_sha256") != approval_packet.get(
        "doc_action_patch_live_execution_approval_packet_sha256"
    ):
        reason_codes.append("doc_action_patch_executor_preflight.approval_packet_hash_mismatch")
    if approval_packet.get("doc_action_patch_live_execution_approval_packet_sha256") != _hash_without(
        approval_packet,
        "doc_action_patch_live_execution_approval_packet_sha256",
    ):
        reason_codes.append("doc_action_patch_executor_preflight.approval_packet_hash_not_current")
    if approval_packet.get("status") != "approved_for_executor_review":
        reason_codes.append("doc_action_patch_executor_preflight.approval_packet_not_ready")
    for key in (
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
        if record.get(key) != approval_packet.get(key):
            reason_codes.append(f"doc_action_patch_executor_preflight.{key}_mismatch")


def _validate_apply_intent(record: dict[str, Any], apply_intent: dict[str, Any], reason_codes: list[str]) -> None:
    expected = deepcopy(apply_intent)
    expected.pop("artifact_hash_verified", None)
    expected.pop("artifact_sha256_current", None)
    expected.pop("source_hash_verified", None)
    expected.pop("current_source_ref", None)
    expected.pop("apply_intent_sha256", None)
    recomputed = _apply_intent(
        root=Path(str(record.get("source_root") or repo_root())).expanduser().resolve(strict=False),
        approval_packet={
            "selected_execution_action": {
                "action_id": apply_intent.get("action_id"),
                "source_path": apply_intent.get("source_path"),
                "planned_operation": apply_intent.get("planned_operation"),
                "patch_kind": apply_intent.get("patch_kind"),
                "target_surface": apply_intent.get("target_surface"),
                "artifact_path": apply_intent.get("artifact_path"),
                "artifact_sha256": apply_intent.get("artifact_sha256"),
                "source_ref": apply_intent.get("source_ref") or {},
                "patch_hunk_count": apply_intent.get("patch_hunk_count", 0),
                "patch_addition_count": apply_intent.get("patch_addition_count", 0),
                "patch_deletion_count": apply_intent.get("patch_deletion_count", 0),
            },
            "approval_actions": [
                {
                    "action_id": apply_intent.get("action_id"),
                    "source_path": apply_intent.get("source_path"),
                    "planned_operation": apply_intent.get("planned_operation"),
                    "artifact_sha256": apply_intent.get("artifact_sha256"),
                    "source_ref_sha256": (apply_intent.get("source_ref") or {}).get("sha256"),
                    "approval_action_sha256": apply_intent.get("approval_action_sha256"),
                }
            ],
        },
    )
    for key in (
        "artifact_sha256_current",
        "artifact_hash_verified",
        "current_source_ref",
        "source_hash_verified",
        "approval_action_matches",
        "apply_intent_sha256",
    ):
        if apply_intent.get(key) != recomputed.get(key):
            reason_codes.append(f"doc_action_patch_executor_preflight.apply_intent_{key}_mismatch")
    for key in (
        "preflight_only",
        "apply_allowed",
        "source_write_performed",
        "source_file_rewritten",
        "source_file_deleted",
        "source_file_moved",
        "archive_created",
        "generated_surface_rewritten",
        "raw_patch_stored_in_ams_state",
        "raw_source_markdown_stored_in_ams_state",
    ):
        expected_value = True if key == "preflight_only" else False
        if apply_intent.get(key) is not expected_value:
            reason_codes.append(f"doc_action_patch_executor_preflight.apply_intent_{key}_mismatch")


def _validate_authority(
    record: dict[str, Any],
    approval_packet: dict[str, Any],
    expected_status: str,
    apply_intent: dict[str, Any],
    reason_codes: list[str],
) -> None:
    preflight_ready = expected_status == "preflight_ready"
    policy = record.get("preflight_policy") or {}
    for key in (
        "preflight_only",
        "requires_live_execution_approval_packet",
        "requires_source_hash_recheck",
        "requires_artifact_hash_recheck",
        "requires_separate_apply_boundary",
    ):
        if policy.get(key) is not True:
            reason_codes.append(f"doc_action_patch_executor_preflight.policy_{key}_not_true")
    for key in (
        "apply_allowed",
        "source_file_write_allowed",
        "source_file_move_allowed",
        "source_file_delete_allowed",
        "archive_create_allowed",
        "generated_surface_rewrite_allowed",
        "raw_patch_stored_in_ams_state",
        "raw_source_markdown_stored_in_ams_state",
        "raw_executor_output_stored_in_ams_state",
    ):
        if policy.get(key) is not False:
            reason_codes.append(f"doc_action_patch_executor_preflight.policy_{key}_not_false")
    if policy.get("approval_granted") is not (approval_packet.get("approval_granted") is True):
        reason_codes.append("doc_action_patch_executor_preflight.policy_approval_granted_mismatch")
    if record.get("approval_granted") is not (approval_packet.get("approval_granted") is True):
        reason_codes.append("doc_action_patch_executor_preflight.approval_granted_mismatch")
    if record.get("preflight_ready") is not preflight_ready:
        reason_codes.append("doc_action_patch_executor_preflight.preflight_ready_mismatch")
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
            reason_codes.append(f"doc_action_patch_executor_preflight.{key}_not_false")
    for key, expected in NON_WRITE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"doc_action_patch_executor_preflight.{key}_boundary_mismatch")
    if (record.get("live_boundaries") or {}).get("preflight_recorded") is not preflight_ready:
        reason_codes.append("doc_action_patch_executor_preflight.preflight_recorded_boundary_mismatch")
    expected_actions = _preflight_actions(apply_intent) if preflight_ready else []
    if record.get("preflight_actions") != expected_actions:
        reason_codes.append("doc_action_patch_executor_preflight.preflight_actions_mismatch")
    if record.get("execution_actions") != []:
        reason_codes.append("doc_action_patch_executor_preflight.execution_actions_not_empty")
    if record.get("source_write_actions") != []:
        reason_codes.append("doc_action_patch_executor_preflight.source_write_actions_not_empty")


def _required_gates(*, approval_packet: dict[str, Any], apply_intent: dict[str, Any]) -> dict[str, bool]:
    return {
        "approval_packet_present": bool(approval_packet.get("doc_action_patch_live_execution_approval_packet_id")),
        "approval_packet_ready": approval_packet.get("status") == "approved_for_executor_review",
        "approval_packet_hash_current": bool(approval_packet)
        and approval_packet.get("doc_action_patch_live_execution_approval_packet_sha256")
        == _hash_without(approval_packet, "doc_action_patch_live_execution_approval_packet_sha256"),
        "approval_granted": approval_packet.get("approval_granted") is True,
        "approval_packet_executes_nothing": approval_packet.get("live_execution_allowed") is False
        and approval_packet.get("source_file_write_allowed") is False,
        "artifact_exists": apply_intent.get("artifact_exists") is True,
        "artifact_hash_verified": apply_intent.get("artifact_hash_verified") is True,
        "source_exists": (apply_intent.get("current_source_ref") or {}).get("exists") is True,
        "source_under_root": (apply_intent.get("current_source_ref") or {}).get("under_source_root") is True,
        "source_hash_verified": apply_intent.get("source_hash_verified") is True,
        "approval_action_matches": apply_intent.get("approval_action_matches") is True,
        "preflight_only": apply_intent.get("preflight_only") is True,
        "apply_not_allowed": apply_intent.get("apply_allowed") is False,
    }


def _status(required_gates: dict[str, bool]) -> str:
    return "preflight_ready" if required_gates and all(required_gates.values()) else "blocked"


def _reason_codes(required_gates: dict[str, bool], status: str) -> list[str]:
    if status == "preflight_ready":
        return ["doc_action_patch_executor_preflight.preflight_ready"]
    missing = [key for key, value in sorted(required_gates.items()) if value is not True]
    return [f"doc_action_patch_executor_preflight.gate_failed:{key}" for key in missing] or [
        "doc_action_patch_executor_preflight.blocked"
    ]


def _approval_action_matches(approval_action: dict[str, Any], selected: dict[str, Any]) -> bool:
    return (
        bool(approval_action)
        and approval_action.get("action_id") == selected.get("action_id")
        and approval_action.get("source_path") == selected.get("source_path")
        and approval_action.get("artifact_sha256") == selected.get("artifact_sha256")
        and approval_action.get("source_ref_sha256") == (selected.get("source_ref") or {}).get("sha256")
    )


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
