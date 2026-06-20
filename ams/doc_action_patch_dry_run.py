from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any

from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore
from .workspace import path_is_under, repo_root


SCHEMA_VERSION = "ams.ams.doc_action_patch_dry_run_plan.v0"
STATUSES = {"dry_run_ready", "blocked"}

LIVE_BOUNDARIES = {
    "approval_granted": False,
    "dry_run_recorded": True,
    "patch_artifact_written": False,
    "source_file_rewritten": False,
    "source_file_deleted": False,
    "source_file_moved": False,
    "archive_created": False,
    "generated_surface_rewritten": False,
    "raw_patch_stored_in_ams_state": False,
    "raw_source_markdown_stored_in_ams_state": False,
    "raw_readback_stored_in_ams_state": False,
    "discord_call_performed": False,
    "terminal_attach_performed": False,
    "terminal_capture_performed": False,
    "terminal_injection_performed": False,
    "persistent_process_started": False,
    "provider_call_performed": False,
    "network_call_performed": False,
    "secret_stored": False,
}


class DocActionPatchDryRunPlanStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        doc_action_patch_artifact_approval_packet_id: str,
        source_root: str | Path | None = None,
        label: str = "manual-doc-action-patch-dry-run",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            approval_packet = (state.get("doc_action_patch_artifact_approval_packets") or {}).get(
                doc_action_patch_artifact_approval_packet_id
            )
            if not approval_packet:
                raise KeyError(
                    "doc action patch artifact approval packet not found: "
                    f"{doc_action_patch_artifact_approval_packet_id}"
                )
            record = build_doc_action_patch_dry_run_plan(
                approval_packet=approval_packet,
                source_root=source_root,
                label=label,
            )
            plan_id = record["doc_action_patch_dry_run_plan_id"]
            state.setdefault("doc_action_patch_dry_run_plans", {})[plan_id] = record
            state.setdefault("indexes", {}).setdefault("doc_action_patch_dry_run_plan_ids", {})[
                plan_id
            ] = plan_id
            return deepcopy(record)


def build_doc_action_patch_dry_run_plan(
    *,
    approval_packet: dict[str, Any],
    source_root: str | Path | None = None,
    label: str = "manual-doc-action-patch-dry-run",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root_value = source_root or approval_packet.get("source_root") or repo_root()
    root = Path(root_value).expanduser().resolve(strict=False)
    action = _dry_run_action(root, approval_packet.get("selected_artifact") or {})
    actions = [action]
    summary = _dry_run_summary(actions)
    required_gates = _required_gates(approval_packet=approval_packet, actions=actions)
    status = _status(required_gates)
    reason_codes = _reason_codes(required_gates, status)
    record = {
        "schema_version": SCHEMA_VERSION,
        "doc_action_patch_dry_run_plan_id": stable_id(
            "docpatchdryrun",
            label,
            approval_packet.get("doc_action_patch_artifact_approval_packet_id"),
            approval_packet.get("doc_action_patch_artifact_approval_packet_sha256"),
            summary,
            now,
        ),
        "label": label,
        "source_root": str(root),
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
        "dry_run_policy": {
            "dry_run_only": True,
            "requires_artifact_approval_packet": True,
            "source_hash_recheck_required": True,
            "artifact_hash_recheck_required": True,
            "approval_granted": False,
            "live_execution_allowed": False,
            "source_file_write_allowed": False,
            "source_file_move_allowed": False,
            "source_file_delete_allowed": False,
            "archive_create_allowed": False,
            "generated_surface_rewrite_allowed": False,
            "patch_artifact_write_allowed": False,
            "raw_patch_stored_in_ams_state": False,
            "raw_source_markdown_stored_in_ams_state": False,
            "raw_readback_stored_in_ams_state": False,
            "executor_required_for_source_writes": True,
        },
        "dry_run_actions": actions,
        "dry_run_summary": summary,
        "required_gates": required_gates,
        "approval_granted": False,
        "live_execution_allowed": False,
        "source_file_write_allowed": False,
        "source_file_move_allowed": False,
        "source_file_delete_allowed": False,
        "archive_create_allowed": False,
        "generated_surface_rewrite_allowed": False,
        "patch_artifact_write_allowed": False,
        "approval_actions": [],
        "execution_actions": [],
        "source_write_actions": [],
        "live_boundaries": dict(LIVE_BOUNDARIES),
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["doc_action_patch_dry_run_plan_sha256"] = _hash_without(
        record,
        "doc_action_patch_dry_run_plan_sha256",
    )
    return deepcopy(record)


def validate_doc_action_patch_dry_run_plan_record(
    record: dict[str, Any],
    *,
    approval_packet: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record(
            "doc_action_patch_dry_run_plan.schema.json",
            record,
            location="doc_action_patch_dry_run_plan",
        )
    except SchemaValidationError:
        reason_codes.append("doc_action_patch_dry_run.schema_invalid")
    expected_hash = record.get("doc_action_patch_dry_run_plan_sha256")
    if expected_hash and expected_hash != _hash_without(record, "doc_action_patch_dry_run_plan_sha256"):
        reason_codes.append("doc_action_patch_dry_run.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("doc_action_patch_dry_run.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("doc_action_patch_dry_run.status_invalid")
    _validate_authority(record, reason_codes)
    actions = [action for action in record.get("dry_run_actions") or [] if isinstance(action, dict)]
    for action in actions:
        _validate_dry_run_action(record, action, reason_codes)
    expected_summary = _dry_run_summary(actions)
    if record.get("dry_run_summary") != expected_summary:
        reason_codes.append("doc_action_patch_dry_run.summary_mismatch")
    if approval_packet is None:
        reason_codes.append("doc_action_patch_dry_run.approval_packet_missing")
    else:
        _validate_approval_packet_ref(record, approval_packet, actions, reason_codes)
    expected_gates = _required_gates(approval_packet=approval_packet or {}, actions=actions)
    if record.get("required_gates") != expected_gates:
        reason_codes.append("doc_action_patch_dry_run.required_gates_mismatch")
    expected_status = _status(expected_gates)
    if record.get("status") != expected_status:
        reason_codes.append("doc_action_patch_dry_run.status_mismatch")
    expected_reasons = _reason_codes(expected_gates, expected_status)
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("doc_action_patch_dry_run.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _dry_run_action(root: Path, selected_artifact: dict[str, Any]) -> dict[str, Any]:
    artifact_path = Path(str(selected_artifact.get("artifact_path") or "")).expanduser().resolve(strict=False)
    artifact_exists = artifact_path.is_file()
    text = artifact_path.read_text(encoding="utf-8") if artifact_exists else ""
    source_ref = deepcopy(selected_artifact.get("source_ref") or {})
    current_source_ref = _source_ref(root, str(selected_artifact.get("source_path") or ""))
    return {
        "action_id": selected_artifact.get("action_id"),
        "source_path": selected_artifact.get("source_path"),
        "target_surface": selected_artifact.get("target_surface"),
        "planned_operation": selected_artifact.get("planned_operation"),
        "patch_kind": selected_artifact.get("patch_kind"),
        "artifact_path": str(artifact_path),
        "artifact_path_under_source_root": path_is_under(artifact_path, root),
        "artifact_sha256": selected_artifact.get("artifact_sha256"),
        "artifact_line_count": selected_artifact.get("artifact_line_count"),
        "artifact_size_bytes": selected_artifact.get("artifact_size_bytes"),
        "artifact_exists": artifact_exists,
        "artifact_hash_verified": artifact_exists and _file_sha256(artifact_path) == selected_artifact.get("artifact_sha256"),
        "artifact_line_count_verified": artifact_exists
        and len(text.splitlines()) == selected_artifact.get("artifact_line_count"),
        "artifact_size_bytes_verified": artifact_exists
        and len(text.encode("utf-8")) == selected_artifact.get("artifact_size_bytes"),
        "source_ref": source_ref,
        "source_hash_matches_approval_packet": _source_ref_matches(source_ref, current_source_ref),
        "source_file_exists": current_source_ref.get("exists") is True,
        "source_file_under_source_root": current_source_ref.get("under_source_root") is True,
        "patch_hunk_count": _count_hunks(text),
        "patch_addition_count": _count_additions(text),
        "patch_deletion_count": _count_deletions(text),
        "patch_nonempty": bool(text.strip()),
        "dry_run_only": True,
        "raw_patch_stored_in_ams_state": False,
        "raw_source_markdown_stored_in_ams_state": False,
        "source_file_rewritten": False,
        "source_file_deleted": False,
        "source_file_moved": False,
        "archive_created": False,
        "generated_surface_rewritten": False,
    }


def _validate_authority(record: dict[str, Any], reason_codes: list[str]) -> None:
    policy = record.get("dry_run_policy") or {}
    for key in (
        "dry_run_only",
        "requires_artifact_approval_packet",
        "source_hash_recheck_required",
        "artifact_hash_recheck_required",
        "executor_required_for_source_writes",
    ):
        if policy.get(key) is not True:
            reason_codes.append(f"doc_action_patch_dry_run.policy_{key}_not_true")
    for key in (
        "approval_granted",
        "live_execution_allowed",
        "source_file_write_allowed",
        "source_file_move_allowed",
        "source_file_delete_allowed",
        "archive_create_allowed",
        "generated_surface_rewrite_allowed",
        "patch_artifact_write_allowed",
        "raw_patch_stored_in_ams_state",
        "raw_source_markdown_stored_in_ams_state",
        "raw_readback_stored_in_ams_state",
    ):
        if policy.get(key) is not False:
            reason_codes.append(f"doc_action_patch_dry_run.policy_{key}_not_false")
    for key in (
        "approval_granted",
        "live_execution_allowed",
        "source_file_write_allowed",
        "source_file_move_allowed",
        "source_file_delete_allowed",
        "archive_create_allowed",
        "generated_surface_rewrite_allowed",
        "patch_artifact_write_allowed",
    ):
        if record.get(key) is not False:
            reason_codes.append(f"doc_action_patch_dry_run.{key}_not_false")
    for key in ("approval_actions", "execution_actions", "source_write_actions"):
        if record.get(key) != []:
            reason_codes.append(f"doc_action_patch_dry_run.{key}_not_empty")
    for key, expected in LIVE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"doc_action_patch_dry_run.{key}_boundary_mismatch")


def _validate_dry_run_action(record: dict[str, Any], action: dict[str, Any], reason_codes: list[str]) -> None:
    root = Path(str(record.get("source_root") or "")).expanduser().resolve(strict=False)
    expected = _dry_run_action(root, action)
    for key in (
        "artifact_path_under_source_root",
        "artifact_exists",
        "artifact_hash_verified",
        "artifact_line_count_verified",
        "artifact_size_bytes_verified",
        "source_hash_matches_approval_packet",
        "source_file_exists",
        "source_file_under_source_root",
        "patch_hunk_count",
        "patch_addition_count",
        "patch_deletion_count",
        "patch_nonempty",
    ):
        if action.get(key) != expected.get(key):
            reason_codes.append(f"doc_action_patch_dry_run.{key}_mismatch:{action.get('action_id')}")
    source_ref = action.get("source_ref") or {}
    current_source_ref = _source_ref(root, str(action.get("source_path") or ""))
    for field in ("path", "exists", "under_source_root", "sha256", "line_count", "size_bytes", "raw_content_stored"):
        if source_ref.get(field) != current_source_ref.get(field):
            reason_codes.append(f"doc_action_patch_dry_run.source_ref_{field}_mismatch:{action.get('action_id')}")
    for key in (
        "dry_run_only",
        "raw_patch_stored_in_ams_state",
        "raw_source_markdown_stored_in_ams_state",
        "source_file_rewritten",
        "source_file_deleted",
        "source_file_moved",
        "archive_created",
        "generated_surface_rewritten",
    ):
        expected_value = True if key == "dry_run_only" else False
        if action.get(key) is not expected_value:
            reason_codes.append(f"doc_action_patch_dry_run.action_{key}_invalid:{action.get('action_id')}")


def _validate_approval_packet_ref(
    record: dict[str, Any],
    approval_packet: dict[str, Any],
    actions: list[dict[str, Any]],
    reason_codes: list[str],
) -> None:
    if record.get("doc_action_patch_artifact_approval_packet_id") != approval_packet.get(
        "doc_action_patch_artifact_approval_packet_id"
    ):
        reason_codes.append("doc_action_patch_dry_run.approval_packet_id_mismatch")
    if record.get("doc_action_patch_artifact_approval_packet_sha256") != approval_packet.get(
        "doc_action_patch_artifact_approval_packet_sha256"
    ):
        reason_codes.append("doc_action_patch_dry_run.approval_packet_hash_mismatch")
    if approval_packet.get("doc_action_patch_artifact_approval_packet_sha256") != _hash_without(
        approval_packet,
        "doc_action_patch_artifact_approval_packet_sha256",
    ):
        reason_codes.append("doc_action_patch_dry_run.approval_packet_hash_not_current")
    if approval_packet.get("status") != "ready_for_operator_review":
        reason_codes.append("doc_action_patch_dry_run.approval_packet_not_ready")
    approval_source_root = str(approval_packet.get("source_root") or "")
    if approval_source_root and record.get("source_root") != str(Path(approval_source_root).resolve(strict=False)):
        reason_codes.append("doc_action_patch_dry_run.source_root_mismatch")
    for key in (
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
            reason_codes.append(f"doc_action_patch_dry_run.{key}_mismatch")
    selected = approval_packet.get("selected_artifact") or {}
    if len(actions) != 1:
        reason_codes.append("doc_action_patch_dry_run.action_count_invalid")
        return
    action = actions[0]
    for key in (
        "action_id",
        "source_path",
        "target_surface",
        "planned_operation",
        "patch_kind",
        "artifact_path",
        "artifact_sha256",
        "artifact_line_count",
        "artifact_size_bytes",
        "source_ref",
    ):
        if action.get(key) != selected.get(key):
            reason_codes.append(f"doc_action_patch_dry_run.selected_artifact_{key}_mismatch")
    for key in (
        "approval_granted",
        "live_execution_allowed",
        "source_file_write_allowed",
        "source_file_move_allowed",
        "source_file_delete_allowed",
        "archive_create_allowed",
        "generated_surface_rewrite_allowed",
    ):
        if approval_packet.get(key) is not False:
            reason_codes.append(f"doc_action_patch_dry_run.approval_packet_{key}_not_false")


def _required_gates(*, approval_packet: dict[str, Any], actions: list[dict[str, Any]]) -> dict[str, bool]:
    approval_hash_current = (
        bool(approval_packet)
        and approval_packet.get("doc_action_patch_artifact_approval_packet_sha256")
        == _hash_without(approval_packet, "doc_action_patch_artifact_approval_packet_sha256")
    )
    return {
        "approval_packet_present": bool(approval_packet.get("doc_action_patch_artifact_approval_packet_id")),
        "approval_packet_ready": approval_packet.get("status") == "ready_for_operator_review",
        "approval_packet_hash_current": approval_hash_current,
        "dry_run_action_present": len(actions) == 1 and bool(actions[0].get("action_id")),
        "artifact_file_present": bool(actions) and actions[0].get("artifact_exists") is True,
        "artifact_hash_verified": bool(actions) and actions[0].get("artifact_hash_verified") is True,
        "artifact_line_count_verified": bool(actions) and actions[0].get("artifact_line_count_verified") is True,
        "artifact_size_bytes_verified": bool(actions) and actions[0].get("artifact_size_bytes_verified") is True,
        "artifact_path_outside_source_root": bool(actions)
        and actions[0].get("artifact_path_under_source_root") is False,
        "source_hash_matches_approval_packet": bool(actions)
        and actions[0].get("source_hash_matches_approval_packet") is True,
        "source_file_present": bool(actions) and actions[0].get("source_file_exists") is True,
        "source_file_under_source_root": bool(actions) and actions[0].get("source_file_under_source_root") is True,
        "patch_nonempty": bool(actions) and actions[0].get("patch_nonempty") is True,
        "raw_patch_not_stored_in_ams_state": all(
            action.get("raw_patch_stored_in_ams_state") is False for action in actions
        ),
        "source_files_not_modified": all(
            action.get("source_file_rewritten") is False
            and action.get("source_file_deleted") is False
            and action.get("source_file_moved") is False
            for action in actions
        ),
        "generated_surfaces_not_rewritten": all(
            action.get("generated_surface_rewritten") is False for action in actions
        ),
        "approval_packet_grants_no_authority": all(
            approval_packet.get(key) is False
            for key in (
                "approval_granted",
                "live_execution_allowed",
                "source_file_write_allowed",
                "source_file_move_allowed",
                "source_file_delete_allowed",
                "archive_create_allowed",
                "generated_surface_rewrite_allowed",
            )
        ),
        "source_writes_disabled": True,
    }


def _dry_run_summary(actions: list[dict[str, Any]]) -> dict[str, Any]:
    action_refs = [
        {
            "action_id": action.get("action_id"),
            "source_path": action.get("source_path"),
            "artifact_sha256": action.get("artifact_sha256"),
            "source_sha256": (action.get("source_ref") or {}).get("sha256"),
            "patch_hunk_count": action.get("patch_hunk_count"),
            "patch_addition_count": action.get("patch_addition_count"),
            "patch_deletion_count": action.get("patch_deletion_count"),
        }
        for action in actions
    ]
    return {
        "dry_run_action_count": len(actions),
        "patch_hunk_count": sum(int(action.get("patch_hunk_count") or 0) for action in actions),
        "patch_addition_count": sum(int(action.get("patch_addition_count") or 0) for action in actions),
        "patch_deletion_count": sum(int(action.get("patch_deletion_count") or 0) for action in actions),
        "action_set_sha256": sha256_text(canonical_json(action_refs)),
        "dry_run_only": True,
        "raw_patch_stored_in_ams_state": False,
        "raw_source_markdown_stored_in_ams_state": False,
        "source_files_modified": False,
    }


def _status(required_gates: dict[str, bool]) -> str:
    return "dry_run_ready" if required_gates and all(required_gates.values()) else "blocked"


def _reason_codes(required_gates: dict[str, bool], status: str) -> list[str]:
    if status == "dry_run_ready":
        return ["doc_action_patch_dry_run.dry_run_ready"]
    missing = [key for key, value in sorted(required_gates.items()) if value is not True]
    return [f"doc_action_patch_dry_run.gate_failed:{key}" for key in missing] or [
        "doc_action_patch_dry_run.blocked"
    ]


def _count_hunks(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.startswith("@@"))


def _count_additions(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.startswith("+") and not line.startswith("+++"))


def _count_deletions(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.startswith("-") and not line.startswith("---"))


def _source_ref_matches(expected: dict[str, Any], current: dict[str, Any]) -> bool:
    return all(
        expected.get(field) == current.get(field)
        for field in ("path", "exists", "under_source_root", "sha256", "line_count", "size_bytes", "raw_content_stored")
    )


def _source_ref(root: Path, relative_path: str) -> dict[str, Any]:
    safe_rel = relative_path.strip("/")
    path = (root / safe_rel).resolve(strict=False)
    under_root = path_is_under(path, root)
    is_file = under_root and path.is_file()
    size_bytes = path.stat().st_size if is_file else None
    sha256 = _file_sha256(path) if is_file else None
    line_count = len(path.read_text(encoding="utf-8").splitlines()) if is_file else None
    return {
        "path": relative_path,
        "exists": bool(is_file),
        "under_source_root": bool(under_root),
        "sha256": sha256,
        "line_count": line_count,
        "size_bytes": size_bytes,
        "raw_content_stored": False,
    }


def _file_sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
