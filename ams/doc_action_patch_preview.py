from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any

from .doc_action_execution import validate_doc_action_execution_plan_record
from .doc_action_operator_approval import validate_doc_action_operator_approval_packet_record
from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore
from .workspace import repo_root


SCHEMA_VERSION = "ams.ams.doc_action_patch_preview.v0"
STATUSES = {"ready_for_review", "blocked"}

LIVE_BOUNDARIES = {
    "source_file_rewritten": False,
    "source_file_deleted": False,
    "source_file_moved": False,
    "archive_created": False,
    "generated_surface_rewritten": False,
    "preview_artifact_written": False,
    "raw_patch_stored": False,
    "raw_source_markdown_stored": False,
    "discord_call_performed": False,
    "terminal_attach_performed": False,
    "terminal_capture_performed": False,
    "terminal_injection_performed": False,
    "provider_call_performed": False,
    "network_call_performed": False,
}

PATCH_KIND_BY_OPERATION = {
    "replace_with_generated_surface_preview": "replace_with_generated_surface_after_approval",
    "split_archive_preview": "split_or_archive_history_after_approval",
    "trim_orientation_preview": "trim_to_orientation_after_approval",
    "metadata_patch_preview": "insert_metadata_after_approval",
    "section_patch_preview": "insert_required_section_after_approval",
    "manual_review_preview": "manual_review_patch_after_approval",
}


class DocActionPatchPreviewStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        doc_action_operator_approval_packet_id: str,
        source_root: str | Path | None = None,
        label: str = "manual-doc-action-patch-preview",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            approval_packet = (state.get("doc_action_operator_approval_packets") or {}).get(
                doc_action_operator_approval_packet_id
            )
            if not approval_packet:
                raise KeyError(f"doc action operator approval packet not found: {doc_action_operator_approval_packet_id}")
            execution_plan_id = approval_packet.get("doc_action_execution_plan_id")
            execution_plan = (state.get("doc_action_execution_plans") or {}).get(execution_plan_id)
            if not execution_plan:
                raise KeyError(f"doc action execution plan not found: {execution_plan_id}")
            record = build_doc_action_patch_preview(
                approval_packet=approval_packet,
                execution_plan=execution_plan,
                source_root=source_root,
                label=label,
            )
            preview_id = record["doc_action_patch_preview_id"]
            state.setdefault("doc_action_patch_previews", {})[preview_id] = record
            state.setdefault("indexes", {}).setdefault("doc_action_patch_preview_ids", {})[preview_id] = preview_id
            return deepcopy(record)


def build_doc_action_patch_preview(
    *,
    approval_packet: dict[str, Any],
    execution_plan: dict[str, Any],
    source_root: str | Path | None = None,
    label: str = "manual-doc-action-patch-preview",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False) if source_root else repo_root()
    patch_previews = [_patch_preview(root, action) for action in execution_plan.get("selected_actions") or []]
    patch_summary = _patch_summary(patch_previews)
    required_gates = _required_gates(
        approval_packet=approval_packet,
        execution_plan=execution_plan,
        patch_previews=patch_previews,
    )
    status = _status(required_gates)
    reason_codes = _reason_codes(required_gates, status)
    record = {
        "schema_version": SCHEMA_VERSION,
        "doc_action_patch_preview_id": stable_id(
            "docpatch",
            label,
            approval_packet.get("doc_action_operator_approval_packet_id"),
            approval_packet.get("doc_action_operator_approval_packet_sha256"),
            execution_plan.get("doc_action_execution_plan_id"),
            execution_plan.get("doc_action_execution_plan_sha256"),
            patch_summary,
            now,
        ),
        "label": label,
        "source_root": str(root),
        "doc_action_operator_approval_packet_id": approval_packet.get("doc_action_operator_approval_packet_id"),
        "doc_action_operator_approval_packet_sha256": approval_packet.get(
            "doc_action_operator_approval_packet_sha256"
        ),
        "doc_action_execution_plan_id": execution_plan.get("doc_action_execution_plan_id"),
        "doc_action_execution_plan_sha256": execution_plan.get("doc_action_execution_plan_sha256"),
        "source_doc_retirement_plan_id": (execution_plan.get("source_plan_ref") or {}).get("doc_retirement_plan_id"),
        "source_doc_retirement_plan_sha256": (execution_plan.get("source_plan_ref") or {}).get(
            "doc_retirement_plan_sha256"
        ),
        "policy": {
            "preview_only": True,
            "operator_review_required": True,
            "literal_patch_stored": False,
            "raw_source_markdown_stored": False,
            "preview_artifact_write_allowed": False,
            "source_file_write_allowed": False,
            "archive_create_allowed": False,
            "generated_surface_rewrite_allowed": False,
            "future_executor_must_recheck_source_sha256": True,
        },
        "live_boundaries": dict(LIVE_BOUNDARIES),
        "patch_previews": patch_previews,
        "patch_summary": patch_summary,
        "required_gates": required_gates,
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["doc_action_patch_preview_sha256"] = _hash_without(record, "doc_action_patch_preview_sha256")
    return deepcopy(record)


def validate_doc_action_patch_preview_record(
    record: dict[str, Any],
    *,
    approval_packet: dict[str, Any] | None = None,
    execution_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("doc_action_patch_preview.schema.json", record, location="doc_action_patch_preview")
    except SchemaValidationError:
        reason_codes.append("doc_action_patch_preview.schema_invalid")
    expected_hash = record.get("doc_action_patch_preview_sha256")
    if expected_hash and expected_hash != _hash_without(record, "doc_action_patch_preview_sha256"):
        reason_codes.append("doc_action_patch_preview.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("doc_action_patch_preview.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("doc_action_patch_preview.status_invalid")
    for key, expected in LIVE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"doc_action_patch_preview.{key}_not_false")
    policy = record.get("policy") or {}
    for key in ("preview_only", "operator_review_required", "future_executor_must_recheck_source_sha256"):
        if policy.get(key) is not True:
            reason_codes.append(f"doc_action_patch_preview.policy_{key}_not_true")
    for key in (
        "literal_patch_stored",
        "raw_source_markdown_stored",
        "preview_artifact_write_allowed",
        "source_file_write_allowed",
        "archive_create_allowed",
        "generated_surface_rewrite_allowed",
    ):
        if policy.get(key) is not False:
            reason_codes.append(f"doc_action_patch_preview.policy_{key}_not_false")
    patch_previews = record.get("patch_previews") or []
    expected_summary = _patch_summary(patch_previews)
    if record.get("patch_summary") != expected_summary:
        reason_codes.append("doc_action_patch_preview.patch_summary_mismatch")
    for preview in patch_previews:
        if not isinstance(preview, dict):
            reason_codes.append("doc_action_patch_preview.preview_not_object")
            continue
        current_source_ref = preview.get("current_source_ref") or {}
        if current_source_ref.get("path") != preview.get("source_path"):
            reason_codes.append(f"doc_action_patch_preview.current_source_ref_path_mismatch:{preview.get('action_id')}")
        if current_source_ref.get("exists") is not True:
            reason_codes.append(f"doc_action_patch_preview.current_source_ref_missing:{preview.get('action_id')}")
        if current_source_ref.get("under_source_root") is not True:
            reason_codes.append(f"doc_action_patch_preview.current_source_ref_outside_root:{preview.get('action_id')}")
        if not current_source_ref.get("sha256"):
            reason_codes.append(f"doc_action_patch_preview.current_source_ref_hash_missing:{preview.get('action_id')}")
        if current_source_ref.get("line_count") is None:
            reason_codes.append(f"doc_action_patch_preview.current_source_ref_line_count_missing:{preview.get('action_id')}")
        if current_source_ref.get("size_bytes") is None:
            reason_codes.append(f"doc_action_patch_preview.current_source_ref_size_bytes_missing:{preview.get('action_id')}")
        if current_source_ref.get("raw_content_stored") is not False:
            reason_codes.append(f"doc_action_patch_preview.current_source_ref_raw_content_not_false:{preview.get('action_id')}")
        expected_preview_hash = _patch_preview_hash(preview)
        if preview.get("patch_preview_sha256") != expected_preview_hash:
            reason_codes.append(f"doc_action_patch_preview.preview_hash_mismatch:{preview.get('action_id')}")
        for key in (
            "preview_only",
            "operator_review_required",
            "future_executor_must_recheck_source_sha256",
        ):
            if preview.get(key) is not True:
                reason_codes.append(f"doc_action_patch_preview.preview_{key}_not_true:{preview.get('action_id')}")
        for key in ("live_boundary", "raw_patch_stored", "raw_source_markdown_stored", "preview_artifact_written"):
            if preview.get(key) is not False:
                reason_codes.append(f"doc_action_patch_preview.preview_{key}_not_false:{preview.get('action_id')}")
    if execution_plan is None:
        reason_codes.append("doc_action_patch_preview.execution_plan_missing")
    else:
        plan_validation = validate_doc_action_execution_plan_record(execution_plan)
        if not plan_validation["ok"]:
            reason_codes.append("doc_action_patch_preview.execution_plan_invalid")
        if execution_plan.get("doc_action_execution_plan_id") != record.get("doc_action_execution_plan_id"):
            reason_codes.append("doc_action_patch_preview.execution_plan_id_mismatch")
        if execution_plan.get("doc_action_execution_plan_sha256") != record.get("doc_action_execution_plan_sha256"):
            reason_codes.append("doc_action_patch_preview.execution_plan_hash_mismatch")
        source_ref = execution_plan.get("source_plan_ref") or {}
        if source_ref.get("doc_retirement_plan_id") != record.get("source_doc_retirement_plan_id"):
            reason_codes.append("doc_action_patch_preview.source_doc_retirement_plan_id_mismatch")
        if source_ref.get("doc_retirement_plan_sha256") != record.get("source_doc_retirement_plan_sha256"):
            reason_codes.append("doc_action_patch_preview.source_doc_retirement_plan_hash_mismatch")
        selected_by_id = {
            action.get("action_id"): action
            for action in execution_plan.get("selected_actions") or []
            if isinstance(action, dict)
        }
        preview_ids = [preview.get("action_id") for preview in patch_previews if isinstance(preview, dict)]
        if sorted(preview_ids) != sorted(selected_by_id):
            reason_codes.append("doc_action_patch_preview.selected_action_set_mismatch")
        for preview in patch_previews:
            if not isinstance(preview, dict):
                continue
            action = selected_by_id.get(preview.get("action_id"))
            if action is None:
                continue
            for field in ("source_path", "planned_operation", "target_surface"):
                if preview.get(field) != action.get(field):
                    reason_codes.append(f"doc_action_patch_preview.action_{field}_mismatch:{preview.get('action_id')}")
            expected_patch_kind = PATCH_KIND_BY_OPERATION.get(
                str(action.get("planned_operation") or ""),
                "manual_review_patch_after_approval",
            )
            if preview.get("patch_kind") != expected_patch_kind:
                reason_codes.append(f"doc_action_patch_preview.patch_kind_mismatch:{preview.get('action_id')}")
            expected_source_ref = action.get("source_ref") or {}
            current_source_ref = preview.get("current_source_ref") or {}
            for field in ("path", "exists", "under_source_root", "sha256", "line_count", "size_bytes", "raw_content_stored"):
                if current_source_ref.get(field) != expected_source_ref.get(field):
                    reason_codes.append(
                        f"doc_action_patch_preview.current_source_ref_{field}_mismatch:{preview.get('action_id')}"
                    )
            expected_match = (
                ((action.get("source_ref") or {}).get("sha256"))
                == ((preview.get("current_source_ref") or {}).get("sha256"))
            )
            if preview.get("source_hash_matches_plan") is not expected_match:
                reason_codes.append(f"doc_action_patch_preview.source_hash_match_mismatch:{preview.get('action_id')}")
            expected_semantic_patch_sha = sha256_text(
                canonical_json(_semantic_patch(action, preview.get("current_source_ref") or {}))
            )
            if preview.get("semantic_patch_sha256") != expected_semantic_patch_sha:
                reason_codes.append(f"doc_action_patch_preview.semantic_patch_hash_mismatch:{preview.get('action_id')}")
    if approval_packet is None:
        reason_codes.append("doc_action_patch_preview.approval_packet_missing")
    else:
        approval_validation = validate_doc_action_operator_approval_packet_record(
            approval_packet,
            execution_plan=execution_plan,
        )
        if not approval_validation["ok"]:
            reason_codes.append("doc_action_patch_preview.approval_packet_invalid")
        if approval_packet.get("doc_action_operator_approval_packet_id") != record.get(
            "doc_action_operator_approval_packet_id"
        ):
            reason_codes.append("doc_action_patch_preview.approval_packet_id_mismatch")
        if approval_packet.get("doc_action_operator_approval_packet_sha256") != record.get(
            "doc_action_operator_approval_packet_sha256"
        ):
            reason_codes.append("doc_action_patch_preview.approval_packet_hash_mismatch")
    expected_gates = _required_gates(
        approval_packet=approval_packet or {},
        execution_plan=execution_plan or {},
        patch_previews=patch_previews,
    )
    if record.get("required_gates") != expected_gates:
        reason_codes.append("doc_action_patch_preview.required_gates_mismatch")
    expected_status = _status(expected_gates)
    if record.get("status") != expected_status:
        reason_codes.append("doc_action_patch_preview.status_mismatch")
    expected_reasons = _reason_codes(expected_gates, expected_status)
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("doc_action_patch_preview.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _patch_preview(root: Path, action: dict[str, Any]) -> dict[str, Any]:
    current_source_ref = _source_ref(root, str(action.get("source_path") or ""))
    semantic_patch = _semantic_patch(action, current_source_ref)
    preview = {
        "action_id": action.get("action_id"),
        "source_path": action.get("source_path"),
        "target_surface": action.get("target_surface"),
        "planned_operation": action.get("planned_operation"),
        "patch_kind": semantic_patch["patch_kind"],
        "current_source_ref": current_source_ref,
        "source_hash_matches_plan": semantic_patch["source_hash_matches_plan"],
        "semantic_patch_sha256": sha256_text(canonical_json(semantic_patch)),
        "preview_only": True,
        "operator_review_required": True,
        "future_executor_must_recheck_source_sha256": True,
        "live_boundary": False,
        "raw_patch_stored": False,
        "raw_source_markdown_stored": False,
        "preview_artifact_written": False,
    }
    preview["patch_preview_sha256"] = _patch_preview_hash(preview)
    return preview


def _semantic_patch(action: dict[str, Any], current_source_ref: dict[str, Any]) -> dict[str, Any]:
    planned_source_ref = action.get("source_ref") or {}
    return {
        "patch_kind": PATCH_KIND_BY_OPERATION.get(
            str(action.get("planned_operation") or ""),
            "manual_review_patch_after_approval",
        ),
        "source_path": action.get("source_path"),
        "target_surface": action.get("target_surface"),
        "planned_operation": action.get("planned_operation"),
        "source_sha256": planned_source_ref.get("sha256"),
        "current_source_sha256": current_source_ref.get("sha256"),
        "source_hash_matches_plan": planned_source_ref.get("sha256") == current_source_ref.get("sha256"),
        "expected_executor_checks": [
            "operator approval packet still matches",
            "execution plan hash still matches",
            "source file sha256 still matches",
            "literal patch reviewed outside AMS state",
        ],
        "literal_patch_stored": False,
    }


def _patch_preview_hash(preview: dict[str, Any]) -> str:
    return _hash_without(preview, "patch_preview_sha256")


def _patch_summary(patch_previews: list[dict[str, Any]]) -> dict[str, Any]:
    patch_hashes = sorted(str(preview.get("patch_preview_sha256") or "") for preview in patch_previews)
    return {
        "patch_count": len(patch_previews),
        "by_planned_operation": dict(Counter(str(preview.get("planned_operation")) for preview in patch_previews)),
        "source_hash_match_count": sum(1 for preview in patch_previews if preview.get("source_hash_matches_plan") is True),
        "source_hash_mismatch_count": sum(1 for preview in patch_previews if preview.get("source_hash_matches_plan") is False),
        "patch_set_sha256": sha256_text(canonical_json(patch_hashes)),
        "raw_patch_stored": False,
        "raw_source_markdown_stored": False,
        "preview_artifact_written": False,
    }


def _required_gates(
    *,
    approval_packet: dict[str, Any],
    execution_plan: dict[str, Any],
    patch_previews: list[dict[str, Any]],
) -> dict[str, bool]:
    plan_policy = execution_plan.get("policy") or {}
    approval_live = approval_packet.get("live_boundaries") or {}
    return {
        "approval_packet_present": bool(approval_packet.get("doc_action_operator_approval_packet_id")),
        "approval_packet_ready_for_review": approval_packet.get("status") == "ready_for_operator_review",
        "approval_packet_grants_no_authority": (
            approval_packet.get("approval_granted") is False
            and approval_packet.get("live_execution_allowed") is False
            and approval_packet.get("file_rewrite_allowed") is False
            and approval_packet.get("file_move_allowed") is False
            and approval_packet.get("file_delete_allowed") is False
            and approval_packet.get("archive_create_allowed") is False
            and approval_packet.get("generated_surface_rewrite_allowed") is False
            and bool(approval_live)
            and all(value is False for value in approval_live.values())
        ),
        "execution_plan_present": bool(execution_plan.get("doc_action_execution_plan_id")),
        "execution_plan_preview_only": plan_policy.get("preview_only") is True,
        "execution_plan_write_disabled": plan_policy.get("write_allowed") is False,
        "execution_plan_hash_matches_packet": execution_plan.get("doc_action_execution_plan_sha256")
        == approval_packet.get("doc_action_execution_plan_sha256"),
        "source_doc_plan_ref_matches_packet": (execution_plan.get("source_plan_ref") or {}).get("doc_retirement_plan_id")
        == approval_packet.get("source_doc_retirement_plan_id")
        and (execution_plan.get("source_plan_ref") or {}).get("doc_retirement_plan_sha256")
        == approval_packet.get("source_doc_retirement_plan_sha256"),
        "selected_actions_present": bool(execution_plan.get("selected_actions")),
        "patch_previews_present": bool(patch_previews),
        "source_hashes_match_plan": bool(patch_previews)
        and all(preview.get("source_hash_matches_plan") is True for preview in patch_previews),
        "patch_hashes_present": bool(patch_previews)
        and all(str(preview.get("patch_preview_sha256") or "").startswith("sha256:") for preview in patch_previews),
        "raw_patch_not_stored": all(preview.get("raw_patch_stored") is False for preview in patch_previews),
        "preview_artifact_not_written": all(preview.get("preview_artifact_written") is False for preview in patch_previews),
    }


def _status(required_gates: dict[str, bool]) -> str:
    return "ready_for_review" if required_gates and all(required_gates.values()) else "blocked"


def _reason_codes(required_gates: dict[str, bool], status: str) -> list[str]:
    if status == "ready_for_review":
        return ["doc_action_patch_preview.ready_for_review"]
    missing = [key for key, value in sorted(required_gates.items()) if value is not True]
    return [f"doc_action_patch_preview.gate_failed:{key}" for key in missing] or [
        "doc_action_patch_preview.blocked"
    ]


def _source_ref(root: Path, relative_path: str) -> dict[str, Any]:
    safe_rel = relative_path.strip("/")
    path = (root / safe_rel).resolve(strict=False)
    under_root = _path_under_root(path, root)
    is_file = under_root and path.is_file()
    size_bytes = path.stat().st_size if is_file else None
    sha256 = _file_sha256(path) if is_file else None
    line_count = _line_count(path) if is_file else None
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


def _line_count(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    return text.count("\n") + (0 if text.endswith("\n") or text == "" else 1)


def _path_under_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
