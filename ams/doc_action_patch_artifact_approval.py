from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any

from .models import hash_without as _hash_without, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore
from .workspace import path_is_under, repo_root


SCHEMA_VERSION = "ams.ams.doc_action_patch_artifact_approval_packet.v0"
STATUSES = {"ready_for_operator_review", "blocked"}

REQUIRED_REVIEW_STEPS = [
    "review_selected_patch_artifact_file",
    "compare_artifact_hash_to_approval_packet",
    "compare_source_hash_to_approval_packet",
    "confirm_patch_artifact_is_review_evidence_only",
    "confirm_source_doc_writes_remain_disabled",
    "confirm_later_executor_must_recheck_hashes",
]

REQUIRED_READBACK_PHRASES = [
    "i reviewed the selected doc patch artifact",
    "artifact hash matches the approval packet",
    "source doc writes remain disabled",
    "source doc moves remain disabled",
    "source doc archives remain disabled",
    "generated surface rewrites remain disabled",
    "a later live execution approval is required",
]

LIVE_BOUNDARIES = {
    "approval_granted": False,
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


class DocActionPatchArtifactApprovalPacketStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        doc_action_patch_artifact_receipt_id: str,
        artifact_action_id: str | None = None,
        source_root: str | Path | None = None,
        label: str = "manual-doc-action-patch-artifact-approval",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            artifact_receipt = (state.get("doc_action_patch_artifact_receipts") or {}).get(
                doc_action_patch_artifact_receipt_id
            )
            if not artifact_receipt:
                raise KeyError(f"doc action patch artifact receipt not found: {doc_action_patch_artifact_receipt_id}")
            record = build_doc_action_patch_artifact_approval_packet(
                artifact_receipt=artifact_receipt,
                artifact_action_id=artifact_action_id,
                source_root=source_root,
                label=label,
            )
            packet_id = record["doc_action_patch_artifact_approval_packet_id"]
            state.setdefault("doc_action_patch_artifact_approval_packets", {})[packet_id] = record
            state.setdefault("indexes", {}).setdefault("doc_action_patch_artifact_approval_packet_ids", {})[
                packet_id
            ] = packet_id
            return deepcopy(record)


def build_doc_action_patch_artifact_approval_packet(
    *,
    artifact_receipt: dict[str, Any],
    artifact_action_id: str | None = None,
    source_root: str | Path | None = None,
    label: str = "manual-doc-action-patch-artifact-approval",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root_value = source_root or artifact_receipt.get("source_root") or repo_root()
    root = Path(root_value).expanduser().resolve(strict=False)
    selected_artifact = _selected_artifact(
        root=root,
        artifact_receipt=artifact_receipt,
        artifact_action_id=artifact_action_id,
    )
    approval_request = _approval_request()
    required_gates = _required_gates(artifact_receipt=artifact_receipt, selected_artifact=selected_artifact)
    status = _status(required_gates)
    reason_codes = _reason_codes(required_gates, status)
    record = {
        "schema_version": SCHEMA_VERSION,
        "doc_action_patch_artifact_approval_packet_id": stable_id(
            "docpatchartifactapproval",
            label,
            artifact_receipt.get("doc_action_patch_artifact_receipt_id"),
            artifact_receipt.get("doc_action_patch_artifact_receipt_sha256"),
            selected_artifact,
            now,
        ),
        "label": label,
        "source_root": str(root),
        "doc_action_patch_artifact_receipt_id": artifact_receipt.get("doc_action_patch_artifact_receipt_id"),
        "doc_action_patch_artifact_receipt_sha256": artifact_receipt.get(
            "doc_action_patch_artifact_receipt_sha256"
        ),
        "doc_action_patch_readback_receipt_id": artifact_receipt.get("doc_action_patch_readback_receipt_id"),
        "doc_action_patch_readback_receipt_sha256": artifact_receipt.get(
            "doc_action_patch_readback_receipt_sha256"
        ),
        "doc_action_patch_preview_id": artifact_receipt.get("doc_action_patch_preview_id"),
        "doc_action_patch_preview_sha256": artifact_receipt.get("doc_action_patch_preview_sha256"),
        "doc_action_operator_approval_packet_id": artifact_receipt.get("doc_action_operator_approval_packet_id"),
        "doc_action_operator_approval_packet_sha256": artifact_receipt.get(
            "doc_action_operator_approval_packet_sha256"
        ),
        "doc_action_execution_plan_id": artifact_receipt.get("doc_action_execution_plan_id"),
        "doc_action_execution_plan_sha256": artifact_receipt.get("doc_action_execution_plan_sha256"),
        "source_doc_retirement_plan_id": artifact_receipt.get("source_doc_retirement_plan_id"),
        "source_doc_retirement_plan_sha256": artifact_receipt.get("source_doc_retirement_plan_sha256"),
        "artifact_selection": {
            "selection_mode": "action_id" if artifact_action_id else "first_artifact",
            "requested_action_id": artifact_action_id,
        },
        "selected_artifact": selected_artifact,
        "approval_request": approval_request,
        "approval_policy": {
            "approval_packet_only": True,
            "requires_artifact_receipt": True,
            "requires_readback_receipt": True,
            "source_hash_recheck_required": True,
            "artifact_hash_recheck_required": True,
            "approval_granted": False,
            "live_execution_allowed": False,
            "source_file_write_allowed": False,
            "source_file_move_allowed": False,
            "source_file_delete_allowed": False,
            "archive_create_allowed": False,
            "generated_surface_rewrite_allowed": False,
            "raw_patch_stored_in_ams_state": False,
            "raw_source_markdown_stored_in_ams_state": False,
            "raw_readback_stored_in_ams_state": False,
            "executor_required_for_source_writes": True,
        },
        "required_gates": required_gates,
        "approval_granted": False,
        "live_execution_allowed": False,
        "source_file_write_allowed": False,
        "source_file_move_allowed": False,
        "source_file_delete_allowed": False,
        "archive_create_allowed": False,
        "generated_surface_rewrite_allowed": False,
        "approval_actions": [],
        "execution_actions": [],
        "source_write_actions": [],
        "live_boundaries": dict(LIVE_BOUNDARIES),
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["doc_action_patch_artifact_approval_packet_sha256"] = _hash_without(
        record,
        "doc_action_patch_artifact_approval_packet_sha256",
    )
    return deepcopy(record)


def validate_doc_action_patch_artifact_approval_packet_record(
    record: dict[str, Any],
    *,
    artifact_receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record(
            "doc_action_patch_artifact_approval_packet.schema.json",
            record,
            location="doc_action_patch_artifact_approval_packet",
        )
    except SchemaValidationError:
        reason_codes.append("doc_action_patch_artifact_approval.schema_invalid")
    expected_hash = record.get("doc_action_patch_artifact_approval_packet_sha256")
    if expected_hash and expected_hash != _hash_without(record, "doc_action_patch_artifact_approval_packet_sha256"):
        reason_codes.append("doc_action_patch_artifact_approval.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("doc_action_patch_artifact_approval.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("doc_action_patch_artifact_approval.status_invalid")
    _validate_authority(record, reason_codes)
    selected_artifact = record.get("selected_artifact") or {}
    _validate_selected_artifact(record, selected_artifact, reason_codes)
    if artifact_receipt is None:
        reason_codes.append("doc_action_patch_artifact_approval.artifact_receipt_missing")
    else:
        _validate_artifact_receipt_ref(record, artifact_receipt, selected_artifact, reason_codes)
    expected_gates = _required_gates(
        artifact_receipt=artifact_receipt or {},
        selected_artifact=selected_artifact,
    )
    if record.get("required_gates") != expected_gates:
        reason_codes.append("doc_action_patch_artifact_approval.required_gates_mismatch")
    expected_status = _status(expected_gates)
    if record.get("status") != expected_status:
        reason_codes.append("doc_action_patch_artifact_approval.status_mismatch")
    expected_reasons = _reason_codes(expected_gates, expected_status)
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("doc_action_patch_artifact_approval.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _approval_request() -> dict[str, Any]:
    return {
        "required_review_steps": REQUIRED_REVIEW_STEPS,
        "required_readback_phrases": REQUIRED_READBACK_PHRASES,
        "operator_readback_captured": False,
        "raw_readback_stored": False,
        "approval_granted_by_readback": False,
    }


def _selected_artifact(
    *,
    root: Path,
    artifact_receipt: dict[str, Any],
    artifact_action_id: str | None,
) -> dict[str, Any]:
    artifacts = [artifact for artifact in artifact_receipt.get("artifacts") or [] if isinstance(artifact, dict)]
    if artifact_action_id:
        matches = [artifact for artifact in artifacts if artifact.get("action_id") == artifact_action_id]
        if not matches:
            raise ValueError(f"doc action patch artifact action not found: {artifact_action_id}")
        artifact = matches[0]
    elif artifacts:
        artifact = sorted(
            artifacts,
            key=lambda item: (str(item.get("artifact_path") or ""), str(item.get("action_id") or "")),
        )[0]
    else:
        raise ValueError("doc action patch artifact receipt has no artifacts")
    artifact_path = Path(str(artifact.get("artifact_path") or "")).expanduser().resolve(strict=False)
    source_ref = deepcopy(artifact.get("source_ref") or {})
    current_source_ref = _source_ref(root, str(artifact.get("source_path") or ""))
    source_hash_matches_artifact_receipt = _source_ref_matches(source_ref, current_source_ref)
    artifact_exists = artifact_path.is_file()
    current_artifact_sha256 = _file_sha256(artifact_path) if artifact_exists else None
    text = artifact_path.read_text(encoding="utf-8") if artifact_exists else ""
    return {
        "action_id": artifact.get("action_id"),
        "source_path": artifact.get("source_path"),
        "target_surface": artifact.get("target_surface"),
        "planned_operation": artifact.get("planned_operation"),
        "patch_kind": artifact.get("patch_kind"),
        "artifact_path": str(artifact_path),
        "artifact_path_under_source_root": path_is_under(artifact_path, root),
        "artifact_sha256": artifact.get("artifact_sha256"),
        "artifact_line_count": artifact.get("artifact_line_count"),
        "artifact_size_bytes": artifact.get("artifact_size_bytes"),
        "artifact_exists": artifact_exists,
        "artifact_hash_verified": artifact_exists and current_artifact_sha256 == artifact.get("artifact_sha256"),
        "artifact_line_count_verified": artifact_exists and len(text.splitlines()) == artifact.get("artifact_line_count"),
        "artifact_size_bytes_verified": artifact_exists and len(text.encode("utf-8")) == artifact.get("artifact_size_bytes"),
        "source_ref": source_ref,
        "source_hash_matches_artifact_receipt": source_hash_matches_artifact_receipt,
        "source_file_exists": current_source_ref.get("exists") is True,
        "source_file_under_source_root": current_source_ref.get("under_source_root") is True,
        "source_file_rewritten": False,
        "source_file_deleted": False,
        "source_file_moved": False,
        "archive_created": False,
        "generated_surface_rewritten": False,
        "raw_patch_stored_in_ams_state": False,
        "raw_source_markdown_stored_in_ams_state": False,
    }


def _validate_authority(record: dict[str, Any], reason_codes: list[str]) -> None:
    approval_request = record.get("approval_request") or {}
    if approval_request.get("required_review_steps") != REQUIRED_REVIEW_STEPS:
        reason_codes.append("doc_action_patch_artifact_approval.required_review_steps_mismatch")
    if approval_request.get("required_readback_phrases") != REQUIRED_READBACK_PHRASES:
        reason_codes.append("doc_action_patch_artifact_approval.required_readback_phrases_mismatch")
    for key in ("operator_readback_captured", "raw_readback_stored", "approval_granted_by_readback"):
        if approval_request.get(key) is not False:
            reason_codes.append(f"doc_action_patch_artifact_approval.approval_request_{key}_not_false")
    policy = record.get("approval_policy") or {}
    for key in (
        "approval_packet_only",
        "requires_artifact_receipt",
        "requires_readback_receipt",
        "source_hash_recheck_required",
        "artifact_hash_recheck_required",
        "executor_required_for_source_writes",
    ):
        if policy.get(key) is not True:
            reason_codes.append(f"doc_action_patch_artifact_approval.policy_{key}_not_true")
    false_policy_keys = (
        "approval_granted",
        "live_execution_allowed",
        "source_file_write_allowed",
        "source_file_move_allowed",
        "source_file_delete_allowed",
        "archive_create_allowed",
        "generated_surface_rewrite_allowed",
        "raw_patch_stored_in_ams_state",
        "raw_source_markdown_stored_in_ams_state",
        "raw_readback_stored_in_ams_state",
    )
    for key in false_policy_keys:
        if policy.get(key) is not False:
            reason_codes.append(f"doc_action_patch_artifact_approval.policy_{key}_not_false")
    for key in (
        "approval_granted",
        "live_execution_allowed",
        "source_file_write_allowed",
        "source_file_move_allowed",
        "source_file_delete_allowed",
        "archive_create_allowed",
        "generated_surface_rewrite_allowed",
    ):
        if record.get(key) is not False:
            reason_codes.append(f"doc_action_patch_artifact_approval.{key}_not_false")
    for key in ("approval_actions", "execution_actions", "source_write_actions"):
        if record.get(key) != []:
            reason_codes.append(f"doc_action_patch_artifact_approval.{key}_not_empty")
    for key, expected in LIVE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"doc_action_patch_artifact_approval.{key}_boundary_mismatch")


def _validate_selected_artifact(
    record: dict[str, Any],
    selected_artifact: dict[str, Any],
    reason_codes: list[str],
) -> None:
    root = Path(str(record.get("source_root") or "")).expanduser().resolve(strict=False)
    artifact_path = Path(str(selected_artifact.get("artifact_path") or "")).expanduser().resolve(strict=False)
    if selected_artifact.get("artifact_path_under_source_root") is not False:
        reason_codes.append("doc_action_patch_artifact_approval.artifact_path_under_source_root")
    if selected_artifact.get("artifact_exists") is not artifact_path.is_file():
        reason_codes.append("doc_action_patch_artifact_approval.artifact_exists_mismatch")
    if artifact_path.is_file():
        text = artifact_path.read_text(encoding="utf-8")
        if selected_artifact.get("artifact_sha256") != _file_sha256(artifact_path):
            reason_codes.append("doc_action_patch_artifact_approval.artifact_hash_mismatch")
        if selected_artifact.get("artifact_line_count") != len(text.splitlines()):
            reason_codes.append("doc_action_patch_artifact_approval.artifact_line_count_mismatch")
        if selected_artifact.get("artifact_size_bytes") != len(text.encode("utf-8")):
            reason_codes.append("doc_action_patch_artifact_approval.artifact_size_bytes_mismatch")
    if selected_artifact.get("artifact_hash_verified") is not bool(
        artifact_path.is_file() and selected_artifact.get("artifact_sha256") == _file_sha256(artifact_path)
    ):
        reason_codes.append("doc_action_patch_artifact_approval.artifact_hash_verified_mismatch")
    source_ref = selected_artifact.get("source_ref") or {}
    current_source_ref = _source_ref(root, str(selected_artifact.get("source_path") or ""))
    if selected_artifact.get("source_hash_matches_artifact_receipt") is not _source_ref_matches(
        source_ref,
        current_source_ref,
    ):
        reason_codes.append("doc_action_patch_artifact_approval.source_hash_match_flag_mismatch")
    for field in ("path", "exists", "under_source_root", "sha256", "line_count", "size_bytes", "raw_content_stored"):
        if source_ref.get(field) != current_source_ref.get(field):
            reason_codes.append(f"doc_action_patch_artifact_approval.source_ref_{field}_mismatch")
    for key in (
        "source_file_rewritten",
        "source_file_deleted",
        "source_file_moved",
        "archive_created",
        "generated_surface_rewritten",
        "raw_patch_stored_in_ams_state",
        "raw_source_markdown_stored_in_ams_state",
    ):
        if selected_artifact.get(key) is not False:
            reason_codes.append(f"doc_action_patch_artifact_approval.selected_artifact_{key}_not_false")


def _validate_artifact_receipt_ref(
    record: dict[str, Any],
    artifact_receipt: dict[str, Any],
    selected_artifact: dict[str, Any],
    reason_codes: list[str],
) -> None:
    if record.get("doc_action_patch_artifact_receipt_id") != artifact_receipt.get(
        "doc_action_patch_artifact_receipt_id"
    ):
        reason_codes.append("doc_action_patch_artifact_approval.artifact_receipt_id_mismatch")
    if record.get("doc_action_patch_artifact_receipt_sha256") != artifact_receipt.get(
        "doc_action_patch_artifact_receipt_sha256"
    ):
        reason_codes.append("doc_action_patch_artifact_approval.artifact_receipt_hash_mismatch")
    artifact_source_root = str(artifact_receipt.get("source_root") or "")
    if artifact_source_root and record.get("source_root") != str(Path(artifact_source_root).resolve(strict=False)):
        reason_codes.append("doc_action_patch_artifact_approval.source_root_mismatch")
    if artifact_receipt.get("doc_action_patch_artifact_receipt_sha256") != _hash_without(
        artifact_receipt,
        "doc_action_patch_artifact_receipt_sha256",
    ):
        reason_codes.append("doc_action_patch_artifact_approval.artifact_receipt_hash_not_current")
    if artifact_receipt.get("status") != "artifact_ready":
        reason_codes.append("doc_action_patch_artifact_approval.artifact_receipt_not_ready")
    for key in (
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
        if record.get(key) != artifact_receipt.get(key):
            reason_codes.append(f"doc_action_patch_artifact_approval.{key}_mismatch")
    matching_artifacts = [
        artifact
        for artifact in artifact_receipt.get("artifacts") or []
        if artifact.get("action_id") == selected_artifact.get("action_id")
        and artifact.get("artifact_path") == selected_artifact.get("artifact_path")
    ]
    if not matching_artifacts:
        reason_codes.append("doc_action_patch_artifact_approval.selected_artifact_missing_from_receipt")
        return
    artifact = matching_artifacts[0]
    for key in (
        "source_path",
        "target_surface",
        "planned_operation",
        "patch_kind",
        "artifact_sha256",
        "artifact_line_count",
        "artifact_size_bytes",
        "source_ref",
    ):
        if selected_artifact.get(key) != artifact.get(key):
            reason_codes.append(f"doc_action_patch_artifact_approval.selected_artifact_{key}_mismatch")


def _required_gates(*, artifact_receipt: dict[str, Any], selected_artifact: dict[str, Any]) -> dict[str, bool]:
    receipt_hash_current = (
        bool(artifact_receipt)
        and artifact_receipt.get("doc_action_patch_artifact_receipt_sha256")
        == _hash_without(artifact_receipt, "doc_action_patch_artifact_receipt_sha256")
    )
    return {
        "artifact_receipt_present": bool(artifact_receipt.get("doc_action_patch_artifact_receipt_id")),
        "artifact_receipt_ready": artifact_receipt.get("status") == "artifact_ready",
        "artifact_receipt_hash_current": receipt_hash_current,
        "selected_artifact_present": bool(selected_artifact.get("action_id")),
        "artifact_file_present": selected_artifact.get("artifact_exists") is True,
        "artifact_hash_verified": selected_artifact.get("artifact_hash_verified") is True,
        "artifact_line_count_verified": selected_artifact.get("artifact_line_count_verified") is True,
        "artifact_size_bytes_verified": selected_artifact.get("artifact_size_bytes_verified") is True,
        "artifact_path_outside_source_root": selected_artifact.get("artifact_path_under_source_root") is False,
        "source_hash_matches_artifact_receipt": selected_artifact.get("source_hash_matches_artifact_receipt") is True,
        "source_file_present": selected_artifact.get("source_file_exists") is True,
        "source_file_under_source_root": selected_artifact.get("source_file_under_source_root") is True,
        "raw_patch_not_stored_in_ams_state": selected_artifact.get("raw_patch_stored_in_ams_state") is False,
        "source_files_not_modified": (
            selected_artifact.get("source_file_rewritten") is False
            and selected_artifact.get("source_file_deleted") is False
            and selected_artifact.get("source_file_moved") is False
        ),
        "generated_surfaces_not_rewritten": selected_artifact.get("generated_surface_rewritten") is False,
        "approval_packet_grants_no_authority": True,
        "source_writes_disabled": True,
    }


def _status(required_gates: dict[str, bool]) -> str:
    return "ready_for_operator_review" if required_gates and all(required_gates.values()) else "blocked"


def _reason_codes(required_gates: dict[str, bool], status: str) -> list[str]:
    if status == "ready_for_operator_review":
        return ["doc_action_patch_artifact_approval.ready_for_operator_review"]
    missing = [key for key, value in sorted(required_gates.items()) if value is not True]
    return [f"doc_action_patch_artifact_approval.gate_failed:{key}" for key in missing] or [
        "doc_action_patch_artifact_approval.blocked"
    ]


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
