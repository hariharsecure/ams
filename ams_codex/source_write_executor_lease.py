from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any

from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .source_write_backup_preimage import validate_source_write_backup_preimage_receipt_record
from .store import JsonStore
from .workspace import path_is_under, repo_root


SCHEMA_VERSION = "ams.ams_codex.source_write_executor_lease.v0"
STATUSES = {"ready_for_source_write_receipt", "blocked"}

LIVE_BOUNDARIES = {
    "source_file_rewritten": False,
    "source_file_deleted": False,
    "source_file_moved": False,
    "source_backup_written": False,
    "rollback_executed": False,
    "archive_created": False,
    "generated_surface_rewritten": False,
    "raw_source_stored_in_ams_state": False,
    "raw_patch_stored_in_ams_state": False,
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


class SourceWriteExecutorLeaseStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        source_write_backup_preimage_receipt_id: str,
        source_root: str | Path | None = None,
        label: str = "manual-source-write-executor-lease",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            receipt = (state.get("source_write_backup_preimage_receipts") or {}).get(
                source_write_backup_preimage_receipt_id
            )
            if not isinstance(receipt, dict):
                raise KeyError(
                    "source write backup/preimage receipt not found: "
                    f"{source_write_backup_preimage_receipt_id}"
                )
            record = build_source_write_executor_lease(
                state=state,
                source_write_backup_preimage_receipt=receipt,
                source_root=source_root,
                label=label,
            )
            validation = validate_source_write_executor_lease_record(record, state=state)
            if not validation["ok"]:
                raise ValueError("; ".join(validation["reason_codes"]))
            lease_id = record["source_write_executor_lease_id"]
            state.setdefault("source_write_executor_leases", {})[lease_id] = record
            state.setdefault("indexes", {}).setdefault("source_write_executor_lease_ids", {})[
                lease_id
            ] = lease_id
            return deepcopy(record)


def build_source_write_executor_lease(
    *,
    state: dict[str, Any],
    source_write_backup_preimage_receipt: dict[str, Any],
    source_root: str | Path | None = None,
    label: str = "manual-source-write-executor-lease",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root_value = source_root or source_write_backup_preimage_receipt.get("source_root") or repo_root()
    root = Path(root_value).expanduser().resolve(strict=False)
    source_path = str(source_write_backup_preimage_receipt.get("source_path") or "")
    current_source_ref = _source_ref(root, source_path)
    backup_artifact_ref = _backup_artifact_ref(source_write_backup_preimage_receipt)
    scope = _lease_scope(root=root, source_path=source_path)
    receipt_validation = validate_source_write_backup_preimage_receipt_record(
        source_write_backup_preimage_receipt,
        state=state,
    )
    planned_id = stable_id(
        "srcwritelease",
        label,
        source_write_backup_preimage_receipt.get("source_write_backup_preimage_receipt_id"),
        source_write_backup_preimage_receipt.get("source_write_backup_preimage_receipt_sha256"),
        scope,
        current_source_ref,
        now,
    )
    overlapping = _active_overlapping_leases(state=state, scope_sha256=scope["scope_sha256"], self_id=planned_id)
    required_gates = _required_gates(
        source_write_backup_preimage_receipt=source_write_backup_preimage_receipt,
        receipt_validation=receipt_validation,
        current_source_ref=current_source_ref,
        backup_artifact_ref=backup_artifact_ref,
        overlapping_active_lease_ids=overlapping,
    )
    status = _status(required_gates)
    ready = status == "ready_for_source_write_receipt"
    lease_scope = {**scope, "exclusive": True, "active": ready, "overlapping_active_lease_ids": overlapping}
    record = {
        "schema_version": SCHEMA_VERSION,
        "source_write_executor_lease_id": planned_id,
        "label": label,
        "source_root": str(root),
        "source_path": source_path,
        "source_write_backup_preimage_receipt_id": source_write_backup_preimage_receipt.get(
            "source_write_backup_preimage_receipt_id"
        ),
        "source_write_backup_preimage_receipt_sha256": source_write_backup_preimage_receipt.get(
            "source_write_backup_preimage_receipt_sha256"
        ),
        "source_write_executor_preflight_id": source_write_backup_preimage_receipt.get(
            "source_write_executor_preflight_id"
        ),
        "source_write_executor_preflight_sha256": source_write_backup_preimage_receipt.get(
            "source_write_executor_preflight_sha256"
        ),
        "current_source_ref": current_source_ref,
        "backup_preimage_ref": {
            "backup_path": backup_artifact_ref.get("backup_path"),
            "backup_sha256": backup_artifact_ref.get("backup_sha256"),
            "source_preimage_sha256": backup_artifact_ref.get("source_preimage_sha256"),
            "backup_exists": backup_artifact_ref.get("backup_exists"),
            "backup_hash_matches_receipt": backup_artifact_ref.get("backup_hash_matches_receipt"),
            "raw_source_stored_in_ams_state": False,
        },
        "lease_scope": lease_scope,
        "lease_policy": {
            "requires_backup_preimage_receipt": True,
            "requires_backup_preimage_hash_current": True,
            "requires_exclusive_scope": True,
            "requires_source_hash_match_before_write": True,
            "requires_source_write_receipt": True,
            "requires_post_write_replay": True,
            "requires_rollback_readback": True,
            "source_write_allowed_by_lease": False,
            "source_file_write_allowed": False,
            "source_file_move_allowed": False,
            "source_file_delete_allowed": False,
            "source_backup_write_allowed": False,
            "rollback_allowed": False,
            "raw_source_stored_in_ams_state": False,
            "raw_patch_stored_in_ams_state": False,
            "raw_executor_output_stored_in_ams_state": False,
        },
        "required_gates": required_gates,
        "lease_active": ready,
        "source_write_receipt_required": True,
        "post_write_replay_required": True,
        "rollback_readback_required": True,
        "apply_allowed": False,
        "live_execution_allowed": False,
        "source_file_write_allowed": False,
        "source_file_move_allowed": False,
        "source_file_delete_allowed": False,
        "source_backup_write_allowed": False,
        "rollback_allowed": False,
        "archive_create_allowed": False,
        "generated_surface_rewrite_allowed": False,
        "provider_call_allowed": False,
        "network_call_allowed": False,
        "lease_actions": _lease_actions(lease_scope, backup_artifact_ref) if ready else [],
        "source_write_actions": [],
        "rollback_actions": [],
        "post_write_replay_actions": [],
        "live_boundaries": dict(LIVE_BOUNDARIES),
        "status": status,
        "reason_codes": _reason_codes(required_gates, status),
        "created_at": now,
    }
    record["source_write_executor_lease_sha256"] = _hash_without(
        record,
        "source_write_executor_lease_sha256",
    )
    return deepcopy(record)


def validate_source_write_executor_lease_record(record: dict[str, Any], *, state: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("source_write_executor_lease.schema.json", record, location="source_write_executor_lease")
    except SchemaValidationError:
        reason_codes.append("source_write_executor_lease.schema_invalid")
    if record.get("source_write_executor_lease_sha256") != _hash_without(
        record,
        "source_write_executor_lease_sha256",
    ):
        reason_codes.append("source_write_executor_lease.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("source_write_executor_lease.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("source_write_executor_lease.status_invalid")
    receipt_id = record.get("source_write_backup_preimage_receipt_id")
    receipt = (state.get("source_write_backup_preimage_receipts") or {}).get(receipt_id)
    if not isinstance(receipt, dict):
        reason_codes.append("source_write_executor_lease.backup_preimage_receipt_missing")
        receipt = {}
    elif record.get("source_write_backup_preimage_receipt_sha256") != receipt.get(
        "source_write_backup_preimage_receipt_sha256"
    ):
        reason_codes.append("source_write_executor_lease.backup_preimage_receipt_hash_mismatch")
    rebuilt = build_source_write_executor_lease(
        state=state,
        source_write_backup_preimage_receipt=receipt,
        source_root=record.get("source_root"),
        label=record.get("label") or "manual-source-write-executor-lease",
        now=record.get("created_at"),
    )
    for key in (
        "source_path",
        "current_source_ref",
        "backup_preimage_ref",
        "lease_scope",
        "required_gates",
        "lease_active",
        "status",
        "reason_codes",
        "lease_actions",
    ):
        if record.get(key) != rebuilt.get(key):
            reason_codes.append(f"source_write_executor_lease.{key}_mismatch")
    _validate_policy_authority_and_boundaries(record, reason_codes)
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _required_gates(
    *,
    source_write_backup_preimage_receipt: dict[str, Any],
    receipt_validation: dict[str, Any],
    current_source_ref: dict[str, Any],
    backup_artifact_ref: dict[str, Any],
    overlapping_active_lease_ids: list[str],
) -> dict[str, bool]:
    captured = source_write_backup_preimage_receipt.get("captured_source_ref") or {}
    return {
        "backup_preimage_receipt_present": bool(
            source_write_backup_preimage_receipt.get("source_write_backup_preimage_receipt_id")
        ),
        "backup_preimage_receipt_hash_current": receipt_validation["ok"],
        "backup_preimage_captured": source_write_backup_preimage_receipt.get("status")
        == "backup_preimage_captured",
        "backup_artifact_exists": backup_artifact_ref.get("backup_exists") is True,
        "backup_hash_matches_receipt": backup_artifact_ref.get("backup_hash_matches_receipt") is True,
        "source_exists": current_source_ref.get("exists") is True,
        "source_under_root": current_source_ref.get("under_source_root") is True,
        "source_hash_matches_backup_preimage": current_source_ref.get("sha256") == captured.get("sha256")
        and current_source_ref.get("size_bytes") == captured.get("size_bytes"),
        "exclusive_scope_clear": not overlapping_active_lease_ids,
        "source_write_receipt_required": True,
        "post_write_replay_required": True,
        "rollback_readback_required": True,
        "lease_grants_no_source_rewrite_authority": True,
    }


def _backup_artifact_ref(receipt: dict[str, Any]) -> dict[str, Any]:
    artifact = receipt.get("backup_artifact") or {}
    backup_path_value = str(artifact.get("backup_path") or "")
    backup_path = Path(backup_path_value).expanduser().resolve(strict=False) if backup_path_value else None
    backup_exists = bool(backup_path and backup_path.is_file())
    backup_sha256 = _file_sha256(backup_path) if backup_exists and backup_path else None
    return {
        "backup_path": str(backup_path) if backup_path else "",
        "backup_exists": backup_exists,
        "backup_sha256": backup_sha256,
        "source_preimage_sha256": artifact.get("source_preimage_sha256"),
        "backup_hash_matches_receipt": backup_exists and backup_sha256 == artifact.get("backup_sha256"),
        "raw_source_stored_in_ams_state": False,
    }


def _lease_scope(*, root: Path, source_path: str) -> dict[str, Any]:
    material = {
        "source_root": str(root),
        "source_path": source_path,
    }
    return {
        **material,
        "scope_sha256": sha256_text(canonical_json(material)),
    }


def _active_overlapping_leases(*, state: dict[str, Any], scope_sha256: str, self_id: str) -> list[str]:
    overlapping: list[str] = []
    for lease_id, lease in (state.get("source_write_executor_leases") or {}).items():
        if lease_id == self_id or not isinstance(lease, dict):
            continue
        if lease.get("lease_active") is not True:
            continue
        if (lease.get("lease_scope") or {}).get("scope_sha256") == scope_sha256:
            overlapping.append(str(lease_id))
    return sorted(overlapping)


def _lease_actions(lease_scope: dict[str, Any], backup_artifact_ref: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "action": "open_exclusive_source_write_executor_lease",
            "scope_sha256": lease_scope.get("scope_sha256"),
            "source_path": lease_scope.get("source_path"),
            "backup_sha256": backup_artifact_ref.get("backup_sha256"),
            "source_write_allowed": False,
            "source_write_receipt_required": True,
            "post_write_replay_required": True,
        }
    ]


def _validate_policy_authority_and_boundaries(record: dict[str, Any], reason_codes: list[str]) -> None:
    policy = record.get("lease_policy") or {}
    for key in (
        "requires_backup_preimage_receipt",
        "requires_backup_preimage_hash_current",
        "requires_exclusive_scope",
        "requires_source_hash_match_before_write",
        "requires_source_write_receipt",
        "requires_post_write_replay",
        "requires_rollback_readback",
    ):
        if policy.get(key) is not True:
            reason_codes.append(f"source_write_executor_lease.policy_{key}_not_true")
    for key in (
        "source_write_allowed_by_lease",
        "source_file_write_allowed",
        "source_file_move_allowed",
        "source_file_delete_allowed",
        "source_backup_write_allowed",
        "rollback_allowed",
        "raw_source_stored_in_ams_state",
        "raw_patch_stored_in_ams_state",
        "raw_executor_output_stored_in_ams_state",
    ):
        if policy.get(key) is not False:
            reason_codes.append(f"source_write_executor_lease.policy_{key}_not_false")
    for key in (
        "apply_allowed",
        "live_execution_allowed",
        "source_file_write_allowed",
        "source_file_move_allowed",
        "source_file_delete_allowed",
        "source_backup_write_allowed",
        "rollback_allowed",
        "archive_create_allowed",
        "generated_surface_rewrite_allowed",
        "provider_call_allowed",
        "network_call_allowed",
    ):
        if record.get(key) is not False:
            reason_codes.append(f"source_write_executor_lease.{key}_not_false")
    if record.get("source_write_actions") != []:
        reason_codes.append("source_write_executor_lease.source_write_actions_not_empty")
    if record.get("rollback_actions") != []:
        reason_codes.append("source_write_executor_lease.rollback_actions_not_empty")
    if record.get("post_write_replay_actions") != []:
        reason_codes.append("source_write_executor_lease.post_write_replay_actions_not_empty")
    for key, expected in LIVE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"source_write_executor_lease.{key}_boundary_mismatch")
    if record.get("lease_active") is not (record.get("status") == "ready_for_source_write_receipt"):
        reason_codes.append("source_write_executor_lease.lease_active_status_mismatch")


def _source_ref(root: Path, relative_path: str) -> dict[str, Any]:
    safe_rel = relative_path.strip("/")
    path = (root / safe_rel).resolve(strict=False)
    under_root = path_is_under(path, root)
    exists = under_root and path.is_file()
    return {
        "path": relative_path,
        "absolute_path": str(path),
        "exists": exists,
        "under_source_root": under_root,
        "sha256": _file_sha256(path) if exists else None,
        "size_bytes": path.stat().st_size if exists else 0,
        "raw_content_stored": False,
    }


def _status(required_gates: dict[str, bool]) -> str:
    return "ready_for_source_write_receipt" if required_gates and all(required_gates.values()) else "blocked"


def _reason_codes(required_gates: dict[str, bool], status: str) -> list[str]:
    if status == "ready_for_source_write_receipt":
        return ["source_write_executor_lease.ready_for_source_write_receipt"]
    missing = [key for key, value in sorted(required_gates.items()) if value is not True]
    return [f"source_write_executor_lease.gate_failed:{key}" for key in missing] or [
        "source_write_executor_lease.blocked"
    ]


def _file_sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
