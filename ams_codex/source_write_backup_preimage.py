from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any

from .durability import fsync_dir, fsync_path
from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .source_write_preflight import validate_source_write_executor_preflight_record
from .store import JsonStore
from .workspace import path_is_under, repo_root


SCHEMA_VERSION = "ams.ams_codex.source_write_backup_preimage_receipt.v0"
STATUSES = {"backup_preimage_captured", "blocked"}
DEFAULT_BACKUP_ROOT = Path.home() / ".ams" / "artifacts" / "source_write_preimages"

LIVE_BOUNDARIES = {
    "source_backup_written": False,
    "backup_artifact_written": False,
    "source_file_rewritten": False,
    "source_file_deleted": False,
    "source_file_moved": False,
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


class SourceWriteBackupPreimageReceiptStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        source_write_executor_preflight_id: str,
        source_root: str | Path | None = None,
        backup_root: str | Path | None = None,
        label: str = "manual-source-write-backup-preimage",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            preflight = (state.get("source_write_executor_preflights") or {}).get(
                source_write_executor_preflight_id
            )
            if not isinstance(preflight, dict):
                raise KeyError(f"source write executor preflight not found: {source_write_executor_preflight_id}")
            record = build_source_write_backup_preimage_receipt(
                state=state,
                source_write_executor_preflight=preflight,
                source_root=source_root,
                backup_root=backup_root,
                label=label,
            )
            validation = validate_source_write_backup_preimage_receipt_record(record, state=state)
            if not validation["ok"]:
                raise ValueError("; ".join(validation["reason_codes"]))
            receipt_id = record["source_write_backup_preimage_receipt_id"]
            state.setdefault("source_write_backup_preimage_receipts", {})[receipt_id] = record
            state.setdefault("indexes", {}).setdefault("source_write_backup_preimage_receipt_ids", {})[
                receipt_id
            ] = receipt_id
            return deepcopy(record)


def build_source_write_backup_preimage_receipt(
    *,
    state: dict[str, Any],
    source_write_executor_preflight: dict[str, Any],
    source_root: str | Path | None = None,
    backup_root: str | Path | None = None,
    label: str = "manual-source-write-backup-preimage",
    now: str | None = None,
    write_backup: bool = True,
) -> dict[str, Any]:
    now = now or utc_now()
    root_value = source_root or source_write_executor_preflight.get("source_root") or repo_root()
    root = Path(root_value).expanduser().resolve(strict=False)
    out_root = Path(backup_root or DEFAULT_BACKUP_ROOT).expanduser().resolve(strict=False)
    source_path = str(source_write_executor_preflight.get("source_path") or "")
    current_source_ref = _source_ref(root, source_path)
    preflight_source_ref = deepcopy(source_write_executor_preflight.get("current_source_ref") or {})
    preflight_validation = validate_source_write_executor_preflight_record(
        source_write_executor_preflight,
        state=state,
    )
    backup_root_allowed = _backup_root_allowed(root=root, backup_root=out_root)
    planned_id = stable_id(
        "srcwritepreimage",
        label,
        source_write_executor_preflight.get("source_write_executor_preflight_id"),
        source_write_executor_preflight.get("source_write_executor_preflight_sha256"),
        source_path,
        current_source_ref,
        str(out_root),
        now,
    )
    backup_dir = out_root / planned_id
    backup_path = backup_dir / f"{_safe_name(source_path)}.preimage.bak"
    can_capture = (
        preflight_validation["ok"]
        and source_write_executor_preflight.get("status") == "ready_for_backup_preimage_capture"
        and _preflight_grants_no_source_write_authority(source_write_executor_preflight)
        and current_source_ref.get("exists") is True
        and current_source_ref.get("under_source_root") is True
        and _source_refs_match(preflight_source_ref, current_source_ref)
        and backup_root_allowed
    )
    if can_capture and write_backup:
        _write_backup(root=root, source_path=source_path, backup_path=backup_path)
    backup_artifact = _backup_artifact_ref(
        root=root,
        backup_root=out_root,
        backup_path=backup_path if can_capture else None,
        source_path=source_path,
        source_preimage_ref=current_source_ref,
    )
    rollback_ref = _rollback_ref(root=root, source_path=source_path, backup_artifact=backup_artifact)
    post_write = {
        "required": True,
        "required_after_source_write": True,
        "performed": False,
        "post_write_replay_receipt_id": "",
        "postimage_sha256": None,
        "raw_executor_output_stored_in_ams_state": False,
    }
    required_gates = _required_gates(
        source_write_executor_preflight=source_write_executor_preflight,
        preflight_validation=preflight_validation,
        current_source_ref=current_source_ref,
        preflight_source_ref=preflight_source_ref,
        backup_root_allowed=backup_root_allowed,
        backup_artifact=backup_artifact,
        rollback_ref=rollback_ref,
        post_write_replay_requirements=post_write,
    )
    status = _status(required_gates)
    record = {
        "schema_version": SCHEMA_VERSION,
        "source_write_backup_preimage_receipt_id": planned_id,
        "label": label,
        "source_root": str(root),
        "backup_root": str(out_root),
        "backup_dir": str(backup_dir),
        "source_write_executor_preflight_id": source_write_executor_preflight.get(
            "source_write_executor_preflight_id"
        ),
        "source_write_executor_preflight_sha256": source_write_executor_preflight.get(
            "source_write_executor_preflight_sha256"
        ),
        "doc_action_patch_apply_acceptance_packet_id": source_write_executor_preflight.get(
            "doc_action_patch_apply_acceptance_packet_id"
        ),
        "doc_action_patch_apply_acceptance_packet_sha256": source_write_executor_preflight.get(
            "doc_action_patch_apply_acceptance_packet_sha256"
        ),
        "source_path": source_path,
        "preflight_source_ref": preflight_source_ref,
        "captured_source_ref": current_source_ref,
        "source_hash_matches_preflight": _source_refs_match(preflight_source_ref, current_source_ref),
        "backup_preimage_policy": {
            "requires_source_write_executor_preflight": True,
            "requires_preflight_hash_current": True,
            "requires_backup_root_outside_source_root": True,
            "requires_source_hash_match_before_backup": True,
            "backup_artifact_write_allowed": True,
            "source_backup_write_allowed": True,
            "source_file_write_allowed": False,
            "source_file_move_allowed": False,
            "source_file_delete_allowed": False,
            "archive_create_allowed": False,
            "generated_surface_rewrite_allowed": False,
            "raw_source_stored_in_ams_state": False,
            "raw_patch_stored_in_ams_state": False,
            "raw_executor_output_stored_in_ams_state": False,
            "post_write_replay_required": True,
        },
        "backup_artifact": backup_artifact,
        "backup_summary": _backup_summary(backup_artifact),
        "rollback_ref": rollback_ref,
        "post_write_replay_requirements": post_write,
        "required_gates": required_gates,
        "backup_preimage_captured": status == "backup_preimage_captured",
        "apply_allowed": False,
        "live_execution_allowed": False,
        "source_file_write_allowed": False,
        "source_file_move_allowed": False,
        "source_file_delete_allowed": False,
        "source_backup_write_allowed": status == "backup_preimage_captured",
        "archive_create_allowed": False,
        "generated_surface_rewrite_allowed": False,
        "provider_call_allowed": False,
        "network_call_allowed": False,
        "backup_actions": _backup_actions(backup_artifact) if status == "backup_preimage_captured" else [],
        "source_write_actions": [],
        "rollback_actions": [],
        "post_write_replay_actions": [],
        "live_boundaries": {
            **LIVE_BOUNDARIES,
            "source_backup_written": status == "backup_preimage_captured",
            "backup_artifact_written": status == "backup_preimage_captured",
        },
        "status": status,
        "reason_codes": _reason_codes(required_gates, status),
        "created_at": now,
    }
    record["source_write_backup_preimage_receipt_sha256"] = _hash_without(
        record,
        "source_write_backup_preimage_receipt_sha256",
    )
    return deepcopy(record)


def validate_source_write_backup_preimage_receipt_record(
    record: dict[str, Any],
    *,
    state: dict[str, Any],
) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record(
            "source_write_backup_preimage_receipt.schema.json",
            record,
            location="source_write_backup_preimage_receipt",
        )
    except SchemaValidationError:
        reason_codes.append("source_write_backup_preimage.schema_invalid")
    if record.get("source_write_backup_preimage_receipt_sha256") != _hash_without(
        record,
        "source_write_backup_preimage_receipt_sha256",
    ):
        reason_codes.append("source_write_backup_preimage.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("source_write_backup_preimage.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("source_write_backup_preimage.status_invalid")
    preflight_id = record.get("source_write_executor_preflight_id")
    preflight = (state.get("source_write_executor_preflights") or {}).get(preflight_id)
    if not isinstance(preflight, dict):
        reason_codes.append("source_write_backup_preimage.preflight_missing")
        preflight = {}
    elif record.get("source_write_executor_preflight_sha256") != preflight.get(
        "source_write_executor_preflight_sha256"
    ):
        reason_codes.append("source_write_backup_preimage.preflight_hash_mismatch")
    rebuilt = build_source_write_backup_preimage_receipt(
        state=state,
        source_write_executor_preflight=preflight,
        source_root=record.get("source_root"),
        backup_root=record.get("backup_root"),
        label=record.get("label") or "manual-source-write-backup-preimage",
        now=record.get("created_at"),
        write_backup=False,
    )
    for key in (
        "source_path",
        "preflight_source_ref",
        "captured_source_ref",
        "source_hash_matches_preflight",
        "backup_artifact",
        "backup_summary",
        "rollback_ref",
        "post_write_replay_requirements",
        "required_gates",
        "backup_preimage_captured",
        "status",
        "reason_codes",
        "backup_actions",
    ):
        if record.get(key) != rebuilt.get(key):
            reason_codes.append(f"source_write_backup_preimage.{key}_mismatch")
    _validate_policy_authority_and_boundaries(record, reason_codes)
    _validate_backup_artifact(record, reason_codes)
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _required_gates(
    *,
    source_write_executor_preflight: dict[str, Any],
    preflight_validation: dict[str, Any],
    current_source_ref: dict[str, Any],
    preflight_source_ref: dict[str, Any],
    backup_root_allowed: bool,
    backup_artifact: dict[str, Any],
    rollback_ref: dict[str, Any],
    post_write_replay_requirements: dict[str, Any],
) -> dict[str, bool]:
    return {
        "preflight_present": bool(source_write_executor_preflight.get("source_write_executor_preflight_id")),
        "preflight_hash_current": preflight_validation["ok"],
        "preflight_ready_for_backup_preimage_capture": source_write_executor_preflight.get("status")
        == "ready_for_backup_preimage_capture",
        "preflight_grants_no_source_write_authority": _preflight_grants_no_source_write_authority(
            source_write_executor_preflight
        ),
        "source_exists": current_source_ref.get("exists") is True,
        "source_under_root": current_source_ref.get("under_source_root") is True,
        "source_hash_matches_preflight": _source_refs_match(preflight_source_ref, current_source_ref),
        "backup_root_outside_source_root": backup_root_allowed,
        "backup_artifact_written": backup_artifact.get("backup_artifact_written") is True,
        "backup_path_outside_source_root": backup_artifact.get("backup_path_under_source_root") is False,
        "backup_path_under_backup_root": backup_artifact.get("backup_path_under_backup_root") is True,
        "backup_hash_matches_source_preimage": backup_artifact.get("backup_hash_matches_source_preimage") is True,
        "raw_source_not_stored_in_ams_state": backup_artifact.get("raw_source_stored_in_ams_state") is False,
        "source_files_not_modified": backup_artifact.get("source_file_rewritten") is False
        and backup_artifact.get("source_file_deleted") is False
        and backup_artifact.get("source_file_moved") is False,
        "rollback_not_executed": rollback_ref.get("restore_performed") is False,
        "post_write_replay_required": post_write_replay_requirements.get("required") is True,
        "post_write_replay_not_yet_performed": post_write_replay_requirements.get("performed") is False,
        "source_write_still_disabled": True,
    }


def _backup_artifact_ref(
    *,
    root: Path,
    backup_root: Path,
    backup_path: Path | None,
    source_path: str,
    source_preimage_ref: dict[str, Any],
) -> dict[str, Any]:
    backup_exists = bool(backup_path and backup_path.is_file())
    backup_sha256 = _file_sha256(backup_path) if backup_exists and backup_path else None
    backup_size = backup_path.stat().st_size if backup_exists and backup_path else 0
    source_sha256 = source_preimage_ref.get("sha256")
    return {
        "source_path": source_path,
        "backup_path": str(backup_path) if backup_path else "",
        "backup_path_under_source_root": path_is_under(backup_path, root) if backup_path else False,
        "backup_path_under_backup_root": path_is_under(backup_path, backup_root) if backup_path else False,
        "backup_exists": backup_exists,
        "backup_sha256": backup_sha256,
        "backup_size_bytes": backup_size,
        "source_preimage_sha256": source_sha256,
        "source_preimage_size_bytes": source_preimage_ref.get("size_bytes"),
        "backup_hash_matches_source_preimage": bool(source_sha256)
        and bool(backup_sha256)
        and source_sha256 == backup_sha256
        and source_preimage_ref.get("size_bytes") == backup_size,
        "backup_artifact_written": backup_exists,
        "raw_source_stored_in_ams_state": False,
        "raw_patch_stored_in_ams_state": False,
        "raw_executor_output_stored_in_ams_state": False,
        "source_file_rewritten": False,
        "source_file_deleted": False,
        "source_file_moved": False,
        "rollback_executed": False,
        "archive_created": False,
        "generated_surface_rewritten": False,
    }


def _backup_summary(backup_artifact: dict[str, Any]) -> dict[str, Any]:
    hashes = [backup_artifact.get("backup_sha256")] if backup_artifact.get("backup_sha256") else []
    return {
        "backup_count": 1 if backup_artifact.get("backup_exists") is True else 0,
        "backup_set_sha256": sha256_text(canonical_json(sorted(hashes))),
        "total_size_bytes": int(backup_artifact.get("backup_size_bytes") or 0),
        "source_preimage_sha256": backup_artifact.get("source_preimage_sha256"),
        "backup_hash_matches_source_preimage": backup_artifact.get("backup_hash_matches_source_preimage") is True,
        "raw_source_stored_in_ams_state": False,
        "source_files_modified": False,
        "rollback_performed": False,
    }


def _rollback_ref(*, root: Path, source_path: str, backup_artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_root": str(root),
        "source_path": source_path,
        "backup_path": backup_artifact.get("backup_path") or "",
        "backup_sha256": backup_artifact.get("backup_sha256"),
        "source_preimage_sha256": backup_artifact.get("source_preimage_sha256"),
        "restore_requires_operator_approval": True,
        "restore_performed": False,
        "post_restore_replay_required": True,
        "raw_source_stored_in_ams_state": False,
    }


def _backup_actions(backup_artifact: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "action": "capture_external_source_preimage_backup",
            "source_path": backup_artifact.get("source_path"),
            "backup_path": backup_artifact.get("backup_path"),
            "backup_sha256": backup_artifact.get("backup_sha256"),
            "source_preimage_sha256": backup_artifact.get("source_preimage_sha256"),
            "raw_source_stored_in_ams_state": False,
            "source_write_allowed": False,
            "post_write_replay_required": True,
        }
    ]


def _validate_policy_authority_and_boundaries(record: dict[str, Any], reason_codes: list[str]) -> None:
    policy = record.get("backup_preimage_policy") or {}
    for key in (
        "requires_source_write_executor_preflight",
        "requires_preflight_hash_current",
        "requires_backup_root_outside_source_root",
        "requires_source_hash_match_before_backup",
        "backup_artifact_write_allowed",
        "source_backup_write_allowed",
        "post_write_replay_required",
    ):
        if policy.get(key) is not True:
            reason_codes.append(f"source_write_backup_preimage.policy_{key}_not_true")
    for key in (
        "source_file_write_allowed",
        "source_file_move_allowed",
        "source_file_delete_allowed",
        "archive_create_allowed",
        "generated_surface_rewrite_allowed",
        "raw_source_stored_in_ams_state",
        "raw_patch_stored_in_ams_state",
        "raw_executor_output_stored_in_ams_state",
    ):
        if policy.get(key) is not False:
            reason_codes.append(f"source_write_backup_preimage.policy_{key}_not_false")
    for key in (
        "apply_allowed",
        "live_execution_allowed",
        "source_file_write_allowed",
        "source_file_move_allowed",
        "source_file_delete_allowed",
        "archive_create_allowed",
        "generated_surface_rewrite_allowed",
        "provider_call_allowed",
        "network_call_allowed",
    ):
        if record.get(key) is not False:
            reason_codes.append(f"source_write_backup_preimage.{key}_not_false")
    expected_backup_allowed = record.get("status") == "backup_preimage_captured"
    if record.get("source_backup_write_allowed") is not expected_backup_allowed:
        reason_codes.append("source_write_backup_preimage.source_backup_write_allowed_mismatch")
    if record.get("source_write_actions") != []:
        reason_codes.append("source_write_backup_preimage.source_write_actions_not_empty")
    if record.get("rollback_actions") != []:
        reason_codes.append("source_write_backup_preimage.rollback_actions_not_empty")
    if record.get("post_write_replay_actions") != []:
        reason_codes.append("source_write_backup_preimage.post_write_replay_actions_not_empty")
    live = record.get("live_boundaries") or {}
    if live.get("source_backup_written") is not expected_backup_allowed:
        reason_codes.append("source_write_backup_preimage.source_backup_written_boundary_mismatch")
    if live.get("backup_artifact_written") is not expected_backup_allowed:
        reason_codes.append("source_write_backup_preimage.backup_artifact_written_boundary_mismatch")
    for key, expected in LIVE_BOUNDARIES.items():
        if key in {"source_backup_written", "backup_artifact_written"}:
            continue
        if live.get(key) is not expected:
            reason_codes.append(f"source_write_backup_preimage.{key}_boundary_mismatch")


def _validate_backup_artifact(record: dict[str, Any], reason_codes: list[str]) -> None:
    root = Path(str(record.get("source_root") or "")).expanduser().resolve(strict=False)
    backup_root = Path(str(record.get("backup_root") or "")).expanduser().resolve(strict=False)
    artifact = record.get("backup_artifact") or {}
    if artifact.get("raw_source_stored_in_ams_state") is not False:
        reason_codes.append("source_write_backup_preimage.raw_source_stored")
    if artifact.get("backup_artifact_written") is not bool(artifact.get("backup_exists")):
        reason_codes.append("source_write_backup_preimage.backup_written_exists_mismatch")
    backup_path_value = str(artifact.get("backup_path") or "")
    if not backup_path_value:
        return
    backup_path = Path(backup_path_value).expanduser().resolve(strict=False)
    if artifact.get("backup_path_under_source_root") is not path_is_under(backup_path, root):
        reason_codes.append("source_write_backup_preimage.backup_path_under_source_root_mismatch")
    if artifact.get("backup_path_under_backup_root") is not path_is_under(backup_path, backup_root):
        reason_codes.append("source_write_backup_preimage.backup_path_under_backup_root_mismatch")
    if artifact.get("backup_path_under_source_root") is not False:
        reason_codes.append("source_write_backup_preimage.backup_path_under_source_root")
    if artifact.get("backup_path_under_backup_root") is not True:
        reason_codes.append("source_write_backup_preimage.backup_path_not_under_backup_root")
    if not backup_path.is_file():
        reason_codes.append("source_write_backup_preimage.backup_artifact_missing")
        return
    actual_sha256 = _file_sha256(backup_path)
    if artifact.get("backup_sha256") != actual_sha256:
        reason_codes.append("source_write_backup_preimage.backup_artifact_hash_mismatch")
    if artifact.get("backup_size_bytes") != backup_path.stat().st_size:
        reason_codes.append("source_write_backup_preimage.backup_artifact_size_mismatch")
    if artifact.get("backup_sha256") != artifact.get("source_preimage_sha256"):
        reason_codes.append("source_write_backup_preimage.backup_hash_source_preimage_mismatch")


def _preflight_grants_no_source_write_authority(preflight: dict[str, Any]) -> bool:
    return (
        preflight.get("apply_allowed") is False
        and preflight.get("live_execution_allowed") is False
        and preflight.get("source_file_write_allowed") is False
        and preflight.get("source_file_move_allowed") is False
        and preflight.get("source_file_delete_allowed") is False
        and preflight.get("source_backup_write_allowed") is False
        and preflight.get("source_write_actions") == []
        and preflight.get("backup_actions") == []
    )


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


def _source_refs_match(expected: dict[str, Any], current: dict[str, Any]) -> bool:
    return (
        bool(expected)
        and expected.get("path") == current.get("path")
        and expected.get("exists") is True
        and current.get("exists") is True
        and expected.get("sha256") == current.get("sha256")
        and expected.get("size_bytes") == current.get("size_bytes")
    )


def _write_backup(*, root: Path, source_path: str, backup_path: Path) -> None:
    source = (root / source_path.strip("/")).resolve(strict=False)
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path.write_bytes(source.read_bytes())
    fsync_path(backup_path)
    fsync_dir(backup_path.parent)


def _backup_root_allowed(*, root: Path, backup_root: Path) -> bool:
    return backup_root != root and not path_is_under(backup_root, root)


def _status(required_gates: dict[str, bool]) -> str:
    return "backup_preimage_captured" if required_gates and all(required_gates.values()) else "blocked"


def _reason_codes(required_gates: dict[str, bool], status: str) -> list[str]:
    if status == "backup_preimage_captured":
        return ["source_write_backup_preimage.backup_preimage_captured"]
    missing = [key for key, value in sorted(required_gates.items()) if value is not True]
    return [f"source_write_backup_preimage.gate_failed:{key}" for key in missing] or [
        "source_write_backup_preimage.blocked"
    ]


def _file_sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_name(source_path: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in source_path)
    return safe.strip("._") or "source"
