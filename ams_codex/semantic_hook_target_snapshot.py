from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any

from .models import hash_without as _hash_without, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .semantic_hook_approval import validate_semantic_hook_approval_binding_record
from .store import JsonStore
from .workspace import path_is_under, repo_root


SCHEMA_VERSION = "ams.ams_codex.semantic_hook_target_snapshot.v0"
STATUSES = {"ready_for_operator_review", "blocked"}
MAX_HASH_BYTES = 1024 * 1024

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
    "raw_content_stored": False,
    "secret_stored": False,
}


class SemanticHookTargetSnapshotStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        semantic_hook_approval_binding_id: str,
        source_root: str | Path | None = None,
        home_root: str | Path | None = None,
        label: str = "manual-semantic-hook-target-snapshot",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            binding = (state.get("semantic_hook_approval_bindings") or {}).get(semantic_hook_approval_binding_id)
            if not binding:
                raise KeyError(f"semantic hook approval binding not found: {semantic_hook_approval_binding_id}")
            install_plan = (state.get("semantic_hook_install_plans") or {}).get(binding.get("semantic_hook_install_plan_id"))
            if not install_plan:
                raise KeyError(f"semantic hook install plan not found: {binding.get('semantic_hook_install_plan_id')}")
            record = build_semantic_hook_target_snapshot(
                binding=binding,
                install_plan=install_plan,
                source_root=source_root,
                home_root=home_root,
                label=label,
            )
            snapshot_id = record["semantic_hook_target_snapshot_id"]
            state.setdefault("semantic_hook_target_snapshots", {})[snapshot_id] = record
            state.setdefault("indexes", {}).setdefault("semantic_hook_target_snapshot_ids", {})[snapshot_id] = snapshot_id
            return deepcopy(record)


def build_semantic_hook_target_snapshot(
    *,
    binding: dict[str, Any],
    install_plan: dict[str, Any],
    source_root: str | Path | None = None,
    home_root: str | Path | None = None,
    label: str = "manual-semantic-hook-target-snapshot",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False) if source_root else repo_root()
    home = Path(home_root).expanduser().resolve(strict=False) if home_root else Path.home().resolve(strict=False)
    target_snapshots = [
        _target_snapshot(target=target, source_root=root, home_root=home)
        for target in install_plan.get("install_targets") or []
    ]
    rollback_drill = _rollback_drill(target_snapshots)
    required_gates = _required_gates(
        binding=binding,
        install_plan=install_plan,
        target_snapshots=target_snapshots,
        rollback_drill=rollback_drill,
    )
    reason_codes = _reason_codes(required_gates, target_snapshots)
    status = "ready_for_operator_review" if reason_codes == ["semantic_hook_target_snapshot.ready_for_operator_review"] else "blocked"
    record = {
        "schema_version": SCHEMA_VERSION,
        "semantic_hook_target_snapshot_id": stable_id(
            "semhooktarget",
            label,
            binding.get("semantic_hook_approval_binding_id"),
            binding.get("semantic_hook_approval_binding_sha256"),
            install_plan.get("semantic_hook_install_plan_id"),
            install_plan.get("semantic_hook_install_plan_sha256"),
            target_snapshots,
            now,
        ),
        "label": label,
        "source_root": str(root),
        "home_root": str(home),
        "semantic_hook_approval_binding_id": binding.get("semantic_hook_approval_binding_id"),
        "semantic_hook_approval_binding_sha256": binding.get("semantic_hook_approval_binding_sha256"),
        "semantic_hook_install_plan_id": install_plan.get("semantic_hook_install_plan_id"),
        "semantic_hook_install_plan_sha256": install_plan.get("semantic_hook_install_plan_sha256"),
        "target_count": len(target_snapshots),
        "target_snapshots": target_snapshots,
        "rollback_drill": rollback_drill,
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
    record["semantic_hook_target_snapshot_sha256"] = _hash_without(record, "semantic_hook_target_snapshot_sha256")
    return deepcopy(record)


def validate_semantic_hook_target_snapshot_record(
    record: dict[str, Any],
    *,
    binding: dict[str, Any] | None = None,
    install_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("semantic_hook_target_snapshot.schema.json", record, location="semantic_hook_target_snapshot")
    except SchemaValidationError:
        reason_codes.append("semantic_hook_target_snapshot.schema_invalid")
    expected_hash = record.get("semantic_hook_target_snapshot_sha256")
    if expected_hash and expected_hash != _hash_without(record, "semantic_hook_target_snapshot_sha256"):
        reason_codes.append("semantic_hook_target_snapshot.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("semantic_hook_target_snapshot.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("semantic_hook_target_snapshot.status_invalid")
    for key, expected in LIVE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"semantic_hook_target_snapshot.{key}_not_false")
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
            reason_codes.append(f"semantic_hook_target_snapshot.{key}_not_false")
    for key in ("install_actions", "trust_actions", "start_actions"):
        if record.get(key) != []:
            reason_codes.append(f"semantic_hook_target_snapshot.{key}_not_empty")
    for snapshot in record.get("target_snapshots") or []:
        if snapshot.get("raw_content_stored") is not False:
            reason_codes.append("semantic_hook_target_snapshot.raw_content_stored_not_false")
        if snapshot.get("secret_stored") is not False:
            reason_codes.append("semantic_hook_target_snapshot.secret_stored_not_false")
        if snapshot.get("write_performed") is not False:
            reason_codes.append("semantic_hook_target_snapshot.write_performed_not_false")
    rollback = record.get("rollback_drill") or {}
    if rollback.get("backup_file_written") is not False:
        reason_codes.append("semantic_hook_target_snapshot.backup_file_written_not_false")
    if rollback.get("restore_performed") is not False:
        reason_codes.append("semantic_hook_target_snapshot.restore_performed_not_false")
    if rollback.get("raw_backup_content_stored") is not False:
        reason_codes.append("semantic_hook_target_snapshot.raw_backup_content_stored_not_false")
    if install_plan is not None:
        if record.get("semantic_hook_install_plan_sha256") != install_plan.get("semantic_hook_install_plan_sha256"):
            reason_codes.append("semantic_hook_target_snapshot.install_plan_hash_mismatch")
        if record.get("target_count") != len(install_plan.get("install_targets") or []):
            reason_codes.append("semantic_hook_target_snapshot.target_count_mismatch")
    if binding is not None:
        if record.get("semantic_hook_approval_binding_sha256") != binding.get("semantic_hook_approval_binding_sha256"):
            reason_codes.append("semantic_hook_target_snapshot.approval_binding_hash_mismatch")
        binding_validation = validate_semantic_hook_approval_binding_record(binding, install_plan=install_plan)
        if not binding_validation["ok"]:
            reason_codes.extend(
                f"semantic_hook_target_snapshot.binding:{reason}" for reason in binding_validation["reason_codes"]
            )
    if binding is not None and install_plan is not None:
        expected_gates = _required_gates(
            binding=binding,
            install_plan=install_plan,
            target_snapshots=record.get("target_snapshots") or [],
            rollback_drill=rollback,
        )
        if record.get("required_gates") != expected_gates:
            reason_codes.append("semantic_hook_target_snapshot.required_gates_mismatch")
        expected_reasons = _reason_codes(expected_gates, record.get("target_snapshots") or [])
        expected_status = (
            "ready_for_operator_review"
            if expected_reasons == ["semantic_hook_target_snapshot.ready_for_operator_review"]
            else "blocked"
        )
        if record.get("status") != expected_status:
            reason_codes.append("semantic_hook_target_snapshot.status_reason_mismatch")
        if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
            reason_codes.append("semantic_hook_target_snapshot.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _target_snapshot(*, target: dict[str, Any], source_root: Path, home_root: Path) -> dict[str, Any]:
    raw_path = str(target.get("path") or "")
    resolved = _resolve_target_path(raw_path, home_root=home_root)
    path = resolved["declared_path"]
    resolved_path = resolved["resolved_path"]
    exists = path.exists()
    is_symlink = path.is_symlink()
    is_file = path.is_file() if exists and not is_symlink else False
    is_dir = path.is_dir() if exists and not is_symlink else False
    traversal = ".." in Path(raw_path.replace("~", "")).parts
    under_allowed_root = path_is_under(resolved_path, source_root) or path_is_under(resolved_path, home_root)
    size_bytes = path.stat().st_size if exists and not is_symlink else 0
    over_hash_limit = is_file and size_bytes > MAX_HASH_BYTES
    current_sha = _file_sha256(path) if is_file and not over_hash_limit else None
    safe = under_allowed_root and not traversal and not is_symlink and not is_dir and not over_hash_limit
    return {
        "target": target.get("target"),
        "declared_path": raw_path,
        "resolved_path": str(resolved_path),
        "path_was_tilde": resolved["path_was_tilde"],
        "exists": exists,
        "is_file": is_file,
        "is_directory": is_dir,
        "is_symlink": is_symlink,
        "path_under_allowed_root": under_allowed_root,
        "traversal_detected": traversal,
        "size_bytes": size_bytes,
        "over_hash_limit": over_hash_limit,
        "current_sha256": current_sha,
        "raw_content_stored": False,
        "secret_stored": False,
        "write_performed": False,
        "restore_action": "restore_file_sha256" if is_file else "delete_created_file",
        "safe_for_no_write_drill": safe,
    }


def _resolve_target_path(raw_path: str, *, home_root: Path) -> dict[str, Any]:
    path_was_tilde = raw_path == "~" or raw_path.startswith("~/")
    if path_was_tilde:
        path = home_root / raw_path[2:]
    else:
        path = Path(raw_path).expanduser()
    declared = path.absolute()
    return {
        "declared_path": declared,
        "resolved_path": declared.resolve(strict=False),
        "path_was_tilde": path_was_tilde,
    }


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return f"sha256:{digest}"


def _rollback_drill(target_snapshots: list[dict[str, Any]]) -> dict[str, Any]:
    ready = all(snapshot.get("safe_for_no_write_drill") is True for snapshot in target_snapshots)
    return {
        "mode": "hash_only_no_write",
        "target_count": len(target_snapshots),
        "safe_target_count": len([snapshot for snapshot in target_snapshots if snapshot.get("safe_for_no_write_drill") is True]),
        "backup_file_written": False,
        "restore_performed": False,
        "raw_backup_content_stored": False,
        "rollback_rehearsal_passed": ready,
        "rollback_strategy": "restore existing file hashes or delete newly-created files; no write performed in this gate",
    }


def _required_gates(
    *,
    binding: dict[str, Any],
    install_plan: dict[str, Any],
    target_snapshots: list[dict[str, Any]],
    rollback_drill: dict[str, Any],
) -> dict[str, bool]:
    binding_ready = binding.get("status") == "ready_for_operator_approval"
    install_plan_ready = install_plan.get("status") == "ready_for_operator_review"
    paths_safe = all(snapshot.get("path_under_allowed_root") is True for snapshot in target_snapshots)
    no_symlinks = all(snapshot.get("is_symlink") is False for snapshot in target_snapshots)
    no_traversal = all(snapshot.get("traversal_detected") is False for snapshot in target_snapshots)
    hash_only = all(
        snapshot.get("raw_content_stored") is False
        and snapshot.get("secret_stored") is False
        and snapshot.get("write_performed") is False
        for snapshot in target_snapshots
    )
    return {
        "approval_binding_ready": binding_ready,
        "approval_binding_inert": _binding_inert(binding),
        "install_plan_ready": install_plan_ready,
        "target_count_matches_install_plan": len(target_snapshots) == len(install_plan.get("install_targets") or []),
        "target_paths_under_allowed_roots": paths_safe,
        "no_symlinks": no_symlinks,
        "no_path_traversal": no_traversal,
        "no_directories": all(snapshot.get("is_directory") is False for snapshot in target_snapshots),
        "within_hash_size_limit": all(snapshot.get("over_hash_limit") is False for snapshot in target_snapshots),
        "snapshots_hash_only": hash_only,
        "rollback_drill_no_write": rollback_drill.get("backup_file_written") is False
        and rollback_drill.get("restore_performed") is False
        and rollback_drill.get("raw_backup_content_stored") is False,
        "rollback_rehearsal_passed": rollback_drill.get("rollback_rehearsal_passed") is True,
        "approval_granted_false": True,
        "live_install_allowed_false": True,
    }


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


def _reason_codes(gates: dict[str, bool], target_snapshots: list[dict[str, Any]]) -> list[str]:
    reasons = [f"semantic_hook_target_snapshot.{key}_missing" for key, ok in gates.items() if not ok]
    for snapshot in target_snapshots:
        target = snapshot.get("target") or "unknown"
        if snapshot.get("is_symlink") is True:
            reasons.append(f"semantic_hook_target_snapshot.symlink_target:{target}")
        if snapshot.get("traversal_detected") is True:
            reasons.append(f"semantic_hook_target_snapshot.traversal_target:{target}")
        if snapshot.get("path_under_allowed_root") is not True:
            reasons.append(f"semantic_hook_target_snapshot.out_of_root_target:{target}")
    return sorted(set(reasons)) or ["semantic_hook_target_snapshot.ready_for_operator_review"]
