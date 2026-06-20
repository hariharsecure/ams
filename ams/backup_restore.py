from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib
from pathlib import Path
import shutil
from typing import Any

from .durability import fsync_dir, fsync_path
from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .store import JsonStore


STATUSES = {"passed", "failed"}


class StoreBackupDrillStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        backup_path: str | Path,
        restore_path: str | Path,
        label: str = "manual-backup-restore-drill",
        overwrite: bool = False,
    ) -> dict[str, Any]:
        source_path = self.store.path.expanduser().resolve(strict=False)
        backup = Path(backup_path).expanduser().resolve(strict=False)
        restore = Path(restore_path).expanduser().resolve(strict=False)
        _copy_store(source_path, backup, overwrite=overwrite)
        _copy_store(backup, restore, overwrite=overwrite)

        source_state = self.store.load()
        backup_state = JsonStore(backup).load()
        restore_state = JsonStore(restore).load()
        record = build_store_backup_drill(
            label=label,
            source_store_path=source_path,
            backup_snapshot_path=backup,
            restore_store_path=restore,
            source_state=source_state,
            backup_state=backup_state,
            restore_state=restore_state,
            backup_file_sha256=_sha256_file(backup),
            overwrite_allowed=overwrite,
        )
        validation = validate_store_backup_drill_record(record)
        if not validation["ok"]:
            raise ValueError("; ".join(validation["reason_codes"]))
        with self.store.locked() as state:
            drill_id = record["store_backup_drill_id"]
            state.setdefault("store_backup_drills", {})[drill_id] = record
            state.setdefault("indexes", {}).setdefault("store_backup_drill_ids", {})[drill_id] = drill_id
        return deepcopy(record)


def build_store_backup_drill(
    *,
    label: str,
    source_store_path: str | Path,
    backup_snapshot_path: str | Path,
    restore_store_path: str | Path,
    source_state: dict[str, Any],
    backup_state: dict[str, Any],
    restore_state: dict[str, Any],
    backup_file_sha256: str,
    overwrite_allowed: bool = False,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    source_replay = _replay_check(source_state)
    backup_replay = _replay_check(backup_state)
    restore_replay = _replay_check(restore_state)
    source_state_sha256 = sha256_text(canonical_json(source_state))
    backup_state_sha256 = sha256_text(canonical_json(backup_state))
    restore_state_sha256 = sha256_text(canonical_json(restore_state))
    reason_codes = _reason_codes(
        source_replay_ok=bool(source_replay["ok"]),
        backup_replay_ok=bool(backup_replay["ok"]),
        restore_replay_ok=bool(restore_replay["ok"]),
        source_state_sha256=source_state_sha256,
        backup_state_sha256=backup_state_sha256,
        restore_state_sha256=restore_state_sha256,
    )
    status = "passed" if reason_codes == ["store_backup_drill.passed"] else "failed"
    record = {
        "schema_version": "ams.ams.store_backup_drill.v0",
        "store_backup_drill_id": stable_id(
            "storedrill",
            label,
            str(source_store_path),
            str(backup_snapshot_path),
            str(restore_store_path),
            source_state_sha256,
            backup_state_sha256,
            restore_state_sha256,
            now,
        ),
        "label": label,
        "source_store_path": str(source_store_path),
        "backup_snapshot_path": str(backup_snapshot_path),
        "restore_store_path": str(restore_store_path),
        "source_state_sha256": source_state_sha256,
        "backup_state_sha256": backup_state_sha256,
        "restore_state_sha256": restore_state_sha256,
        "backup_file_sha256": backup_file_sha256,
        "copy_method": "shutil.copy2+fsync",
        "overwrite_allowed": overwrite_allowed,
        "source_replay_ok": bool(source_replay["ok"]),
        "backup_replay_ok": bool(backup_replay["ok"]),
        "restore_replay_ok": bool(restore_replay["ok"]),
        "source_error_count": len(source_replay.get("errors") or []),
        "backup_error_count": len(backup_replay.get("errors") or []),
        "restore_error_count": len(restore_replay.get("errors") or []),
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["drill_sha256"] = _hash_without(record, "drill_sha256")
    return deepcopy(record)


def validate_store_backup_drill_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    expected_hash = record.get("drill_sha256")
    if expected_hash and expected_hash != _hash_without(record, "drill_sha256"):
        reason_codes.append("store_backup_drill.hash_mismatch")
    if record.get("status") not in STATUSES:
        reason_codes.append("store_backup_drill.status_invalid")
    for key in (
        "source_state_sha256",
        "backup_state_sha256",
        "restore_state_sha256",
        "backup_file_sha256",
    ):
        if not str(record.get(key) or "").startswith("sha256:"):
            reason_codes.append(f"store_backup_drill.{key}_missing")
    expected_reasons = _reason_codes(
        source_replay_ok=bool(record.get("source_replay_ok")),
        backup_replay_ok=bool(record.get("backup_replay_ok")),
        restore_replay_ok=bool(record.get("restore_replay_ok")),
        source_state_sha256=str(record.get("source_state_sha256") or ""),
        backup_state_sha256=str(record.get("backup_state_sha256") or ""),
        restore_state_sha256=str(record.get("restore_state_sha256") or ""),
    )
    expected_status = "passed" if expected_reasons == ["store_backup_drill.passed"] else "failed"
    if record.get("status") != expected_status:
        reason_codes.append("store_backup_drill.status_reason_mismatch")
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("store_backup_drill.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _reason_codes(
    *,
    source_replay_ok: bool,
    backup_replay_ok: bool,
    restore_replay_ok: bool,
    source_state_sha256: str,
    backup_state_sha256: str,
    restore_state_sha256: str,
) -> list[str]:
    reasons: list[str] = []
    if not source_replay_ok:
        reasons.append("store_backup_drill.source_replay_failed")
    if not backup_replay_ok:
        reasons.append("store_backup_drill.backup_replay_failed")
    if not restore_replay_ok:
        reasons.append("store_backup_drill.restore_replay_failed")
    if backup_state_sha256 != source_state_sha256:
        reasons.append("store_backup_drill.backup_state_hash_mismatch")
    if restore_state_sha256 != backup_state_sha256:
        reasons.append("store_backup_drill.restore_state_hash_mismatch")
    return reasons or ["store_backup_drill.passed"]


def _copy_store(source: Path, target: Path, *, overwrite: bool) -> None:
    if not source.exists():
        raise FileNotFoundError(source)
    if target.exists() and not overwrite:
        raise FileExistsError(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    fsync_path(target)
    fsync_dir(target.parent)


def _replay_check(state: dict[str, Any]) -> dict[str, Any]:
    module = importlib.import_module("ams.replay")
    return module.replay_check(state)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()
