from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .store import JsonStore


SOURCE_TYPES = {"url", "file", "dataset", "unknown"}
DOWNLOAD_STATUSES = {"not_downloaded", "downloaded_external"}
QUARANTINE_STATUSES = {"quarantined", "approved_for_index", "rejected"}
FORBIDDEN_RAW_KEYS = {"text", "content", "raw", "raw_content", "body", "bytes"}


class DownloadedArtifactQuarantineStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        source_uri: str,
        source_type: str = "unknown",
        declared_media_type: str | None = None,
        declared_sha256: str | None = None,
        size_bytes: int | None = None,
        download_status: str = "not_downloaded",
        quarantine_status: str = "quarantined",
        local_path: str | None = None,
        reviewed_by: str | None = None,
        reviewed_at: str | None = None,
        reason_codes: list[str] | None = None,
    ) -> dict[str, Any]:
        record = build_downloaded_artifact_quarantine(
            source_uri=source_uri,
            source_type=source_type,
            declared_media_type=declared_media_type,
            declared_sha256=declared_sha256,
            size_bytes=size_bytes,
            download_status=download_status,
            quarantine_status=quarantine_status,
            local_path=local_path,
            reviewed_by=reviewed_by,
            reviewed_at=reviewed_at,
            reason_codes=reason_codes,
        )
        validation = validate_downloaded_artifact_quarantine_record(record)
        if not validation["ok"]:
            raise ValueError("; ".join(validation["reason_codes"]))
        with self.store.locked() as state:
            quarantine_id = record["downloaded_artifact_quarantine_id"]
            state.setdefault("downloaded_artifact_quarantines", {})[quarantine_id] = record
            state.setdefault("indexes", {}).setdefault("downloaded_artifact_quarantine_ids", {})[
                quarantine_id
            ] = quarantine_id
        return deepcopy(record)


def build_downloaded_artifact_quarantine(
    *,
    source_uri: str,
    source_type: str = "unknown",
    declared_media_type: str | None = None,
    declared_sha256: str | None = None,
    size_bytes: int | None = None,
    download_status: str = "not_downloaded",
    quarantine_status: str = "quarantined",
    local_path: str | None = None,
    reviewed_by: str | None = None,
    reviewed_at: str | None = None,
    reason_codes: list[str] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    source_type = source_type if source_type in SOURCE_TYPES else "unknown"
    download_status = download_status if download_status in DOWNLOAD_STATUSES else "not_downloaded"
    quarantine_status = quarantine_status if quarantine_status in QUARANTINE_STATUSES else "quarantined"
    codes = list(reason_codes or [])
    if not codes:
        codes = _default_reason_codes(download_status, quarantine_status)
    record = {
        "schema_version": "ams.ams_codex.downloaded_artifact_quarantine.v0",
        "downloaded_artifact_quarantine_id": stable_id(
            "daq",
            source_uri,
            source_type,
            declared_sha256,
            size_bytes,
            download_status,
            quarantine_status,
            now,
        ),
        "source_uri": source_uri,
        "source_type": source_type,
        "declared_media_type": declared_media_type,
        "declared_sha256": declared_sha256,
        "size_bytes": size_bytes,
        "download_status": download_status,
        "quarantine_status": quarantine_status,
        "network_fetch_allowed": False,
        "raw_content_stored": False,
        "local_path": local_path,
        "reviewed_by": reviewed_by,
        "reviewed_at": reviewed_at,
        "reason_codes": codes,
        "created_at": now,
        "updated_at": now,
    }
    record["quarantine_sha256"] = _hash_without(record, "quarantine_sha256")
    return deepcopy(record)


def validate_downloaded_artifact_quarantine_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    expected_hash = record.get("quarantine_sha256")
    if expected_hash and expected_hash != _hash_without(record, "quarantine_sha256"):
        reason_codes.append("downloaded_artifact_quarantine.hash_mismatch")
    if record.get("downloaded_artifact_quarantine_id") is None:
        reason_codes.append("downloaded_artifact_quarantine.id_missing")
    if not record.get("source_uri"):
        reason_codes.append("downloaded_artifact_quarantine.source_uri_missing")
    if record.get("source_type") not in SOURCE_TYPES:
        reason_codes.append("downloaded_artifact_quarantine.source_type_invalid")
    if record.get("download_status") not in DOWNLOAD_STATUSES:
        reason_codes.append("downloaded_artifact_quarantine.download_status_invalid")
    if record.get("quarantine_status") not in QUARANTINE_STATUSES:
        reason_codes.append("downloaded_artifact_quarantine.quarantine_status_invalid")
    if record.get("network_fetch_allowed") is not False:
        reason_codes.append("downloaded_artifact_quarantine.network_fetch_allowed_not_false")
    if record.get("raw_content_stored") is not False:
        reason_codes.append("downloaded_artifact_quarantine.raw_content_stored_not_false")
    declared_sha = record.get("declared_sha256")
    if declared_sha is not None and not str(declared_sha).startswith("sha256:"):
        reason_codes.append("downloaded_artifact_quarantine.declared_sha256_invalid")
    if record.get("quarantine_status") == "approved_for_index":
        if not record.get("reviewed_by") or not record.get("reviewed_at"):
            reason_codes.append("downloaded_artifact_quarantine.approval_without_review")
        if record.get("download_status") != "downloaded_external":
            reason_codes.append("downloaded_artifact_quarantine.approval_without_external_download")
        if not record.get("declared_sha256"):
            reason_codes.append("downloaded_artifact_quarantine.approval_without_hash")
    for key in FORBIDDEN_RAW_KEYS:
        if key in record:
            reason_codes.append("downloaded_artifact_quarantine.raw_field_present")
            break
    return {"ok": not reason_codes, "reason_codes": reason_codes}


def quarantine_is_approved(record: dict[str, Any]) -> bool:
    return (
        record.get("download_status") == "downloaded_external"
        and record.get("quarantine_status") == "approved_for_index"
        and bool(record.get("declared_sha256"))
        and bool(record.get("reviewed_by"))
        and bool(record.get("reviewed_at"))
        and validate_downloaded_artifact_quarantine_record(record)["ok"]
    )


def _default_reason_codes(download_status: str, quarantine_status: str) -> list[str]:
    if quarantine_status == "approved_for_index":
        return ["downloaded_artifact_quarantine.operator_approved"]
    if quarantine_status == "rejected":
        return ["downloaded_artifact_quarantine.rejected"]
    if download_status == "downloaded_external":
        return ["downloaded_artifact_quarantine.external_artifact_quarantined"]
    return ["downloaded_artifact_quarantine.no_download_performed"]
