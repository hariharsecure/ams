from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import re
from typing import Any

from .markdown_governance import _file_summary, _markdown_files, _milestone_sort_key
from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore


INDEX_SCHEMA_VERSION = "ams.ams.markdown_authority_index.v0"
ENTRY_SCHEMA_VERSION = "ams.ams.markdown_authority_entry.v0"

AUTHORITY_LEVELS = {"current", "supporting", "historical", "superseded", "evidence-only"}
STARTUP_AUTHORITY_LEVELS = {"current", "supporting"}
STATUSES = {"allow", "defer", "deny"}
ENTRY_STATUSES = {"active", "inactive"}
SUPERSESSION_MODES = {"correction", "temporal_update", "scope_refinement", "revocation", "duplicate"}

REQUIRED_STARTUP_PATHS = ("AGENTS.md", "GENERATED_STATUS.md", "STATUS.md", "MAP.md")
CURRENT_CONTROL_PATHS = {
    "AGENTS.md",
    "CLAUDE.md",
    "README.md",
    "STATUS.md",
    "MAP.md",
    "MILESTONES.md",
    "SYSTEM_DESIGN.md",
}
GENERATED_PATHS = {"GENERATED_STATUS.md", "NEW_CODEX_SESSION.md"}


class MarkdownAuthorityStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        source_root: str | Path,
        label: str = "manual-markdown-authority-index",
        supersession_edges: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        record_set = build_markdown_authority_index(
            source_root=source_root,
            label=label,
            supersession_edges=supersession_edges,
        )
        with self.store.locked() as state:
            entries = record_set["entries"]
            for entry in entries:
                entry_id = entry["markdown_authority_entry_id"]
                state.setdefault("markdown_authority_entries", {})[entry_id] = entry
                state.setdefault("indexes", {}).setdefault("markdown_authority_entry_ids", {})[entry_id] = entry_id
            index = record_set["index"]
            index_id = index["markdown_authority_index_id"]
            state.setdefault("markdown_authority_indexes", {})[index_id] = index
            state.setdefault("indexes", {}).setdefault("markdown_authority_index_ids", {})[index_id] = index_id
            return deepcopy(record_set)


def build_markdown_authority_index(
    *,
    source_root: str | Path,
    label: str = "manual-markdown-authority-index",
    supersession_edges: list[dict[str, str]] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False)
    summaries = [_file_summary(path, root) for path in _markdown_files(root)]
    latest_milestone = _latest_milestone(summaries)
    generated_status = _generated_status_ref(root, latest_milestone)
    edges = _normalise_edges(supersession_edges or [])
    entries = [
        _entry_from_summary(
            summary,
            source_root=str(root),
            label=label,
            latest_milestone=latest_milestone,
            generated_status=generated_status,
            edges=edges,
            now=now,
        )
        for summary in summaries
    ]
    entries_by_path = {entry["path"]: entry for entry in entries}
    _apply_supersession_edges(entries_by_path, edges, now=now)
    for entry in entries:
        entry["reason_codes"] = _entry_reason_codes(entry)
        entry["markdown_authority_entry_sha256"] = _hash_without(entry, "markdown_authority_entry_sha256")

    startup_surface = sorted(entry["path"] for entry in entries if entry.get("startup_include"))
    entry_refs = [
        {
            "path": entry["path"],
            "markdown_authority_entry_id": entry["markdown_authority_entry_id"],
            "markdown_authority_entry_sha256": entry["markdown_authority_entry_sha256"],
        }
        for entry in sorted(entries, key=lambda row: str(row.get("path")))
    ]
    snapshot = _snapshot_hash(entries)
    policy = {
        "required_startup_paths": list(REQUIRED_STARTUP_PATHS),
        "startup_authority_levels": sorted(STARTUP_AUTHORITY_LEVELS),
        "raw_markdown_stored": False,
        "raw_session_content_stored": False,
        "prompt_text_stored": False,
        "transcript_text_stored": False,
        "embedding_payload_stored": False,
        "vector_payload_stored": False,
    }
    reason_codes = _index_reason_codes(
        entries=entries,
        generated_status=generated_status,
        edges=edges,
    )
    status = "allow" if reason_codes == ["markdown_authority_index.allow"] else "defer"
    index = {
        "schema_version": INDEX_SCHEMA_VERSION,
        "markdown_authority_index_id": stable_id(
            "mdauthidx",
            str(root),
            label,
            snapshot,
            generated_status,
            edges,
            now,
        ),
        "label": label,
        "source_root": str(root),
        "scan_mode": "markdown_authority_hash_only",
        "network_required": False,
        "raw_markdown_stored": False,
        "markdown_file_count": len(entries),
        "total_line_count": int(sum(entry["line_count"] for entry in entries)),
        "total_size_bytes": int(sum(entry["size_bytes"] for entry in entries)),
        "markdown_snapshot_sha256": snapshot,
        "entry_refs": entry_refs,
        "latest_milestone_doc": latest_milestone,
        "startup_surface": startup_surface,
        "generated_status": generated_status,
        "policy": policy,
        "supersession_edges": edges,
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    index["markdown_authority_index_sha256"] = _hash_without(index, "markdown_authority_index_sha256")
    return {"index": deepcopy(index), "entries": deepcopy(entries)}


def validate_markdown_authority_entry_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("markdown_authority_entry.schema.json", record, location="markdown_authority_entry")
    except SchemaValidationError:
        reason_codes.append("markdown_authority_entry.schema_invalid")
    if record.get("markdown_authority_entry_sha256") != _hash_without(
        record,
        "markdown_authority_entry_sha256",
    ):
        reason_codes.append("markdown_authority_entry.hash_mismatch")
    if record.get("schema_version") != ENTRY_SCHEMA_VERSION:
        reason_codes.append("markdown_authority_entry.schema_version_invalid")
    if record.get("authority_level") not in AUTHORITY_LEVELS:
        reason_codes.append("markdown_authority_entry.authority_level_invalid")
    if record.get("status") not in ENTRY_STATUSES:
        reason_codes.append("markdown_authority_entry.status_invalid")
    if record.get("raw_content_stored") is not False:
        reason_codes.append("markdown_authority_entry.raw_content_stored_not_false")
    if not str(record.get("source_sha256") or "").startswith("sha256:"):
        reason_codes.append("markdown_authority_entry.source_hash_missing")
    if record.get("startup_include") and record.get("authority_level") not in STARTUP_AUTHORITY_LEVELS:
        reason_codes.append("markdown_authority_entry.invalid_startup_authority")
    if record.get("startup_include") and record.get("status") != "active":
        reason_codes.append("markdown_authority_entry.invalid_startup_status")
    if record.get("authority_level") == "superseded":
        if record.get("startup_include") is not False:
            reason_codes.append("markdown_authority_entry.superseded_startup_include")
        if not record.get("superseded_by"):
            reason_codes.append("markdown_authority_entry.superseded_by_missing")
        if record.get("status") != "inactive":
            reason_codes.append("markdown_authority_entry.superseded_status_active")
        if not record.get("valid_until"):
            reason_codes.append("markdown_authority_entry.superseded_valid_until_missing")
    if record.get("authority_level") == "current" and record.get("superseded_by"):
        reason_codes.append("markdown_authority_entry.current_has_superseded_by")
    if record.get("reason_codes") != _entry_reason_codes(record):
        reason_codes.append("markdown_authority_entry.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def validate_markdown_authority_index_record(record: dict[str, Any], *, state: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("markdown_authority_index.schema.json", record, location="markdown_authority_index")
    except SchemaValidationError:
        reason_codes.append("markdown_authority_index.schema_invalid")
    if record.get("markdown_authority_index_sha256") != _hash_without(
        record,
        "markdown_authority_index_sha256",
    ):
        reason_codes.append("markdown_authority_index.hash_mismatch")
    if record.get("schema_version") != INDEX_SCHEMA_VERSION:
        reason_codes.append("markdown_authority_index.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("markdown_authority_index.status_invalid")
    if record.get("network_required") is not False or record.get("raw_markdown_stored") is not False:
        reason_codes.append("markdown_authority_index.live_or_raw_boundary_crossed")
    policy = record.get("policy") or {}
    for key in (
        "raw_markdown_stored",
        "raw_session_content_stored",
        "prompt_text_stored",
        "transcript_text_stored",
        "embedding_payload_stored",
        "vector_payload_stored",
    ):
        if policy.get(key) is not False:
            reason_codes.append(f"markdown_authority_index.policy_{key}_not_false")
    generated_status = record.get("generated_status") or {}
    if generated_status.get("raw_content_stored") is not False:
        reason_codes.append("markdown_authority_index.generated_status_raw_content_stored")
    refs = record.get("entry_refs") or []
    if len(refs) != len({ref.get("path") for ref in refs if isinstance(ref, dict)}):
        reason_codes.append("markdown_authority_index.duplicate_entry_path")
    entries: list[dict[str, Any]] = []
    entries_by_path: dict[str, dict[str, Any]] = {}
    for ref in refs:
        entry_id = ref.get("markdown_authority_entry_id")
        entry = (state.get("markdown_authority_entries") or {}).get(entry_id)
        if not entry:
            reason_codes.append("markdown_authority_index.entry_missing")
            continue
        entries.append(entry)
        entries_by_path[str(entry.get("path") or "")] = entry
        if ref.get("path") != entry.get("path"):
            reason_codes.append("markdown_authority_index.entry_path_mismatch")
        if ref.get("markdown_authority_entry_sha256") != entry.get("markdown_authority_entry_sha256"):
            reason_codes.append("markdown_authority_index.entry_hash_mismatch")
        validation = validate_markdown_authority_entry_record(entry)
        if not validation["ok"]:
            reason_codes.extend(validation["reason_codes"])
    if record.get("markdown_file_count") != len(entries):
        reason_codes.append("markdown_authority_index.file_count_mismatch")
    if record.get("total_line_count") != sum(int(entry.get("line_count", 0) or 0) for entry in entries):
        reason_codes.append("markdown_authority_index.total_line_count_mismatch")
    if record.get("total_size_bytes") != sum(int(entry.get("size_bytes", 0) or 0) for entry in entries):
        reason_codes.append("markdown_authority_index.total_size_bytes_mismatch")
    if entries and record.get("markdown_snapshot_sha256") != _snapshot_hash(entries):
        reason_codes.append("markdown_authority_index.snapshot_hash_mismatch")
    expected_startup = sorted(entry["path"] for entry in entries if entry.get("startup_include"))
    if record.get("startup_surface") != expected_startup:
        reason_codes.append("markdown_authority_index.startup_surface_mismatch")
    for path in record.get("startup_surface") or []:
        entry = entries_by_path.get(path)
        if not entry:
            reason_codes.append("markdown_authority_index.startup_entry_missing")
        elif entry.get("authority_level") not in STARTUP_AUTHORITY_LEVELS or entry.get("status") != "active":
            reason_codes.append("markdown_authority_index.invalid_startup_entry")
    for edge in record.get("supersession_edges") or []:
        old_path = edge.get("old_path")
        new_path = edge.get("new_path")
        old_entry = entries_by_path.get(old_path)
        new_entry = entries_by_path.get(new_path)
        if edge.get("mode") not in SUPERSESSION_MODES:
            reason_codes.append("markdown_authority_index.supersession_mode_invalid")
        if not old_entry or not new_entry:
            reason_codes.append("markdown_authority_index.supersession_entry_missing")
            continue
        if old_entry.get("authority_level") != "superseded":
            reason_codes.append("markdown_authority_index.supersession_old_not_superseded")
        if new_path not in (old_entry.get("superseded_by") or []):
            reason_codes.append("markdown_authority_index.supersession_reverse_missing")
        if old_path not in (new_entry.get("supersedes") or []):
            reason_codes.append("markdown_authority_index.supersession_forward_missing")
    expected_reasons = _index_reason_codes(
        entries=entries,
        generated_status=generated_status,
        edges=record.get("supersession_edges") or [],
    )
    if record.get("reason_codes") != expected_reasons:
        reason_codes.append("markdown_authority_index.reason_codes_mismatch")
    if record.get("status") == "allow" and record.get("reason_codes") != ["markdown_authority_index.allow"]:
        reason_codes.append("markdown_authority_index.allow_reason_mismatch")
    if record.get("status") != "allow" and record.get("reason_codes") == ["markdown_authority_index.allow"]:
        reason_codes.append("markdown_authority_index.non_allow_with_allow_reason")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def latest_markdown_authority_index(
    state: dict[str, Any],
    *,
    source_root: str | Path | None = None,
) -> dict[str, Any] | None:
    root = str(Path(source_root).expanduser().resolve(strict=False)) if source_root else None
    candidates = []
    for record in (state.get("markdown_authority_indexes") or {}).values():
        if root and record.get("source_root") != root:
            continue
        candidates.append(record)
    return max(candidates, key=lambda row: str(row.get("created_at") or "")) if candidates else None


def authority_startup_refs(
    state: dict[str, Any],
    *,
    source_root: str | Path,
    output_rel: str | None = None,
) -> list[dict[str, Any]]:
    index = latest_markdown_authority_index(state, source_root=source_root)
    if not index:
        return []
    entry_ids = {
        ref.get("path"): ref.get("markdown_authority_entry_id")
        for ref in index.get("entry_refs") or []
        if isinstance(ref, dict)
    }
    refs = []
    for path in index.get("startup_surface") or []:
        if output_rel and path == output_rel:
            continue
        entry = (state.get("markdown_authority_entries") or {}).get(entry_ids.get(path))
        if not entry:
            continue
        refs.append(
            {
                "path": path,
                "exists": True,
                "required": path in REQUIRED_STARTUP_PATHS or path == index.get("latest_milestone_doc"),
                "sha256": entry.get("source_sha256"),
                "line_count": entry.get("line_count", 0),
                "raw_content_stored": False,
            }
        )
    return sorted(refs, key=lambda item: item["path"])


def parse_supersession_edge(value: str) -> dict[str, str]:
    if "=" not in value:
        raise ValueError("supersession edge must be OLD=NEW")
    old_path, new_path = value.split("=", 1)
    old_path = old_path.strip().strip("/")
    new_path = new_path.strip().strip("/")
    if not old_path or not new_path:
        raise ValueError("supersession edge requires both OLD and NEW paths")
    return {"old_path": old_path, "new_path": new_path, "mode": "temporal_update"}


def _entry_from_summary(
    summary: dict[str, Any],
    *,
    source_root: str,
    label: str,
    latest_milestone: str | None,
    generated_status: dict[str, Any],
    edges: list[dict[str, str]],
    now: str,
) -> dict[str, Any]:
    path = str(summary["path"])
    doc_role = _authority_doc_role(path, str(summary.get("doc_role") or "support"))
    authority_level = _authority_level(
        path,
        doc_role=doc_role,
        latest_milestone=latest_milestone,
        generated_status=generated_status,
    )
    startup_include = _startup_include(
        path,
        authority_level=authority_level,
        latest_milestone=latest_milestone,
        generated_status=generated_status,
    )
    entry = {
        "schema_version": ENTRY_SCHEMA_VERSION,
        "markdown_authority_entry_id": stable_id("mdauthentry", source_root, path, summary["sha256"], label),
        "label": label,
        "source_root": source_root,
        "path": path,
        "source_sha256": summary["sha256"],
        "size_bytes": int(summary["size_bytes"]),
        "line_count": int(summary["line_count"]),
        "doc_role": doc_role,
        "authority_level": authority_level,
        "status": "active" if authority_level in {"current", "supporting"} else "inactive",
        "valid_from": None,
        "valid_until": None,
        "supersedes": _supersedes_paths(path, edges),
        "superseded_by": _superseded_by_paths(path, edges),
        "startup_include": startup_include,
        "memory_claim_refs": [],
        "raw_content_stored": False,
        "reason_codes": ["markdown_authority_entry.pending"],
        "created_at": now,
    }
    if entry["superseded_by"]:
        entry["authority_level"] = "superseded"
        entry["status"] = "inactive"
        entry["startup_include"] = False
        entry["valid_until"] = now
    return entry


def _authority_doc_role(path: str, fallback: str) -> str:
    name = Path(path).name
    if name in GENERATED_PATHS:
        return "generated"
    return fallback


def _authority_level(
    path: str,
    *,
    doc_role: str,
    latest_milestone: str | None,
    generated_status: dict[str, Any],
) -> str:
    name = Path(path).name
    if path == latest_milestone:
        return "current"
    if name in CURRENT_CONTROL_PATHS:
        return "current"
    if name == "GENERATED_STATUS.md":
        return "current" if generated_status.get("matches_computed_latest") else "supporting"
    if name == "NEW_CODEX_SESSION.md":
        return "supporting"
    if doc_role in {"research_plan", "support"}:
        return "supporting"
    if doc_role == "external_review_contract":
        return "evidence-only"
    return "historical"


def _startup_include(
    path: str,
    *,
    authority_level: str,
    latest_milestone: str | None,
    generated_status: dict[str, Any],
) -> bool:
    if authority_level not in STARTUP_AUTHORITY_LEVELS:
        return False
    if path == latest_milestone:
        return True
    if path in {"AGENTS.md", "STATUS.md", "MAP.md"}:
        return True
    if path == "GENERATED_STATUS.md":
        return bool(generated_status.get("matches_computed_latest"))
    return False


def _apply_supersession_edges(entries_by_path: dict[str, dict[str, Any]], edges: list[dict[str, str]], *, now: str) -> None:
    for edge in edges:
        old_entry = entries_by_path.get(edge["old_path"])
        new_entry = entries_by_path.get(edge["new_path"])
        if old_entry:
            old_entry["authority_level"] = "superseded"
            old_entry["status"] = "inactive"
            old_entry["startup_include"] = False
            old_entry["valid_until"] = now
            if edge["new_path"] not in old_entry["superseded_by"]:
                old_entry["superseded_by"].append(edge["new_path"])
                old_entry["superseded_by"].sort()
        if new_entry and edge["old_path"] not in new_entry["supersedes"]:
            new_entry["supersedes"].append(edge["old_path"])
            new_entry["supersedes"].sort()


def _normalise_edges(edges: list[dict[str, str]]) -> list[dict[str, str]]:
    normalised = []
    seen: set[tuple[str, str, str]] = set()
    for edge in edges:
        old_path = str(edge.get("old_path") or "").strip().strip("/")
        new_path = str(edge.get("new_path") or "").strip().strip("/")
        mode = str(edge.get("mode") or "temporal_update")
        key = (old_path, new_path, mode)
        if not old_path or not new_path or key in seen:
            continue
        seen.add(key)
        normalised.append({"old_path": old_path, "new_path": new_path, "mode": mode})
    return sorted(normalised, key=lambda item: (item["old_path"], item["new_path"], item["mode"]))


def _latest_milestone(summaries: list[dict[str, Any]]) -> str | None:
    milestones = [summary for summary in summaries if summary.get("doc_role") == "milestone"]
    if not milestones:
        return None
    return sorted(milestones, key=lambda row: _milestone_sort_key(str(row.get("path") or "")))[-1]["path"]


def _generated_status_ref(root: Path, computed_latest: str | None) -> dict[str, Any]:
    path = root / "GENERATED_STATUS.md"
    if not path.exists() or not path.is_file() or path.is_symlink():
        return {
            "path": "GENERATED_STATUS.md",
            "exists": False,
            "sha256": None,
            "latest_milestone_doc": None,
            "computed_latest_milestone_doc": computed_latest,
            "matches_computed_latest": False,
            "raw_content_stored": False,
        }
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"Latest milestone:\s+`([^`]+)`", text)
    latest = match.group(1) if match else None
    return {
        "path": "GENERATED_STATUS.md",
        "exists": True,
        "sha256": sha256_text(text),
        "latest_milestone_doc": latest,
        "computed_latest_milestone_doc": computed_latest,
        "matches_computed_latest": bool(latest and computed_latest and latest == computed_latest),
        "raw_content_stored": False,
    }


def _entry_reason_codes(entry: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if entry.get("raw_content_stored") is not False:
        reasons.append("markdown_authority_entry.raw_content_stored_not_false")
    if not str(entry.get("source_sha256") or "").startswith("sha256:"):
        reasons.append("markdown_authority_entry.source_hash_missing")
    if entry.get("startup_include") and entry.get("authority_level") not in STARTUP_AUTHORITY_LEVELS:
        reasons.append("markdown_authority_entry.invalid_startup_authority")
    if entry.get("authority_level") == "superseded":
        if not entry.get("superseded_by"):
            reasons.append("markdown_authority_entry.superseded_by_missing")
        if entry.get("startup_include"):
            reasons.append("markdown_authority_entry.superseded_startup_include")
    if reasons:
        return sorted(set(reasons))
    return [f"markdown_authority_entry.{str(entry.get('authority_level')).replace('-', '_')}"]


def _index_reason_codes(
    *,
    entries: list[dict[str, Any]],
    generated_status: dict[str, Any],
    edges: list[dict[str, str]],
) -> list[str]:
    reasons: list[str] = []
    paths = {entry.get("path") for entry in entries}
    if not entries:
        reasons.append("markdown_authority_index.no_markdown_files")
    for required in REQUIRED_STARTUP_PATHS:
        if required not in paths:
            reasons.append(f"markdown_authority_index.required_startup_missing:{required}")
    startup_paths = {entry.get("path") for entry in entries if entry.get("startup_include")}
    for required in REQUIRED_STARTUP_PATHS:
        if required in paths and required not in startup_paths:
            reasons.append(f"markdown_authority_index.required_startup_not_included:{required}")
    if generated_status.get("exists") and not generated_status.get("matches_computed_latest"):
        reasons.append("markdown_authority_index.generated_status_stale")
    if not generated_status.get("exists"):
        reasons.append("markdown_authority_index.generated_status_missing")
    for edge in edges:
        if edge.get("mode") not in SUPERSESSION_MODES:
            reasons.append("markdown_authority_index.supersession_mode_invalid")
        if edge.get("old_path") not in paths or edge.get("new_path") not in paths:
            reasons.append("markdown_authority_index.supersession_entry_missing")
    for entry in entries:
        entry_reasons = _entry_reason_codes(entry)
        if any(not reason.startswith("markdown_authority_entry.") for reason in entry_reasons):
            reasons.extend(entry_reasons)
        if any(
            reason
            in {
                "markdown_authority_entry.raw_content_stored_not_false",
                "markdown_authority_entry.source_hash_missing",
                "markdown_authority_entry.invalid_startup_authority",
                "markdown_authority_entry.superseded_by_missing",
                "markdown_authority_entry.superseded_startup_include",
            }
            for reason in entry_reasons
        ):
            reasons.extend(entry_reasons)
    return sorted(set(reasons)) or ["markdown_authority_index.allow"]


def _supersedes_paths(path: str, edges: list[dict[str, str]]) -> list[str]:
    return sorted(edge["old_path"] for edge in edges if edge["new_path"] == path)


def _superseded_by_paths(path: str, edges: list[dict[str, str]]) -> list[str]:
    return sorted(edge["new_path"] for edge in edges if edge["old_path"] == path)


def _snapshot_hash(entries: list[dict[str, Any]]) -> str:
    material = [
        {
            "path": entry.get("path"),
            "source_sha256": entry.get("source_sha256"),
            "line_count": entry.get("line_count"),
            "size_bytes": entry.get("size_bytes"),
            "doc_role": entry.get("doc_role"),
            "authority_level": entry.get("authority_level"),
            "status": entry.get("status"),
            "supersedes": entry.get("supersedes") or [],
            "superseded_by": entry.get("superseded_by") or [],
            "startup_include": entry.get("startup_include"),
        }
        for entry in sorted(entries, key=lambda row: str(row.get("path") or ""))
    ]
    return sha256_text(canonical_json(material))
