from __future__ import annotations

from collections import Counter
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

from .schema_validation import SchemaValidationError, validate_record
from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .store import JsonStore


SCHEMA_VERSION = "ams.ams_codex.markdown_audit.v0"
STATUSES = {"allow", "defer", "deny"}
CONTROL_DOCS = {"README.md", "MAP.md", "STATUS.md", "MILESTONES.md", "SYSTEM_DESIGN.md", "NEW_CODEX_SESSION.md"}
REQUIRED_INSTRUCTION_FILES = ("AGENTS.md", "CLAUDE.md")
DEFAULT_MAX_FILE_LINES = 450
DEFAULT_MAX_CONTROL_LINES = 900


class MarkdownAuditStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        source_root: str | Path,
        label: str = "manual-markdown-audit",
        include_local_session_metadata: bool = False,
        session_window_days: int = 92,
    ) -> dict[str, Any]:
        record = build_markdown_audit(
            source_root=source_root,
            label=label,
            include_local_session_metadata=include_local_session_metadata,
            session_window_days=session_window_days,
        )
        with self.store.locked() as state:
            audit_id = record["markdown_audit_id"]
            state.setdefault("markdown_audits", {})[audit_id] = record
            state.setdefault("indexes", {}).setdefault("markdown_audit_ids", {})[audit_id] = audit_id
            return deepcopy(record)


def build_markdown_audit(
    *,
    source_root: str | Path,
    label: str = "manual-markdown-audit",
    include_local_session_metadata: bool = False,
    session_window_days: int = 92,
    exclude_relative_paths: list[str] | tuple[str, ...] | set[str] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    if session_window_days < 1:
        raise ValueError("session_window_days must be >= 1")
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False)
    excluded_paths = sorted({str(path).strip("/") for path in (exclude_relative_paths or []) if str(path).strip("/")})
    files = _markdown_files(root, exclude_relative_paths=set(excluded_paths))
    file_summaries = [_file_summary(path, root) for path in files]
    role_counts = dict(Counter(summary["doc_role"] for summary in file_summaries))
    policy = {
        "max_file_lines": DEFAULT_MAX_FILE_LINES,
        "max_control_doc_lines": DEFAULT_MAX_CONTROL_LINES,
        "required_instruction_files": list(REQUIRED_INSTRUCTION_FILES),
        "excluded_paths": excluded_paths,
        "raw_markdown_stored": False,
        "raw_session_content_stored": False,
        "prompt_text_stored": False,
        "transcript_text_stored": False,
    }
    metadata_gaps = _metadata_gaps(file_summaries)
    structure_gaps = _structure_gaps(file_summaries)
    oversized = _oversized(file_summaries)
    instruction_files = _instruction_file_status(file_summaries)
    session_metadata = _session_metadata(
        include=include_local_session_metadata,
        window_days=session_window_days,
        now=now,
    )
    authority_index = _authority_index(file_summaries)
    reason_codes = _reason_codes(
        file_summaries=file_summaries,
        metadata_gaps=metadata_gaps,
        structure_gaps=structure_gaps,
        oversized=oversized,
        instruction_files=instruction_files,
        session_metadata=session_metadata,
    )
    status = "allow" if reason_codes == ["markdown_audit.ok"] else "defer"
    markdown_snapshot_sha256 = _snapshot_hash(file_summaries)
    record = {
        "schema_version": SCHEMA_VERSION,
        "markdown_audit_id": stable_id(
            "mdaudit",
            str(root),
            label,
            markdown_snapshot_sha256,
            session_metadata.get("metadata_window_sha256"),
        ),
        "label": label,
        "source_root": str(root),
        "scan_mode": "metadata_hash_only",
        "network_required": False,
        "raw_markdown_stored": False,
        "markdown_file_count": len(file_summaries),
        "total_line_count": int(sum(summary["line_count"] for summary in file_summaries)),
        "total_size_bytes": int(sum(summary["size_bytes"] for summary in file_summaries)),
        "markdown_snapshot_sha256": markdown_snapshot_sha256,
        "role_counts": role_counts,
        "authority_index": authority_index,
        "policy": policy,
        "file_summaries": file_summaries,
        "metadata_gaps": metadata_gaps,
        "structure_gaps": structure_gaps,
        "oversized_files": oversized,
        "instruction_files": instruction_files,
        "session_metadata": session_metadata,
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["markdown_audit_sha256"] = _hash_without(record, "markdown_audit_sha256")
    return deepcopy(record)


def validate_markdown_audit_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("markdown_audit.schema.json", record, location="markdown_audit")
    except SchemaValidationError:
        reason_codes.append("markdown_audit.schema_invalid")
    expected_hash = record.get("markdown_audit_sha256")
    if expected_hash and expected_hash != _hash_without(record, "markdown_audit_sha256"):
        reason_codes.append("markdown_audit.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("markdown_audit.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("markdown_audit.status_invalid")
    for key in ("network_required", "raw_markdown_stored"):
        if record.get(key) is not False:
            reason_codes.append(f"markdown_audit.{key}_not_false")
    policy = record.get("policy") or {}
    for key in ("raw_markdown_stored", "raw_session_content_stored", "prompt_text_stored", "transcript_text_stored"):
        if policy.get(key) is not False:
            reason_codes.append(f"markdown_audit.policy_{key}_not_false")
    session_metadata = record.get("session_metadata") or {}
    for key in ("raw_content_stored", "prompt_text_stored", "transcript_text_stored"):
        if session_metadata.get(key) is not False:
            reason_codes.append(f"markdown_audit.session_{key}_not_false")
    summaries = record.get("file_summaries") or []
    for summary in summaries:
        for raw_field in ("title", "status_field", "date_field", "updated_field"):
            if raw_field in summary:
                reason_codes.append("markdown_audit.raw_metadata_field_present")
    if record.get("markdown_file_count") != len(summaries):
        reason_codes.append("markdown_audit.file_count_mismatch")
    if record.get("total_line_count") != sum(int(summary.get("line_count", 0) or 0) for summary in summaries):
        reason_codes.append("markdown_audit.total_line_count_mismatch")
    if record.get("total_size_bytes") != sum(int(summary.get("size_bytes", 0) or 0) for summary in summaries):
        reason_codes.append("markdown_audit.total_size_bytes_mismatch")
    paths = [summary.get("path") for summary in summaries if isinstance(summary, dict)]
    if len(paths) != len(set(paths)):
        reason_codes.append("markdown_audit.duplicate_path")
    if record.get("markdown_snapshot_sha256") != _snapshot_hash(summaries):
        reason_codes.append("markdown_audit.snapshot_hash_mismatch")
    expected_roles = dict(Counter(summary.get("doc_role") for summary in summaries))
    if record.get("role_counts") != expected_roles:
        reason_codes.append("markdown_audit.role_counts_mismatch")
    if record.get("metadata_gaps") != _metadata_gaps(summaries):
        reason_codes.append("markdown_audit.metadata_gaps_mismatch")
    if record.get("structure_gaps") != _structure_gaps(summaries):
        reason_codes.append("markdown_audit.structure_gaps_mismatch")
    for summary in summaries:
        if summary.get("raw_content_stored") is not False:
            reason_codes.append("markdown_audit.file_summary_raw_content_not_false")
    expected_window_hash = _hash_without(session_metadata, "metadata_window_sha256")
    if session_metadata.get("metadata_window_sha256") != expected_window_hash:
        reason_codes.append("markdown_audit.session_metadata_hash_mismatch")
    if record.get("status") == "allow" and record.get("reason_codes") != ["markdown_audit.ok"]:
        reason_codes.append("markdown_audit.allow_with_non_ok_reasons")
    if record.get("status") != "allow" and record.get("reason_codes") == ["markdown_audit.ok"]:
        reason_codes.append("markdown_audit.non_allow_with_ok_reason")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _markdown_files(root: Path, *, exclude_relative_paths: set[str] | None = None) -> list[Path]:
    deny_parts = {
        ".git",
        ".ams_sim",
        ".codex",
        ".claude",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "node_modules",
        ".venv",
        "venv",
        "dist",
        "build",
        "site",
        ".next",
        "transcripts",
        "session_logs",
        "raw_sessions",
        "secrets",
        ".secrets",
    }
    exclude_relative_paths = exclude_relative_paths or set()
    files: list[Path] = []
    if not root.exists():
        return files
    for path in root.rglob("*"):
        if path.suffix.lower() != ".md" or not path.is_file() or path.is_symlink():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in deny_parts for part in rel_parts):
            continue
        rel = path.relative_to(root).as_posix()
        if rel in exclude_relative_paths:
            continue
        files.append(path)
    return sorted(files)


def _file_summary(path: Path, root: Path) -> dict[str, Any]:
    stats = _file_stats(path)
    text = stats["preview"].decode("utf-8", errors="replace")
    lines = text.splitlines()
    rel = path.resolve(strict=False).relative_to(root).as_posix()
    headings = [line for line in lines if re.match(r"^#{1,6}\s+", line)]
    return {
        "path": rel,
        "sha256": stats["sha256"],
        "size_bytes": stats["size_bytes"],
        "line_count": stats["line_count"],
        "parse_truncated": stats["parse_truncated"],
        "title_present": _has_first_heading(lines),
        "doc_role": _doc_role(rel),
        "milestone_id": _milestone_id(rel),
        "status_present": _front_matter_has(lines, "status") or _prefix_has(lines, "Status"),
        "date_present": _front_matter_has(lines, "date") or _prefix_has(lines, "Date"),
        "updated_present": _front_matter_has(lines, "updated") or _prefix_has(lines, "Updated"),
        "heading_count": len(headings),
        "has_verification_section": _has_heading(lines, "verification") or "python3 -m pytest" in text,
        "has_next_section": _has_heading(lines, "next")
        or _has_heading(lines, "next risk")
        or "Next risk:" in text
        or "What Remains" in text,
        "has_sources_section": _has_heading(lines, "research grounding") or _has_heading(lines, "sources"),
        "frontmatter_present": bool(lines and lines[0].strip() == "---"),
        "raw_content_stored": False,
    }


def _doc_role(rel: str) -> str:
    name = Path(rel).name
    if name in CONTROL_DOCS or name in REQUIRED_INSTRUCTION_FILES:
        return "control"
    if rel.startswith("notes/"):
        return "handoff"
    if re.match(r"MILESTONE[_-]\d", name):
        return "milestone"
    if "RESEARCH" in name or "PLAN" in name or name in {"RESEARCH_LENSES.md", "INNOVATION_LENSES.md"}:
        return "research_plan"
    if "REVIEW" in name or "CONTRACT" in name:
        return "external_review_contract"
    return "support"


def _milestone_id(rel: str) -> str | None:
    match = re.match(r"(MILESTONE(?:[_-]\d+)?(?:[_-][A-Z])?)", Path(rel).name)
    if not match:
        return None
    return match.group(1).replace("_", "-")


def _metadata_gaps(summaries: list[dict[str, Any]]) -> list[dict[str, str]]:
    gaps: list[dict[str, str]] = []
    for summary in summaries:
        role = summary.get("doc_role")
        if summary.get("path") in REQUIRED_INSTRUCTION_FILES:
            continue
        if role in {"milestone", "control"} and not summary.get("status_present"):
            gaps.append({"path": summary["path"], "field": "status"})
        if role in {"milestone", "research_plan", "external_review_contract"} and not (
            summary.get("date_present") or summary.get("updated_present")
        ):
            gaps.append({"path": summary["path"], "field": "date_or_updated"})
    return gaps


def _structure_gaps(summaries: list[dict[str, Any]]) -> list[dict[str, str]]:
    gaps: list[dict[str, str]] = []
    for summary in summaries:
        role = summary.get("doc_role")
        if role == "milestone":
            if not summary.get("has_verification_section"):
                gaps.append({"path": summary["path"], "field": "verification"})
            if not summary.get("has_next_section"):
                gaps.append({"path": summary["path"], "field": "next"})
        if role == "research_plan" and not summary.get("has_sources_section"):
            gaps.append({"path": summary["path"], "field": "sources"})
    return gaps


def _oversized(summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    oversized: list[dict[str, Any]] = []
    for summary in summaries:
        limit = DEFAULT_MAX_CONTROL_LINES if summary.get("doc_role") == "control" else DEFAULT_MAX_FILE_LINES
        if int(summary.get("line_count", 0) or 0) > limit:
            oversized.append({"path": summary["path"], "line_count": summary["line_count"], "limit": limit})
    return oversized


def _instruction_file_status(summaries: list[dict[str, Any]]) -> dict[str, Any]:
    paths = {summary["path"]: summary for summary in summaries}
    files = []
    for required in REQUIRED_INSTRUCTION_FILES:
        summary = paths.get(required)
        files.append(
            {
                "path": required,
                "present": summary is not None,
                "line_count": int(summary.get("line_count", 0) or 0) if summary else 0,
                "sha256": summary.get("sha256") if summary else None,
            }
        )
    return {
        "files": files,
        "all_present": all(item["present"] for item in files),
        "max_recommended_lines": 200,
    }


def _authority_index(summaries: list[dict[str, Any]]) -> dict[str, Any]:
    by_path = {summary["path"]: summary for summary in summaries}
    milestone_docs = [summary for summary in summaries if summary.get("doc_role") == "milestone"]
    latest_milestone = sorted(milestone_docs, key=lambda row: _milestone_sort_key(str(row.get("path"))))[-1]["path"] if milestone_docs else None
    return {
        "instruction_docs": [path for path in REQUIRED_INSTRUCTION_FILES if path in by_path],
        "control_docs": [path for path in sorted(by_path) if Path(path).name in CONTROL_DOCS],
        "latest_milestone_doc": latest_milestone,
        "status_doc": "STATUS.md" if "STATUS.md" in by_path else None,
        "map_doc": "MAP.md" if "MAP.md" in by_path else None,
        "readme_doc": "README.md" if "README.md" in by_path else None,
    }


def _reason_codes(
    *,
    file_summaries: list[dict[str, Any]],
    metadata_gaps: list[dict[str, str]],
    structure_gaps: list[dict[str, str]],
    oversized: list[dict[str, Any]],
    instruction_files: dict[str, Any],
    session_metadata: dict[str, Any],
) -> list[str]:
    reasons: list[str] = []
    if not file_summaries:
        reasons.append("markdown_audit.no_markdown_files")
    if not instruction_files.get("all_present"):
        reasons.append("markdown_audit.instruction_files_missing")
    if metadata_gaps:
        reasons.append("markdown_audit.metadata_gaps")
    if structure_gaps:
        reasons.append("markdown_audit.structure_gaps")
    if oversized:
        reasons.append("markdown_audit.oversized_docs")
    if session_metadata.get("included") and (session_metadata.get("codex") or {}).get("thread_count", 0) > 50:
        reasons.append("markdown_audit.high_session_volume")
    if session_metadata.get("included") and (session_metadata.get("claude") or {}).get("project_bytes", 0) > 100_000_000:
        reasons.append("markdown_audit.large_transcript_surface")
    return reasons or ["markdown_audit.ok"]


def _session_metadata(*, include: bool, window_days: int, now: str) -> dict[str, Any]:
    window_end = _parse_utc(now)
    window_start = window_end - timedelta(days=window_days)
    record = {
        "included": include,
        "window_days": window_days,
        "window_start": _iso(window_start),
        "window_end": _iso(window_end),
        "raw_content_stored": False,
        "prompt_text_stored": False,
        "transcript_text_stored": False,
        "sources": [],
        "codex": {},
        "claude": {},
        "reason_codes": ["session_metadata.not_requested"],
    }
    if include:
        record["sources"] = [
            "~/.codex/state_5.sqlite",
            "~/.codex/logs_2.sqlite",
            "~/.codex/goals_1.sqlite",
            "~/.codex/memories_1.sqlite",
            "~/.claude/projects",
            "~/.claude/tasks",
        ]
        record["codex"] = _codex_metadata(window_start)
        record["claude"] = _claude_metadata(window_start)
        record["reason_codes"] = ["session_metadata.metadata_only"]
    record["metadata_window_sha256"] = _hash_without(record, "metadata_window_sha256")
    return record


def _codex_metadata(window_start: datetime) -> dict[str, Any]:
    home = Path.home()
    since_seconds = int(window_start.timestamp())
    state_db = home / ".codex" / "state_5.sqlite"
    goals_db = home / ".codex" / "goals_1.sqlite"
    logs_db = home / ".codex" / "logs_2.sqlite"
    memories_db = home / ".codex" / "memories_1.sqlite"
    return {
        "thread_count": _sqlite_scalar(
            state_db,
            "SELECT COUNT(*) FROM threads WHERE created_at_ms >= ?",
            (since_seconds * 1000,),
        ),
        "token_sum": _sqlite_scalar(
            state_db,
            "SELECT COALESCE(SUM(tokens_used),0) FROM threads WHERE created_at_ms >= ?",
            (since_seconds * 1000,),
        ),
        "active_goal_count": _sqlite_scalar(
            goals_db,
            "SELECT COUNT(*) FROM thread_goals WHERE created_at_ms >= ?",
            (since_seconds * 1000,),
        ),
        "memory_stage1_count": _sqlite_scalar(
            memories_db,
            "SELECT COUNT(*) FROM stage1_outputs WHERE source_updated_at >= ?",
            (since_seconds,),
        ),
        "log_count": _sqlite_scalar(logs_db, "SELECT COUNT(*) FROM logs WHERE ts >= ?", (since_seconds,)),
    }


def _claude_metadata(window_start: datetime) -> dict[str, Any]:
    cutoff = window_start.timestamp()
    projects = _file_tree_metadata(Path.home() / ".claude" / "projects", cutoff, count_jsonl_lines=True)
    tasks = _file_tree_metadata(Path.home() / ".claude" / "tasks", cutoff, count_jsonl_lines=False)
    return {
        "project_file_count": projects["file_count"],
        "project_session_count": projects["top_level_count"],
        "project_bytes": projects["bytes"],
        "project_jsonl_lines": projects["jsonl_lines"],
        "task_file_count": tasks["file_count"],
        "task_session_count": tasks["top_level_count"],
        "task_bytes": tasks["bytes"],
    }


def _file_tree_metadata(root: Path, cutoff: float, *, count_jsonl_lines: bool) -> dict[str, int]:
    if not root.exists():
        return {"file_count": 0, "top_level_count": 0, "bytes": 0, "jsonl_lines": 0}
    file_count = 0
    total_bytes = 0
    top_level: set[str] = set()
    jsonl_lines = 0
    for path in root.rglob("*"):
        try:
            stat = path.stat()
        except OSError:
            continue
        if path.is_symlink() or not path.is_file() or stat.st_mtime < cutoff:
            continue
        file_count += 1
        total_bytes += stat.st_size
        rel = path.relative_to(root)
        if rel.parts:
            top_level.add(rel.parts[0])
        if count_jsonl_lines and path.suffix == ".jsonl":
            try:
                with path.open("rb") as fh:
                    jsonl_lines += sum(1 for _ in fh)
            except OSError:
                continue
    return {"file_count": file_count, "top_level_count": len(top_level), "bytes": total_bytes, "jsonl_lines": jsonl_lines}


def _sqlite_scalar(path: Path, query: str, params: tuple[Any, ...]) -> int:
    if not path.exists():
        return 0
    try:
        with sqlite3.connect(path) as conn:
            value = conn.execute(query, params).fetchone()[0]
    except sqlite3.Error:
        return 0
    return int(value or 0)


def _file_stats(path: Path, *, preview_limit: int = 262_144) -> dict[str, Any]:
    digest = hashlib.sha256()
    preview = bytearray()
    size = 0
    newline_count = 0
    last_byte: int | None = None
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
            size += len(chunk)
            newline_count += chunk.count(b"\n")
            last_byte = chunk[-1]
            if len(preview) < preview_limit:
                take = min(preview_limit - len(preview), len(chunk))
                preview.extend(chunk[:take])
    line_count = 0 if size == 0 else newline_count + (0 if last_byte == 10 else 1)
    return {
        "sha256": "sha256:" + digest.hexdigest(),
        "size_bytes": size,
        "line_count": line_count,
        "preview": bytes(preview),
        "parse_truncated": size > len(preview),
    }


def _has_first_heading(lines: list[str]) -> bool:
    for line in lines:
        if line.startswith("# "):
            return True
    return False


def _front_matter_has(lines: list[str], key: str) -> bool:
    if not lines or lines[0].strip() != "---":
        return False
    for line in lines[1:80]:
        if line.strip() == "---":
            return False
        if line.lower().startswith(f"{key.lower()}:"):
            return True
    return False


def _prefix_has(lines: list[str], key: str) -> bool:
    for line in lines[:40]:
        if line.lower().startswith(f"{key.lower()}:"):
            return True
    return False


def _has_heading(lines: list[str], heading: str) -> bool:
    target = heading.lower()
    for line in lines:
        match = re.match(r"^#{1,6}\s+(.+?)\s*$", line)
        if match and match.group(1).strip().lower() == target:
            return True
    return False


def _milestone_sort_key(path: str) -> tuple[int, int, int, int, str]:
    name = Path(path).name
    match = re.match(r"MILESTONE(?:([A-Z]))?(?:[_-](\d+))?(?:[_-]([A-Z]))?", name)
    if not match:
        return (0, 0, 0, 0, name)
    letter, minor, suffix_letter = match.groups()
    return (
        0,
        _letter_sort(letter),
        int(minor or 0),
        _letter_sort(suffix_letter),
        name,
    )


def _letter_sort(value: str | None) -> int:
    if not value:
        return 0
    return ord(value.upper()[0]) - ord("A") + 1


def _snapshot_hash(summaries: list[dict[str, Any]]) -> str:
    material = [
        {
            "path": summary.get("path"),
            "sha256": summary.get("sha256"),
            "line_count": summary.get("line_count"),
            "size_bytes": summary.get("size_bytes"),
            "doc_role": summary.get("doc_role"),
            "status_present": summary.get("status_present"),
            "date_present": summary.get("date_present"),
            "updated_present": summary.get("updated_present"),
        }
        for summary in sorted(summaries, key=lambda row: str(row.get("path")))
    ]
    return sha256_text(canonical_json(material))



def _parse_utc(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
