from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from .doc_retirement import build_doc_retirement_plan
from .generated_artifact import (
    generated_output_status,
    hash_without,
    path_is_under,
    previous_text_file,
    resolve_output_path,
    safe_int,
    text_stats,
)
from .models import stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore


SCHEMA_VERSION = "ams.ams_codex.generated_status_snapshot.v0"
STATUSES = {"allow", "defer", "deny"}
DEFAULT_OUTPUT_PATH = "GENERATED_STATUS.md"
DEFAULT_SESSION_START_OUTPUT = "NEW_CODEX_SESSION.md"
DEFAULT_LINE_BUDGET = 160
DANGEROUS_BOUNDARIES = {
    "source_file_deleted": False,
    "source_file_moved": False,
    "source_file_rewritten": False,
    "raw_source_markdown_stored": False,
    "raw_session_content_stored": False,
    "prompt_text_stored": False,
    "transcript_text_stored": False,
    "network_call_performed": False,
}


class GeneratedStatusSnapshotStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        source_root: str | Path,
        output_path: str | Path = DEFAULT_OUTPUT_PATH,
        label: str = "manual-generated-status",
        include_local_session_metadata: bool = False,
        session_window_days: int = 92,
        write_file: bool = True,
        allow_overwrite: bool = False,
    ) -> dict[str, Any]:
        record = build_generated_status_snapshot(
            source_root=source_root,
            output_path=output_path,
            label=label,
            include_local_session_metadata=include_local_session_metadata,
            session_window_days=session_window_days,
            write_file=write_file,
            allow_overwrite=allow_overwrite,
        )
        with self.store.locked() as state:
            snapshot_id = record["generated_status_snapshot_id"]
            state.setdefault("generated_status_snapshots", {})[snapshot_id] = record
            state.setdefault("indexes", {}).setdefault("generated_status_snapshot_ids", {})[snapshot_id] = snapshot_id
            return deepcopy(record)


def build_generated_status_snapshot(
    *,
    source_root: str | Path,
    output_path: str | Path = DEFAULT_OUTPUT_PATH,
    label: str = "manual-generated-status",
    include_local_session_metadata: bool = False,
    session_window_days: int = 92,
    write_file: bool = True,
    allow_overwrite: bool = False,
    now: str | None = None,
) -> dict[str, Any]:
    if session_window_days < 1:
        raise ValueError("session_window_days must be >= 1")
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False)
    output = resolve_output_path(root, output_path)
    generated_excludes = {
        output.relative_to(root).as_posix(),
        DEFAULT_SESSION_START_OUTPUT,
    }
    plan = build_doc_retirement_plan(
        source_root=root,
        label=f"{label}-doc-plan",
        include_local_session_metadata=include_local_session_metadata,
        session_window_days=session_window_days,
        exclude_relative_paths=generated_excludes,
        now=now,
    )
    rendered = _render_generated_status(plan, output_rel=output.relative_to(root).as_posix())
    rendered_stats = text_stats(rendered)
    previous = previous_text_file(output)
    can_write = bool(write_file and path_is_under(output, root) and not output.is_symlink())
    output_already_current = previous["exists"] and previous["sha256"] == rendered_stats["sha256"]
    write_performed = False
    reason_codes: list[str] = []
    if not write_file:
        reason_codes.append("generated_status_snapshot.write_not_requested")
    elif not can_write:
        reason_codes.append("generated_status_snapshot.output_path_invalid")
    elif output_already_current:
        pass
    elif previous["exists"] and previous["sha256"] != rendered_stats["sha256"] and not allow_overwrite:
        reason_codes.append("generated_status_snapshot.overwrite_requires_approval")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        write_performed = True
    status = generated_output_status(
        output_available=write_performed or output_already_current,
        rendered_stats=rendered_stats,
        reason_codes=reason_codes,
        line_budget=DEFAULT_LINE_BUDGET,
    )
    if status == "allow":
        reason_codes = ["generated_status_snapshot.allow"]
    elif not reason_codes:
        reason_codes = ["generated_status_snapshot.defer"]
    record = {
        "schema_version": SCHEMA_VERSION,
        "generated_status_snapshot_id": stable_id(
            "genstatus",
            str(root),
            str(output.relative_to(root)),
            label,
            plan["doc_retirement_plan_sha256"],
            rendered_stats["sha256"],
            now,
        ),
        "label": label,
        "source_root": str(root),
        "output_path": str(output),
        "output_path_relative": output.relative_to(root).as_posix(),
        "line_budget": DEFAULT_LINE_BUDGET,
        "source_plan_ref": {
            "doc_retirement_plan_id": plan["doc_retirement_plan_id"],
            "doc_retirement_plan_sha256": plan["doc_retirement_plan_sha256"],
            "status": plan["status"],
            "action_count": plan["action_summary"]["action_count"],
            "generated_status_latest_milestone_doc": plan["generated_status"]["latest_milestone_doc"],
        },
        "rendered": {
            "sha256": rendered_stats["sha256"],
            "line_count": rendered_stats["line_count"],
            "size_bytes": rendered_stats["size_bytes"],
            "within_line_budget": rendered_stats["line_count"] <= DEFAULT_LINE_BUDGET,
            "raw_content_stored_in_record": False,
        },
        "write_result": {
            "write_requested": bool(write_file),
            "write_performed": write_performed,
            "allow_overwrite": bool(allow_overwrite),
            "previous_file_exists": previous["exists"],
            "previous_file_sha256": previous["sha256"],
            "output_already_current": output_already_current,
            "created_new_file": write_performed and not previous["exists"],
            "rewrote_existing_generated_file": write_performed and previous["exists"] and previous["sha256"] != rendered_stats["sha256"],
        },
        "dangerous_boundaries": dict(DANGEROUS_BOUNDARIES),
        "generated_status_summary": plan["generated_status"],
        "remaining_doc_actions": plan["action_summary"],
        "status": status,
        "reason_codes": sorted(set(reason_codes)),
        "created_at": now,
    }
    record["generated_status_snapshot_sha256"] = hash_without(record, "generated_status_snapshot_sha256")
    return deepcopy(record)


def validate_generated_status_snapshot_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("generated_status_snapshot.schema.json", record, location="generated_status_snapshot")
    except SchemaValidationError:
        reason_codes.append("generated_status_snapshot.schema_invalid")
    expected_hash = record.get("generated_status_snapshot_sha256")
    if expected_hash and expected_hash != hash_without(record, "generated_status_snapshot_sha256"):
        reason_codes.append("generated_status_snapshot.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("generated_status_snapshot.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("generated_status_snapshot.status_invalid")
    for key, expected in DANGEROUS_BOUNDARIES.items():
        if (record.get("dangerous_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"generated_status_snapshot.{key}_not_false")
    rendered = record.get("rendered") or {}
    if rendered.get("raw_content_stored_in_record") is not False:
        reason_codes.append("generated_status_snapshot.rendered_raw_content_stored")
    line_count = safe_int(rendered.get("line_count"), default=0)
    line_budget = safe_int(record.get("line_budget"), default=DEFAULT_LINE_BUDGET)
    if bool(rendered.get("within_line_budget")) != (line_count <= line_budget):
        reason_codes.append("generated_status_snapshot.line_budget_mismatch")
    write_result = record.get("write_result") or {}
    output_already_current = bool(write_result.get("output_already_current"))
    if output_already_current:
        if write_result.get("previous_file_exists") is not True:
            reason_codes.append("generated_status_snapshot.output_current_without_previous_file")
        if write_result.get("previous_file_sha256") != rendered.get("sha256"):
            reason_codes.append("generated_status_snapshot.output_current_hash_mismatch")
        if write_result.get("write_performed") is not False:
            reason_codes.append("generated_status_snapshot.output_current_rewritten")
    if write_result.get("rewrote_existing_generated_file") is True and write_result.get("allow_overwrite") is not True:
        reason_codes.append("generated_status_snapshot.rewrite_without_approval")
    expected_status = generated_output_status(
        output_available=bool(write_result.get("write_performed") or output_already_current),
        rendered_stats={
            "line_count": line_count,
            "sha256": rendered.get("sha256"),
            "size_bytes": rendered.get("size_bytes"),
        },
        reason_codes=[reason for reason in record.get("reason_codes") or [] if reason != "generated_status_snapshot.allow"],
        line_budget=DEFAULT_LINE_BUDGET,
    )
    if record.get("status") != expected_status:
        reason_codes.append("generated_status_snapshot.status_mismatch")
    if record.get("status") == "allow" and record.get("reason_codes") != ["generated_status_snapshot.allow"]:
        reason_codes.append("generated_status_snapshot.allow_reason_mismatch")
    if (record.get("generated_status_summary") or {}).get("raw_content_stored") is not False:
        reason_codes.append("generated_status_snapshot.summary_raw_content_stored")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _render_generated_status(plan: dict[str, Any], *, output_rel: str) -> str:
    summary = plan["generated_status"]
    actions = plan["action_summary"]
    source_snapshot = (plan.get("markdown_audit_ref") or {}).get("markdown_snapshot_sha256")
    high_actions = [
        action for action in plan.get("decision_actions") or []
        if action.get("severity") == "high"
    ]
    lines = [
        "# AMS Generated Status",
        "",
        "Status: generated",
        f"Source snapshot: {source_snapshot}",
        "",
        "This file is generated from AMS authority records. Do not hand-edit it.",
        "",
        "## Source",
        "",
        f"- Output: `{output_rel}`",
        f"- Source record kind: `{summary['source_record_kind']}`",
        f"- Source snapshot: `{source_snapshot}`",
        "",
        "## Current",
        "",
        f"- Latest milestone: `{summary['latest_milestone_doc']}`",
        f"- Markdown files: {summary['markdown_file_count']}",
        f"- Markdown lines: {summary['total_line_count']}",
        f"- Metadata gaps: {summary['metadata_gap_count']}",
        f"- Structure gaps: {summary['structure_gap_count']}",
        f"- Oversized files: {summary['oversized_file_count']}",
        f"- Remaining doc actions: {actions['action_count']}",
        f"- High-severity doc actions: {actions['by_severity'].get('high', 0)}",
        "",
        "## High Actions",
        "",
    ]
    if high_actions:
        for action in high_actions:
            lines.append(
                f"- `{action['source_path']}` -> `{action['action_kind']}` -> `{action['target_surface']}`"
            )
    else:
        lines.append("- None")
    lines.extend(
        [
            "",
            "## Boundaries",
            "",
            "- Discord, terminal, provider, embedding, vector, and network boundaries are not crossed.",
            "- Raw source markdown, raw sessions, prompt text, and transcript text are not stored in AMS state.",
            "- Historical docs are not deleted, moved, or rewritten by this generated-status snapshot.",
            "",
        ]
    )
    return "\n".join(lines)
