from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path
from typing import Any

from .generated_artifact import (
    generated_output_status,
    hash_without,
    path_is_under,
    previous_text_file,
    resolve_output_path,
    safe_int,
    text_stats,
)
from .markdown_authority import authority_startup_refs
from .models import canonical_json, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore


SCHEMA_VERSION = "ams.ams.session_start_brief.v0"
DEFAULT_OUTPUT_PATH = "NEW_CODEX_SESSION.md"
DEFAULT_LINE_BUDGET = 120
STATUSES = {"allow", "defer", "deny"}
BOUNDARIES = {
    "source_file_deleted": False,
    "source_file_moved": False,
    "raw_source_markdown_stored": False,
    "raw_session_content_stored": False,
    "prompt_text_stored": False,
    "transcript_text_stored": False,
    "network_call_performed": False,
    "live_process_started": False,
}


class SessionStartBriefStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        source_root: str | Path,
        output_path: str | Path = DEFAULT_OUTPUT_PATH,
        label: str = "manual-session-start-brief",
        write_file: bool = True,
        allow_overwrite: bool = False,
    ) -> dict[str, Any]:
        state = self.store.load()
        record = build_session_start_brief(
            source_root=source_root,
            output_path=output_path,
            label=label,
            write_file=write_file,
            allow_overwrite=allow_overwrite,
            state=state,
        )
        with self.store.locked() as state:
            brief_id = record["session_start_brief_id"]
            state.setdefault("session_start_briefs", {})[brief_id] = record
            state.setdefault("indexes", {}).setdefault("session_start_brief_ids", {})[brief_id] = brief_id
            return deepcopy(record)


def build_session_start_brief(
    *,
    source_root: str | Path,
    output_path: str | Path = DEFAULT_OUTPUT_PATH,
    label: str = "manual-session-start-brief",
    write_file: bool = True,
    allow_overwrite: bool = False,
    state: dict[str, Any] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False)
    output = resolve_output_path(root, output_path)
    source_refs = _source_refs(root, output.relative_to(root).as_posix(), state=state)
    latest = _latest_milestone(source_refs)
    rendered = _render_session_start_brief(
        source_root=str(root),
        output_rel=output.relative_to(root).as_posix(),
        latest_milestone_doc=latest,
        source_snapshot_sha256=_source_refs_snapshot(source_refs),
    )
    rendered_stats = text_stats(rendered)
    previous = previous_text_file(output)
    can_write = bool(write_file and path_is_under(output, root) and not output.is_symlink())
    output_already_current = previous["exists"] and previous["sha256"] == rendered_stats["sha256"]
    write_performed = False
    reason_codes: list[str] = []
    if not write_file:
        reason_codes.append("session_start_brief.write_not_requested")
    elif not can_write:
        reason_codes.append("session_start_brief.output_path_invalid")
    elif output_already_current:
        pass
    elif previous["exists"] and previous["sha256"] != rendered_stats["sha256"] and not allow_overwrite:
        reason_codes.append("session_start_brief.overwrite_requires_approval")
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
        reason_codes = ["session_start_brief.allow"]
    elif not reason_codes:
        reason_codes = ["session_start_brief.defer"]
    record = {
        "schema_version": SCHEMA_VERSION,
        "session_start_brief_id": stable_id(
            "startbrief",
            str(root),
            output.relative_to(root).as_posix(),
            label,
            latest,
            source_refs,
            rendered_stats["sha256"],
            now,
        ),
        "label": label,
        "source_root": str(root),
        "output_path": str(output),
        "output_path_relative": output.relative_to(root).as_posix(),
        "line_budget": DEFAULT_LINE_BUDGET,
        "source_refs": source_refs,
        "latest_milestone_doc": latest,
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
            "rewrote_existing_session_start_file": write_performed
            and previous["exists"]
            and previous["sha256"] != rendered_stats["sha256"],
        },
        "operator_guidance": {
            "read_all_milestones_on_start": False,
            "start_surface": [
                path for path in ("AGENTS.md", "GENERATED_STATUS.md", "STATUS.md", "MAP.md", latest) if path
            ],
            "use_map_for_deep_links": True,
            "raw_transcript_required": False,
            "live_boundary_approval_required": True,
        },
        "boundaries": dict(BOUNDARIES),
        "status": status,
        "reason_codes": sorted(set(reason_codes)),
        "created_at": now,
    }
    record["session_start_brief_sha256"] = hash_without(record, "session_start_brief_sha256")
    return deepcopy(record)


def validate_session_start_brief_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("session_start_brief.schema.json", record, location="session_start_brief")
    except SchemaValidationError:
        reason_codes.append("session_start_brief.schema_invalid")
    expected_hash = record.get("session_start_brief_sha256")
    if expected_hash and expected_hash != hash_without(record, "session_start_brief_sha256"):
        reason_codes.append("session_start_brief.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("session_start_brief.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("session_start_brief.status_invalid")
    for key, expected in BOUNDARIES.items():
        if (record.get("boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"session_start_brief.{key}_not_false")
    rendered = record.get("rendered") or {}
    if rendered.get("raw_content_stored_in_record") is not False:
        reason_codes.append("session_start_brief.rendered_raw_content_stored")
    line_count = safe_int(rendered.get("line_count"), default=0)
    line_budget = safe_int(record.get("line_budget"), default=DEFAULT_LINE_BUDGET)
    if bool(rendered.get("within_line_budget")) != (line_count <= line_budget):
        reason_codes.append("session_start_brief.line_budget_mismatch")
    guidance = record.get("operator_guidance") or {}
    if guidance.get("read_all_milestones_on_start") is not False:
        reason_codes.append("session_start_brief.bulk_milestone_read_enabled")
    if guidance.get("raw_transcript_required") is not False:
        reason_codes.append("session_start_brief.raw_transcript_required")
    write_result = record.get("write_result") or {}
    output_already_current = bool(write_result.get("output_already_current"))
    if output_already_current:
        if write_result.get("previous_file_exists") is not True:
            reason_codes.append("session_start_brief.output_current_without_previous_file")
        if write_result.get("previous_file_sha256") != rendered.get("sha256"):
            reason_codes.append("session_start_brief.output_current_hash_mismatch")
        if write_result.get("write_performed") is not False:
            reason_codes.append("session_start_brief.output_current_rewritten")
    if write_result.get("rewrote_existing_session_start_file") is True and write_result.get("allow_overwrite") is not True:
        reason_codes.append("session_start_brief.rewrite_without_approval")
    expected_status = generated_output_status(
        output_available=bool(write_result.get("write_performed") or output_already_current),
        rendered_stats={"line_count": line_count, "sha256": rendered.get("sha256")},
        reason_codes=[reason for reason in record.get("reason_codes") or [] if reason != "session_start_brief.allow"],
        line_budget=DEFAULT_LINE_BUDGET,
    )
    if record.get("status") != expected_status:
        reason_codes.append("session_start_brief.status_mismatch")
    if record.get("status") == "allow" and record.get("reason_codes") != ["session_start_brief.allow"]:
        reason_codes.append("session_start_brief.allow_reason_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _source_refs(root: Path, output_rel: str, *, state: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    if state:
        authority_refs = authority_startup_refs(state, source_root=root, output_rel=output_rel)
        if authority_refs:
            return authority_refs
    generated_status = _file_ref(root, "GENERATED_STATUS.md", required=True)
    latest = _latest_from_generated_status(root / "GENERATED_STATUS.md") or _latest_milestone_from_files(root)
    paths = ["AGENTS.md", "GENERATED_STATUS.md", "STATUS.md", "MAP.md"]
    if latest:
        paths.append(latest)
    refs = [_file_ref(root, path, required=True) for path in paths if path != output_rel]
    if generated_status not in refs and generated_status["path"] != output_rel:
        refs.append(generated_status)
    return sorted(refs, key=lambda item: item["path"])


def _file_ref(root: Path, rel: str, *, required: bool) -> dict[str, Any]:
    path = (root / rel).resolve(strict=False)
    if path.exists() and path.is_file() and not path.is_symlink() and path_is_under(path, root):
        text = path.read_text(encoding="utf-8", errors="replace")
        return {
            "path": rel,
            "exists": True,
            "required": required,
            "sha256": sha256_text(text),
            "line_count": len(text.splitlines()),
            "raw_content_stored": False,
        }
    return {
        "path": rel,
        "exists": False,
        "required": required,
        "sha256": None,
        "line_count": 0,
        "raw_content_stored": False,
    }


def _source_refs_snapshot(source_refs: list[dict[str, Any]]) -> str:
    material = [
        {
            "path": ref.get("path"),
            "exists": ref.get("exists"),
            "sha256": ref.get("sha256"),
            "line_count": ref.get("line_count"),
        }
        for ref in source_refs
    ]
    return sha256_text(canonical_json(sorted(material, key=lambda item: str(item.get("path") or ""))))


def _latest_milestone(source_refs: list[dict[str, Any]]) -> str | None:
    for ref in source_refs:
        path = str(ref.get("path") or "")
        if re.fullmatch(r"MILESTONE_\d+_[A-Z0-9_]+\.md", path):
            return path
    return None


def _latest_from_generated_status(path: Path) -> str | None:
    if not path.exists() or not path.is_file() or path.is_symlink():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"Latest milestone:\s+`([^`]+)`", text)
    return match.group(1) if match else None


def _latest_milestone_from_files(root: Path) -> str | None:
    candidates = sorted(path.name for path in root.glob("MILESTONE_*.md") if path.is_file() and not path.is_symlink())
    return candidates[-1] if candidates else None


def _render_session_start_brief(
    *,
    source_root: str,
    output_rel: str,
    latest_milestone_doc: str | None,
    source_snapshot_sha256: str,
) -> str:
    latest = latest_milestone_doc or "latest MILESTONE_*.md"
    next_work = _next_work_lines(latest)
    lines = [
        "# How To Use This From A New Codex Session",
        "",
        "Status: generated",
        f"Source snapshot: {source_snapshot_sha256}",
        "",
        "This file is generated from AMS authority records. Do not hand-edit it.",
        "",
        "## Start Here",
        "",
        "```bash",
        f"cd {source_root}",
        "sed -n '1,120p' AGENTS.md",
        "sed -n '1,120p' GENERATED_STATUS.md",
        "sed -n '1,170p' STATUS.md",
        "sed -n '1,180p' MAP.md",
        f"sed -n '1,180p' {latest}",
        "```",
        "",
        "## Verify",
        "",
        "```bash",
        "python3 -m pytest -q",
        "python3 -m py_compile ams/*.py",
        "jq empty schemas/*.json examples/*.json data/demo_store.json data/dual_demo_store.json data/m8g_sim_store.json data/m8h_incident_store.json",
        "git status --short --branch",
        "```",
        "",
        "## Working Rule",
        "",
        "- Treat `GENERATED_STATUS.md`, `STATUS.md`, `MAP.md`, and the latest milestone as the startup surface.",
        "- Do not bulk-read every milestone on session start; use `MAP.md` for targeted deep links.",
        "- Keep live boundaries inert unless the operator explicitly approves them.",
        "- Store source facts as hashes, refs, summaries, and AMS records; do not store raw Discord, terminal, prompt, transcript, embedding, vector, secret, or token content.",
        "- Before ending a milestone, update generated/status docs, run focused and full checks when feasible, commit, and tag.",
        "",
        "## Current Next Work",
        "",
        *next_work,
        "",
        "## Boundaries",
        "",
        f"- Output: `{output_rel}`.",
        "- No Discord, provider, terminal, embedding, vector, downloader, daemon, or network boundary is crossed by generating this file.",
        "- Historical milestone docs stay available; this file is only the compact start surface.",
        "",
    ]
    return "\n".join(lines)


def _next_work_lines(latest_milestone_doc: str) -> list[str]:
    if latest_milestone_doc.startswith("MILESTONE_76_"):
        return [
            "- Use the no-Discord real-agent system trial as the local canary gate before live Discord/terminal/provider surfaces: compare stubbed baselines with `--allow-real-agents` receipts when explicitly approved.",
            "- Return to the source-write receipt and post-write replay/readback settlement: consume one active executor lease, record preimage/postimage hashes, require rollback readback, and distinguish authorized postimage changes from source drift.",
            "- Keep live Discord and terminal/tmux boundaries disabled; provider CLI execution is only for explicit bounded `real-agent-system-trial --allow-real-agents` canaries with artifact refs and no raw prompt/output stored in AMS state.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_75_"):
        return [
            "- Build the source-write receipt and post-write replay/readback settlement: consume one active executor lease, record source preimage/postimage hashes, and require rollback readback evidence.",
            "- The executor must write only the approved source path and replay must distinguish authorized postimage changes from stale source drift.",
            "- Keep live Discord/provider/terminal/process boundaries disabled; source-write authority must remain limited to the explicit source-write receipt path.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_74_"):
        return [
            "- Build the post-write replay/readback settlement for the source-write executor path: require source postimage hash, backup/preimage receipt hash, rollback ref, and replay evidence before any write can be considered settled.",
            "- Add the final source-write receipt/exclusive executor boundary only after replay can distinguish authorized postimage changes from source drift.",
            "- Keep actual source rewrites disabled until preflight, backup/preimage receipt, exclusive executor lease, source-write receipt, rollback/readback evidence, and post-write replay are all replay-clean.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_73_"):
        return [
            "- Build the backup/preimage receipt for the source-write executor path: capture backup file hash, source preimage hash, rollback ref, and no-raw-source evidence before any write.",
            "- Add post-write replay/readback settlement as the next required gate before a source-write executor can be considered complete.",
            "- Keep actual source writes disabled until preflight, backup/preimage receipt, exclusive executor lease, source-write receipt, and post-write replay are all replay-clean.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_72_"):
        return [
            "- Build the exclusive source-write executor preflight: require `BlastRadiusReview`, architecture gate, backup/preimage evidence, and post-write replay before any AMS-authority source write.",
            "- Wire doc-action/source-write execution paths to consume blast-radius proof instead of letting agents apply authority-path edits directly.",
            "- Keep Tree-sitter, SCIP, CodeQL, PanelGate, and vector/RAG adapters as later graph adapters until the Python/static proof path remains stable under executor tests.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_71_"):
        return [
            "- Build graph-backed source-change preflight: require fresh impact/test query receipts before AMS-authority source edits.",
            "- Add a compact `BlastRadiusReview` or architecture gate extension that consumes graph slices instead of dumping the full graph.",
            "- Keep Tree-sitter, SCIP, CodeQL, PanelGate, and vector/RAG adapters as later adapters until the static Python graph is a stable gate input.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_70_"):
        return [
            "- Build `CodebaseSpiderGraphIndex` from the existing Python AST architecture audit.",
            "- Add graph queries for impact slices, related tests, hidden paths, and stale graph checks.",
            "- Keep Tree-sitter, SCIP, CodeQL, PanelGate, and vector/RAG adapters behind later records until the static Python graph is replay-clean.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_69_"):
        return [
            "- Build `MarkdownAuthorityIndex` so markdown files have explicit authority, supersession, validity, and startup-inclusion metadata.",
            "- Add memory-source readback to new session briefs so active memory claims show proof refs instead of relying on model recall.",
            "- Keep production vector adapters, live retrieval, and API/storage promotion behind the existing receipt, replay, and operator gates.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_68_"):
        return [
            "- Resolve verifier findings on MILESTONE-68, then build MILESTONE-69: StorageRepository protocol plus SQLite WAL parity backend.",
            "- Keep Docker/API/source-write/live workers inert until storage export passes canonical JSON replay and replay-oracle parity.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_67_"):
        return [
            "- Build backup/preimage evidence for the MILESTONE-67 operator apply-acceptance packet before any source rewrite/split/archive.",
            "- Keep source writes disabled until backup evidence, rollback preimage, exact post-apply readback, and replay-clean settlement are all present.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_66_"):
        return [
            "- Build an explicit operator apply-acceptance/readback packet for the MILESTONE-66 apply boundary before any source rewrite/split/archive.",
            "- Keep source writes disabled until operator acceptance, rollback preimage evidence, backup evidence, and post-apply readback are all replay-clean.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_65_"):
        return [
            "- Build an explicit source patch apply boundary for the MILESTONE-65 executor preflight, with source/artifact hash rechecks immediately before any write.",
            "- Keep apply disabled unless the operator explicitly accepts the final apply packet and rollback/readback evidence requirements.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_64_"):
        return [
            "- Build a source patch executor preflight for the MILESTONE-64 live-execution approval packet before any source rewrite/split/archive.",
            "- Keep actual source writes disabled until the executor rechecks artifact/source hashes and a separate explicit apply boundary is verified.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_63_"):
        return [
            "- Build an explicit live execution approval packet for the MILESTONE-63 dry-run readback before any source rewrite/split/archive.",
            "- Keep source-file writes, moves, deletes, archives, and generated-surface rewrites disabled until live execution approval is separately verified.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_62_"):
        return [
            "- Build an operator dry-run readback receipt for the MILESTONE-62 dry-run plan before any source rewrite/split/archive.",
            "- Keep source-file writes, moves, deletes, archives, and generated-surface rewrites disabled until a later live execution approval exists.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_61_"):
        return [
            "- Build a dry-run doc patch executor plan that consumes a selected MILESTONE-61 approval packet and rechecks artifact/source hashes.",
            "- Keep source-file writes, moves, deletes, archives, and generated-surface rewrites disabled until a later live execution approval exists.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_60_"):
        return [
            "- Build an explicit operator approval packet for a selected MILESTONE-60 patch artifact before any source rewrite/split/archive.",
            "- Keep source-file writes, moves, deletes, archives, and generated-surface rewrites disabled until a later live execution approval exists.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_59_"):
        return [
            "- Build a separately reviewed literal patch artifact renderer or executor boundary for MILESTONE-59 readback-verified doc patch previews.",
            "- Keep source-file writes, moves, deletes, archives, generated-surface rewrites, and literal patch storage disabled until explicit live execution approval exists.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_58_"):
        return [
            "- Build the operator readback binding for the MILESTONE-58 dry-run doc patch previews.",
            "- Keep literal patches and source-file writes outside AMS until an explicit reviewed executor milestone.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_57_"):
        return [
            "- Build the dry-run patch renderer for the MILESTONE-57 doc-action approval packet.",
            "- Keep historical control docs unwritten, unmoved, and unarchived while producing reviewable patch hashes/previews.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_56_"):
        return [
            "- Build the operator-readback approval packet or dry-run patch renderer for the MILESTONE-56 doc-action plan.",
            "- Keep historical control docs unwritten, unmoved, and unarchived until approval, source-hash recheck, and replay gates pass.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_53_"):
        return [
            "- Use MILESTONE-49/MILESTONE-53 emulation and receiver proofs before promoting any remaining live boundary.",
            "- Next build priority: controlled live canary/source/receipt adapters, then approved remote/continuous pull, OS-level resource enforcement, RAG/vector adapter receipts, and generated truth surfaces.",
            "- Keep hook writes, trust, provider execution, non-owned process management, Discord, terminal, vector, embedding, network, SSH, push, pull, and remote-publication boundaries false until explicit approval exists.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_52_"):
        return [
            "- Use MILESTONE-49 as the emulation gate before promoting any remaining live boundary.",
            "- Next build priority: controlled live canary/source/receipt adapters, then approved remote/continuous pull, OS-level resource enforcement, RAG/vector adapter receipts, and generated truth surfaces.",
            "- Keep hook writes, trust, provider execution, non-owned process management, Discord, terminal, vector, embedding, network, SSH, push, and pull boundaries false until explicit approval exists.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_51_"):
        return [
            "- Use MILESTONE-49 as the emulation gate before promoting any remaining live boundary.",
            "- Next build priority: controlled live canary/source/receipt adapters, then remote/shareability, OS-level resource enforcement, RAG/vector adapter receipts, and generated truth surfaces.",
            "- Keep hook writes, trust, provider execution, non-owned process management, Discord, terminal, vector, embedding, and network boundaries false until explicit approval exists.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_50_"):
        return [
            "- Use MILESTONE-49 as the emulation gate before promoting any remaining live boundary.",
            "- Next build priority: controlled live canary/source/receipt adapters, then remote/shareability, resource enforcement, RAG/vector adapter receipts, and generated truth surfaces.",
            "- Keep hook writes, trust, provider execution, process start, Discord, terminal, vector, embedding, and network boundaries false until explicit approval exists.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_49_"):
        return [
            "- Use MILESTONE-49 as the emulation gate for remaining production-readiness work.",
            "- Next build priority: MILESTONE-50 operator readback receipt/verifier for the exact MILESTONE-48 approval packet, then live canary receipts, remote/shareability, resource enforcement, RAG/vector adapter receipts, and generated truth surfaces.",
            "- Keep hook writes, trust, provider execution, process start, Discord, terminal, vector, embedding, and network boundaries false until explicit approval exists.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_48_"):
        return [
            "- Build MILESTONE-49 agent sandbox emulation, then MILESTONE-50 operator readback receipt/verifier for the exact MILESTONE-48 approval packet.",
            "- Keep hook writes, trust, provider execution, process start, Discord, terminal, vector, embedding, and network boundaries false until explicit approval exists.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_47_"):
        return [
            "- Build MILESTONE-48 operator approval packet for the exact MILESTONE-47 hook install transaction.",
            "- Keep hook writes, trust, provider execution, process start, Discord, terminal, and network boundaries false until explicit approval exists.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_46_"):
        return [
            "- Build MILESTONE-47 no-write hook install transaction packet for the exact MILESTONE-46 target snapshot.",
            "- Render exact hook payload hashes and atomic rollback steps while keeping write, trust, execute, and process-start flags false.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_45_"):
        return [
            "- Build MILESTONE-46 hook-target snapshot and rollback drill records for the exact MILESTONE-45 binding.",
            "- Keep hook files unwritten, untrusted, and unexecuted while proving path/symlink safety and restore evidence.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_44_"):
        return [
            "- Build MILESTONE-45 signed-package/provenance and operator-approval binding for the exact MILESTONE-44 hook install plan.",
            "- Keep hook files unwritten and untrusted until signature, rollback, no-egress controls, and approval records are replay-clean.",
        ]
    if latest_milestone_doc.startswith("MILESTONE_43_"):
        return [
            "- Build MILESTONE-44 live-readiness bridge from sandbox hook records to trusted hook installation plans.",
            "- Keep live hooks uninstalled until signatures, trust review, rollback, no-egress controls, and operator approval are recorded.",
        ]
    return [
        "- Continue the MILESTONE-34 doc-retirement actions in small batches.",
        "- Then reduce architecture depth/locality/redundancy blockers before any production promotion.",
    ]
