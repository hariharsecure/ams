from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from .models import hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore
from .workspace import repo_root


SCHEMA_VERSION = "ams.ams_codex.work_mode_decision.v0"
DECISIONS = {"standard_verification", "session_isolation", "cleanup_audit", "both"}
STATUSES = {"allow", "defer", "deny"}

SESSION_TERMS = {
    "agent",
    "agents",
    "claude",
    "codex",
    "compact",
    "compaction",
    "context",
    "forget",
    "forgetting",
    "hallucination",
    "handoff",
    "hook",
    "hooks",
    "isolation",
    "memory",
    "restart",
    "resume",
    "session",
    "subagent",
    "subagents",
    "surface",
    "terminal",
    "tmux",
    "worktree",
}

CLEANUP_TERMS = {
    "abandoned",
    "api",
    "cleanup",
    "complex",
    "complexity",
    "dead",
    "debt",
    "dependency",
    "duplicate",
    "legacy",
    "maintainability",
    "redundant",
    "simplify",
    "unused",
}

SESSION_PATH_HINTS = (
    "agent_memory_sim.py",
    "attention_router.py",
    "checkpoint.py",
    "claude_adapter.py",
    "codex_adapter.py",
    "context.py",
    "context_validation.py",
    "discord_source.py",
    "manager_intervention.py",
    "provider_bindings.py",
    "real_agent_trial.py",
    "session_registry.py",
    "session_start_brief.py",
    "surface_bindings.py",
    "terminal_source.py",
    "schemas/agent_memory_trial.schema.json",
    "schemas/attention_signal.schema.json",
    "schemas/real_agent_trial.schema.json",
    "schemas/session_registry.schema.json",
)

CLEANUP_PATH_HINTS = (
    "architecture_audit.py",
    "doc_action_execution.py",
    "doc_action_operator_approval.py",
    "doc_action_patch_preview.py",
    "doc_action_patch_readback.py",
    "doc_action_patch_artifact.py",
    "doc_action_patch_artifact_approval.py",
    "doc_action_patch_dry_run.py",
    "doc_action_patch_dry_run_readback.py",
    "doc_action_patch_live_execution_approval.py",
    "doc_action_patch_executor_preflight.py",
    "doc_action_patch_apply_boundary.py",
    "doc_action_patch_apply_acceptance.py",
    "doc_retirement.py",
    "generated_status.py",
    "markdown_governance.py",
    "readiness_review.py",
    "replay.py",
    "replay_oracle.py",
    "cli.py",
    "MILESTONES.md",
    "README.md",
    "STATUS.md",
    "GENERATED_STATUS.md",
)

RESEARCH_BASIS = [
    {
        "lens": "codex_instruction_scope",
        "source": "OpenAI Codex manual: Custom instructions with AGENTS.md",
        "url": "https://developers.openai.com/codex/guides/agents-md.md",
    },
    {
        "lens": "codex_lifecycle_hooks",
        "source": "OpenAI Codex manual: Hooks",
        "url": "https://developers.openai.com/codex/hooks.md",
    },
    {
        "lens": "codex_context_isolation",
        "source": "OpenAI Codex manual: Subagents",
        "url": "https://developers.openai.com/codex/concepts/subagents.md",
    },
    {
        "lens": "codex_worktree_isolation",
        "source": "OpenAI Codex manual: Worktrees",
        "url": "https://developers.openai.com/codex/app/worktrees.md",
    },
]

LIVE_BOUNDARIES = {
    "raw_request_stored": False,
    "raw_session_content_stored": False,
    "transcript_text_stored": False,
    "network_call_performed": False,
    "provider_call_performed": False,
    "discord_egress_performed": False,
    "process_started": False,
}


class WorkModeDecisionStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        request_text: str | None = None,
        request_ref: str | None = None,
        changed_paths: list[str] | tuple[str, ...] | None = None,
        source_root: str | Path | None = None,
        label: str = "manual-work-mode-decision",
        source_surface: str = "codex",
        session_id: str | None = None,
    ) -> dict[str, Any]:
        record = build_work_mode_decision(
            request_text=request_text,
            request_ref=request_ref,
            changed_paths=changed_paths,
            source_root=source_root,
            label=label,
            source_surface=source_surface,
            session_id=session_id,
        )
        with self.store.locked() as state:
            decision_id = record["work_mode_decision_id"]
            state.setdefault("work_mode_decisions", {})[decision_id] = record
            state.setdefault("indexes", {}).setdefault("work_mode_decision_ids", {})[decision_id] = decision_id
            return deepcopy(record)


def build_work_mode_decision(
    *,
    request_text: str | None = None,
    request_ref: str | None = None,
    changed_paths: list[str] | tuple[str, ...] | None = None,
    source_root: str | Path | None = None,
    label: str = "manual-work-mode-decision",
    source_surface: str = "codex",
    session_id: str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False) if source_root else repo_root()
    paths = _unique_sorted([str(path) for path in (changed_paths or []) if str(path)])
    text = request_text or ""
    text_lc = text.lower()
    path_blob = "\n".join(paths).lower()

    session_term_hits = _term_hits(text_lc, SESSION_TERMS)
    cleanup_term_hits = _term_hits(text_lc, CLEANUP_TERMS)
    session_path_hits = _path_hits(path_blob, SESSION_PATH_HINTS)
    cleanup_path_hits = _path_hits(path_blob, CLEANUP_PATH_HINTS)

    session_required = bool(session_term_hits or session_path_hits)
    cleanup_required = bool(cleanup_term_hits or cleanup_path_hits)
    if session_required and cleanup_required:
        decision = "both"
    elif session_required:
        decision = "session_isolation"
    elif cleanup_required:
        decision = "cleanup_audit"
    else:
        decision = "standard_verification"

    mode_flags = {
        "session_isolation_tests_required": session_required,
        "cleanup_audit_required": cleanup_required,
        "standard_verification_required": True,
    }
    reason_codes = _reason_codes(
        decision=decision,
        session_term_hits=session_term_hits,
        cleanup_term_hits=cleanup_term_hits,
        session_path_hits=session_path_hits,
        cleanup_path_hits=cleanup_path_hits,
    )
    record = {
        "schema_version": SCHEMA_VERSION,
        "work_mode_decision_id": stable_id(
            "workmode",
            label,
            request_ref,
            sha256_text(text) if text else None,
            paths,
            decision,
            now,
        ),
        "label": label,
        "source_surface": source_surface,
        "session_id": session_id,
        "source_root": str(root),
        "request_ref": request_ref,
        "request_sha256": sha256_text(text) if text else None,
        "request_length": len(text),
        "raw_request_stored": False,
        "changed_paths": paths,
        "decision": decision,
        "mode_flags": mode_flags,
        "trigger_summary": {
            "session_terms": session_term_hits,
            "cleanup_terms": cleanup_term_hits,
            "session_path_hints": session_path_hits,
            "cleanup_path_hints": cleanup_path_hits,
        },
        "recommended_commands": _recommended_commands(decision=decision, source_root=str(root)),
        "codex_surface_guidance": [
            {
                "surface": "AGENTS.md",
                "use": "Durable baseline rules loaded at Codex session start; not enough for per-prompt routing.",
            },
            {
                "surface": "hooks",
                "use": "Use UserPromptSubmit or SessionStart hooks to create this decision before work starts; use PreCompact/PostCompact to force isolation checks around compaction.",
            },
            {
                "surface": "subagents",
                "use": "Use only when explicitly requested or when AMS records a bounded parallel review plan; keep noisy exploration out of the main thread.",
            },
            {
                "surface": "worktrees",
                "use": "Use for isolated/background edits or experiments that should not disturb the foreground checkout.",
            },
        ],
        "research_basis": RESEARCH_BASIS,
        "live_boundaries": dict(LIVE_BOUNDARIES),
        "status": "allow",
        "reason_codes": reason_codes,
        "created_at": now,
        "updated_at": now,
    }
    record["work_mode_decision_sha256"] = _hash_without(record, "work_mode_decision_sha256")
    return deepcopy(record)


def validate_work_mode_decision_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("work_mode_decision.schema.json", record, location="work_mode_decision")
    except SchemaValidationError:
        reason_codes.append("work_mode_decision.schema_invalid")
    expected_hash = record.get("work_mode_decision_sha256")
    if expected_hash and expected_hash != _hash_without(record, "work_mode_decision_sha256"):
        reason_codes.append("work_mode_decision.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("work_mode_decision.schema_version_invalid")
    if record.get("decision") not in DECISIONS:
        reason_codes.append("work_mode_decision.decision_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("work_mode_decision.status_invalid")
    if record.get("raw_request_stored") is not False:
        reason_codes.append("work_mode_decision.raw_request_stored_not_false")
    for key, expected in LIVE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"work_mode_decision.{key}_not_false")
    expected_decision = _decision_from_flags(record.get("mode_flags") or {})
    if record.get("decision") != expected_decision:
        reason_codes.append("work_mode_decision.decision_flags_mismatch")
    command_modes = {command.get("mode") for command in record.get("recommended_commands") or []}
    if "standard_verification" not in command_modes:
        reason_codes.append("work_mode_decision.standard_command_missing")
    flags = record.get("mode_flags") or {}
    if flags.get("session_isolation_tests_required") and "session_isolation_tests" not in command_modes:
        reason_codes.append("work_mode_decision.session_isolation_command_missing")
    if flags.get("cleanup_audit_required") and "cleanup_audit" not in command_modes:
        reason_codes.append("work_mode_decision.cleanup_command_missing")
    for command in record.get("recommended_commands") or []:
        if command.get("live_boundary") is not False:
            reason_codes.append("work_mode_decision.command_live_boundary_not_false")
    if record.get("request_length", 0) and not record.get("request_sha256"):
        reason_codes.append("work_mode_decision.request_hash_missing")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _decision_from_flags(flags: dict[str, Any]) -> str:
    session_required = flags.get("session_isolation_tests_required") is True
    cleanup_required = flags.get("cleanup_audit_required") is True
    if session_required and cleanup_required:
        return "both"
    if session_required:
        return "session_isolation"
    if cleanup_required:
        return "cleanup_audit"
    return "standard_verification"


def _term_hits(text: str, terms: set[str]) -> list[str]:
    hits = []
    for term in terms:
        pattern = rf"(?<![A-Za-z0-9_]){re.escape(term)}(?![A-Za-z0-9_])"
        if re.search(pattern, text):
            hits.append(term)
    return sorted(hits)


def _path_hits(path_blob: str, hints: tuple[str, ...]) -> list[str]:
    return sorted({hint for hint in hints if hint.lower() in path_blob})


def _unique_sorted(values: list[str]) -> list[str]:
    return sorted(set(values))


def _reason_codes(
    *,
    decision: str,
    session_term_hits: list[str],
    cleanup_term_hits: list[str],
    session_path_hits: list[str],
    cleanup_path_hits: list[str],
) -> list[str]:
    reasons = [f"work_mode.decision_{decision}", "work_mode.standard_verification_required"]
    if session_term_hits:
        reasons.append("work_mode.session_terms_detected")
    if cleanup_term_hits:
        reasons.append("work_mode.cleanup_terms_detected")
    if session_path_hits:
        reasons.append("work_mode.session_paths_detected")
    if cleanup_path_hits:
        reasons.append("work_mode.cleanup_paths_detected")
    if decision == "standard_verification":
        reasons.append("work_mode.no_special_route_detected")
    return sorted(set(reasons))


def _recommended_commands(*, decision: str, source_root: str) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []
    audit_store_path = os.path.join(tempfile.gettempdir(), "ams_work_mode_architecture_audit.json")
    if decision in {"session_isolation", "both"}:
        commands.extend(
            [
                _command(
                    mode="session_isolation_tests",
                    command="python3 -m pytest tests/test_agent_memory_sim.py tests/test_attention_router.py tests/test_session_registry.py tests/test_context_checkpoint.py -q",
                    reason_code="work_mode.run_session_memory_and_routing_tests",
                    effect="read_only_test",
                ),
                _command(
                    mode="session_isolation_tests",
                    command="python3 -m pytest tests/test_codex_adapter.py tests/test_claude_adapter.py tests/test_m8g_full.py -q",
                    reason_code="work_mode.run_provider_session_resume_tests",
                    effect="read_only_test",
                ),
            ]
        )
    if decision in {"cleanup_audit", "both"}:
        commands.extend(
            [
                _command(
                    mode="cleanup_audit",
                    command="python3 -m pytest tests/test_architecture_audit.py tests/test_doc_retirement.py tests/test_generated_status.py -q",
                    reason_code="work_mode.run_cleanup_governance_tests",
                    effect="read_only_test",
                ),
                _command(
                    mode="cleanup_audit",
                    command=f"python3 -m ams_codex.cli --store {audit_store_path} architecture-audit --source-root {source_root} --package-name ams_codex",
                    reason_code="work_mode.run_architecture_audit",
                    effect="runtime_store_write",
                ),
            ]
        )
    commands.extend(
        [
            _command(
                mode="standard_verification",
                command="git diff --check",
                reason_code="work_mode.run_diff_check",
                effect="read_only_test",
            ),
            _command(
                mode="standard_verification",
                command="python3 -m pytest -q",
                reason_code="work_mode.run_full_tests",
                effect="read_only_test",
            ),
        ]
    )
    return commands


def _command(*, mode: str, command: str, reason_code: str, effect: str) -> dict[str, Any]:
    return {
        "command_id": stable_id("wmcmd", mode, command, reason_code, length=12),
        "mode": mode,
        "command": command,
        "reason_code": reason_code,
        "effect": effect,
        "required": True,
        "live_boundary": False,
    }
