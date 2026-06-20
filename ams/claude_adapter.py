from __future__ import annotations

from copy import deepcopy
from typing import Any

from .context_validation import validate_fresh_context
from .models import stable_id, utc_now
from .provider_bindings import upsert_provider_session
from .session_registry import bump_session_revision
from .store import JsonStore


def claude_context_prompt(context: dict[str, Any], role: str = "verifier") -> str:
    return (
        "AMS/Claude dry-run context slice.\n"
        "Role: " + role + ".\n"
        "Do not post to Discord. Do not start persistent monitors. AMS state is authoritative.\n\n"
        f"session_id: {context['session_id']}\n"
        f"attention_id: {context['attention_id']}\n"
        f"target: {context['target']}\n"
        f"compaction_epoch: {context.get('compaction_epoch', 0)}\n"
        f"summary_checkpoint_id: {context.get('summary_checkpoint_id')}\n"
        f"source_refs: {context.get('source_refs', [])}\n"
        f"artifact_refs: {context.get('artifact_refs', [])}\n"
        "Task: verify Codex output against AMS constraints, identify gate risks, "
        "and return a concise verifier report. Do not execute egress.\n"
    )


def default_hook_plan() -> dict[str, Any]:
    return {
        "PreToolUse": [
            {
                "matcher": "Bash|Write|Edit|mcp__.*",
                "action": "call_ams_gate_shadow_or_signed_engine",
                "deny_priority": "deny > defer > ask > allow",
            }
        ],
        "PreCompact": [
            {
                "matcher": "*",
                "action": "write_summary_checkpoint_before_compaction",
            }
        ],
        "Stop": [
            {
                "matcher": "*",
                "action": "write_turn_completed_checkpoint",
            }
        ],
        "SubagentStart": [
            {
                "matcher": "*",
                "action": "create_child_attention_record",
            }
        ],
        "SubagentStop": [
            {
                "matcher": "*",
                "action": "merge_child_attention_summary",
            }
        ],
    }


def default_agent_definitions() -> dict[str, Any]:
    return {
        "ams-verifier": {
            "description": "Verifies Codex outputs against AMS gates and ATP context.",
            "tools": ["Read", "Glob", "Grep"],
            "prompt": "Check evidence, risk, no-repeat, and egress constraints. Return verifier report only.",
        },
        "ams-safety-lens": {
            "description": "Reviews proposed actions for gate bypass, secret exposure, and authority drift.",
            "tools": ["Read", "Glob", "Grep"],
            "prompt": "Identify safety/governance violations and required AMS gate decisions.",
        },
    }


def build_claude_request(
    session: dict[str, Any],
    context: dict[str, Any],
    *,
    role: str = "verifier",
    allowed_tools: list[str] | None = None,
) -> dict[str, Any]:
    request_id = stable_id("clauderpc", session["session_id"], context["context_id"], role, length=12)
    options = {
        "allowed_tools": allowed_tools or ["Read", "Glob", "Grep", "Agent"],
        "hooks": default_hook_plan(),
        "agents": default_agent_definitions(),
        "mcp_servers": {},
        "setting_sources": [],
    }
    if session.get("claude_session_id"):
        options["resume"] = session["claude_session_id"]
    return {
        "id": request_id,
        "surface": "claude-agent-sdk",
        "dry_run": True,
        "prompt": claude_context_prompt(context, role=role),
        "options": options,
        "expected_result": {
            "type": "verifier_report",
            "fields": ["verdict", "reasons", "risk_flags", "required_next_action"],
        },
    }


class ClaudeDryRunAdapter:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def prepare_request(self, session_id: str, context_id: str, *, role: str = "verifier") -> dict[str, Any]:
        with self.store.locked() as state:
            session = state["sessions"].get(session_id)
            context = state["contexts"].get(context_id)
            if not session:
                raise KeyError(f"unknown session_id: {session_id}")
            if not context:
                raise KeyError(f"unknown context_id: {context_id}")
            validate_fresh_context(session, context)
            request = build_claude_request(deepcopy(session), deepcopy(context), role=role)
            state.setdefault("claude_requests", {})[request["id"]] = {
                "created_at": utc_now(),
                "session_id": session_id,
                "context_id": context_id,
                "dry_run": True,
                "request": request,
            }
        return request

    def bind_session(
        self,
        session_id: str,
        claude_session_id: str,
        *,
        claude_agent_id: str | None = None,
        surface: str = "agent-sdk",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            session = deepcopy(state.get("sessions", {}).get(session_id))
            if not session:
                raise KeyError(f"unknown session_id: {session_id}")
            session["claude_session_id"] = claude_session_id
            session["claude_agent_id"] = claude_agent_id
            session["claude_surface"] = surface
            session = upsert_provider_session(
                session,
                provider="anthropic_claude",
                surface=surface,
                provider_session_id=claude_session_id,
                provider_agent_id=claude_agent_id,
                status="active",
            )
            session = bump_session_revision(session, updated_at=utc_now())
            state["sessions"][session_id] = session
        return session
