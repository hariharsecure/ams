from __future__ import annotations

from copy import deepcopy
from typing import Any

from .context_validation import validate_fresh_context
from .models import stable_id, utc_now
from .provider_bindings import upsert_provider_session
from .session_registry import bump_session_revision
from .store import JsonStore
from .workspace import workspace_root


def sandbox_policy(kind: str = "read-only") -> dict[str, Any]:
    if kind == "workspace-write":
        return {"type": "workspaceWrite", "networkAccess": False, "writableRoots": []}
    if kind == "danger-full-access":
        return {"type": "dangerFullAccess"}
    return {"type": "readOnly", "networkAccess": False}


def context_prompt(context: dict[str, Any]) -> str:
    return (
        "AMS dry-run context slice.\n"
        "Do not post to Discord. Do not start persistent monitors. AMS state is authoritative.\n\n"
        f"session_id: {context['session_id']}\n"
        f"attention_id: {context['attention_id']}\n"
        f"target: {context['target']}\n"
        f"state: {context['state']}\n"
        f"compaction_epoch: {context.get('compaction_epoch', 0)}\n"
        f"lease: {context['lease']}\n"
        f"summary_checkpoint_id: {context.get('summary_checkpoint_id')}\n"
        f"source_refs: {context.get('source_refs', [])}\n"
        f"artifact_refs: {context.get('artifact_refs', [])}\n"
        f"constraints: {context.get('constraints', [])}\n"
        f"requested_action: {context['requested_action']}\n"
    )


def build_codex_request(
    session: dict[str, Any],
    context: dict[str, Any],
    *,
    model: str = "gpt-5.5",
    cwd: str | None = None,
    sandbox: str = "read-only",
    active_turn_id: str | None = None,
) -> dict[str, Any]:
    cwd = cwd or workspace_root()
    request_id = stable_id("rpc", session["session_id"], context["context_id"], length=12)
    prompt = context_prompt(context)
    if session.get("codex_thread_id") and active_turn_id:
        return {
            "id": request_id,
            "method": "turn/steer",
            "params": {
                "threadId": session["codex_thread_id"],
                "expectedTurnId": active_turn_id,
                "input": [{"type": "text", "text": prompt}],
            },
        }
    if session.get("codex_thread_id"):
        return {
            "id": request_id,
            "method": "turn/start",
            "params": {
                "threadId": session["codex_thread_id"],
                "input": [{"type": "text", "text": prompt}],
                "approvalPolicy": "never",
                "sandboxPolicy": sandbox_policy(sandbox),
                "cwd": cwd,
                "model": model,
            },
        }
    return {
        "id": request_id,
        "method": "thread/start",
        "params": {
            "model": model,
            "cwd": cwd,
            "sandboxPolicy": sandbox_policy(sandbox),
            "approvalPolicy": "never",
            "initialUserMessage": prompt,
        },
    }


def build_codex_resume_request(
    session: dict[str, Any],
    *,
    model: str = "gpt-5.5",
    cwd: str | None = None,
    sandbox: str = "read-only",
) -> dict[str, Any]:
    cwd = cwd or workspace_root()
    if not session.get("codex_thread_id"):
        raise ValueError("cannot resume Codex without codex_thread_id")
    return {
        "id": stable_id("rpcresume", session["session_id"], session["codex_thread_id"], length=12),
        "method": "thread/resume",
        "params": {
            "threadId": session["codex_thread_id"],
            "model": model,
            "cwd": cwd,
            "sandboxPolicy": sandbox_policy(sandbox),
            "approvalPolicy": "never",
        },
    }


class CodexDryRunAdapter:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def prepare_request(
        self,
        session_id: str,
        context_id: str,
        *,
        model: str = "gpt-5.5",
        cwd: str | None = None,
        sandbox: str = "read-only",
        active_turn_id: str | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            session = state["sessions"].get(session_id)
            context = state["contexts"].get(context_id)
            if not session:
                raise KeyError(f"unknown session_id: {session_id}")
            if not context:
                raise KeyError(f"unknown context_id: {context_id}")
            validate_fresh_context(session, context)
            request = build_codex_request(
                deepcopy(session),
                deepcopy(context),
                model=model,
                cwd=cwd,
                sandbox=sandbox,
                active_turn_id=active_turn_id,
            )
            state.setdefault("codex_requests", {})[request["id"]] = {
                "created_at": utc_now(),
                "session_id": session_id,
                "context_id": context_id,
                "dry_run": True,
                "request": request,
            }
        return request

    def bind_thread(self, session_id: str, thread_id: str, surface: str = "app-server") -> dict[str, Any]:
        with self.store.locked() as state:
            session = deepcopy(state.get("sessions", {}).get(session_id))
            if not session:
                raise KeyError(f"unknown session_id: {session_id}")
            session["codex_thread_id"] = thread_id
            session["codex_surface"] = surface
            session["state"] = "active"
            session = upsert_provider_session(
                session,
                provider="openai_codex",
                surface=surface,
                provider_session_id=thread_id,
                status="active",
            )
            session = bump_session_revision(session, updated_at=utc_now())
            state["sessions"][session_id] = session
        return session

    def prepare_resume_request(
        self,
        session_id: str,
        *,
        model: str = "gpt-5.5",
        cwd: str | None = None,
        sandbox: str = "read-only",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            session = state["sessions"].get(session_id)
            if not session:
                raise KeyError(f"unknown session_id: {session_id}")
            request = build_codex_resume_request(deepcopy(session), model=model, cwd=cwd, sandbox=sandbox)
            state.setdefault("codex_requests", {})[request["id"]] = {
                "created_at": utc_now(),
                "session_id": session_id,
                "context_id": None,
                "dry_run": True,
                "request": request,
            }
        return request
