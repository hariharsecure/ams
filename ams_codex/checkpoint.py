from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import canonical_json, sha256_text, stable_id, utc_now
from .session_registry import bump_session_revision
from .store import JsonStore


def build_summary_checkpoint(
    session: dict[str, Any],
    *,
    trigger: str,
    state_summary: str,
    next_action: str,
    token_usage: dict[str, Any] | None = None,
    decisions: list[str] | None = None,
    open_questions: list[str] | None = None,
    constraints: list[str] | None = None,
    source_refs: list[str] | None = None,
    artifact_refs: list[str] | None = None,
) -> dict[str, Any]:
    epoch = int(session.get("compaction_epoch", 0) or 0)
    if trigger == "post_compact":
        epoch += 1
    checkpoint = {
        "summary_checkpoint_id": stable_id("sum", session["session_id"], epoch, trigger, state_summary),
        "session_id": session["session_id"],
        "attention_id": session["attention_id"],
        "codex_thread_id": session.get("codex_thread_id"),
        "epoch": epoch,
        "trigger": trigger,
        "token_usage": token_usage or {},
        "state_summary": state_summary,
        "decisions": decisions or [],
        "open_questions": open_questions or [],
        "constraints": constraints or [],
        "source_refs": source_refs or list(session.get("source_refs", [])),
        "artifact_refs": artifact_refs or list(session.get("artifact_refs", [])),
        "no_repeat_keys": list(session.get("no_repeat_keys", [])),
        "lease_id": session.get("lease_id"),
        "next_action": next_action,
        "created_at": utc_now(),
    }
    checkpoint["checkpoint_sha256"] = sha256_text(canonical_json(checkpoint))
    return checkpoint


class CheckpointStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        session_id: str,
        *,
        trigger: str,
        state_summary: str,
        next_action: str,
        token_usage: dict[str, Any] | None = None,
        decisions: list[str] | None = None,
        open_questions: list[str] | None = None,
        constraints: list[str] | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            session = deepcopy(state.get("sessions", {}).get(session_id))
            if not session:
                raise KeyError(f"unknown session_id: {session_id}")
            checkpoint = build_summary_checkpoint(
                session,
                trigger=trigger,
                state_summary=state_summary,
                next_action=next_action,
                token_usage=token_usage,
                decisions=decisions,
                open_questions=open_questions,
                constraints=constraints,
            )
            state["checkpoints"][checkpoint["summary_checkpoint_id"]] = deepcopy(checkpoint)
            session["last_summary_checkpoint_id"] = checkpoint["summary_checkpoint_id"]
            session["compaction_epoch"] = checkpoint["epoch"]
            for binding in session.get("provider_sessions") or []:
                binding["last_checkpoint_id"] = checkpoint["summary_checkpoint_id"]
                binding["compaction_epoch"] = checkpoint["epoch"]
                binding["updated_at"] = checkpoint["created_at"]
            session = bump_session_revision(session, updated_at=checkpoint["created_at"])
            state["sessions"][session["session_id"]] = session
        return checkpoint
