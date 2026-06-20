from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import DiscordEvent, iso_after, priority_weight, stable_id, utc_now
from .predicate import default_intent, end_state_hash
from .store import JsonStore


def build_attention_context(session: dict[str, Any], raw_event: dict[str, Any]) -> dict[str, Any]:
    event = DiscordEvent.from_dict(raw_event)
    session_revision = int(session.get("session_revision", 0) or 0)
    target = {
        "kind": "discord_message",
        "id": event.message_id,
        "channel_id": event.channel_id,
    }
    constraints = [
        "do_not_post_to_discord_without_explicit_approval",
        "do_not_start_persistent_monitor_without_explicit_approval",
        "ams_state_wins_over_codex_transcript",
    ]
    intent = default_intent(requested_action=event.requested_action, constraints=constraints)
    context = {
        "context_id": stable_id(
            "ctx",
            session["session_id"],
            event.event_id,
            session.get("compaction_epoch", 0),
            session_revision,
        ),
        "attention_id": session["attention_id"],
        "parent_attention_id": event.parent_attention_id,
        "session_id": session["session_id"],
        "session_revision": session_revision,
        "target": target,
        "state": "working" if session.get("state") == "active" else "seen",
        "compaction_epoch": int(session.get("compaction_epoch", 0) or 0),
        "weight": priority_weight(event.priority),
        "lease": {
            "lease_id": session.get("lease_id"),
            "holder": session.get("lease_holder") or "agent_b",
            "expires_at": iso_after(1800),
            "end_state_sha256": end_state_hash(intent["end_state"]),
        },
        "source_refs": list(dict.fromkeys([*session.get("source_refs", []), event.to_ref()])),
        "artifact_refs": list(session.get("artifact_refs", [])),
        "summary_checkpoint_id": session.get("last_summary_checkpoint_id"),
        "open_questions": [],
        "constraints": constraints,
        "intent": intent,
        "source_class": "trusted",
        "requested_action": event.requested_action,
        "created_at": utc_now(),
    }
    return context


class ContextStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create_for_event(self, session: dict[str, Any], raw_event: dict[str, Any]) -> dict[str, Any]:
        with self.store.locked() as state:
            stored_session = state.get("sessions", {}).get(session["session_id"])
            context = build_attention_context(stored_session or session, raw_event)
            state["contexts"][context["context_id"]] = deepcopy(context)
        return context
