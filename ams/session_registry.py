from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import AGENT_B, DiscordEvent, sha256_text, stable_id, utc_now
from .store import JsonStore


ACTIVE_STATES = {"pending", "active", "blocked"}


def bump_session_revision(session: dict[str, Any], *, updated_at: str | None = None) -> dict[str, Any]:
    session = deepcopy(session)
    session["session_revision"] = int(session.get("session_revision", 0) or 0) + 1
    session["updated_at"] = updated_at or utc_now()
    return session


class SessionRegistry:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def ingest_event(self, raw_event: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        event = DiscordEvent.from_dict(raw_event)
        with self.store.locked() as state:
            session_id = self._select_session_id(state, event)
            created = False
            if session_id and session_id in state["sessions"]:
                session = self._update_session(state, state["sessions"][session_id], event)
            else:
                session = self._create_session(event)
                state["sessions"][session["session_id"]] = session
                created = True

            state["events"][event.event_id] = event.to_dict()
            self._index_event(state, session, event)
        return deepcopy(session), created

    def get(self, session_id: str) -> dict[str, Any] | None:
        return deepcopy(self.store.load()["sessions"].get(session_id))

    def list_sessions(self) -> list[dict[str, Any]]:
        sessions = list(self.store.load()["sessions"].values())
        return sorted((deepcopy(s) for s in sessions), key=lambda s: s.get("updated_at", ""), reverse=True)

    def update_session(self, session: dict[str, Any]) -> None:
        with self.store.locked() as state:
            if session["session_id"] not in state["sessions"]:
                raise KeyError(f"unknown session_id: {session['session_id']}")
            session = bump_session_revision(session)
            state["sessions"][session["session_id"]] = session

    def _select_session_id(self, state: dict[str, Any], event: DiscordEvent) -> str | None:
        indexes = state["indexes"]
        candidates = [
            indexes["message_to_session"].get(event.reply_to_message_id or ""),
            indexes["thread_to_session"].get(event.discord_thread_id or ""),
            indexes["attention_to_session"].get(event.parent_attention_id or ""),
            indexes["root_to_session"].get(self._root_key(event)),
        ]
        for candidate in candidates:
            if not candidate:
                continue
            session = state["sessions"].get(candidate)
            if session and session.get("state") in ACTIVE_STATES:
                return str(candidate)
        return None

    def _create_session(self, event: DiscordEvent) -> dict[str, Any]:
        root_key = self._root_key(event)
        base = [event.channel_id, event.effective_root_message_id, event.content_sha256]
        session_id = stable_id("sess", *base)
        attention_id = event.attention_id or stable_id("attn", event.channel_id, event.effective_root_message_id)
        now = utc_now()
        no_repeat_keys = self._no_repeat_keys(event, attention_id)
        return {
            "session_id": session_id,
            "ams_task_id": stable_id("task", *base),
            "attention_id": attention_id,
            "discord_channel_id": event.channel_id,
            "discord_root_message_id": event.effective_root_message_id,
            "discord_thread_id": event.discord_thread_id,
            "codex_thread_id": None,
            "codex_surface": "unknown",
            "claude_session_id": None,
            "claude_agent_id": None,
            "claude_surface": "unknown",
            "provider_sessions": [],
            "state": "pending",
            "lease_id": stable_id("lease", session_id, AGENT_B),
            "lease_holder": AGENT_B,
            "last_summary_checkpoint_id": None,
            "compaction_epoch": 0,
            "session_revision": 1,
            "no_repeat_keys": no_repeat_keys,
            "artifact_refs": [],
            "source_refs": [event.to_ref()],
            "message_ids": [event.message_id],
            "event_ids": [event.event_id],
            "root_key": root_key,
            "created_at": now,
            "updated_at": now,
        }

    def _update_session(self, state: dict[str, Any], session: dict[str, Any], event: DiscordEvent) -> dict[str, Any]:
        session = deepcopy(session)
        session.setdefault("source_refs", [])
        session.setdefault("message_ids", [])
        session.setdefault("event_ids", [])
        session.setdefault("no_repeat_keys", [])
        for ref in [event.to_ref()]:
            if ref not in session["source_refs"]:
                session["source_refs"].append(ref)
        if event.message_id not in session["message_ids"]:
            session["message_ids"].append(event.message_id)
        if event.event_id not in session["event_ids"]:
            session["event_ids"].append(event.event_id)
        for key in self._no_repeat_keys(event, session["attention_id"]):
            if key not in session["no_repeat_keys"]:
                session["no_repeat_keys"].append(key)
        if event.discord_thread_id and not session.get("discord_thread_id"):
            session["discord_thread_id"] = event.discord_thread_id
        session = bump_session_revision(session)
        state["sessions"][session["session_id"]] = session
        return session

    def _index_event(self, state: dict[str, Any], session: dict[str, Any], event: DiscordEvent) -> None:
        indexes = state["indexes"]
        sid = session["session_id"]
        indexes["root_to_session"][self._root_key(event)] = sid
        indexes["message_to_session"][event.message_id] = sid
        indexes["attention_to_session"][session["attention_id"]] = sid
        if event.parent_attention_id:
            indexes["attention_to_session"][event.parent_attention_id] = sid
        if event.discord_thread_id:
            indexes["thread_to_session"][event.discord_thread_id] = sid
        if event.content_sha256:
            indexes["content_to_session"][event.content_sha256] = sid

    def _root_key(self, event: DiscordEvent) -> str:
        return f"discord:{event.channel_id}:{event.effective_root_message_id}"

    def _no_repeat_keys(self, event: DiscordEvent, attention_id: str) -> list[str]:
        keys = [
            sha256_text(f"attention:{attention_id}"),
            sha256_text(f"discord:{event.channel_id}:{event.effective_root_message_id}"),
        ]
        if event.content_sha256:
            keys.append(sha256_text(f"content:{event.content_sha256}"))
        return keys
