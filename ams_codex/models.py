from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any


AGENT_B_BOT_ID = "000000000000000001"
AGENT_B = "agent_b"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(ts: str | None) -> datetime:
    if not ts:
        return datetime.now(timezone.utc)
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


def iso_after(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_without(record: dict[str, Any], key: str) -> str:
    material = deepcopy(record)
    material.pop(key, None)
    return sha256_text(canonical_json(material))


def stable_id(prefix: str, *parts: Any, length: int = 20) -> str:
    digest = hashlib.sha256(canonical_json(parts).encode("utf-8")).hexdigest()[:length]
    return f"{prefix}_{digest}"


def content_hash(content: str | None) -> str | None:
    if content is None:
        return None
    return sha256_text(content)


def priority_weight(priority: str | None) -> int:
    return {
        "P0": 100,
        "P1": 85,
        "P2": 65,
        "P3": 45,
        "P4": 30,
    }.get(str(priority or "").upper(), 25)


@dataclass
class DiscordEvent:
    event_id: str
    channel_id: str
    message_id: str
    author_id: str | None = None
    author_name: str | None = None
    content: str | None = None
    content_sha256: str | None = None
    discord_thread_id: str | None = None
    reply_to_message_id: str | None = None
    root_message_id: str | None = None
    event_type: str = "message_create"
    priority: str = "P2"
    reason_code: str = "manual_dry_run"
    source_surface: str = "discord"
    received_at: str = field(default_factory=utc_now)
    attention_id: str | None = None
    parent_attention_id: str | None = None
    requested_action: str = "inspect_and_plan"
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "DiscordEvent":
        channel_id = str(raw.get("channel_id") or raw.get("discord_channel_id") or "")
        message_id = str(raw.get("message_id") or raw.get("discord_message_id") or "")
        if not channel_id or not message_id:
            raise ValueError("Discord event requires channel_id and message_id")

        content = raw.get("content")
        digest = raw.get("content_sha256") or raw.get("payload_sha256") or content_hash(content)
        root = raw.get("root_message_id") or raw.get("discord_root_message_id")
        event_id = raw.get("event_id") or raw.get("event_key") or stable_id(
            "evt", channel_id, message_id, raw.get("event") or raw.get("event_type") or "message_create"
        )
        return cls(
            event_id=str(event_id),
            channel_id=channel_id,
            message_id=message_id,
            author_id=str(raw["author_id"]) if raw.get("author_id") is not None else None,
            author_name=raw.get("author_name"),
            content=content,
            content_sha256=str(digest) if digest else None,
            discord_thread_id=str(raw["discord_thread_id"] or raw["thread_id"]) if raw.get("discord_thread_id") or raw.get("thread_id") else None,
            reply_to_message_id=str(raw["reply_to_message_id"] or raw["reply_to"]) if raw.get("reply_to_message_id") or raw.get("reply_to") else None,
            root_message_id=str(root) if root else None,
            event_type=str(raw.get("event") or raw.get("event_type") or "message_create"),
            priority=str(raw.get("priority") or "P2"),
            reason_code=str(raw.get("reason_code") or "manual_dry_run"),
            source_surface=str(raw.get("source_surface") or "discord"),
            received_at=str(raw.get("received_at") or utc_now()),
            attention_id=str(raw["attention_id"]) if raw.get("attention_id") else None,
            parent_attention_id=str(raw["parent_attention_id"]) if raw.get("parent_attention_id") else None,
            requested_action=str(raw.get("requested_action") or "inspect_and_plan"),
            metadata={k: v for k, v in raw.items() if k not in EVENT_TOP_LEVEL_KEYS},
        )

    @property
    def effective_root_message_id(self) -> str:
        return self.root_message_id or self.discord_thread_id or self.reply_to_message_id or self.message_id

    def to_ref(self) -> str:
        return f"discord://{self.channel_id}/{self.message_id}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "channel_id": self.channel_id,
            "message_id": self.message_id,
            "author_id": self.author_id,
            "author_name": self.author_name,
            "content_sha256": self.content_sha256,
            "content_length": len(self.content or "") if self.content is not None else None,
            "discord_thread_id": self.discord_thread_id,
            "reply_to_message_id": self.reply_to_message_id,
            "root_message_id": self.root_message_id,
            "event_type": self.event_type,
            "priority": self.priority,
            "reason_code": self.reason_code,
            "source_surface": self.source_surface,
            "received_at": self.received_at,
            "attention_id": self.attention_id,
            "parent_attention_id": self.parent_attention_id,
            "requested_action": self.requested_action,
            "metadata": self.metadata,
        }


EVENT_TOP_LEVEL_KEYS = {
    "event_id",
    "event_key",
    "channel_id",
    "discord_channel_id",
    "message_id",
    "discord_message_id",
    "author_id",
    "author_name",
    "content",
    "content_sha256",
    "payload_sha256",
    "discord_thread_id",
    "thread_id",
    "reply_to_message_id",
    "reply_to",
    "root_message_id",
    "discord_root_message_id",
    "event",
    "event_type",
    "priority",
    "reason_code",
    "source_surface",
    "received_at",
    "attention_id",
    "parent_attention_id",
    "requested_action",
}
