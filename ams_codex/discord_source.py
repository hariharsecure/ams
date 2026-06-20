from __future__ import annotations

from copy import deepcopy
from typing import Any

from .attention_router import build_attention_signal, validate_attention_signal_record
from .models import hash_without as _hash_without, canonical_json, content_hash, sha256_text, stable_id, utc_now
from .source_packet_common import (
    forbidden_keys as _forbidden_keys,
    optional_str as _optional_str,
    required_str as _required_str,
    unique as _unique,
)
from .store import JsonStore


SCHEMA_VERSION = "ams.ams_codex.discord_source_packet.v0"
STATUSES = {"ready_for_attention", "blocked"}
FORBIDDEN_SECRET_KEYS = {
    "authorization",
    "bot_token",
    "cookie",
    "discord_token",
    "password",
    "secret",
    "session_cookie",
    "token",
    "webhook_token",
}
FORBIDDEN_SEND_KEYS = {
    "send_allowed",
    "send_endpoint",
    "send_message",
    "webhook_url",
    "write_endpoint",
}


class DiscordSourcePacketStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        raw_packet: dict[str, Any],
        *,
        create_attention_signal: bool = False,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            record = build_discord_source_packet(raw_packet)
            if create_attention_signal and record["status"] != "blocked":
                signal = build_attention_signal(state, _attention_raw(record))
                signal_validation = validate_attention_signal_record(signal, state=state)
                if signal_validation["ok"]:
                    signal_id = signal["attention_signal_id"]
                    state.setdefault("attention_signals", {})[signal_id] = signal
                    indexes = state.setdefault("indexes", {})
                    indexes.setdefault("attention_signal_ids", {})[signal_id] = signal_id
                    indexes.setdefault("source_ref_to_attention_signal", {})[signal["source_ref"]] = signal_id
                    indexes.setdefault("content_to_attention_signal", {})[signal["content_sha256"]] = signal_id
                    record["attention_signal_created"] = True
                    record["attention_signal_id"] = signal_id
                    record["attention_signal_sha256"] = signal["attention_signal_sha256"]
                    record["reason_codes"] = _unique(
                        [*record["reason_codes"], "discord_source.attention_signal_created"]
                    )
                    record["source_packet_sha256"] = _hash_without(record, "source_packet_sha256")
                else:
                    record["status"] = "blocked"
                    record["reason_codes"] = _unique(
                        [
                            reason
                            for reason in record["reason_codes"]
                            if reason != "discord_source.ready_read_only"
                        ]
                        + [f"discord_source.attention_signal_invalid:{reason}" for reason in signal_validation["reason_codes"]]
                    )
                    record["source_packet_sha256"] = _hash_without(record, "source_packet_sha256")

            validation = validate_discord_source_packet_record(record, state=state)
            if not validation["ok"]:
                raise ValueError("; ".join(validation["reason_codes"]))
            packet_id = record["discord_source_packet_id"]
            indexes = state.setdefault("indexes", {})
            state.setdefault("discord_source_packets", {})[packet_id] = record
            indexes.setdefault("discord_source_packet_ids", {})[packet_id] = packet_id
            indexes.setdefault("source_ref_to_discord_source_packet", {})[record["source_ref"]] = packet_id
        return deepcopy(record)


def build_discord_source_packet(raw_packet: dict[str, Any], *, now: str | None = None) -> dict[str, Any]:
    now = now or utc_now()
    channel_id = _required_str(raw_packet, "channel_id", "discord_channel_id")
    message_id = _required_str(raw_packet, "message_id", "discord_message_id")
    event_type = str(raw_packet.get("event_type") or raw_packet.get("event") or "message_create")
    content = _extract_content(raw_packet)
    digest = str(raw_packet.get("content_sha256") or raw_packet.get("payload_sha256") or content_hash(content) or "")
    summary = str(raw_packet.get("summary") or raw_packet.get("classification_hint") or "")
    forbidden_secret_keys = _forbidden_keys(raw_packet, FORBIDDEN_SECRET_KEYS)
    forbidden_send_keys = _forbidden_keys(raw_packet, FORBIDDEN_SEND_KEYS)
    reason_codes = _reason_codes(
        raw_packet,
        content_sha256=digest,
        summary=summary,
        forbidden_secret_keys=forbidden_secret_keys,
        forbidden_send_keys=forbidden_send_keys,
    )
    status = "blocked" if any(reason.startswith("discord_source.blocked") for reason in reason_codes) else "ready_for_attention"
    source_ref = str(raw_packet.get("source_ref") or f"discord://{channel_id}/{message_id}")
    attachments = _attachment_refs(raw_packet)
    record = {
        "schema_version": SCHEMA_VERSION,
        "discord_source_packet_id": stable_id(
            "discsrc",
            channel_id,
            message_id,
            event_type,
            digest,
            summary,
            now,
        ),
        "source_surface": "discord",
        "source_kind": event_type,
        "source_ref": source_ref,
        "channel_id": channel_id,
        "message_id": message_id,
        "thread_id": _optional_str(raw_packet, "thread_id", "discord_thread_id"),
        "root_message_id": _optional_str(raw_packet, "root_message_id", "discord_root_message_id"),
        "reply_to_message_id": _optional_str(raw_packet, "reply_to_message_id", "reply_to"),
        "source_event_id": _optional_str(raw_packet, "source_event_id", "event_id") or message_id,
        "source_actor": _optional_str(raw_packet, "source_actor", "author_id", "author_name"),
        "observed_at": str(raw_packet.get("observed_at") or raw_packet.get("received_at") or raw_packet.get("timestamp") or now),
        "ingest_mode": "source_packet",
        "read_only": True,
        "gateway_started": False,
        "send_allowed": False,
        "bulk_history_allowed": False,
        "token_stored": False,
        "raw_content_stored": False,
        "content_sha256": digest,
        "content_length": int(raw_packet.get("content_length") or len(content or "")),
        "summary": summary,
        "summary_sha256": sha256_text(summary),
        "attachment_refs": attachments,
        "attachment_count": len(attachments),
        "forbidden_secret_key_count": len(forbidden_secret_keys),
        "forbidden_send_key_count": len(forbidden_send_keys),
        "input_shape_sha256": _input_shape_hash(raw_packet),
        "attention_signal_created": False,
        "attention_signal_id": None,
        "attention_signal_sha256": None,
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["source_packet_sha256"] = _hash_without(record, "source_packet_sha256")
    return deepcopy(record)


def validate_discord_source_packet_record(
    record: dict[str, Any],
    *,
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("discord_source.schema_version_invalid")
    expected_hash = record.get("source_packet_sha256")
    if expected_hash and expected_hash != _hash_without(record, "source_packet_sha256"):
        reason_codes.append("discord_source.hash_mismatch")
    for key in ("read_only",):
        if record.get(key) is not True:
            reason_codes.append(f"discord_source.{key}_not_true")
    for key in ("gateway_started", "send_allowed", "bulk_history_allowed", "token_stored", "raw_content_stored"):
        if record.get(key) is not False:
            reason_codes.append(f"discord_source.{key}_not_false")
    if record.get("source_surface") != "discord":
        reason_codes.append("discord_source.source_surface_not_discord")
    if record.get("status") not in STATUSES:
        reason_codes.append("discord_source.status_invalid")
    if not str(record.get("source_ref") or "").startswith("discord://"):
        reason_codes.append("discord_source.source_ref_invalid")
    if not str(record.get("content_sha256") or "").startswith("sha256:"):
        reason_codes.append("discord_source.content_sha256_missing")
    if record.get("summary_sha256") != sha256_text(str(record.get("summary") or "")):
        reason_codes.append("discord_source.summary_hash_mismatch")
    if int(record.get("attachment_count") or 0) != len(record.get("attachment_refs") or []):
        reason_codes.append("discord_source.attachment_count_mismatch")
    expected_status = (
        "blocked"
        if any(str(reason).startswith("discord_source.blocked") for reason in record.get("reason_codes") or [])
        else "ready_for_attention"
    )
    if record.get("status") != expected_status:
        reason_codes.append("discord_source.status_reason_mismatch")
    if state is not None and record.get("attention_signal_id"):
        signal = (state.get("attention_signals") or {}).get(record.get("attention_signal_id"))
        if not signal:
            reason_codes.append("discord_source.attention_signal_missing")
        elif record.get("attention_signal_sha256") != signal.get("attention_signal_sha256"):
            reason_codes.append("discord_source.attention_signal_hash_mismatch")
    if bool(record.get("attention_signal_created")) != bool(record.get("attention_signal_id")):
        reason_codes.append("discord_source.attention_signal_flag_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _attention_raw(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_surface": "discord",
        "source_kind": record["source_kind"],
        "source_ref": record["source_ref"],
        "source_event_id": record["source_event_id"],
        "source_actor": record["source_actor"],
        "source_trust": "source_packet",
        "observed_at": record["observed_at"],
        "channel_id": record["channel_id"],
        "message_id": record["message_id"],
        "root_message_id": record.get("root_message_id"),
        "reply_to_message_id": record.get("reply_to_message_id"),
        "content_sha256": record["content_sha256"],
        "content_length": record["content_length"],
        "summary": record["summary"],
        "requested_action": "route_discord_source_packet",
    }


def _reason_codes(
    raw_packet: dict[str, Any],
    *,
    content_sha256: str,
    summary: str,
    forbidden_secret_keys: list[str],
    forbidden_send_keys: list[str],
) -> list[str]:
    reasons: list[str] = []
    if forbidden_secret_keys:
        reasons.append("discord_source.blocked_secret_field_present")
    if forbidden_send_keys:
        reasons.append("discord_source.blocked_send_field_present")
    if str(raw_packet.get("source_surface") or "discord") != "discord":
        reasons.append("discord_source.blocked_non_discord_source")
    if not content_sha256:
        reasons.append("discord_source.blocked_content_hash_missing")
    if not summary:
        reasons.append("discord_source.summary_missing_hash_only")
    if raw_packet.get("attachments"):
        reasons.append("discord_source.attachment_refs_recorded")
    if not reasons or all(not reason.startswith("discord_source.blocked") for reason in reasons):
        reasons.append("discord_source.ready_read_only")
    return _unique(reasons)


def _attachment_refs(raw_packet: dict[str, Any]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for index, attachment in enumerate(raw_packet.get("attachments") or []):
        if not isinstance(attachment, dict):
            continue
        ref = str(attachment.get("ref") or attachment.get("url_ref") or attachment.get("id") or f"attachment:{index}")
        refs.append(
            {
                "ref": ref,
                "media_type": attachment.get("media_type") or attachment.get("content_type"),
                "size": int(attachment.get("size") or 0),
                "sha256": attachment.get("sha256"),
            }
        )
    return refs


def _extract_content(raw_packet: dict[str, Any]) -> str | None:
    value = raw_packet.get("content") or raw_packet.get("text")
    if isinstance(value, str):
        return value
    message = raw_packet.get("message")
    if isinstance(message, dict) and isinstance(message.get("content"), str):
        return message["content"]
    return None


def _input_shape_hash(raw_packet: dict[str, Any]) -> str:
    shape = {
        "keys": sorted(str(key) for key in raw_packet.keys()),
        "attachment_count": len(raw_packet.get("attachments") or []),
        "has_content": _extract_content(raw_packet) is not None,
        "has_summary": bool(raw_packet.get("summary") or raw_packet.get("classification_hint")),
    }
    return sha256_text(canonical_json(shape))
