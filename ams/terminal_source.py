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


SCHEMA_VERSION = "ams.ams.terminal_source_packet.v0"
STATUSES = {"ready_for_attention", "blocked"}
SOURCE_SURFACES = {"terminal", "tmux"}
OBSERVATION_MODES = {"external_observed", "operator_supplied", "simulated_success"}
FORBIDDEN_SECRET_KEYS = {
    "authorization",
    "aws_secret_access_key",
    "cookie",
    "password",
    "secret",
    "session_cookie",
    "token",
}
FORBIDDEN_INJECTION_KEYS = {
    "command",
    "command_to_run",
    "input",
    "kill",
    "paste_buffer",
    "process_signal",
    "send_keys",
    "signal_process",
    "stdin",
    "tmux_command",
}


class TerminalSourcePacketStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        raw_packet: dict[str, Any],
        *,
        create_attention_signal: bool = False,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            record = build_terminal_source_packet(raw_packet)
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
                        [*record["reason_codes"], "terminal_source.attention_signal_created"]
                    )
                    record["source_packet_sha256"] = _hash_without(record, "source_packet_sha256")
                else:
                    record["status"] = "blocked"
                    record["reason_codes"] = _unique(
                        [
                            reason
                            for reason in record["reason_codes"]
                            if reason != "terminal_source.ready_read_only"
                        ]
                        + [
                            f"terminal_source.attention_signal_invalid:{reason}"
                            for reason in signal_validation["reason_codes"]
                        ]
                    )
                    record["source_packet_sha256"] = _hash_without(record, "source_packet_sha256")

            validation = validate_terminal_source_packet_record(record, state=state)
            if not validation["ok"]:
                raise ValueError("; ".join(validation["reason_codes"]))
            packet_id = record["terminal_source_packet_id"]
            indexes = state.setdefault("indexes", {})
            state.setdefault("terminal_source_packets", {})[packet_id] = record
            indexes.setdefault("terminal_source_packet_ids", {})[packet_id] = packet_id
            indexes.setdefault("source_ref_to_terminal_source_packet", {})[record["source_ref"]] = packet_id
        return deepcopy(record)


def build_terminal_source_packet(raw_packet: dict[str, Any], *, now: str | None = None) -> dict[str, Any]:
    now = now or utc_now()
    source_surface = str(raw_packet.get("source_surface") or raw_packet.get("surface") or "terminal")
    stored_source_surface = source_surface if source_surface in SOURCE_SURFACES else "terminal"
    terminal_session_id = _required_str(raw_packet, "terminal_session_id", "session_id", "tmux_session_name")
    source_event_id = _required_str(raw_packet, "source_event_id", "event_id", "event_ref")
    source_kind = str(raw_packet.get("source_kind") or raw_packet.get("event_type") or "terminal_observation")
    content = _extract_content(raw_packet)
    digest = str(raw_packet.get("content_sha256") or raw_packet.get("payload_sha256") or content_hash(content) or "")
    summary = str(raw_packet.get("summary") or raw_packet.get("classification_hint") or "")
    observation_mode = str(raw_packet.get("observation_mode") or "operator_supplied")
    forbidden_secret_keys = _forbidden_keys(raw_packet, FORBIDDEN_SECRET_KEYS)
    forbidden_injection_keys = _forbidden_keys(raw_packet, FORBIDDEN_INJECTION_KEYS)
    reason_codes = _reason_codes(
        raw_packet,
        source_surface=source_surface,
        observation_mode=observation_mode,
        content_sha256=digest,
        summary=summary,
        forbidden_secret_keys=forbidden_secret_keys,
        forbidden_injection_keys=forbidden_injection_keys,
    )
    status = "blocked" if any(reason.startswith("terminal_source.blocked") for reason in reason_codes) else "ready_for_attention"
    source_ref = str(raw_packet.get("source_ref") or _source_ref(raw_packet, stored_source_surface, terminal_session_id, source_event_id))
    artifact_refs = _artifact_refs(raw_packet)
    record = {
        "schema_version": SCHEMA_VERSION,
        "terminal_source_packet_id": stable_id(
            "termsrc",
            stored_source_surface,
            terminal_session_id,
            source_event_id,
            source_kind,
            digest,
            summary,
            now,
        ),
        "source_surface": stored_source_surface,
        "source_kind": source_kind,
        "source_ref": source_ref,
        "runtime_surface_id": _optional_str(raw_packet, "runtime_surface_id"),
        "host_id": _optional_str(raw_packet, "host_id", "hostname"),
        "terminal_session_id": terminal_session_id,
        "tmux_session_name": _optional_str(raw_packet, "tmux_session_name"),
        "tmux_window_id": _optional_str(raw_packet, "tmux_window_id", "window_id"),
        "tmux_pane_id": _optional_str(raw_packet, "tmux_pane_id", "pane_id"),
        "source_event_id": source_event_id,
        "source_actor": _optional_str(raw_packet, "source_actor", "user", "operator"),
        "observed_at": str(raw_packet.get("observed_at") or raw_packet.get("timestamp") or now),
        "ingest_mode": "source_packet",
        "observation_mode": observation_mode,
        "read_only": True,
        "monitor_started": False,
        "attach_performed": False,
        "capture_performed": False,
        "command_input_allowed": False,
        "keystroke_injection_allowed": False,
        "process_signal_allowed": False,
        "token_stored": False,
        "raw_content_stored": False,
        "content_sha256": digest,
        "content_length": int(raw_packet.get("content_length") or len(content or "")),
        "summary": summary,
        "summary_sha256": sha256_text(summary),
        "artifact_refs": artifact_refs,
        "artifact_count": len(artifact_refs),
        "forbidden_secret_key_count": len(forbidden_secret_keys),
        "forbidden_injection_key_count": len(forbidden_injection_keys),
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


def validate_terminal_source_packet_record(
    record: dict[str, Any],
    *,
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("terminal_source.schema_version_invalid")
    expected_hash = record.get("source_packet_sha256")
    if expected_hash and expected_hash != _hash_without(record, "source_packet_sha256"):
        reason_codes.append("terminal_source.hash_mismatch")
    if record.get("source_surface") not in SOURCE_SURFACES:
        reason_codes.append("terminal_source.source_surface_invalid")
    if record.get("observation_mode") not in OBSERVATION_MODES:
        reason_codes.append("terminal_source.observation_mode_invalid")
    if record.get("read_only") is not True:
        reason_codes.append("terminal_source.read_only_not_true")
    for key in (
        "monitor_started",
        "attach_performed",
        "capture_performed",
        "command_input_allowed",
        "keystroke_injection_allowed",
        "process_signal_allowed",
        "token_stored",
        "raw_content_stored",
    ):
        if record.get(key) is not False:
            reason_codes.append(f"terminal_source.{key}_not_false")
    if record.get("status") not in STATUSES:
        reason_codes.append("terminal_source.status_invalid")
    source_ref = str(record.get("source_ref") or "")
    if not (source_ref.startswith("terminal://") or source_ref.startswith("tmux://")):
        reason_codes.append("terminal_source.source_ref_invalid")
    if not str(record.get("content_sha256") or "").startswith("sha256:"):
        reason_codes.append("terminal_source.content_sha256_missing")
    if record.get("summary_sha256") != sha256_text(str(record.get("summary") or "")):
        reason_codes.append("terminal_source.summary_hash_mismatch")
    if int(record.get("artifact_count") or 0) != len(record.get("artifact_refs") or []):
        reason_codes.append("terminal_source.artifact_count_mismatch")
    expected_status = (
        "blocked"
        if any(str(reason).startswith("terminal_source.blocked") for reason in record.get("reason_codes") or [])
        else "ready_for_attention"
    )
    if record.get("status") != expected_status:
        reason_codes.append("terminal_source.status_reason_mismatch")
    if state is not None and record.get("attention_signal_id"):
        signal = (state.get("attention_signals") or {}).get(record.get("attention_signal_id"))
        if not signal:
            reason_codes.append("terminal_source.attention_signal_missing")
        elif record.get("attention_signal_sha256") != signal.get("attention_signal_sha256"):
            reason_codes.append("terminal_source.attention_signal_hash_mismatch")
    if bool(record.get("attention_signal_created")) != bool(record.get("attention_signal_id")):
        reason_codes.append("terminal_source.attention_signal_flag_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _attention_raw(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_surface": record["source_surface"],
        "source_kind": record["source_kind"],
        "source_ref": record["source_ref"],
        "source_event_id": record["source_event_id"],
        "source_actor": record["source_actor"],
        "source_trust": "source_packet",
        "observed_at": record["observed_at"],
        "content_sha256": record["content_sha256"],
        "content_length": record["content_length"],
        "summary": record["summary"],
        "requested_action": "route_terminal_source_packet",
    }


def _reason_codes(
    raw_packet: dict[str, Any],
    *,
    source_surface: str,
    observation_mode: str,
    content_sha256: str,
    summary: str,
    forbidden_secret_keys: list[str],
    forbidden_injection_keys: list[str],
) -> list[str]:
    reasons: list[str] = []
    if forbidden_secret_keys:
        reasons.append("terminal_source.blocked_secret_field_present")
    if forbidden_injection_keys:
        reasons.append("terminal_source.blocked_injection_field_present")
    if source_surface not in SOURCE_SURFACES:
        reasons.append("terminal_source.blocked_source_surface_invalid")
    if observation_mode not in OBSERVATION_MODES:
        reasons.append("terminal_source.blocked_observation_mode_invalid")
    if not content_sha256:
        reasons.append("terminal_source.blocked_content_hash_missing")
    if not summary:
        reasons.append("terminal_source.summary_missing_hash_only")
    if raw_packet.get("artifact_refs"):
        reasons.append("terminal_source.artifact_refs_recorded")
    if not reasons or all(not reason.startswith("terminal_source.blocked") for reason in reasons):
        reasons.append("terminal_source.ready_read_only")
    return _unique(reasons)


def _artifact_refs(raw_packet: dict[str, Any]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for index, artifact in enumerate(raw_packet.get("artifact_refs") or []):
        if not isinstance(artifact, dict):
            continue
        refs.append(
            {
                "ref": str(artifact.get("ref") or f"artifact:{index}"),
                "kind": artifact.get("kind") or artifact.get("type"),
                "sha256": artifact.get("sha256"),
            }
        )
    return refs


def _source_ref(raw_packet: dict[str, Any], source_surface: str, session_id: str, event_id: str) -> str:
    if source_surface == "tmux":
        window = raw_packet.get("tmux_window_id") or raw_packet.get("window_id") or "window"
        pane = raw_packet.get("tmux_pane_id") or raw_packet.get("pane_id") or "pane"
        return f"tmux://{session_id}/{window}/{pane}/{event_id}"
    host = raw_packet.get("host_id") or raw_packet.get("hostname") or "local"
    return f"terminal://{host}/{session_id}/{event_id}"


def _extract_content(raw_packet: dict[str, Any]) -> str | None:
    value = raw_packet.get("content") or raw_packet.get("text")
    if isinstance(value, str):
        return value
    packet = raw_packet.get("packet")
    if isinstance(packet, dict):
        for key in ("content", "text", "summary"):
            if isinstance(packet.get(key), str):
                return packet[key]
    return None


def _input_shape_hash(raw_packet: dict[str, Any]) -> str:
    shape = {
        "keys": sorted(str(key) for key in raw_packet.keys()),
        "artifact_count": len(raw_packet.get("artifact_refs") or []),
        "has_content": _extract_content(raw_packet) is not None,
        "has_summary": bool(raw_packet.get("summary") or raw_packet.get("classification_hint")),
    }
    return sha256_text(canonical_json(shape))
