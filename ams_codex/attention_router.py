from __future__ import annotations

from copy import deepcopy
from datetime import timedelta
import re
from typing import Any

from .models import hash_without as _hash_without, canonical_json, content_hash, parse_utc, sha256_text, stable_id, utc_now
from .store import JsonStore


PRIORITIES = {"P0", "P1", "P2", "P3", "P4"}
LEVELS = {"low", "medium", "high", "critical"}
ACK_STATUSES = {"new", "acknowledged", "routed", "deferred", "resolved"}

DOMAIN_COVERAGE = {
    "surface_discord": "Discord messages, channel routing, gateway health, readback, and cross-surface ordering.",
    "surface_terminal": "Terminal and tmux observations, read-only transcript refs, pane/window refs, and shell-surface attention.",
    "training_ops": "Training jobs, checkpoints, schedulers, requeue, loss spikes, and model-build health.",
    "cloud_ops": "AWS, WAF, CloudFront, ALB, security-group cleanup, billing, and teardown evidence.",
    "ams_kernel": "AMS/ATP authority, leases, sessions, gates, replay, policy, outbox, and surface promises.",
    "provider_session": "Claude, Codex, local model sessions, compaction, hooks, tools, and provider lifecycle.",
    "security": "Secrets, credentials, tokens, permissions, repo attacks, and unsafe egress.",
    "resource_capacity": "CPU, GPU, memory, disk, quota, preemption, broken pipes, and resource limits.",
    "cyber_physical_ops": "Farm, IoT, gateway, device telemetry, control-loop observations, restarts, and offline recovery.",
    "animal_welfare": "Animal welfare, flock health, mortality, biosecurity, heat stress, feed access, and water access.",
    "research_memory": "Research tasks, papers, RAG ingestion, long-term notes, and knowledge synthesis.",
    "unknown": "Signals that need triage before domain ownership is clear.",
}

ACK_SECONDS = {
    "P0": 60,
    "P1": 300,
    "P2": 1800,
}


def build_attention_signal(
    state: dict[str, Any],
    raw_signal: dict[str, Any],
    *,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    text = _extract_text(raw_signal)
    content_sha256 = str(raw_signal.get("content_sha256") or content_hash(text) or "")
    content_length = int(raw_signal.get("content_length") or len(text or ""))
    source = _source_from_raw(raw_signal)
    route = classify_attention_signal(text, raw_signal)
    session_id = _resolve_session_id(state, raw_signal)
    session = (state.get("sessions") or {}).get(session_id or "") or {}
    attention_id = raw_signal.get("attention_id") or session.get("attention_id")
    ack_required = bool(raw_signal.get("ack_required", route["priority"] in ACK_SECONDS))
    ack_due_at = raw_signal.get("ack_due_at") or (_iso_after(now, ACK_SECONDS[route["priority"]]) if ack_required else None)
    status = str(raw_signal.get("ack_status") or raw_signal.get("status") or "new")
    if status not in ACK_STATUSES:
        status = "new"
    signal_id = stable_id(
        "attsig",
        source["source_surface"],
        source["source_ref"],
        source.get("source_event_id"),
        content_sha256,
        route["route_domain"],
    )
    vector_memory = _vector_memory_plan(
        signal_id,
        domain=route["route_domain"],
        additional_domains=route["additional_domains"],
        priority=route["priority"],
        content_sha256=content_sha256,
        session_id=session_id,
        source=source,
        created_at=now,
    )
    record = {
        "schema_version": "ams.ams_codex.attention_signal.v0",
        "attention_signal_id": signal_id,
        "attention_id": attention_id,
        "parent_attention_id": raw_signal.get("parent_attention_id"),
        "session_id": session_id,
        "context_id": raw_signal.get("context_id"),
        "task_run_id": raw_signal.get("task_run_id"),
        "source_surface": source["source_surface"],
        "source_kind": source["source_kind"],
        "source_ref": source["source_ref"],
        "source_event_id": source.get("source_event_id"),
        "source_actor": source.get("source_actor"),
        "source_trust": source["source_trust"],
        "observed_at": source["observed_at"],
        "content_sha256": content_sha256,
        "content_length": content_length,
        "raw_content_stored": False,
        "classification_input_sha256": sha256_text(canonical_json(_classification_material(raw_signal, text))),
        "importance": route["importance"],
        "urgency": route["urgency"],
        "priority": route["priority"],
        "route_domain": route["route_domain"],
        "additional_domains": route["additional_domains"],
        "route_status": "needs_ack" if ack_required and status not in {"resolved", "acknowledged"} else "routed",
        "ack_required": ack_required,
        "ack_status": status,
        "ack_due_at": ack_due_at,
        "acked_at": raw_signal.get("acked_at"),
        "resolved_at": raw_signal.get("resolved_at"),
        "requested_action": raw_signal.get("requested_action") or route["requested_action"],
        "reason_codes": route["reason_codes"],
        "vector_memory": vector_memory,
        "created_at": now,
        "updated_at": now,
    }
    record["attention_signal_sha256"] = _hash_without(record, "attention_signal_sha256")
    return record


def classify_attention_signal(text: str, raw_signal: dict[str, Any] | None = None) -> dict[str, Any]:
    raw_signal = raw_signal or {}
    haystack = _normalize(" ".join([
        text or "",
        str(raw_signal.get("summary") or ""),
        str(raw_signal.get("source_surface") or ""),
        str(raw_signal.get("event_type") or raw_signal.get("source_kind") or ""),
    ]))
    domains, domain_reasons = _domains_for(haystack)
    domains, domain_reasons = _prioritize_source_packet_domain(raw_signal, domains, domain_reasons)
    importance_score, importance_reasons = _importance_score(haystack)
    urgency_score, urgency_reasons = _urgency_score(haystack)
    explicit_priority = str(raw_signal.get("priority") or "").upper()
    if explicit_priority in PRIORITIES:
        priority = explicit_priority
        priority_reasons = ["attention.priority_explicit"]
    else:
        priority = _priority_for(importance_score, urgency_score)
        priority_reasons = [f"attention.priority_inferred:{priority}"]
    route_domain = domains[0] if domains else "unknown"
    requested_action = raw_signal.get("requested_action") or _requested_action_for(route_domain, priority)
    reason_codes = [
        *domain_reasons,
        *importance_reasons,
        *urgency_reasons,
        *priority_reasons,
    ]
    if not text:
        reason_codes.append("attention.content_hash_only")
    if priority in {"P0", "P1", "P2"}:
        reason_codes.append("attention.ack_required")
    return {
        "importance": _level_for(importance_score),
        "urgency": _level_for(urgency_score),
        "priority": priority,
        "route_domain": route_domain,
        "additional_domains": domains[1:],
        "requested_action": requested_action,
        "reason_codes": _unique(reason_codes) or ["attention.route_default"],
    }


def validate_attention_signal_record(
    record: dict[str, Any],
    *,
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    expected_hash = record.get("attention_signal_sha256")
    if expected_hash and expected_hash != _hash_without(record, "attention_signal_sha256"):
        reason_codes.append("attention_signal.hash_mismatch")
    if record.get("raw_content_stored") is not False:
        reason_codes.append("attention_signal.raw_content_stored")
    if record.get("priority") not in PRIORITIES:
        reason_codes.append("attention_signal.priority_invalid")
    if record.get("importance") not in LEVELS:
        reason_codes.append("attention_signal.importance_invalid")
    if record.get("urgency") not in LEVELS:
        reason_codes.append("attention_signal.urgency_invalid")
    route_domain = str(record.get("route_domain") or "")
    if route_domain not in DOMAIN_COVERAGE:
        reason_codes.append("attention_signal.route_domain_invalid")
    if record.get("priority") in {"P0", "P1"} and record.get("ack_required") is not True:
        reason_codes.append("attention_signal.high_priority_without_ack")
    if record.get("ack_required") and not record.get("ack_due_at"):
        reason_codes.append("attention_signal.ack_due_at_missing")
    if record.get("ack_status") not in ACK_STATUSES:
        reason_codes.append("attention_signal.ack_status_invalid")
    vector_memory = record.get("vector_memory") or {}
    expected_collection = f"ams_attention_{route_domain}"
    if vector_memory.get("collection") != expected_collection:
        reason_codes.append("attention_signal.vector_collection_mismatch")
    metadata = vector_memory.get("metadata") or {}
    if metadata.get("attention_signal_id") != record.get("attention_signal_id"):
        reason_codes.append("attention_signal.vector_signal_id_mismatch")
    if metadata.get("domain") != route_domain:
        reason_codes.append("attention_signal.vector_domain_mismatch")
    if metadata.get("priority") != record.get("priority"):
        reason_codes.append("attention_signal.vector_priority_mismatch")
    if state is not None:
        _validate_references(reason_codes, state, record)
    return {"ok": not reason_codes, "reason_codes": reason_codes}


class AttentionRouterStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def ingest(self, raw_signal: dict[str, Any]) -> dict[str, Any]:
        with self.store.locked() as state:
            record = build_attention_signal(state, raw_signal)
            signal_id = record["attention_signal_id"]
            state.setdefault("attention_signals", {})[signal_id] = record
            indexes = state.setdefault("indexes", {})
            indexes.setdefault("attention_signal_ids", {})[signal_id] = signal_id
            indexes.setdefault("source_ref_to_attention_signal", {})[record["source_ref"]] = signal_id
            if record.get("content_sha256"):
                indexes.setdefault("content_to_attention_signal", {})[record["content_sha256"]] = signal_id
            return deepcopy(record)


def _source_from_raw(raw: dict[str, Any]) -> dict[str, Any]:
    source_surface = str(raw.get("source_surface") or raw.get("surface") or "manual")
    source_kind = str(raw.get("source_kind") or raw.get("event_type") or raw.get("hook_event_name") or "attention")
    channel_id = raw.get("channel_id") or raw.get("discord_channel_id")
    message_id = raw.get("message_id") or raw.get("discord_message_id")
    if raw.get("source_ref"):
        source_ref = str(raw["source_ref"])
    elif channel_id and message_id:
        source_ref = f"discord://{channel_id}/{message_id}"
        source_surface = "discord"
    elif raw.get("claude_session_id") or raw.get("session_id"):
        source_ref = f"claude://{raw.get('claude_session_id') or raw.get('session_id')}/{raw.get('source_event_id') or source_kind}"
        if source_surface == "manual":
            source_surface = "claude_code"
    elif raw.get("transcript_path"):
        source_ref = f"claude-transcript://{raw['transcript_path']}"
        if source_surface == "manual":
            source_surface = "claude_code"
    else:
        source_ref = f"manual://{stable_id('src', raw)}"
    source_event_id = raw.get("source_event_id") or raw.get("event_id") or message_id
    source_actor = raw.get("source_actor") or raw.get("author_id") or raw.get("author_name")
    return {
        "source_surface": source_surface,
        "source_kind": source_kind,
        "source_ref": source_ref,
        "source_event_id": str(source_event_id) if source_event_id is not None else None,
        "source_actor": str(source_actor) if source_actor is not None else None,
        "source_trust": str(raw.get("source_trust") or "observed"),
        "observed_at": str(raw.get("observed_at") or raw.get("received_at") or raw.get("timestamp") or utc_now()),
    }


def _extract_text(raw: dict[str, Any]) -> str:
    for key in ("content", "text", "event", "summary", "body"):
        value = raw.get(key)
        if isinstance(value, str):
            return _redact(value)
    message = raw.get("message")
    if isinstance(message, str):
        return _redact(message)
    if isinstance(message, dict):
        for key in ("content", "text"):
            if isinstance(message.get(key), str):
                return _redact(message[key])
    return ""


def _resolve_session_id(state: dict[str, Any], raw: dict[str, Any]) -> str | None:
    sessions = state.get("sessions") or {}
    indexes = state.get("indexes") or {}
    session_id = raw.get("session_id")
    if session_id in sessions:
        return str(session_id)
    for key in ("attention_id", "parent_attention_id"):
        mapped = (indexes.get("attention_to_session") or {}).get(raw.get(key) or "")
        if mapped in sessions:
            return str(mapped)
    message_id = raw.get("message_id") or raw.get("discord_message_id")
    mapped = (indexes.get("message_to_session") or {}).get(message_id or "")
    if mapped in sessions:
        return str(mapped)
    channel_id = raw.get("channel_id") or raw.get("discord_channel_id")
    root_id = raw.get("root_message_id") or raw.get("discord_root_message_id")
    if channel_id and root_id:
        mapped = (indexes.get("root_to_session") or {}).get(f"discord:{channel_id}:{root_id}")
        if mapped in sessions:
            return str(mapped)
    return None


def _domains_for(text: str) -> tuple[list[str], list[str]]:
    ordered: list[tuple[str, str, tuple[str, ...]]] = [
        ("security", "attention.domain.security", ("secret", "token", "credential", "password", "permission", "repo attack", "unsafe egress")),
        ("training_ops", "attention.domain.training_ops", ("track-a", "track-b", "training", "sft", "checkpoint", "loss", "spike", "requeue", "slurm", "sacct")),
        ("ams_kernel", "attention.domain.ams_kernel", ("ams", "atp", "surface promise", "outbox", "lease", "replay", "gate", "kernel")),
        ("surface_discord", "attention.domain.surface_discord", ("discord", "#channel-b", "#channel-a", "#channel-c", "gateway.disconnect", "message", "channel", "route-a", "operator-authored", "not answering")),
        ("surface_terminal", "attention.domain.surface_terminal", ("terminal", "tmux", "pane", "shell", "stdout", "stderr", "exit code", "transcript")),
        ("cloud_ops", "attention.domain.cloud_ops", ("aws", "waf", "cloudfront", "alb", "security group", "teardown", "billing", "web-acl")),
        ("provider_session", "attention.domain.provider_session", ("claude", "codex", "session", "compaction", "hook", "tool_use", "provider", "transcript")),
        ("resource_capacity", "attention.domain.resource_capacity", ("disk", "memory", "cpu", "gpu", "quota", "preemption", "sigusr", "broken pipe", "rsync", "capacity")),
        (
            "animal_welfare",
            "attention.domain.animal_welfare",
            (
                "animal welfare",
                "bird welfare",
                "mortality",
                "mortality spike",
                "mass mortality",
                "dead birds",
                "heat stress",
                "panting",
                "respiratory",
                "disease",
                "avian influenza",
                "biosecurity",
                "no water",
                "water outage",
                "no feed",
                "feed outage",
            ),
        ),
        (
            "cyber_physical_ops",
            "attention.domain.cyber_physical_ops",
            (
                "farm",
                "poultry",
                "broiler",
                "flock",
                "house",
                "barn",
                "iot",
                "edge gateway",
                "gateway restart",
                "device restart",
                "telemetry gap",
                "sensor",
                "actuator",
                "ventilation",
                "ventilation failure",
                "fan",
                "inlet",
                "curtain",
                "heater",
                "brooder",
                "water line",
                "drinker",
                "feed line",
                "auger",
                "ammonia",
                "co2",
                "carbon monoxide",
                "humidity",
                "temperature",
                "static pressure",
                "power outage",
                "generator",
            ),
        ),
        ("research_memory", "attention.domain.research_memory", ("research", "rag", "vector", "paper", "download", "synthesis")),
    ]
    domains: list[str] = []
    reasons: list[str] = []
    for domain, reason, keywords in ordered:
        if any(_keyword_in_text(text, keyword) for keyword in keywords):
            domains.append(domain)
            reasons.append(reason)
    if not domains:
        domains.append("unknown")
        reasons.append("attention.domain.unknown")
    return domains, reasons


def _prioritize_source_packet_domain(
    raw_signal: dict[str, Any],
    domains: list[str],
    domain_reasons: list[str],
) -> tuple[list[str], list[str]]:
    requested_action = str(raw_signal.get("requested_action") or "")
    source_surface = str(raw_signal.get("source_surface") or raw_signal.get("surface") or "")
    preferred: str | None = None
    if requested_action == "route_terminal_source_packet" and source_surface in {"terminal", "tmux"}:
        preferred = "surface_terminal"
    elif requested_action == "route_discord_source_packet" and source_surface == "discord":
        preferred = "surface_discord"
    if not preferred or preferred not in domains:
        return domains, domain_reasons
    index = domains.index(preferred)
    reordered_domains = [domains[index], *domains[:index], *domains[index + 1 :]]
    reordered_reasons = [domain_reasons[index], *domain_reasons[:index], *domain_reasons[index + 1 :]]
    return reordered_domains, reordered_reasons


def _importance_score(text: str) -> tuple[int, list[str]]:
    score = 1
    reasons: list[str] = []
    if _has(text, "fatal", "failed", "crash", "didn't catch", "did not catch", "miss", "orphan", "billing", "security", "secret"):
        score = max(score, 4)
        reasons.append("attention.importance.failure_or_risk")
    if _has(text, "fire", "smoke", "power outage", "no water", "water outage", "ventilation failure", "mass mortality", "mortality spike"):
        score = max(score, 4)
        reasons.append("attention.importance.cyber_physical_safety")
    if _has(text, "heat stress", "ammonia", "co2", "carbon monoxide", "feed outage", "biosecurity breach", "telemetry gap", "gateway restart"):
        score = max(score, 3)
        reasons.append("attention.importance.farm_ops_risk")
    if _has(text, "gateway.disconnect", "not answering", "rca", "route-a", "operator-authored", "update"):
        score = max(score, 3)
        reasons.append("attention.importance.surface_or_user_visible")
    if _has(text, "question", "what is needed", "please", "status"):
        score = max(score, 2)
        reasons.append("attention.importance.user_request")
    return score, reasons or ["attention.importance.default"]


def _urgency_score(text: str) -> tuple[int, list[str]]:
    score = 1
    reasons: list[str] = []
    if _has(text, "urgent", "immediately", "now", "p0", "secret", "billing", "orphan"):
        score = max(score, 4)
        reasons.append("attention.urgency.immediate")
    if _has(text, "fire", "smoke", "power outage", "no water", "water outage", "ventilation failure", "mass mortality", "mortality spike"):
        score = max(score, 4)
        reasons.append("attention.urgency.cyber_physical_safety")
    if _has(text, "heat stress", "ammonia", "co2", "carbon monoxide", "feed outage", "biosecurity breach", "telemetry gap", "gateway restart"):
        score = max(score, 3)
        reasons.append("attention.urgency.farm_ops_near_term")
    if _has(text, "failed", "fatal", "blocked", "didn't catch", "did not catch", "gateway.disconnect", "rca", "route-a", "preemption", "sigusr"):
        score = max(score, 3)
        reasons.append("attention.urgency.near_term")
    if _has(text, "update", "what is needed", "question", "please"):
        score = max(score, 2)
        reasons.append("attention.urgency.user_waiting")
    return score, reasons or ["attention.urgency.default"]


def _priority_for(importance: int, urgency: int) -> str:
    if importance >= 4 and urgency >= 4:
        return "P0"
    if importance >= 4 or (importance >= 3 and urgency >= 3):
        return "P1"
    if importance >= 2 or urgency >= 2:
        return "P2"
    return "P3"


def _level_for(score: int) -> str:
    if score >= 4:
        return "critical"
    if score == 3:
        return "high"
    if score == 2:
        return "medium"
    return "low"


def _requested_action_for(domain: str, priority: str) -> str:
    if priority in {"P0", "P1"}:
        return f"ack_route_and_open_{domain}_work_item"
    if domain == "unknown":
        return "triage_and_classify"
    return f"route_to_{domain}_backlog"


def _vector_memory_plan(
    signal_id: str,
    *,
    domain: str,
    additional_domains: list[str],
    priority: str,
    content_sha256: str,
    session_id: str | None,
    source: dict[str, Any],
    created_at: str,
) -> dict[str, Any]:
    collection = f"ams_attention_{domain}"
    point_id = stable_id("vecattn", signal_id, content_sha256, domain)
    return {
        "authority": "ams_store",
        "collection": collection,
        "point_id": point_id,
        "chunk_ref": f"vector://{collection}/{point_id}",
        "embedding_status": "not_embedded",
        "coverage": DOMAIN_COVERAGE.get(domain, DOMAIN_COVERAGE["unknown"]),
        "metadata": {
            "attention_signal_id": signal_id,
            "domain": domain,
            "additional_domains": additional_domains,
            "priority": priority,
            "session_id": session_id,
            "source_surface": source["source_surface"],
            "source_ref": source["source_ref"],
            "content_sha256": content_sha256,
            "created_at": created_at,
            "redaction": "raw_content_not_in_ams_store",
        },
        "filter_keys": [
            "domain",
            "additional_domains",
            "priority",
            "session_id",
            "source_surface",
            "content_sha256",
        ],
    }


def _validate_references(reason_codes: list[str], state: dict[str, Any], record: dict[str, Any]) -> None:
    for field, collection in (
        ("session_id", "sessions"),
        ("context_id", "contexts"),
        ("task_run_id", "task_runs"),
    ):
        value = record.get(field)
        if value and value not in (state.get(collection) or {}):
            reason_codes.append(f"attention_signal.{field}_missing")


def _classification_material(raw: dict[str, Any], text: str) -> dict[str, Any]:
    return {
        "text_sha256": content_hash(text),
        "source_surface": raw.get("source_surface"),
        "source_kind": raw.get("source_kind") or raw.get("event_type") or raw.get("hook_event_name"),
        "priority": raw.get("priority"),
        "requested_action": raw.get("requested_action"),
    }



def _iso_after(now: str, seconds: int) -> str:
    return (parse_utc(now) + timedelta(seconds=seconds)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def _has(text: str, *needles: str) -> bool:
    return any(_keyword_in_text(text, needle) for needle in needles)


def _keyword_in_text(text: str, keyword: str) -> bool:
    if not keyword:
        return False
    if keyword == "gate":
        return bool(re.search(rf"(?<![a-z0-9_-]){re.escape(keyword)}(?![a-z0-9_-])", text))
    return keyword in text


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _redact(text: str) -> str:
    patterns = [
        re.compile(r"(?i)sk-[A-Za-z0-9_-]{8,}"),
        re.compile(r"(?i)xox[baprs]-[A-Za-z0-9-]{8,}"),
        re.compile(r"(?i)(authorization|token|api[_-]?key|secret|password)\s*[:=]\s*\S+"),
    ]
    redacted = text
    for pattern in patterns:
        redacted = pattern.sub("[REDACTED_SECRET]", redacted)
    return redacted
