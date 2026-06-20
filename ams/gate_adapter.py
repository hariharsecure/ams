from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import canonical_json, sha256_text, stable_id, utc_now
from .store import JsonStore


RISK_FLAGS = {
    "destructive",
    "egress",
    "non_trivial",
    "requires_validity",
    "production_touch",
    "live_touch",
    "corpus_mutation",
    "rag_mutation",
    "secret_access",
    "unknown_tool",
}


def build_action(
    *,
    tool: str,
    endpoint: str | None,
    method: str | None,
    payload: dict[str, Any],
    channel_id: str | None = None,
    requester: str = "agent:agent_b",
    host: str = "example-host.local",
    risk_flags: list[str] | None = None,
    writes: bool | None = None,
    reversible: bool | None = None,
) -> dict[str, Any]:
    flags = sorted(set(risk_flags or []))
    unknown = [flag for flag in flags if flag not in RISK_FLAGS]
    if unknown:
        raise ValueError(f"unknown risk flags: {unknown}")
    if writes is None:
        writes = bool({"destructive", "egress", "corpus_mutation", "rag_mutation"} & set(flags))
    if reversible is None:
        reversible = "destructive" not in flags
    return {
        "tool": tool,
        "endpoint": endpoint,
        "method": method,
        "writes": writes,
        "reversible": reversible,
        "payload_sha256": sha256_text(canonical_json(payload)),
        "channel_id": channel_id,
        "requester": requester,
        "host": host,
        "risk_flags": flags,
    }


def shadow_verdict(action: dict[str, Any]) -> dict[str, Any]:
    flags = set(action.get("risk_flags") or [])
    reasons: list[str] = []
    if "unknown_tool" in flags:
        return _verdict("deny", ["shadow-deny-unknown-tool"], action)
    if {"destructive", "secret_access"} & flags:
        reasons.append("shadow-defer-high-risk")
        return _verdict("defer", reasons, action)
    if "egress" in flags or action.get("tool", "").startswith("discord"):
        reasons.append("shadow-defer-egress-needs-signed-engine")
        return _verdict("defer", reasons, action)
    if action.get("writes") and not action.get("reversible"):
        reasons.append("shadow-defer-irreversible-write")
        return _verdict("defer", reasons, action)
    return _verdict("allow", ["shadow-allow-local-dry-run"], action)


def _verdict(verdict: str, reasons: list[str], action: dict[str, Any]) -> dict[str, Any]:
    return {
        "verdict": verdict,
        "reasons": reasons,
        "engine_version": "ams-local-shadow/v0.1.0",
        "ledger_event_id": stable_id("shadowevt", action.get("tool"), action.get("payload_sha256")),
        "shadow_only": True,
        "created_at": utc_now(),
    }


class GateShadowAdapter:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def check(self, action: dict[str, Any]) -> dict[str, Any]:
        verdict = shadow_verdict(action)
        with self.store.locked() as state:
            state.setdefault("gate_checks", {})[verdict["ledger_event_id"]] = {
                "created_at": verdict["created_at"],
                "action": deepcopy(action),
                "verdict": deepcopy(verdict),
            }
        return verdict
