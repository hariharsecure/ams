from __future__ import annotations

from copy import deepcopy
from typing import Any

from .ams_event import build_ams_event
from .models import canonical_json, sha256_text, stable_id, utc_now
from .run_trace import append_run_event_to_state
from .store import JsonStore


def _hash_incident(packet: dict[str, Any]) -> str:
    material = dict(packet)
    material.pop("incident_sha256", None)
    return sha256_text(canonical_json(material))


def build_incident_packet(
    state: dict[str, Any],
    *,
    trigger: str,
    task_run_id: str | None = None,
    session_id: str | None = None,
    predicate_results: list[dict[str, Any]] | None = None,
    reason_codes: list[str] | None = None,
) -> dict[str, Any]:
    task_run = (state.get("task_runs") or {}).get(task_run_id or "") or {}
    session_id = session_id or task_run.get("session_id")
    context_id = task_run.get("context_id")
    context = (state.get("contexts") or {}).get(context_id or "") or {}
    events = sorted(
        [
            event for event in (state.get("run_events") or {}).values()
            if not task_run_id or event.get("task_run_id") == task_run_id
        ],
        key=lambda event: (str(event.get("created_at")), int(event.get("sequence", 0) or 0)),
    )
    ams_events = sorted(
        [
            event for event in (state.get("ams_events") or {}).values()
            if not task_run_id or event.get("task_run_id") == task_run_id
        ],
        key=lambda event: str(event.get("time")),
    )
    policy_hashes = []
    for review in (state.get("admission_reviews") or {}).values():
        if task_run_id and review.get("subject_id") != task_run_id:
            continue
        policy_hashes.extend(review.get("policy_refs") or [])
    for claim in (state.get("resource_claims") or {}).values():
        if task_run_id and claim.get("task_run_id") != task_run_id:
            continue
        if claim.get("policy_sha256"):
            policy_hashes.append(str(claim["policy_sha256"]))
    now = utc_now()
    packet = {
        "schema_version": "ams.ams.incident_packet.v0",
        "incident_packet_id": stable_id("inc", trigger, task_run_id, session_id, now),
        "trigger": trigger,
        "task_run_id": task_run_id,
        "session_id": session_id,
        "ids": {
            "task_run_id": task_run_id,
            "session_id": session_id,
            "context_id": context_id,
            "lease_id": task_run.get("lease_id") or (context.get("lease") or {}).get("lease_id"),
            "summary_checkpoint_id": task_run.get("summary_checkpoint_id") or context.get("summary_checkpoint_id"),
        },
        "last_events": [deepcopy(event) for event in (ams_events[-5:] + events[-5:])],
        "policy_hashes": sorted(set(policy_hashes)),
        "store_revision": int(state.get("revision", 0) or 0),
        "predicate_results": predicate_results or [],
        "compaction_epoch": int(task_run.get("compaction_epoch", context.get("compaction_epoch", 0)) or 0),
        "reason_codes": reason_codes or [],
        "created_at": now,
    }
    packet["incident_sha256"] = _hash_incident(packet)
    return packet


def open_incident_in_state(
    state: dict[str, Any],
    *,
    trigger: str,
    task_run_id: str | None = None,
    session_id: str | None = None,
    predicate_results: list[dict[str, Any]] | None = None,
    reason_codes: list[str] | None = None,
) -> dict[str, Any]:
    packet = build_incident_packet(
        state,
        trigger=trigger,
        task_run_id=task_run_id,
        session_id=session_id,
        predicate_results=predicate_results,
        reason_codes=reason_codes,
    )
    event = build_ams_event(
        event_type="ams.ams.incident.opened",
        source="ams://kernel/incident",
        subject=task_run_id or session_id or packet["incident_packet_id"],
        data={
            "incident_packet_id": packet["incident_packet_id"],
            "trigger": trigger,
            "reason_codes": reason_codes or [],
        },
        session_id=packet.get("session_id"),
        task_run_id=task_run_id,
        dataschema="ams:ams:incident-packet:v0",
    )
    packet.setdefault("ids", {})["ams_event_id"] = event["id"]
    packet["incident_sha256"] = _hash_incident(packet)
    state.setdefault("incident_packets", {})[packet["incident_packet_id"]] = packet
    state.setdefault("ams_events", {})[event["id"]] = event
    if task_run_id:
        append_run_event_to_state(
            state,
            task_run_id,
            "incident.opened",
            payload={
                "incident_packet_id": packet["incident_packet_id"],
                "trigger": trigger,
            },
            reason_codes=reason_codes or [trigger],
        )
    return deepcopy(packet)


class IncidentStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def open(
        self,
        *,
        trigger: str,
        task_run_id: str | None = None,
        session_id: str | None = None,
        predicate_results: list[dict[str, Any]] | None = None,
        reason_codes: list[str] | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            return open_incident_in_state(
                state,
                trigger=trigger,
                task_run_id=task_run_id,
                session_id=session_id,
                predicate_results=predicate_results,
                reason_codes=reason_codes,
            )
