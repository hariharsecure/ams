from __future__ import annotations

from copy import deepcopy
from typing import Any

from .ams_event import build_ams_event
from .architecture_gate import architecture_gate_result_for_request
from .blast_radius import blast_radius_result_for_request
from .context_validation import validate_fresh_context
from .definition_registry import validate_task_run_definition_pins
from .incident import open_incident_in_state
from .manager_intervention import unresolved_interventions_for_task
from .models import canonical_json, parse_utc, sha256_text, stable_id, utc_now
from .predicate import end_state_hash
from .provider_bindings import find_provider_session
from .run_trace import append_run_event_to_state
from .store import JsonStore


REFUSAL_EVENT_TYPE = "ams.dispatch.refused"


def dispatch(store: JsonStore, task_run_id: str, *, now: str | None = None) -> dict[str, Any]:
    now = now or utc_now()
    with store.locked() as state:
        task_run = state.get("task_runs", {}).get(task_run_id)
        if not task_run or task_run.get("state") != "planned":
            return _refuse(state, task_run_id, "dispatch.run_not_planned", now=now)
        session = state.get("sessions", {}).get(task_run.get("session_id"))
        if not session:
            return _refuse(state, task_run_id, "dispatch.session_missing", now=now)
        if session.get("state") == "blocked":
            return _refuse(state, task_run_id, "dispatch.session_blocked", now=now)
        definition_result = validate_task_run_definition_pins(state, task_run)
        if not definition_result["ok"]:
            return _refuse(
                state,
                task_run_id,
                "dispatch.definition_pins_invalid",
                now=now,
                details={"reason_codes": definition_result["reason_codes"]},
            )
        context = state.get("contexts", {}).get(task_run.get("context_id"))
        if not context:
            return _refuse(state, task_run_id, "dispatch.context_stale", now=now)
        unresolved_interventions = unresolved_interventions_for_task(state, task_run_id)
        if unresolved_interventions:
            return _refuse(
                state,
                task_run_id,
                "dispatch.manager_intervention_unresolved",
                now=now,
                details={
                    "manager_intervention_ids": [
                        intervention["manager_intervention_id"]
                        for intervention in unresolved_interventions
                    ],
                },
            )
        try:
            validate_fresh_context(session, context)
        except ValueError:
            return _refuse(state, task_run_id, "dispatch.context_stale", now=now)
        if not _lease_valid(task_run, context, now):
            return _refuse(state, task_run_id, "dispatch.lease_invalid", now=now)
        intent = context.get("intent") or {}
        end_state = intent.get("end_state") or {}
        if not _has_end_state_check(end_state):
            return _refuse(state, task_run_id, "dispatch.intent_missing", now=now)
        if (context.get("lease") or {}).get("end_state_sha256") != end_state_hash(end_state):
            return _refuse(state, task_run_id, "dispatch.intent_missing", now=now)
        architecture_gate = _architecture_gate_ready(state, task_run)
        if not architecture_gate["ok"]:
            return _refuse(
                state,
                task_run_id,
                str(architecture_gate["reason_code"]),
                now=now,
                details={key: value for key, value in architecture_gate.items() if key not in {"ok", "reason_code"}},
            )
        blast_radius = _blast_radius_ready(state, task_run)
        if not blast_radius["ok"]:
            return _refuse(
                state,
                task_run_id,
                str(blast_radius["reason_code"]),
                now=now,
                details={key: value for key, value in blast_radius.items() if key not in {"ok", "reason_code"}},
            )
        if not _capability_allowed(state, task_run):
            return _refuse(state, task_run_id, "dispatch.capability_not_allowed", now=now)
        claim = _active_claim(state, task_run_id)
        if not claim:
            return _refuse(state, task_run_id, "dispatch.claim_not_active", now=now)
        binding = find_provider_session(session, str(task_run.get("provider")), task_run.get("provider_surface"))
        if not binding:
            return _refuse(state, task_run_id, "dispatch.no_provider_binding", now=now)
        provider_request_id = stable_id(
            "preq",
            task_run_id,
            task_run.get("provider"),
            task_run.get("provider_surface"),
            task_run.get("idempotency_key"),
        )
        intent_event = append_run_event_to_state(
            state,
            task_run_id,
            "run.dispatch_intent",
            payload={
                "intent_sha256": sha256_text(canonical_json(intent)),
                "end_state_sha256": end_state_hash(end_state),
                "resource_claim_id": claim["resource_claim_id"],
                "definition_snapshot_sha256": task_run.get("definition_snapshot_sha256"),
            },
            reason_codes=["dispatch.intent_recorded"],
        )
        envelope = _build_dispatch_envelope(
            task_run=state["task_runs"][task_run_id],
            context=context,
            intent=intent,
            claim=claim,
            binding=binding,
            provider_request_id=provider_request_id,
            parent_span_id=intent_event["run_event_id"],
            now=now,
        )
        dispatched_event = append_run_event_to_state(
            state,
            task_run_id,
            "run.dispatched",
            payload={
                "provider_request_id": provider_request_id,
                "dispatch_envelope_id": envelope["dispatch_envelope_id"],
                "summary": "provider request envelope built by AMS dispatch",
            },
            reason_codes=["dispatch.envelope_ready"],
        )
        return {
            "dispatched": True,
            "envelope": envelope,
            "events": [intent_event, dispatched_event],
        }


def _build_dispatch_envelope(
    *,
    task_run: dict[str, Any],
    context: dict[str, Any],
    intent: dict[str, Any],
    claim: dict[str, Any],
    binding: dict[str, Any],
    provider_request_id: str,
    parent_span_id: str,
    now: str,
) -> dict[str, Any]:
    envelope = {
        "schema_version": "ams.ams.dispatch_envelope.v0",
        "dispatch_envelope_id": stable_id("dispenv", task_run["task_run_id"], provider_request_id),
        "task_run_id": task_run["task_run_id"],
        "session_id": task_run["session_id"],
        "context_id": task_run["context_id"],
        "provider": task_run.get("provider"),
        "surface": task_run.get("provider_surface"),
        "provider_session_id": binding.get("provider_session_id"),
        "provider_request_id": provider_request_id,
        "method": task_run.get("method"),
        "action": task_run.get("action"),
        "cwd": task_run.get("cwd"),
        "sandbox": task_run.get("sandbox"),
        "model": task_run.get("model"),
        "tool_scope": list(task_run.get("tool_scope") or []),
        "tool_definition_refs": deepcopy(task_run.get("tool_definition_refs") or []),
        "surface_definition_ref": deepcopy(task_run.get("surface_definition_ref")),
        "definition_snapshot_sha256": task_run.get("definition_snapshot_sha256"),
        "idempotency_key": task_run.get("idempotency_key"),
        "lease_id": task_run.get("lease_id"),
        "resource_claim_id": claim.get("resource_claim_id"),
        "intent": deepcopy(intent),
        "intent_sha256": sha256_text(canonical_json(intent)),
        "context_sha256": sha256_text(canonical_json(context)),
        "trace_id": stable_id("trace", task_run["session_id"], task_run["task_run_id"]),
        "parent_span_id": parent_span_id,
        "created_at": now,
    }
    envelope["sha256"] = sha256_text(canonical_json(envelope))
    return envelope


def _refuse(
    state: dict[str, Any],
    task_run_id: str,
    reason_code: str,
    *,
    now: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    task_run = state.get("task_runs", {}).get(task_run_id)
    session_id = task_run.get("session_id") if task_run else None
    event = build_ams_event(
        event_type=REFUSAL_EVENT_TYPE,
        source="ams://local/dispatch",
        subject=task_run_id,
        data={"reason_code": reason_code, "at": now, **(details or {})},
        session_id=session_id,
        task_run_id=task_run_id if task_run else None,
    )
    state.setdefault("ams_events", {})[event["id"]] = event
    refusal_count = sum(
        1 for item in (state.get("ams_events") or {}).values()
        if item.get("type") == REFUSAL_EVENT_TYPE
        and item.get("task_run_id") == task_run_id
        and (item.get("data") or {}).get("reason_code") == reason_code
    )
    incident = None
    if task_run and refusal_count >= 3:
        incident = open_incident_in_state(
            state,
            trigger="dispatch.repeated_refusal",
            task_run_id=task_run_id,
            reason_codes=[reason_code],
        )
    result = {
        "dispatched": False,
        "reason_code": reason_code,
        "ams_event_id": event["id"],
        "refusal_count": refusal_count,
    }
    if details:
        result.update(details)
    if incident:
        result["incident_packet_id"] = incident["incident_packet_id"]
    return result


def _lease_valid(task_run: dict[str, Any], context: dict[str, Any], now: str) -> bool:
    lease = context.get("lease") or {}
    if not lease.get("lease_id") or not lease.get("holder") or not lease.get("expires_at"):
        return False
    if task_run.get("lease_id") != lease.get("lease_id"):
        return False
    if task_run.get("actor") != lease.get("holder"):
        return False
    return parse_utc(str(lease["expires_at"])) > parse_utc(now)


def _has_end_state_check(end_state: dict[str, Any]) -> bool:
    node_type = end_state.get("type")
    if node_type in {"all", "any"}:
        return bool(end_state.get("checks"))
    return bool(node_type)


def _capability_allowed(state: dict[str, Any], task_run: dict[str, Any]) -> bool:
    return bool(_allowed_capability_reviews(state, task_run))


def _allowed_capability_reviews(state: dict[str, Any], task_run: dict[str, Any]) -> list[dict[str, Any]]:
    reviews: list[dict[str, Any]] = []
    for review in (state.get("admission_reviews") or {}).values():
        if review.get("subject_kind") != "task_run":
            continue
        if review.get("subject_id") != task_run.get("task_run_id"):
            continue
        if not str(review.get("operation") or "").startswith("capability"):
            continue
        response = review.get("response") or {}
        request = review.get("request") or {}
        requested_tools = set(request.get("tools") or [])
        run_tools = set(task_run.get("tool_scope") or [])
        if run_tools and not run_tools.issubset(requested_tools):
            continue
        if response.get("status") == "allow" and response.get("allowed") is True:
            reviews.append(review)
    return reviews


def _architecture_gate_ready(state: dict[str, Any], task_run: dict[str, Any]) -> dict[str, Any]:
    for review in _allowed_capability_reviews(state, task_run):
        result = architecture_gate_result_for_request(
            state,
            task_run_id=str(task_run.get("task_run_id") or ""),
            request=review.get("request") or {},
        )
        if not result["ok"]:
            return result
    return {"ok": True, "required": False, "reason_code": "architecture_gate.not_required"}


def _blast_radius_ready(state: dict[str, Any], task_run: dict[str, Any]) -> dict[str, Any]:
    for review in _allowed_capability_reviews(state, task_run):
        result = blast_radius_result_for_request(
            state,
            task_run_id=str(task_run.get("task_run_id") or ""),
            request=review.get("request") or {},
        )
        if not result["ok"]:
            return result
    return {"ok": True, "required": False, "reason_code": "blast_radius.not_required"}


def _active_claim(state: dict[str, Any], task_run_id: str) -> dict[str, Any] | None:
    for claim in (state.get("resource_claims") or {}).values():
        if claim.get("task_run_id") == task_run_id and claim.get("state") == "active":
            return deepcopy(claim)
    return None
