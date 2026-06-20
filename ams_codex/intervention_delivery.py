from __future__ import annotations

from copy import deepcopy
from typing import Any

from .manager_intervention import _hash_without as _hash_intervention_without
from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .outbox import build_outbox_item
from .store import JsonStore
from .surface_promise import build_surface_promise, evaluate_surface_promise_record


DELIVERY_STATUSES = {"attached"}
SOURCE_REF_PREFIX = "manager-intervention://"


class ManagerInterventionDeliveryStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def attach(
        self,
        manager_intervention_id: str,
        *,
        target_agents: list[dict[str, str]] | None = None,
        surface: str | None = None,
        target: str | None = None,
        channel_id: str | None = None,
        endpoint: str | None = None,
        admission_review_id: str | None = None,
        promise_reason: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            intervention = (state.get("manager_interventions") or {}).get(manager_intervention_id)
            if not intervention:
                raise KeyError(f"unknown manager_intervention_id: {manager_intervention_id}")
            task_run_id = intervention.get("task_run_id")
            task_run = (state.get("task_runs") or {}).get(task_run_id)
            if not task_run:
                raise ValueError("manager intervention delivery attachment requires a task_run_id")
            if admission_review_id and admission_review_id not in (state.get("admission_reviews") or {}):
                raise KeyError(f"unknown admission_review_id: {admission_review_id}")
            targets = _normalize_targets(target_agents or _targets_from_intervention(intervention))
            _ensure_targets_match(intervention, targets)
            routes = _delivery_routes(
                intervention,
                targets,
                surface=surface,
                target=target,
                channel_id=channel_id,
                endpoint=endpoint,
            )
            key = idempotency_key or stable_id(
                "mgrdelkey",
                manager_intervention_id,
                routes,
                admission_review_id,
                promise_reason,
            )
            delivery_id = stable_id("mgrdel", manager_intervention_id, key)
            source_packet_ref = f"{SOURCE_REF_PREFIX}{manager_intervention_id}"
            fingerprint = _idempotency_fingerprint(
                manager_intervention_id=manager_intervention_id,
                routes=routes,
                admission_review_id=admission_review_id,
                promise_reason=promise_reason,
                source_packet_ref=source_packet_ref,
            )
            existing = (state.get("manager_intervention_deliveries") or {}).get(delivery_id)
            if existing:
                if existing.get("idempotency_fingerprint") != fingerprint:
                    raise ValueError("idempotency key reused with different manager intervention delivery payload")
                return deepcopy(existing)

            outbox_items = []
            for route in routes:
                payload = _outbox_payload(intervention, delivery_id, route)
                item = build_outbox_item(
                    task_run,
                    target=route["target"],
                    channel_id=route.get("channel_id"),
                    endpoint=route.get("endpoint"),
                    payload=payload,
                    admission_review_id=admission_review_id,
                    idempotency_key=stable_id("mgrdelout", delivery_id, route["target_agent"]),
                )
                existing_item = (state.get("outbox_items") or {}).get(item["outbox_id"])
                if existing_item:
                    if existing_item.get("payload_sha256") != item["payload_sha256"]:
                        raise ValueError("existing manager intervention outbox item payload differs")
                    outbox_items.append(deepcopy(existing_item))
                    continue
                state.setdefault("outbox_items", {})[item["outbox_id"]] = item
                outbox_items.append(deepcopy(item))

            promised_surfaces = []
            if len(routes) != len(outbox_items):
                raise RuntimeError("manager intervention delivery route/outbox count mismatch")
            for route, item in zip(routes, outbox_items):
                promised_surfaces.append(
                    {
                        "surface": route["surface"],
                        "target": route["target"],
                        "channel_id": route.get("channel_id"),
                        "outbox_id": item["outbox_id"],
                        "required": True,
                        "required_readback": True,
                    }
                )
                route["outbox_id"] = item["outbox_id"]

            promise = build_surface_promise(
                task_run,
                promised_surfaces=promised_surfaces,
                source_packet_ref=source_packet_ref,
                promise_reason=promise_reason or "manager_intervention_delivery_attachment",
            )
            existing_promise = (state.get("surface_promises") or {}).get(promise["surface_promise_id"])
            if existing_promise:
                promise = deepcopy(existing_promise)
            else:
                result = evaluate_surface_promise_record(promise, state)
                promise["surface_delivery_status"] = result["surface_delivery_status"]
                promise["evaluation"] = result["evaluation"]
                promise["updated_at"] = utc_now()
                promise["surface_promise_sha256"] = _hash_without(promise, "surface_promise_sha256")
                state.setdefault("surface_promises", {})[promise["surface_promise_id"]] = promise

            record = _build_delivery_record(
                intervention,
                delivery_id=delivery_id,
                routes=routes,
                surface_promise_id=promise["surface_promise_id"],
                source_packet_ref=source_packet_ref,
                admission_review_id=admission_review_id,
                promise_reason=promise_reason,
                idempotency_key=key,
                idempotency_fingerprint=fingerprint,
            )
            state.setdefault("manager_intervention_deliveries", {})[delivery_id] = record
            state.setdefault("indexes", {}).setdefault("manager_intervention_delivery_ids", {})[
                delivery_id
            ] = delivery_id
            state.setdefault("manager_interventions", {})[manager_intervention_id] = _append_delivery_action(
                intervention,
                record,
            )
            return deepcopy(record)


def validate_manager_intervention_delivery_record(
    record: dict[str, Any],
    *,
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    expected_hash = record.get("delivery_sha256")
    if expected_hash and expected_hash != _hash_without(record, "delivery_sha256"):
        reason_codes.append("manager_intervention_delivery.hash_mismatch")
    if record.get("status") not in DELIVERY_STATUSES:
        reason_codes.append("manager_intervention_delivery.status_invalid")
    if record.get("idempotency_fingerprint") != _idempotency_fingerprint_from_record(record):
        reason_codes.append("manager_intervention_delivery.idempotency_fingerprint_mismatch")
    if not record.get("delivery_targets"):
        reason_codes.append("manager_intervention_delivery.targets_empty")
    if sorted(record.get("outbox_ids") or []) != sorted(
        route.get("outbox_id") for route in (record.get("delivery_targets") or [])
    ):
        reason_codes.append("manager_intervention_delivery.outbox_ids_mismatch")
    if state is not None:
        _validate_state_links(reason_codes, record, state)
    return {"ok": not reason_codes, "reason_codes": reason_codes}


def _build_delivery_record(
    intervention: dict[str, Any],
    *,
    delivery_id: str,
    routes: list[dict[str, Any]],
    surface_promise_id: str,
    source_packet_ref: str,
    admission_review_id: str | None,
    promise_reason: str | None,
    idempotency_key: str,
    idempotency_fingerprint: str,
) -> dict[str, Any]:
    now = utc_now()
    record = {
        "schema_version": "ams.ams_codex.manager_intervention_delivery.v0",
        "manager_intervention_delivery_id": delivery_id,
        "manager_intervention_id": intervention.get("manager_intervention_id"),
        "task_run_id": intervention.get("task_run_id"),
        "session_id": intervention.get("session_id"),
        "context_id": intervention.get("context_id"),
        "attention_id": intervention.get("attention_id"),
        "target_agents": [deepcopy(route["target_agent"]) for route in routes],
        "delivery_targets": deepcopy(routes),
        "outbox_ids": [str(route["outbox_id"]) for route in routes],
        "surface_promise_id": surface_promise_id,
        "source_packet_ref": source_packet_ref,
        "status": "attached",
        "admission_review_id": admission_review_id,
        "promise_reason": promise_reason,
        "idempotency_key": idempotency_key,
        "idempotency_fingerprint": idempotency_fingerprint,
        "created_at": now,
    }
    record["delivery_sha256"] = _hash_without(record, "delivery_sha256")
    return record


def _append_delivery_action(intervention: dict[str, Any], delivery: dict[str, Any]) -> dict[str, Any]:
    updated = deepcopy(intervention)
    action = {
        "type": "manager_intervention_delivery_attachment",
        "manager_intervention_delivery_id": delivery["manager_intervention_delivery_id"],
        "surface_promise_id": delivery["surface_promise_id"],
        "outbox_ids": list(delivery.get("outbox_ids") or []),
        "idempotency_key": delivery["idempotency_key"],
        "created_at": delivery["created_at"],
    }
    existing_ids = {
        item.get("manager_intervention_delivery_id")
        for item in updated.get("delivery_actions") or []
        if isinstance(item, dict)
    }
    if action["manager_intervention_delivery_id"] not in existing_ids:
        updated.setdefault("delivery_actions", []).append(action)
    updated["updated_at"] = delivery["created_at"]
    updated["manager_intervention_sha256"] = _hash_intervention_without(
        updated,
        "manager_intervention_sha256",
    )
    return updated


def _delivery_routes(
    intervention: dict[str, Any],
    targets: list[dict[str, str]],
    *,
    surface: str | None,
    target: str | None,
    channel_id: str | None,
    endpoint: str | None,
) -> list[dict[str, Any]]:
    routes = []
    for agent in targets:
        resolved_surface = str(surface or agent["surface"])
        resolved_target = str(target or agent["provider"])
        resolved_endpoint = endpoint or _default_endpoint(intervention, agent, resolved_target, channel_id)
        routes.append(
            {
                "target_agent": deepcopy(agent),
                "surface": resolved_surface,
                "target": resolved_target,
                "channel_id": str(channel_id) if channel_id is not None else None,
                "endpoint": resolved_endpoint,
            }
        )
    return routes


def _default_endpoint(
    intervention: dict[str, Any],
    agent: dict[str, str],
    target: str,
    channel_id: str | None,
) -> str:
    if target == "discord" and channel_id:
        return f"/channels/{channel_id}/messages"
    return (
        f"ams://manager-interventions/{intervention.get('manager_intervention_id')}"
        f"/{agent['agent_name']}/{agent['surface']}"
    )


def _outbox_payload(
    intervention: dict[str, Any],
    delivery_id: str,
    route: dict[str, Any],
) -> dict[str, Any]:
    payload = intervention.get("payload") or {}
    target_agent = route["target_agent"]
    return {
        "kind": "manager_intervention_delivery",
        "manager_intervention_delivery_id": delivery_id,
        "manager_intervention_id": intervention.get("manager_intervention_id"),
        "intervention_type": intervention.get("intervention_type"),
        "priority": intervention.get("priority"),
        "primary_domain": intervention.get("primary_domain"),
        "additional_domains": list(intervention.get("additional_domains") or []),
        "target_agent": deepcopy(target_agent),
        "must_remember": list(payload.get("must_remember") or []),
        "do_not_do": list(payload.get("do_not_do") or []),
        "required_readback": list(payload.get("required_readback") or []),
        "source_refs": list(intervention.get("source_refs") or []),
        "source_attention_signal_ids": list(intervention.get("source_attention_signal_ids") or []),
        "settlement_command": {
            "command": "manager-intervention-settle",
            "manager_intervention_id": intervention.get("manager_intervention_id"),
            "target_agent": _format_target_agent(target_agent),
            "ack_statuses": ["acknowledged", "deferred", "resolved"],
        },
        "delivery_constraints": [
            "do_not_send_directly",
            "record_manager_intervention_settlement_in_ams",
            "preserve_source_refs_in_readback",
        ],
    }


def _validate_state_links(reason_codes: list[str], record: dict[str, Any], state: dict[str, Any]) -> None:
    intervention = (state.get("manager_interventions") or {}).get(record.get("manager_intervention_id"))
    if not intervention:
        reason_codes.append("manager_intervention_delivery.intervention_missing")
    else:
        if intervention.get("task_run_id") != record.get("task_run_id"):
            reason_codes.append("manager_intervention_delivery.intervention_task_run_mismatch")
        _validate_delivery_action(reason_codes, intervention, record)
    task_run = (state.get("task_runs") or {}).get(record.get("task_run_id"))
    if not task_run:
        reason_codes.append("manager_intervention_delivery.task_run_missing")
    elif task_run.get("session_id") != record.get("session_id"):
        reason_codes.append("manager_intervention_delivery.session_mismatch")
    if record.get("admission_review_id") and record["admission_review_id"] not in (state.get("admission_reviews") or {}):
        reason_codes.append("manager_intervention_delivery.admission_review_missing")
    outbox_items = state.get("outbox_items") or {}
    for route in record.get("delivery_targets") or []:
        outbox_id = route.get("outbox_id")
        item = outbox_items.get(outbox_id)
        if not item:
            reason_codes.append(f"manager_intervention_delivery.outbox_missing:{outbox_id}")
            continue
        if item.get("task_run_id") != record.get("task_run_id"):
            reason_codes.append("manager_intervention_delivery.outbox_task_run_mismatch")
        if item.get("target") != route.get("target"):
            reason_codes.append("manager_intervention_delivery.outbox_target_mismatch")
        if item.get("channel_id") != route.get("channel_id"):
            reason_codes.append("manager_intervention_delivery.outbox_channel_mismatch")
        if item.get("endpoint") != route.get("endpoint"):
            reason_codes.append("manager_intervention_delivery.outbox_endpoint_mismatch")
        payload = item.get("payload") or {}
        if payload.get("manager_intervention_id") != record.get("manager_intervention_id"):
            reason_codes.append("manager_intervention_delivery.outbox_payload_intervention_mismatch")
        if payload.get("manager_intervention_delivery_id") != record.get("manager_intervention_delivery_id"):
            reason_codes.append("manager_intervention_delivery.outbox_payload_delivery_mismatch")
    promise = (state.get("surface_promises") or {}).get(record.get("surface_promise_id"))
    if not promise:
        reason_codes.append("manager_intervention_delivery.surface_promise_missing")
    else:
        if promise.get("task_run_id") != record.get("task_run_id"):
            reason_codes.append("manager_intervention_delivery.surface_promise_task_run_mismatch")
        if promise.get("source_packet_ref") != record.get("source_packet_ref"):
            reason_codes.append("manager_intervention_delivery.surface_promise_source_ref_mismatch")
        promised_outbox_ids = {
            item.get("outbox_id")
            for item in promise.get("promised_surfaces") or []
            if isinstance(item, dict)
        }
        if set(record.get("outbox_ids") or []) - promised_outbox_ids:
            reason_codes.append("manager_intervention_delivery.surface_promise_outbox_missing")


def _validate_delivery_action(
    reason_codes: list[str],
    intervention: dict[str, Any],
    record: dict[str, Any],
) -> None:
    action_ids = [
        action.get("manager_intervention_delivery_id")
        for action in intervention.get("delivery_actions") or []
        if isinstance(action, dict)
    ]
    if record.get("manager_intervention_delivery_id") not in action_ids:
        reason_codes.append("manager_intervention_delivery.action_missing_from_intervention")


def _targets_from_intervention(intervention: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "agent_name": str(target.get("agent_name") or ""),
            "provider": str(target.get("provider") or ""),
            "surface": str(target.get("surface") or ""),
        }
        for target in intervention.get("target_agents") or []
    ]


def _ensure_targets_match(intervention: dict[str, Any], targets: list[dict[str, str]]) -> None:
    known = {_target_key(target) for target in _targets_from_intervention(intervention)}
    for target in targets:
        if _target_key(target) not in known:
            raise ValueError("target agent is not listed on manager intervention")


def _normalize_targets(targets: list[dict[str, str]]) -> list[dict[str, str]]:
    normalized = []
    for target in targets:
        agent = {
            "agent_name": str(target.get("agent_name") or "").strip(),
            "provider": str(target.get("provider") or "").strip(),
            "surface": str(target.get("surface") or "").strip(),
        }
        if not all(agent.values()):
            raise ValueError("target_agent requires agent_name, provider, and surface")
        if _target_key(agent) not in {_target_key(item) for item in normalized}:
            normalized.append(agent)
    if not normalized:
        raise ValueError("manager intervention delivery requires at least one target agent")
    return normalized


def _target_key(target: dict[str, str]) -> tuple[str, str, str]:
    return (str(target.get("agent_name") or ""), str(target.get("provider") or ""), str(target.get("surface") or ""))


def _format_target_agent(target: dict[str, str]) -> str:
    return f"{target['agent_name']}:{target['provider']}:{target['surface']}"


def _idempotency_fingerprint(
    *,
    manager_intervention_id: str,
    routes: list[dict[str, Any]],
    admission_review_id: str | None,
    promise_reason: str | None,
    source_packet_ref: str,
) -> str:
    return sha256_text(
        canonical_json(
            {
                "manager_intervention_id": manager_intervention_id,
                "routes": _fingerprint_routes(routes),
                "admission_review_id": admission_review_id,
                "promise_reason": promise_reason,
                "source_packet_ref": source_packet_ref,
            }
        )
    )


def _fingerprint_routes(routes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for route in routes:
        item = deepcopy(route)
        item.pop("outbox_id", None)
        normalized.append(item)
    return normalized


def _idempotency_fingerprint_from_record(record: dict[str, Any]) -> str:
    return _idempotency_fingerprint(
        manager_intervention_id=str(record.get("manager_intervention_id") or ""),
        routes=record.get("delivery_targets") or [],
        admission_review_id=record.get("admission_review_id"),
        promise_reason=record.get("promise_reason"),
        source_packet_ref=str(record.get("source_packet_ref") or ""),
    )
