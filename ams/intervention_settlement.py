from __future__ import annotations

from copy import deepcopy
from typing import Any

from .attention_router import DOMAIN_COVERAGE
from .manager_intervention import ACK_STATUSES, _hash_without as _hash_intervention_without
from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .store import JsonStore


SETTLEMENT_ACK_STATUSES = ACK_STATUSES - {"new"}
SETTLEMENT_STATUSES = {"accepted", "rejected"}
PRIORITY_DECISIONS = {"none_deferred", "deferred"}


class ManagerInterventionSettlementStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def settle(
        self,
        manager_intervention_id: str,
        *,
        target_agent: dict[str, str],
        ack_status: str,
        readback_ref: str | None = None,
        readback_summary: str | None = None,
        source_refs_used: list[str] | None = None,
        priority_decision: str = "none_deferred",
        deferred_signal_ids: list[str] | None = None,
        priority_reason: str | None = None,
        next_domain: str | None = None,
        crosses_domains: bool = False,
        domain_reason: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            intervention = (state.get("manager_interventions") or {}).get(manager_intervention_id)
            if not intervention:
                raise KeyError(f"unknown manager_intervention_id: {manager_intervention_id}")
            record = build_manager_intervention_settlement(
                intervention,
                target_agent=target_agent,
                ack_status=ack_status,
                readback_ref=readback_ref,
                readback_summary=readback_summary,
                source_refs_used=source_refs_used or [],
                priority_decision=priority_decision,
                deferred_signal_ids=deferred_signal_ids or [],
                priority_reason=priority_reason,
                next_domain=next_domain,
                crosses_domains=crosses_domains,
                domain_reason=domain_reason,
                idempotency_key=idempotency_key,
            )
            settlement_id = record["manager_intervention_settlement_id"]
            existing = (state.get("manager_intervention_settlements") or {}).get(settlement_id)
            if existing:
                if existing.get("idempotency_fingerprint") != record.get("idempotency_fingerprint"):
                    raise ValueError("idempotency key reused with different manager intervention settlement payload")
                return deepcopy(existing)

            if record["settlement_status"] == "accepted":
                record["applied_to_intervention"] = True
                record["settlement_sha256"] = _hash_without(record, "settlement_sha256")
                updated = apply_settlement_to_intervention(intervention, record)
                state.setdefault("manager_interventions", {})[manager_intervention_id] = updated
                _apply_settlement_to_attention_signals(state, updated, record)
            state.setdefault("manager_intervention_settlements", {})[settlement_id] = record
            state.setdefault("indexes", {}).setdefault("manager_intervention_settlement_ids", {})[
                settlement_id
            ] = settlement_id
            return deepcopy(record)


def build_manager_intervention_settlement(
    intervention: dict[str, Any],
    *,
    target_agent: dict[str, str],
    ack_status: str,
    readback_ref: str | None = None,
    readback_summary: str | None = None,
    source_refs_used: list[str] | None = None,
    priority_decision: str = "none_deferred",
    deferred_signal_ids: list[str] | None = None,
    priority_reason: str | None = None,
    next_domain: str | None = None,
    crosses_domains: bool = False,
    domain_reason: str | None = None,
    idempotency_key: str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    normalized_target = _normalize_target(target_agent)
    if not _target_matches(intervention, normalized_target):
        raise ValueError("target agent is not listed on manager intervention")
    if ack_status not in SETTLEMENT_ACK_STATUSES:
        raise ValueError(f"invalid settlement ack_status: {ack_status}")
    readback_summary = readback_summary or ""
    source_refs_used = _unique_str(source_refs_used or [])
    deferred_signal_ids = _unique_str(deferred_signal_ids or [])
    priority_decision = priority_decision if priority_decision in PRIORITY_DECISIONS else "none_deferred"
    next_domain = next_domain or intervention.get("primary_domain") or "unknown"
    readback = {
        "ref": readback_ref,
        "summary": readback_summary,
        "summary_sha256": sha256_text(readback_summary),
        "source_refs_used": source_refs_used,
        "priority_decision": priority_decision,
        "deferred_signal_ids": deferred_signal_ids,
        "priority_reason": priority_reason,
        "domain_decision": {
            "next_domain": next_domain,
            "crosses_domains": bool(crosses_domains),
            "reason": domain_reason,
        },
    }
    checks = _readback_checks(intervention, ack_status=ack_status, readback=readback)
    settlement_status = "accepted" if _checks_accept(checks) else "rejected"
    fingerprint = _idempotency_fingerprint(
        intervention,
        target_agent=normalized_target,
        ack_status=ack_status,
        readback=readback,
    )
    key = idempotency_key or stable_id(
        "mgrsetkey",
        intervention.get("manager_intervention_id"),
        normalized_target,
        ack_status,
        readback.get("ref"),
        readback.get("summary_sha256"),
    )
    record = {
        "schema_version": "ams.ams.manager_intervention_settlement.v0",
        "manager_intervention_settlement_id": stable_id(
            "mgrset",
            intervention.get("manager_intervention_id"),
            key,
        ),
        "manager_intervention_id": intervention.get("manager_intervention_id"),
        "target_agent": normalized_target,
        "ack_status": ack_status,
        "settlement_status": settlement_status,
        "readback": readback,
        "readback_checks": checks,
        "idempotency_key": key,
        "idempotency_fingerprint": fingerprint,
        "applied_to_intervention": settlement_status == "accepted",
        "created_at": now,
    }
    record["settlement_sha256"] = _hash_without(record, "settlement_sha256")
    return deepcopy(record)


def apply_settlement_to_intervention(
    intervention: dict[str, Any],
    settlement: dict[str, Any],
) -> dict[str, Any]:
    updated = deepcopy(intervention)
    ack_status = str(settlement.get("ack_status") or "")
    delivery_status = "acked" if ack_status in {"acknowledged", "resolved"} else "delivered"
    updated["ack_status"] = ack_status
    updated["delivery_status"] = delivery_status
    updated["target_agents"] = [
        _update_target_status(target, settlement["target_agent"], delivery_status)
        for target in updated.get("target_agents") or []
    ]
    updated.setdefault("delivery_actions", []).append(
        {
            "type": "manager_intervention_settlement",
            "manager_intervention_settlement_id": settlement["manager_intervention_settlement_id"],
            "target_agent": settlement["target_agent"],
            "ack_status": ack_status,
            "settlement_status": settlement["settlement_status"],
            "idempotency_key": settlement["idempotency_key"],
            "created_at": settlement["created_at"],
        }
    )
    updated["updated_at"] = settlement["created_at"]
    updated["manager_intervention_sha256"] = _hash_intervention_without(
        updated,
        "manager_intervention_sha256",
    )
    return updated


def validate_manager_intervention_settlement_record(
    record: dict[str, Any],
    *,
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    expected_hash = record.get("settlement_sha256")
    if expected_hash and expected_hash != _hash_without(record, "settlement_sha256"):
        reason_codes.append("manager_intervention_settlement.hash_mismatch")
    if record.get("ack_status") not in SETTLEMENT_ACK_STATUSES:
        reason_codes.append("manager_intervention_settlement.ack_status_invalid")
    if record.get("settlement_status") not in SETTLEMENT_STATUSES:
        reason_codes.append("manager_intervention_settlement.status_invalid")
    readback = record.get("readback") or {}
    if readback.get("summary_sha256") != sha256_text(str(readback.get("summary") or "")):
        reason_codes.append("manager_intervention_settlement.readback_summary_hash_mismatch")
    if readback.get("priority_decision") not in PRIORITY_DECISIONS:
        reason_codes.append("manager_intervention_settlement.priority_decision_invalid")
    domain = ((readback.get("domain_decision") or {}).get("next_domain") or "")
    if domain not in DOMAIN_COVERAGE:
        reason_codes.append("manager_intervention_settlement.next_domain_invalid")
    checks = record.get("readback_checks") or []
    if record.get("settlement_status") == "accepted" and not _checks_accept(checks):
        reason_codes.append("manager_intervention_settlement.accepted_with_failed_checks")
    if record.get("settlement_status") == "rejected" and record.get("applied_to_intervention"):
        reason_codes.append("manager_intervention_settlement.rejected_applied")
    if record.get("idempotency_fingerprint") != _idempotency_fingerprint_from_record(record, state):
        reason_codes.append("manager_intervention_settlement.idempotency_fingerprint_mismatch")
    if state is not None:
        intervention = (state.get("manager_interventions") or {}).get(record.get("manager_intervention_id"))
        if not intervention:
            reason_codes.append("manager_intervention_settlement.intervention_missing")
        else:
            if not _target_matches(intervention, record.get("target_agent") or {}):
                reason_codes.append("manager_intervention_settlement.target_missing")
            if record.get("settlement_status") == "accepted":
                _validate_applied_settlement(reason_codes, intervention, record)
    return {"ok": not reason_codes, "reason_codes": reason_codes}


def _apply_settlement_to_attention_signals(
    state: dict[str, Any],
    intervention: dict[str, Any],
    settlement: dict[str, Any],
) -> None:
    for signal_id in intervention.get("source_attention_signal_ids") or []:
        signal = (state.get("attention_signals") or {}).get(signal_id)
        if not signal:
            continue
        updated = deepcopy(signal)
        updated["ack_status"] = settlement["ack_status"]
        if settlement["ack_status"] in {"acknowledged", "resolved"}:
            updated["route_status"] = "routed"
            updated["acked_at"] = settlement["created_at"]
        else:
            updated["route_status"] = "needs_ack"
        if settlement["ack_status"] == "resolved":
            updated["resolved_at"] = settlement["created_at"]
        updated["updated_at"] = settlement["created_at"]
        updated["attention_signal_sha256"] = _hash_without(updated, "attention_signal_sha256")
        state.setdefault("attention_signals", {})[signal_id] = updated


def _readback_checks(
    intervention: dict[str, Any],
    *,
    ack_status: str,
    readback: dict[str, Any],
) -> list[dict[str, Any]]:
    source_refs = list(intervention.get("source_refs") or [])
    source_refs_used = list(readback.get("source_refs_used") or [])
    priority_decision = str(readback.get("priority_decision") or "")
    deferred_signal_ids = list(readback.get("deferred_signal_ids") or [])
    domain_decision = readback.get("domain_decision") or {}
    checks = [
        {
            "check_type": "readback_present",
            "required": True,
            "passed": bool(readback.get("ref") or readback.get("summary")),
            "evidence": {"readback_ref": readback.get("ref"), "summary_sha256": readback.get("summary_sha256")},
        },
        {
            "check_type": "source_refs_named",
            "required": bool(source_refs),
            "passed": (not source_refs) or bool(source_refs_used),
            "evidence": {"expected_source_refs": source_refs, "source_refs_used": source_refs_used},
        },
        {
            "check_type": "priority_deferral_stated",
            "required": intervention.get("priority") in {"P0", "P1", "P2"},
            "passed": (
                priority_decision == "none_deferred"
                or (
                    priority_decision == "deferred"
                    and bool(deferred_signal_ids)
                    and bool(readback.get("priority_reason"))
                )
            ),
            "evidence": {
                "priority": intervention.get("priority"),
                "ack_status": ack_status,
                "priority_decision": priority_decision,
                "deferred_signal_ids": deferred_signal_ids,
                "priority_reason": readback.get("priority_reason"),
            },
        },
        {
            "check_type": "domain_transition_stated",
            "required": True,
            "passed": (
                domain_decision.get("next_domain") in DOMAIN_COVERAGE
                and bool(domain_decision.get("reason"))
            ),
            "evidence": domain_decision,
        },
    ]
    return checks


def _checks_accept(checks: list[dict[str, Any]]) -> bool:
    return all((not check.get("required")) or check.get("passed") is True for check in checks)


def _idempotency_fingerprint(
    intervention: dict[str, Any],
    *,
    target_agent: dict[str, str],
    ack_status: str,
    readback: dict[str, Any],
) -> str:
    return sha256_text(
        canonical_json(
            {
                "manager_intervention_id": intervention.get("manager_intervention_id"),
                "target_agent": target_agent,
                "ack_status": ack_status,
                "readback": readback,
            }
        )
    )


def _idempotency_fingerprint_from_record(record: dict[str, Any], state: dict[str, Any] | None) -> str:
    if state is not None:
        intervention = (state.get("manager_interventions") or {}).get(record.get("manager_intervention_id")) or {}
    else:
        intervention = {"manager_intervention_id": record.get("manager_intervention_id")}
    return _idempotency_fingerprint(
        intervention,
        target_agent=record.get("target_agent") or {},
        ack_status=str(record.get("ack_status") or ""),
        readback=record.get("readback") or {},
    )


def _validate_applied_settlement(
    reason_codes: list[str],
    intervention: dict[str, Any],
    settlement: dict[str, Any],
) -> None:
    action_ids = [
        action.get("manager_intervention_settlement_id")
        for action in intervention.get("delivery_actions") or []
        if isinstance(action, dict)
    ]
    if settlement.get("manager_intervention_settlement_id") not in action_ids:
        reason_codes.append("manager_intervention_settlement.action_missing_from_intervention")
    if intervention.get("ack_status") != settlement.get("ack_status"):
        reason_codes.append("manager_intervention_settlement.intervention_ack_status_mismatch")
    expected_delivery = "acked" if settlement.get("ack_status") in {"acknowledged", "resolved"} else "delivered"
    if intervention.get("delivery_status") != expected_delivery:
        reason_codes.append("manager_intervention_settlement.intervention_delivery_status_mismatch")


def _normalize_target(target_agent: dict[str, str]) -> dict[str, str]:
    target = {
        "agent_name": str(target_agent.get("agent_name") or "").strip(),
        "provider": str(target_agent.get("provider") or "").strip(),
        "surface": str(target_agent.get("surface") or "").strip(),
    }
    if not all(target.values()):
        raise ValueError("target_agent requires agent_name, provider, and surface")
    return target


def _target_matches(intervention: dict[str, Any], target_agent: dict[str, str]) -> bool:
    target = _normalize_target(target_agent)
    return any(
        packet.get("agent_name") == target["agent_name"]
        and packet.get("provider") == target["provider"]
        and packet.get("surface") == target["surface"]
        for packet in intervention.get("target_agents") or []
    )


def _update_target_status(
    target: dict[str, Any],
    settlement_target: dict[str, str],
    delivery_status: str,
) -> dict[str, Any]:
    updated = deepcopy(target)
    if (
        updated.get("agent_name") == settlement_target.get("agent_name")
        and updated.get("provider") == settlement_target.get("provider")
        and updated.get("surface") == settlement_target.get("surface")
    ):
        updated["delivery_status"] = delivery_status
    return updated


def _unique_str(values: list[str]) -> list[str]:
    return list(dict.fromkeys(str(value) for value in values if str(value)))
