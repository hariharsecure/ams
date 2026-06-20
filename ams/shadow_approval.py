from __future__ import annotations

from copy import deepcopy
from typing import Any

from .backup_restore import validate_store_backup_drill_record
from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .runner_parity import validate_runner_dry_run_parity_record
from .shadow_launch import validate_shadow_launch_plan_record
from .shadow_runner import validate_shadow_runner_transaction_record
from .store import JsonStore


SCHEMA_VERSION = "ams.ams.shadow_approval_packet.v0"
STATUSES = {"ready_for_operator_approval", "blocked"}
REQUIRED_READBACK_PHRASES = [
    "no persistent process will start from this packet",
    "egress mode is none",
    "discord provider terminal injection remain disabled",
    "rollback is discard packet and restore from backup",
]


class ShadowApprovalPacketStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        shadow_launch_plan_id: str,
        shadow_runner_transaction_id: str,
        runner_dry_run_parity_id: str,
        store_backup_drill_id: str,
        requested_by: str = "operator",
        readback_ref: str | None = None,
        readback_text: str = "",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            record = build_shadow_approval_packet(
                state=state,
                shadow_launch_plan_id=shadow_launch_plan_id,
                shadow_runner_transaction_id=shadow_runner_transaction_id,
                runner_dry_run_parity_id=runner_dry_run_parity_id,
                store_backup_drill_id=store_backup_drill_id,
                requested_by=requested_by,
                readback_ref=readback_ref,
                readback_text=readback_text,
            )
            validation = validate_shadow_approval_packet_record(record, state=state)
            if not validation["ok"]:
                raise ValueError("; ".join(validation["reason_codes"]))
            packet_id = record["shadow_approval_packet_id"]
            state.setdefault("shadow_approval_packets", {})[packet_id] = record
            state.setdefault("indexes", {}).setdefault("shadow_approval_packet_ids", {})[packet_id] = packet_id
        return deepcopy(record)


def build_shadow_approval_packet(
    *,
    state: dict[str, Any],
    shadow_launch_plan_id: str,
    shadow_runner_transaction_id: str,
    runner_dry_run_parity_id: str,
    store_backup_drill_id: str,
    requested_by: str = "operator",
    readback_ref: str | None = None,
    readback_text: str = "",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    plan = (state.get("shadow_launch_plans") or {}).get(shadow_launch_plan_id) or {}
    transaction = (state.get("shadow_runner_transactions") or {}).get(shadow_runner_transaction_id) or {}
    parity = (state.get("runner_dry_run_parities") or {}).get(runner_dry_run_parity_id) or {}
    drill = (state.get("store_backup_drills") or {}).get(store_backup_drill_id) or {}
    readback = _build_readback(
        requested_by=requested_by,
        readback_ref=readback_ref,
        readback_text=readback_text,
        now=now,
    )
    evaluation = _evaluate(
        state=state,
        plan=plan,
        transaction=transaction,
        parity=parity,
        drill=drill,
        readback=readback,
    )
    record = {
        "schema_version": SCHEMA_VERSION,
        "shadow_approval_packet_id": stable_id(
            "shadowapprove",
            shadow_launch_plan_id,
            shadow_runner_transaction_id,
            runner_dry_run_parity_id,
            store_backup_drill_id,
            readback.get("summary_sha256"),
            now,
        ),
        "shadow_launch_plan_id": shadow_launch_plan_id,
        "shadow_launch_plan_sha256": plan.get("shadow_launch_plan_sha256"),
        "shadow_runner_transaction_id": shadow_runner_transaction_id,
        "shadow_runner_transaction_sha256": transaction.get("shadow_runner_transaction_sha256"),
        "runner_dry_run_parity_id": runner_dry_run_parity_id,
        "runner_dry_run_parity_sha256": parity.get("parity_sha256"),
        "store_backup_drill_id": store_backup_drill_id,
        "store_backup_drill_sha256": drill.get("drill_sha256"),
        "operator_readback": readback,
        "required_readback_phrases": list(REQUIRED_READBACK_PHRASES),
        "required_gates": evaluation["required_gates"],
        "approval_granted": False,
        "live_start_allowed": False,
        "process_start_allowed": False,
        "network_egress_allowed": False,
        "start_actions": [],
        "status": evaluation["status"],
        "reason_codes": evaluation["reason_codes"],
        "created_at": now,
    }
    record["approval_packet_sha256"] = _hash_without(record, "approval_packet_sha256")
    return deepcopy(record)


def validate_shadow_approval_packet_record(record: dict[str, Any], *, state: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("shadow_approval.schema_version_invalid")
    expected_hash = record.get("approval_packet_sha256")
    if expected_hash and expected_hash != _hash_without(record, "approval_packet_sha256"):
        reason_codes.append("shadow_approval.hash_mismatch")
    if record.get("approval_granted") is not False:
        reason_codes.append("shadow_approval.approval_granted_not_false")
    for key in ("live_start_allowed", "process_start_allowed", "network_egress_allowed"):
        if record.get(key) is not False:
            reason_codes.append(f"shadow_approval.{key}_not_false")
    if record.get("start_actions") != []:
        reason_codes.append("shadow_approval.start_actions_not_empty")

    plan = (state.get("shadow_launch_plans") or {}).get(record.get("shadow_launch_plan_id")) or {}
    transaction = (state.get("shadow_runner_transactions") or {}).get(record.get("shadow_runner_transaction_id")) or {}
    parity = (state.get("runner_dry_run_parities") or {}).get(record.get("runner_dry_run_parity_id")) or {}
    drill = (state.get("store_backup_drills") or {}).get(record.get("store_backup_drill_id")) or {}
    if record.get("shadow_launch_plan_sha256") != plan.get("shadow_launch_plan_sha256"):
        reason_codes.append("shadow_approval.shadow_launch_plan_hash_mismatch")
    if record.get("shadow_runner_transaction_sha256") != transaction.get("shadow_runner_transaction_sha256"):
        reason_codes.append("shadow_approval.shadow_runner_transaction_hash_mismatch")
    if record.get("runner_dry_run_parity_sha256") != parity.get("parity_sha256"):
        reason_codes.append("shadow_approval.runner_parity_hash_mismatch")
    if record.get("store_backup_drill_sha256") != drill.get("drill_sha256"):
        reason_codes.append("shadow_approval.store_backup_drill_hash_mismatch")

    readback = record.get("operator_readback") or {}
    if readback.get("summary_sha256") != sha256_text(str(readback.get("summary") or "")):
        reason_codes.append("shadow_approval.readback_summary_hash_mismatch")
    evaluation = _evaluate(
        state=state,
        plan=plan,
        transaction=transaction,
        parity=parity,
        drill=drill,
        readback=readback,
    )
    if record.get("required_gates") != evaluation["required_gates"]:
        reason_codes.append("shadow_approval.required_gates_mismatch")
    if record.get("status") != evaluation["status"]:
        reason_codes.append("shadow_approval.status_reason_mismatch")
    if sorted(record.get("reason_codes") or []) != sorted(evaluation["reason_codes"]):
        reason_codes.append("shadow_approval.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _evaluate(
    *,
    state: dict[str, Any],
    plan: dict[str, Any],
    transaction: dict[str, Any],
    parity: dict[str, Any],
    drill: dict[str, Any],
    readback: dict[str, Any],
) -> dict[str, Any]:
    plan_validation = validate_shadow_launch_plan_record(plan, state=state) if plan else {"ok": False, "reason_codes": ["missing"]}
    transaction_validation = (
        validate_shadow_runner_transaction_record(transaction, state=state)
        if transaction else {"ok": False, "reason_codes": ["missing"]}
    )
    parity_validation = (
        validate_runner_dry_run_parity_record(parity, state=state)
        if parity else {"ok": False, "reason_codes": ["missing"]}
    )
    drill_validation = validate_store_backup_drill_record(drill) if drill else {"ok": False, "reason_codes": ["missing"]}
    readback_checks = _readback_checks(readback)
    same_plan = (
        bool(plan)
        and transaction.get("shadow_launch_plan_id") == plan.get("shadow_launch_plan_id")
        and transaction.get("shadow_launch_plan_sha256") == plan.get("shadow_launch_plan_sha256")
        and parity.get("shadow_launch_plan_id") == plan.get("shadow_launch_plan_id")
        and parity.get("shadow_launch_plan_sha256") == plan.get("shadow_launch_plan_sha256")
    )
    required_gates = {
        "shadow_launch_plan_ready": plan.get("ready_to_launch") is True
        and plan.get("status") == "allow"
        and plan_validation["ok"],
        "shadow_launch_plan_no_egress": plan.get("egress_mode") == "none",
        "shadow_launch_plan_inert": plan.get("launch_actions") == []
        and plan.get("downstream_consumers") == [],
        "runner_transaction_ready": transaction.get("ready_for_operator_review") is True
        and transaction.get("status") == "allow"
        and transaction_validation["ok"],
        "runner_transaction_inert": transaction.get("process_start_allowed") is False
        and transaction.get("start_actions") == [],
        "runner_parity_ready": parity.get("status") == "ready_for_operator_review"
        and parity_validation["ok"],
        "runner_parity_inert": parity.get("process_start_allowed") is False
        and parity.get("network_egress_allowed") is False
        and parity.get("start_actions") == [],
        "backup_drill_passed": drill.get("status") == "passed" and drill_validation["ok"],
        "all_refs_same_shadow_launch_plan": same_plan,
        "operator_readback_present": readback_checks["present"],
        "operator_readback_required_phrases": readback_checks["required_phrases"],
        "approval_granted_false": True,
        "live_start_allowed_false": True,
    }
    reason_codes = _reason_codes(
        required_gates,
        plan_reasons=plan_validation["reason_codes"],
        transaction_reasons=transaction_validation["reason_codes"],
        parity_reasons=parity_validation["reason_codes"],
        drill_reasons=drill_validation["reason_codes"],
        missing_phrases=readback_checks["missing_phrases"],
    )
    status = "ready_for_operator_approval" if reason_codes == ["shadow_approval.ready_for_operator_approval"] else "blocked"
    return {"status": status, "reason_codes": reason_codes, "required_gates": required_gates}


def _reason_codes(
    gates: dict[str, bool],
    *,
    plan_reasons: list[str],
    transaction_reasons: list[str],
    parity_reasons: list[str],
    drill_reasons: list[str],
    missing_phrases: list[str],
) -> list[str]:
    reasons: list[str] = []
    for key, ok in gates.items():
        if not ok:
            reasons.append(f"shadow_approval.{key}_missing")
    for prefix, details in (
        ("shadow_approval.plan", plan_reasons),
        ("shadow_approval.transaction", transaction_reasons),
        ("shadow_approval.parity", parity_reasons),
        ("shadow_approval.backup", drill_reasons),
    ):
        if details and details != ["missing"]:
            reasons.extend(f"{prefix}:{reason}" for reason in details)
    reasons.extend(f"shadow_approval.readback_phrase_missing:{phrase}" for phrase in missing_phrases)
    return sorted(set(reasons)) or ["shadow_approval.ready_for_operator_approval"]


def _build_readback(
    *,
    requested_by: str,
    readback_ref: str | None,
    readback_text: str,
    now: str,
) -> dict[str, Any]:
    missing = _missing_phrases(readback_text)
    return {
        "requested_by": requested_by,
        "ref": readback_ref,
        "summary": readback_text,
        "summary_sha256": sha256_text(readback_text),
        "required_phrases_present": not missing,
        "missing_required_phrases": missing,
        "created_at": now,
    }


def _readback_checks(readback: dict[str, Any]) -> dict[str, Any]:
    text = str(readback.get("summary") or "")
    missing = _missing_phrases(text)
    return {
        "present": bool(readback.get("ref") or text),
        "required_phrases": not missing,
        "missing_phrases": missing,
    }


def _missing_phrases(text: str) -> list[str]:
    normalized = " ".join(text.lower().replace(",", " ").replace(";", " ").split())
    return [phrase for phrase in REQUIRED_READBACK_PHRASES if phrase not in normalized]
