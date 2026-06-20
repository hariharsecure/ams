from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .store import JsonStore


SCHEMA_VERSION = "ams.ams_codex.discord_canary_send_plan.v0"
STATUSES = {"ready_for_operator_approval", "blocked"}


class DiscordCanarySendPlanStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        outbox_id: str,
        admission_review_id: str,
        surface_promise_id: str | None = None,
        discord_source_packet_id: str | None = None,
        operator_review_ref: str | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            record = build_discord_canary_send_plan(
                state,
                outbox_id=outbox_id,
                admission_review_id=admission_review_id,
                surface_promise_id=surface_promise_id,
                discord_source_packet_id=discord_source_packet_id,
                operator_review_ref=operator_review_ref,
            )
            validation = validate_discord_canary_send_plan_record(record, state=state)
            if not validation["ok"]:
                raise ValueError("; ".join(validation["reason_codes"]))
            plan_id = record["discord_canary_send_plan_id"]
            state.setdefault("discord_canary_send_plans", {})[plan_id] = record
            state.setdefault("indexes", {}).setdefault("discord_canary_send_plan_ids", {})[plan_id] = plan_id
        return deepcopy(record)


def build_discord_canary_send_plan(
    state: dict[str, Any],
    *,
    outbox_id: str,
    admission_review_id: str,
    surface_promise_id: str | None = None,
    discord_source_packet_id: str | None = None,
    operator_review_ref: str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    outbox = (state.get("outbox_items") or {}).get(outbox_id) or {}
    admission = (state.get("admission_reviews") or {}).get(admission_review_id) or {}
    promise = (state.get("surface_promises") or {}).get(surface_promise_id or "") or {}
    source = (state.get("discord_source_packets") or {}).get(discord_source_packet_id or "") or {}
    evaluation = _evaluate(
        outbox=outbox,
        admission=admission,
        promise=promise,
        source=source,
        surface_promise_id=surface_promise_id,
        discord_source_packet_id=discord_source_packet_id,
    )
    channel_id = outbox.get("channel_id")
    record = {
        "schema_version": SCHEMA_VERSION,
        "discord_canary_send_plan_id": stable_id(
            "disccanary",
            outbox_id,
            admission_review_id,
            surface_promise_id,
            discord_source_packet_id,
            operator_review_ref,
            now,
        ),
        "mode": "canary",
        "outbox_id": outbox_id,
        "outbox_sha256": outbox.get("outbox_sha256"),
        "admission_review_id": admission_review_id,
        "admission_review_sha256": admission.get("review_sha256"),
        "surface_promise_id": surface_promise_id,
        "surface_promise_sha256": promise.get("surface_promise_sha256"),
        "discord_source_packet_id": discord_source_packet_id,
        "discord_source_packet_sha256": source.get("source_packet_sha256"),
        "task_run_id": outbox.get("task_run_id"),
        "session_id": outbox.get("session_id"),
        "target": outbox.get("target"),
        "channel_id": channel_id,
        "endpoint": outbox.get("endpoint"),
        "method": outbox.get("method"),
        "payload_sha256": outbox.get("payload_sha256"),
        "outbox_nonce": outbox.get("nonce"),
        "nonce_semantics": "provider_validation_only",
        "exactly_once_claimed": False,
        "canary_mode": True,
        "network_call_allowed": False,
        "send_performed": False,
        "gateway_started": False,
        "token_stored": False,
        "readback_required": True,
        "expected_readback": {
            "provider": "discord",
            "status": "readback_verified",
            "required_provider_message_id": True,
            "required_readback_ref_prefix": f"discord://{channel_id}/" if channel_id else None,
            "nonce_must_match": True,
            "nonce_is_provider_validation_only": True,
        },
        "operator_review_ref": operator_review_ref,
        "required_gates": evaluation["required_gates"],
        "status": evaluation["status"],
        "reason_codes": evaluation["reason_codes"],
        "created_at": now,
    }
    record["canary_send_plan_sha256"] = _hash_without(record, "canary_send_plan_sha256")
    return deepcopy(record)


def validate_discord_canary_send_plan_record(
    record: dict[str, Any],
    *,
    state: dict[str, Any],
) -> dict[str, Any]:
    reason_codes: list[str] = []
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("discord_canary.schema_version_invalid")
    expected_hash = record.get("canary_send_plan_sha256")
    if expected_hash and expected_hash != _hash_without(record, "canary_send_plan_sha256"):
        reason_codes.append("discord_canary.hash_mismatch")
    for key in ("canary_mode", "readback_required"):
        if record.get(key) is not True:
            reason_codes.append(f"discord_canary.{key}_not_true")
    for key in ("network_call_allowed", "send_performed", "gateway_started", "token_stored", "exactly_once_claimed"):
        if record.get(key) is not False:
            reason_codes.append(f"discord_canary.{key}_not_false")
    if record.get("nonce_semantics") != "provider_validation_only":
        reason_codes.append("discord_canary.nonce_semantics_invalid")

    outbox = (state.get("outbox_items") or {}).get(record.get("outbox_id")) or {}
    admission = (state.get("admission_reviews") or {}).get(record.get("admission_review_id")) or {}
    promise = (state.get("surface_promises") or {}).get(record.get("surface_promise_id") or "") or {}
    source = (state.get("discord_source_packets") or {}).get(record.get("discord_source_packet_id") or "") or {}
    verified_by_receipt = _verified_by_recorded_receipt(record, outbox, state)
    if record.get("outbox_sha256") != outbox.get("outbox_sha256") and not verified_by_receipt:
        reason_codes.append("discord_canary.outbox_hash_mismatch")
    if record.get("admission_review_sha256") != admission.get("review_sha256"):
        reason_codes.append("discord_canary.admission_hash_mismatch")
    if (
        record.get("surface_promise_id")
        and record.get("surface_promise_sha256") != promise.get("surface_promise_sha256")
        and not verified_by_receipt
    ):
        reason_codes.append("discord_canary.surface_promise_hash_mismatch")
    if record.get("discord_source_packet_id") and record.get("discord_source_packet_sha256") != source.get("source_packet_sha256"):
        reason_codes.append("discord_canary.source_packet_hash_mismatch")
    evaluation_outbox = deepcopy(outbox)
    if verified_by_receipt:
        evaluation_outbox["state"] = "queued"
    evaluation = _evaluate(
        outbox=evaluation_outbox,
        admission=admission,
        promise=promise,
        source=source,
        surface_promise_id=record.get("surface_promise_id"),
        discord_source_packet_id=record.get("discord_source_packet_id"),
    )
    if record.get("required_gates") != evaluation["required_gates"]:
        reason_codes.append("discord_canary.required_gates_mismatch")
    if record.get("status") != evaluation["status"]:
        reason_codes.append("discord_canary.status_reason_mismatch")
    if sorted(record.get("reason_codes") or []) != sorted(evaluation["reason_codes"]):
        reason_codes.append("discord_canary.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _evaluate(
    *,
    outbox: dict[str, Any],
    admission: dict[str, Any],
    promise: dict[str, Any],
    source: dict[str, Any],
    surface_promise_id: str | None,
    discord_source_packet_id: str | None,
) -> dict[str, Any]:
    response = admission.get("response") or {}
    promised_outbox_ids = [
        item.get("outbox_id")
        for item in promise.get("promised_surfaces") or []
        if item.get("target") == "discord" or item.get("surface") == "discord"
    ]
    required_gates = {
        "outbox_exists": bool(outbox),
        "outbox_target_discord": outbox.get("target") == "discord",
        "outbox_queued": outbox.get("state") == "queued",
        "outbox_method_post": outbox.get("method") == "POST",
        "outbox_channel_present": bool(outbox.get("channel_id")),
        "outbox_endpoint_present": bool(outbox.get("endpoint")),
        "outbox_nonce_present": bool(outbox.get("nonce")),
        "admission_exists": bool(admission),
        "admission_allows_canary": response.get("allowed") is True
        and admission.get("operation") in {"egress.discord.canary_send", "egress.discord"},
        "surface_promise_matches_outbox": not surface_promise_id or outbox.get("outbox_id") in promised_outbox_ids,
        "source_packet_read_only": not discord_source_packet_id
        or (
            source.get("read_only") is True
            and source.get("send_allowed") is False
            and source.get("raw_content_stored") is False
            and source.get("token_stored") is False
        ),
        "network_call_allowed_false": True,
        "send_performed_false": True,
        "nonce_provider_validation_only": True,
        "exactly_once_not_claimed": True,
        "readback_required": True,
    }
    reasons = [f"discord_canary.{key}_missing" for key, ok in required_gates.items() if not ok]
    status = "ready_for_operator_approval" if not reasons else "blocked"
    return {
        "status": status,
        "reason_codes": reasons or ["discord_canary.ready_for_operator_approval"],
        "required_gates": required_gates,
    }


def _verified_by_recorded_receipt(
    record: dict[str, Any],
    outbox: dict[str, Any],
    state: dict[str, Any],
) -> bool:
    if not outbox or outbox.get("state") != "readback_verified":
        return False
    for receipt in (state.get("discord_canary_receipts") or {}).values():
        if receipt.get("discord_canary_send_plan_id") != record.get("discord_canary_send_plan_id"):
            continue
        if receipt.get("discord_canary_send_plan_sha256") != record.get("canary_send_plan_sha256"):
            continue
        if receipt.get("status") != "recorded":
            continue
        if receipt.get("outbox_id") != record.get("outbox_id"):
            continue
        if receipt.get("outbox_sha256") != outbox.get("outbox_sha256"):
            continue
        if receipt.get("outbox_receipt_id") != outbox.get("last_receipt_id"):
            continue
        if receipt.get("network_call_performed") is not False or receipt.get("token_stored") is not False:
            continue
        if receipt.get("raw_content_stored") is not False or receipt.get("exactly_once_claimed") is not False:
            continue
        if receipt.get("nonce_match") is not True:
            continue
        outbox_receipt = (state.get("outbox_receipts") or {}).get(receipt.get("outbox_receipt_id")) or {}
        if outbox_receipt.get("receipt_sha256") != receipt.get("outbox_receipt_sha256"):
            continue
        if outbox_receipt.get("outbox_id") != record.get("outbox_id"):
            continue
        if outbox_receipt.get("status") != "readback_verified":
            continue
        return True
    return False
