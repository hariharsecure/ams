from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .outbox import build_outbox_receipt
from .store import JsonStore
from .surface_receipt import provider_message_id as _provider_message_id
from .surface_promise import evaluate_surface_promise_record, _hash_without as surface_promise_hash_without


SCHEMA_VERSION = "ams.ams_codex.discord_canary_receipt.v0"
STATUSES = {"recorded", "blocked"}
OBSERVATION_MODES = {"external_observed", "operator_supplied", "simulated_success"}


class DiscordCanaryReceiptStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        discord_canary_send_plan_id: str,
        response_payload: dict[str, Any],
        readback_ref: str,
        observed_nonce: str | None = None,
        observation_mode: str = "external_observed",
    ) -> dict[str, Any]:
        if observation_mode not in OBSERVATION_MODES:
            raise ValueError(f"invalid observation_mode: {observation_mode}")
        with self.store.locked() as state:
            plan = (state.get("discord_canary_send_plans") or {}).get(discord_canary_send_plan_id) or {}
            outbox = (state.get("outbox_items") or {}).get(plan.get("outbox_id")) or {}
            preview = build_discord_canary_receipt(
                state,
                plan=plan,
                outbox=outbox,
                response_payload=response_payload,
                readback_ref=readback_ref,
                observed_nonce=observed_nonce,
                observation_mode=observation_mode,
                require_outbox_receipt=False,
            )
            if preview["status"] == "recorded":
                receipt = build_outbox_receipt(
                    outbox,
                    status="readback_verified",
                    response_payload=response_payload,
                    readback_ref=readback_ref,
                    reason_codes=[f"discord_canary_receipt.{observation_mode}"],
                )
                outbox = deepcopy(outbox)
                outbox["state"] = "readback_verified"
                outbox["attempt_count"] = int(outbox.get("attempt_count", 0) or 0) + 1
                outbox["last_receipt_id"] = receipt["outbox_receipt_id"]
                outbox["updated_at"] = receipt["created_at"]
                outbox["outbox_sha256"] = _hash_without(outbox, "outbox_sha256")
                state.setdefault("outbox_items", {})[outbox["outbox_id"]] = outbox
                state.setdefault("outbox_receipts", {})[receipt["outbox_receipt_id"]] = receipt
                _refresh_surface_promise(state, plan.get("surface_promise_id"))
                record = build_discord_canary_receipt(
                    state,
                    plan=plan,
                    outbox=outbox,
                    response_payload=response_payload,
                    readback_ref=readback_ref,
                    observed_nonce=observed_nonce,
                    observation_mode=observation_mode,
                    outbox_receipt=receipt,
                )
            else:
                record = preview

            validation = validate_discord_canary_receipt_record(record, state=state)
            if not validation["ok"]:
                raise ValueError("; ".join(validation["reason_codes"]))
            receipt_id = record["discord_canary_receipt_id"]
            state.setdefault("discord_canary_receipts", {})[receipt_id] = record
            state.setdefault("indexes", {}).setdefault("discord_canary_receipt_ids", {})[receipt_id] = receipt_id
        return deepcopy(record)


def build_discord_canary_receipt(
    state: dict[str, Any],
    *,
    plan: dict[str, Any],
    outbox: dict[str, Any],
    response_payload: dict[str, Any],
    readback_ref: str,
    observed_nonce: str | None,
    observation_mode: str,
    outbox_receipt: dict[str, Any] | None = None,
    require_outbox_receipt: bool = True,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    expected = plan.get("expected_readback") or {}
    provider_message_id = _provider_message_id(response_payload)
    response_sha256 = sha256_text(canonical_json(response_payload))
    expected_nonce = plan.get("outbox_nonce")
    nonce_match = bool(expected_nonce and observed_nonce == expected_nonce)
    readback_prefix = expected.get("required_readback_ref_prefix")
    readback_ref_matches = bool(readback_ref and (not readback_prefix or readback_ref.startswith(readback_prefix)))
    gates = {
        "plan_exists": bool(plan),
        "plan_ready": plan.get("status") == "ready_for_operator_approval",
        "plan_no_network_call": plan.get("network_call_allowed") is False,
        "plan_no_send_performed": plan.get("send_performed") is False,
        "outbox_exists": bool(outbox),
        "outbox_matches_plan": bool(outbox) and outbox.get("outbox_id") == plan.get("outbox_id"),
        "provider_message_id_present": bool(provider_message_id),
        "readback_ref_matches_expected_prefix": readback_ref_matches,
        "nonce_matches_plan": nonce_match,
        "nonce_provider_validation_only": plan.get("nonce_semantics") == "provider_validation_only",
        "exactly_once_not_claimed": plan.get("exactly_once_claimed") is False,
        "network_call_performed_false": True,
        "token_stored_false": True,
        "raw_content_stored_false": True,
    }
    core_valid = all(gates.values())
    gates["outbox_receipt_recorded_when_valid"] = (
        bool(outbox_receipt) if require_outbox_receipt and core_valid else True
    )
    reasons = [f"discord_canary_receipt.{key}_missing" for key, ok in gates.items() if not ok]
    status = "recorded" if not reasons else "blocked"
    record = {
        "schema_version": SCHEMA_VERSION,
        "discord_canary_receipt_id": stable_id(
            "disccanaryrec",
            plan.get("discord_canary_send_plan_id"),
            response_sha256,
            readback_ref,
            observed_nonce,
            observation_mode,
            now,
        ),
        "discord_canary_send_plan_id": plan.get("discord_canary_send_plan_id"),
        "discord_canary_send_plan_sha256": plan.get("canary_send_plan_sha256"),
        "outbox_id": plan.get("outbox_id"),
        "outbox_sha256": outbox.get("outbox_sha256"),
        "outbox_receipt_id": (outbox_receipt or {}).get("outbox_receipt_id"),
        "outbox_receipt_sha256": (outbox_receipt or {}).get("receipt_sha256"),
        "observation_mode": observation_mode,
        "provider": "discord",
        "response_payload_sha256": response_sha256,
        "provider_message_id": provider_message_id,
        "readback_ref": readback_ref,
        "expected_nonce": expected_nonce,
        "observed_nonce_sha256": sha256_text(observed_nonce or ""),
        "nonce_match": nonce_match,
        "nonce_semantics": "provider_validation_only",
        "exactly_once_claimed": False,
        "network_call_performed": False,
        "token_stored": False,
        "raw_content_stored": False,
        "required_gates": gates,
        "status": status,
        "reason_codes": reasons or ["discord_canary_receipt.recorded"],
        "created_at": now,
    }
    record["canary_receipt_sha256"] = _hash_without(record, "canary_receipt_sha256")
    return deepcopy(record)


def validate_discord_canary_receipt_record(record: dict[str, Any], *, state: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("discord_canary_receipt.schema_version_invalid")
    expected_hash = record.get("canary_receipt_sha256")
    if expected_hash and expected_hash != _hash_without(record, "canary_receipt_sha256"):
        reason_codes.append("discord_canary_receipt.hash_mismatch")
    if record.get("status") not in STATUSES:
        reason_codes.append("discord_canary_receipt.status_invalid")
    if record.get("observation_mode") not in OBSERVATION_MODES:
        reason_codes.append("discord_canary_receipt.observation_mode_invalid")
    for key in ("network_call_performed", "token_stored", "raw_content_stored", "exactly_once_claimed"):
        if record.get(key) is not False:
            reason_codes.append(f"discord_canary_receipt.{key}_not_false")
    if record.get("nonce_semantics") != "provider_validation_only":
        reason_codes.append("discord_canary_receipt.nonce_semantics_invalid")
    if record.get("nonce_match") is not True and record.get("status") == "recorded":
        reason_codes.append("discord_canary_receipt.recorded_without_nonce_match")
    if record.get("status") == "recorded" and not record.get("outbox_receipt_id"):
        reason_codes.append("discord_canary_receipt.recorded_without_outbox_receipt")

    plan = (state.get("discord_canary_send_plans") or {}).get(record.get("discord_canary_send_plan_id")) or {}
    outbox = (state.get("outbox_items") or {}).get(record.get("outbox_id")) or {}
    outbox_receipt = (state.get("outbox_receipts") or {}).get(record.get("outbox_receipt_id") or "") or {}
    if record.get("discord_canary_send_plan_sha256") != plan.get("canary_send_plan_sha256"):
        reason_codes.append("discord_canary_receipt.plan_hash_mismatch")
    if record.get("outbox_sha256") != outbox.get("outbox_sha256"):
        reason_codes.append("discord_canary_receipt.outbox_hash_mismatch")
    if record.get("outbox_receipt_id"):
        if record.get("outbox_receipt_sha256") != outbox_receipt.get("receipt_sha256"):
            reason_codes.append("discord_canary_receipt.outbox_receipt_hash_mismatch")
        response_sha256 = sha256_text(canonical_json(outbox_receipt.get("response_payload") or {}))
        if record.get("response_payload_sha256") != response_sha256:
            reason_codes.append("discord_canary_receipt.response_payload_hash_mismatch")
        if outbox_receipt.get("status") != "readback_verified":
            reason_codes.append("discord_canary_receipt.outbox_receipt_status_invalid")
        if outbox_receipt.get("readback_ref") != record.get("readback_ref"):
            reason_codes.append("discord_canary_receipt.outbox_receipt_readback_mismatch")
        if _provider_message_id(outbox_receipt.get("response_payload") or {}) != record.get("provider_message_id"):
            reason_codes.append("discord_canary_receipt.outbox_receipt_provider_message_id_mismatch")
    if record.get("expected_nonce") != plan.get("outbox_nonce"):
        reason_codes.append("discord_canary_receipt.expected_nonce_mismatch")
    if record.get("nonce_match") is True and record.get("observed_nonce_sha256") != sha256_text(record.get("expected_nonce") or ""):
        reason_codes.append("discord_canary_receipt.observed_nonce_hash_mismatch")

    expected = build_discord_canary_receipt(
        state,
        plan=plan,
        outbox=outbox,
        response_payload=outbox_receipt.get("response_payload") or {},
        readback_ref=record.get("readback_ref") or "",
        observed_nonce=record.get("expected_nonce") if record.get("nonce_match") else None,
        observation_mode=record.get("observation_mode") or "external_observed",
        outbox_receipt=outbox_receipt or None,
        now=record.get("created_at"),
    )
    if record.get("outbox_receipt_id"):
        for key in ("required_gates", "status", "reason_codes"):
            if record.get(key) != expected[key]:
                reason_codes.append(f"discord_canary_receipt.{key}_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _refresh_surface_promise(state: dict[str, Any], surface_promise_id: str | None) -> None:
    if not surface_promise_id:
        return
    promise = (state.get("surface_promises") or {}).get(surface_promise_id)
    if not promise:
        return
    updated = deepcopy(promise)
    result = evaluate_surface_promise_record(updated, state)
    updated["surface_delivery_status"] = result["surface_delivery_status"]
    updated["evaluation"] = result["evaluation"]
    updated["updated_at"] = utc_now()
    updated["surface_promise_sha256"] = surface_promise_hash_without(updated, "surface_promise_sha256")
    state["surface_promises"][surface_promise_id] = updated
