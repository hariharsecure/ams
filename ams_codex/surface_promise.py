from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .store import JsonStore
from .surface_receipt import provider_message_id as _provider_message_id


ACCEPTABLE_DELIVERY_STATUSES = {
    "delivered_and_readback_verified",
    "not_required_by_packet",
    "blocked_with_reason_and_deferred",
}

def build_surface_promise(
    task_run: dict[str, Any],
    *,
    promised_surfaces: list[dict[str, Any]],
    source_packet_ref: str | None = None,
    promise_reason: str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    normalized = [_normalize_promised_surface(item) for item in promised_surfaces]
    record = {
        "schema_version": "ams.ams_codex.surface_promise.v0",
        "surface_promise_id": stable_id(
            "surfprom",
            task_run.get("task_run_id"),
            normalized,
            source_packet_ref,
        ),
        "task_run_id": task_run.get("task_run_id"),
        "session_id": task_run.get("session_id"),
        "source_packet_ref": source_packet_ref,
        "promise_reason": promise_reason,
        "promised_surfaces": normalized,
        "surface_delivery_status": "pending",
        "evaluation": _empty_evaluation(),
        "created_at": now,
        "updated_at": now,
    }
    record["surface_promise_sha256"] = _hash_without(record, "surface_promise_sha256")
    return record


def evaluate_surface_promise_record(record: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    promised = list(record.get("promised_surfaces") or [])
    required = [item for item in promised if item.get("required", True)]
    if not required:
        return {
            "surface_delivery_status": "not_required_by_packet",
            "evaluation": {
                **_empty_evaluation(),
                "promised_surfaces": len(promised),
                "required_readbacks": 0,
            },
        }

    outbox_items = state.get("outbox_items") or {}
    outbox_receipts = state.get("outbox_receipts") or {}
    delivered: list[str] = []
    deferred: list[str] = []
    pending: list[str] = []
    missing: list[str] = []
    readback_missing: list[str] = []
    failed: list[str] = []
    ambiguous: list[str] = []

    for item in required:
        outbox_item = _find_outbox_item(item, record, outbox_items)
        label = _promise_label(item)
        if not outbox_item:
            missing.append(label)
            continue

        receipt = _last_receipt(outbox_item, outbox_receipts)
        state_name = str(outbox_item.get("state") or "")
        if state_name == "readback_verified":
            if _receipt_has_readback(receipt):
                delivered.append(label)
            else:
                readback_missing.append(label)
        elif state_name == "sent":
            if item.get("required_readback", True):
                readback_missing.append(label)
            else:
                delivered.append(label)
        elif state_name == "deferred":
            if receipt and receipt.get("reason_codes"):
                deferred.append(label)
            else:
                readback_missing.append(label)
        elif state_name == "queued":
            pending.append(label)
        elif state_name == "failed":
            failed.append(label)
        elif state_name == "ambiguous":
            ambiguous.append(label)
        else:
            failed.append(label)

    if missing or readback_missing or failed or ambiguous:
        surface_delivery_status = "surface_promise_mismatch"
    elif pending:
        surface_delivery_status = "pending"
    elif deferred:
        surface_delivery_status = "blocked_with_reason_and_deferred"
    else:
        surface_delivery_status = "delivered_and_readback_verified"

    evaluation = {
        "promised_surfaces": len(promised),
        "required_readbacks": sum(1 for item in required if item.get("required_readback", True)),
        "observed_surfaces": len(delivered) + len(deferred),
        "surface_promise_mismatch_count": len(missing) + len(readback_missing) + len(failed) + len(ambiguous),
        "postproof_required_surface_missing_count": len(missing),
        "readback_required_but_missing_count": len(readback_missing),
        "pending_count": len(pending),
        "deferred_count": len(deferred),
        "failed_count": len(failed),
        "ambiguous_count": len(ambiguous),
        "delivered": delivered,
        "deferred": deferred,
        "pending": pending,
        "missing": missing,
        "readback_missing": readback_missing,
        "failed": failed,
        "ambiguous": ambiguous,
    }
    return {
        "surface_delivery_status": surface_delivery_status,
        "evaluation": evaluation,
    }


def validate_surface_promise_record(record: dict[str, Any], *, state: dict[str, Any] | None = None) -> dict[str, Any]:
    reason_codes: list[str] = []
    expected_hash = record.get("surface_promise_sha256")
    if expected_hash and expected_hash != _hash_without(record, "surface_promise_sha256"):
        reason_codes.append("surface_promise.hash_mismatch")

    if state is not None:
        task_run = (state.get("task_runs") or {}).get(record.get("task_run_id"))
        if not task_run:
            reason_codes.append(f"surface_promise.task_run_missing:{record.get('task_run_id')}")
        elif task_run.get("session_id") != record.get("session_id"):
            reason_codes.append("surface_promise.session_mismatch")
        result = evaluate_surface_promise_record(record, state)
        if result["surface_delivery_status"] != record.get("surface_delivery_status"):
            reason_codes.append("surface_promise.status_stale")
        if result["evaluation"] != record.get("evaluation"):
            reason_codes.append("surface_promise.evaluation_stale")
        if task_run and task_run.get("state") in {"completed", "verified"}:
            if record.get("surface_delivery_status") not in ACCEPTABLE_DELIVERY_STATUSES:
                reason_codes.append("surface_promise.terminal_task_missing_surface_delivery")
    return {"ok": not reason_codes, "reason_codes": reason_codes}


class SurfacePromiseStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        task_run_id: str,
        *,
        promised_surfaces: list[dict[str, Any]],
        source_packet_ref: str | None = None,
        promise_reason: str | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            task_run = (state.get("task_runs") or {}).get(task_run_id)
            if not task_run:
                raise KeyError(f"unknown task_run_id: {task_run_id}")
            record = build_surface_promise(
                task_run,
                promised_surfaces=promised_surfaces,
                source_packet_ref=source_packet_ref,
                promise_reason=promise_reason,
            )
            result = evaluate_surface_promise_record(record, state)
            record["surface_delivery_status"] = result["surface_delivery_status"]
            record["evaluation"] = result["evaluation"]
            record["updated_at"] = utc_now()
            record["surface_promise_sha256"] = _hash_without(record, "surface_promise_sha256")
            state.setdefault("surface_promises", {})[record["surface_promise_id"]] = record
            return deepcopy(record)

    def check(self, surface_promise_id: str) -> dict[str, Any]:
        with self.store.locked() as state:
            record = (state.get("surface_promises") or {}).get(surface_promise_id)
            if not record:
                raise KeyError(f"unknown surface_promise_id: {surface_promise_id}")
            updated = deepcopy(record)
            result = evaluate_surface_promise_record(updated, state)
            updated["surface_delivery_status"] = result["surface_delivery_status"]
            updated["evaluation"] = result["evaluation"]
            updated["updated_at"] = utc_now()
            updated["surface_promise_sha256"] = _hash_without(updated, "surface_promise_sha256")
            state["surface_promises"][surface_promise_id] = updated
            return deepcopy(updated)


def _empty_evaluation() -> dict[str, Any]:
    return {
        "promised_surfaces": 0,
        "required_readbacks": 0,
        "observed_surfaces": 0,
        "surface_promise_mismatch_count": 0,
        "postproof_required_surface_missing_count": 0,
        "readback_required_but_missing_count": 0,
        "pending_count": 0,
        "deferred_count": 0,
        "failed_count": 0,
        "ambiguous_count": 0,
        "delivered": [],
        "deferred": [],
        "pending": [],
        "missing": [],
        "readback_missing": [],
        "failed": [],
        "ambiguous": [],
    }


def _normalize_promised_surface(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "surface": str(item.get("surface") or "discord"),
        "target": str(item.get("target") or "discord"),
        "channel_id": item.get("channel_id"),
        "outbox_id": item.get("outbox_id"),
        "required": bool(item.get("required", True)),
        "required_readback": bool(item.get("required_readback", True)),
    }


def _promise_label(item: dict[str, Any]) -> str:
    parts = [str(item.get("surface") or ""), str(item.get("target") or "")]
    if item.get("channel_id"):
        parts.append(str(item["channel_id"]))
    if item.get("outbox_id"):
        parts.append(str(item["outbox_id"]))
    return ":".join(parts)


def _find_outbox_item(
    promised_surface: dict[str, Any],
    promise: dict[str, Any],
    outbox_items: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    outbox_id = promised_surface.get("outbox_id")
    if outbox_id:
        return outbox_items.get(outbox_id)
    candidates = [
        item for item in outbox_items.values()
        if item.get("task_run_id") == promise.get("task_run_id")
        and item.get("target") == promised_surface.get("target")
        and (
            not promised_surface.get("channel_id")
            or item.get("channel_id") == promised_surface.get("channel_id")
        )
    ]
    candidates.sort(key=lambda item: str(item.get("created_at") or ""))
    return candidates[-1] if candidates else None


def _last_receipt(outbox_item: dict[str, Any], outbox_receipts: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    last_receipt_id = outbox_item.get("last_receipt_id")
    if last_receipt_id:
        return outbox_receipts.get(last_receipt_id)
    matches = [
        receipt for receipt in outbox_receipts.values()
        if receipt.get("outbox_id") == outbox_item.get("outbox_id")
    ]
    matches.sort(key=lambda item: str(item.get("created_at") or ""))
    return matches[-1] if matches else None


def _receipt_has_readback(receipt: dict[str, Any] | None) -> bool:
    if not receipt:
        return False
    return bool(receipt.get("readback_ref")) and bool(_provider_message_id(receipt.get("response_payload") or {}))
