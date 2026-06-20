from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .store import JsonStore
from .surface_receipt import provider_message_id as _provider_message_id


OUTBOX_STATES = {"queued", "sent", "readback_verified", "deferred", "failed", "ambiguous"}

def build_outbox_item(
    task_run: dict[str, Any],
    *,
    target: str = "discord",
    channel_id: str | None = None,
    endpoint: str | None = None,
    method: str = "POST",
    payload: dict[str, Any] | None = None,
    admission_review_id: str | None = None,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    payload = payload or {}
    now = utc_now()
    key = idempotency_key or stable_id(
        "outidem",
        task_run.get("task_run_id"),
        target,
        channel_id,
        endpoint,
        payload,
    )
    item = {
        "schema_version": "ams.ams.outbox_item.v0",
        "outbox_id": stable_id("outbox", key),
        "task_run_id": task_run.get("task_run_id"),
        "session_id": task_run.get("session_id"),
        "target": target,
        "channel_id": channel_id,
        "endpoint": endpoint,
        "method": method,
        "payload": payload,
        "payload_sha256": sha256_text(canonical_json(payload)),
        "admission_review_id": admission_review_id,
        "idempotency_key": key,
        "nonce": stable_id("nonce", key),
        "state": "queued",
        "attempt_count": 0,
        "created_at": now,
        "updated_at": now,
        "last_receipt_id": None,
    }
    item["outbox_sha256"] = _hash_without(item, "outbox_sha256")
    return item


def build_outbox_receipt(
    outbox_item: dict[str, Any],
    *,
    status: str,
    response_payload: dict[str, Any] | None = None,
    readback_ref: str | None = None,
    reason_codes: list[str] | None = None,
) -> dict[str, Any]:
    if status not in OUTBOX_STATES - {"queued"}:
        raise ValueError(f"invalid outbox receipt status: {status}")
    response_payload = response_payload or {}
    if status in {"sent", "readback_verified"}:
        if not readback_ref or not _provider_message_id(response_payload):
            raise ValueError("sent/readback_verified receipts require readback_ref and provider message id")
    now = utc_now()
    receipt = {
        "schema_version": "ams.ams.outbox_receipt.v0",
        "outbox_receipt_id": stable_id(
            "outrec",
            outbox_item.get("outbox_id"),
            status,
            response_payload,
            readback_ref,
            now,
        ),
        "outbox_id": outbox_item.get("outbox_id"),
        "task_run_id": outbox_item.get("task_run_id"),
        "status": status,
        "attempt": int(outbox_item.get("attempt_count", 0) or 0) + 1,
        "response_payload": response_payload,
        "response_sha256": sha256_text(canonical_json(response_payload)),
        "readback_ref": readback_ref,
        "reason_codes": reason_codes or [],
        "created_at": now,
    }
    receipt["receipt_sha256"] = _hash_without(receipt, "receipt_sha256")
    return receipt


class OutboxStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create_item(
        self,
        task_run_id: str,
        *,
        target: str = "discord",
        channel_id: str | None = None,
        endpoint: str | None = None,
        method: str = "POST",
        payload: dict[str, Any] | None = None,
        admission_review_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            task_run = state.get("task_runs", {}).get(task_run_id)
            if not task_run:
                raise KeyError(f"unknown task_run_id: {task_run_id}")
            if admission_review_id and admission_review_id not in state.get("admission_reviews", {}):
                raise KeyError(f"unknown admission_review_id: {admission_review_id}")
            item = build_outbox_item(
                task_run,
                target=target,
                channel_id=channel_id,
                endpoint=endpoint,
                method=method,
                payload=payload,
                admission_review_id=admission_review_id,
                idempotency_key=idempotency_key,
            )
            state.setdefault("outbox_items", {})[item["outbox_id"]] = item
        return deepcopy(item)

    def record_receipt(
        self,
        outbox_id: str,
        *,
        status: str,
        response_payload: dict[str, Any] | None = None,
        readback_ref: str | None = None,
        reason_codes: list[str] | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            item = state.get("outbox_items", {}).get(outbox_id)
            if not item:
                raise KeyError(f"unknown outbox_id: {outbox_id}")
            receipt = build_outbox_receipt(
                item,
                status=status,
                response_payload=response_payload,
                readback_ref=readback_ref,
                reason_codes=reason_codes,
            )
            item = deepcopy(item)
            item["state"] = status
            item["attempt_count"] = int(item.get("attempt_count", 0) or 0) + 1
            item["last_receipt_id"] = receipt["outbox_receipt_id"]
            item["updated_at"] = receipt["created_at"]
            item["outbox_sha256"] = _hash_without(item, "outbox_sha256")
            state.setdefault("outbox_items", {})[outbox_id] = item
            state.setdefault("outbox_receipts", {})[receipt["outbox_receipt_id"]] = receipt
        return deepcopy(receipt)
