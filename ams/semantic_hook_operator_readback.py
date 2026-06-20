from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from .models import hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .semantic_hook_operator_approval import (
    LIVE_BOUNDARIES,
    REQUIRED_READBACK_PHRASES,
    validate_semantic_hook_operator_approval_packet_record,
)
from .store import JsonStore
from .workspace import repo_root


SCHEMA_VERSION = "ams.ams.semantic_hook_operator_readback_receipt.v0"
STATUSES = {"readback_verified", "blocked"}


class SemanticHookOperatorReadbackReceiptStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        semantic_hook_operator_approval_packet_id: str,
        readback_ref: str,
        readback_text: str,
        requested_by: str = "operator",
        source_root: str | Path | None = None,
        label: str = "manual-semantic-hook-operator-readback",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            packet = (state.get("semantic_hook_operator_approval_packets") or {}).get(
                semantic_hook_operator_approval_packet_id
            )
            if not packet:
                raise KeyError(
                    f"semantic hook operator approval packet not found: {semantic_hook_operator_approval_packet_id}"
                )
            record = build_semantic_hook_operator_readback_receipt(
                packet=packet,
                readback_ref=readback_ref,
                readback_text=readback_text,
                requested_by=requested_by,
                source_root=source_root,
                label=label,
            )
            receipt_id = record["semantic_hook_operator_readback_receipt_id"]
            state.setdefault("semantic_hook_operator_readback_receipts", {})[receipt_id] = record
            state.setdefault("indexes", {}).setdefault("semantic_hook_operator_readback_receipt_ids", {})[
                receipt_id
            ] = receipt_id
            return deepcopy(record)


def build_semantic_hook_operator_readback_receipt(
    *,
    packet: dict[str, Any],
    readback_ref: str,
    readback_text: str,
    requested_by: str = "operator",
    source_root: str | Path | None = None,
    label: str = "manual-semantic-hook-operator-readback",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False) if source_root else repo_root()
    readback = _readback(
        readback_ref=readback_ref,
        readback_text=readback_text,
        requested_by=requested_by,
        now=now,
    )
    required_gates = _required_gates(packet=packet, readback=readback)
    reason_codes = _reason_codes(required_gates)
    status = "readback_verified" if reason_codes == ["semantic_hook_operator_readback.readback_verified"] else "blocked"
    record = {
        "schema_version": SCHEMA_VERSION,
        "semantic_hook_operator_readback_receipt_id": stable_id(
            "semhookreadback",
            label,
            packet.get("semantic_hook_operator_approval_packet_id"),
            packet.get("semantic_hook_operator_approval_packet_sha256"),
            readback.get("readback_text_sha256"),
            now,
        ),
        "label": label,
        "source_root": str(root),
        "semantic_hook_operator_approval_packet_id": packet.get("semantic_hook_operator_approval_packet_id"),
        "semantic_hook_operator_approval_packet_sha256": packet.get(
            "semantic_hook_operator_approval_packet_sha256"
        ),
        "semantic_hook_install_transaction_id": packet.get("semantic_hook_install_transaction_id"),
        "semantic_hook_install_transaction_sha256": packet.get("semantic_hook_install_transaction_sha256"),
        "readback": readback,
        "required_readback_phrases": list(REQUIRED_READBACK_PHRASES),
        "required_gates": required_gates,
        "receipt_verifies_readback_only": True,
        "approval_granted": False,
        "live_install_allowed": False,
        "hook_file_write_allowed": False,
        "hook_trust_allowed": False,
        "provider_hook_execution_allowed": False,
        "backup_write_allowed": False,
        "restore_allowed": False,
        "approval_actions": [],
        "install_actions": [],
        "trust_actions": [],
        "start_actions": [],
        "live_boundaries": dict(LIVE_BOUNDARIES),
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["semantic_hook_operator_readback_receipt_sha256"] = _hash_without(
        record,
        "semantic_hook_operator_readback_receipt_sha256",
    )
    return deepcopy(record)


def validate_semantic_hook_operator_readback_receipt_record(
    record: dict[str, Any],
    *,
    packet: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record(
            "semantic_hook_operator_readback_receipt.schema.json",
            record,
            location="semantic_hook_operator_readback_receipt",
        )
    except SchemaValidationError:
        reason_codes.append("semantic_hook_operator_readback.schema_invalid")
    expected_hash = record.get("semantic_hook_operator_readback_receipt_sha256")
    if expected_hash and expected_hash != _hash_without(record, "semantic_hook_operator_readback_receipt_sha256"):
        reason_codes.append("semantic_hook_operator_readback.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("semantic_hook_operator_readback.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("semantic_hook_operator_readback.status_invalid")
    if record.get("receipt_verifies_readback_only") is not True:
        reason_codes.append("semantic_hook_operator_readback.receipt_verifies_readback_only_not_true")
    for key, expected in LIVE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"semantic_hook_operator_readback.{key}_not_false")
    for key in (
        "approval_granted",
        "live_install_allowed",
        "hook_file_write_allowed",
        "hook_trust_allowed",
        "provider_hook_execution_allowed",
        "backup_write_allowed",
        "restore_allowed",
    ):
        if record.get(key) is not False:
            reason_codes.append(f"semantic_hook_operator_readback.{key}_not_false")
    for key in ("approval_actions", "install_actions", "trust_actions", "start_actions"):
        if record.get(key) != []:
            reason_codes.append(f"semantic_hook_operator_readback.{key}_not_empty")
    readback = record.get("readback") or {}
    if readback.get("raw_readback_stored") is not False:
        reason_codes.append("semantic_hook_operator_readback.raw_readback_stored_not_false")
    if readback.get("readback_text_sha256") != readback.get("normalized_readback_sha256"):
        reason_codes.append("semantic_hook_operator_readback.readback_hash_mismatch")
    phrase_results = readback.get("phrase_results") or []
    present_by_phrase = {row.get("phrase"): row.get("present") for row in phrase_results}
    missing = [phrase for phrase in REQUIRED_READBACK_PHRASES if present_by_phrase.get(phrase) is not True]
    if record.get("required_readback_phrases") != REQUIRED_READBACK_PHRASES:
        reason_codes.append("semantic_hook_operator_readback.required_readback_phrases_mismatch")
    if missing != readback.get("missing_required_phrases"):
        reason_codes.append("semantic_hook_operator_readback.missing_required_phrases_mismatch")
    if packet is not None:
        if record.get("semantic_hook_operator_approval_packet_sha256") != packet.get(
            "semantic_hook_operator_approval_packet_sha256"
        ):
            reason_codes.append("semantic_hook_operator_readback.packet_hash_mismatch")
        packet_validation = validate_semantic_hook_operator_approval_packet_record(packet)
        if not packet_validation["ok"]:
            reason_codes.extend(
                f"semantic_hook_operator_readback.packet:{reason}"
                for reason in packet_validation["reason_codes"]
            )
    required_gates = _required_gates(packet=packet or {}, readback=readback)
    if record.get("required_gates") != required_gates:
        reason_codes.append("semantic_hook_operator_readback.required_gates_mismatch")
    expected_status = (
        "readback_verified"
        if _reason_codes(required_gates) == ["semantic_hook_operator_readback.readback_verified"]
        else "blocked"
    )
    if record.get("status") != expected_status:
        reason_codes.append("semantic_hook_operator_readback.status_reason_mismatch")
    if sorted(record.get("reason_codes") or []) != sorted(_reason_codes(required_gates)):
        reason_codes.append("semantic_hook_operator_readback.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _readback(
    *,
    readback_ref: str,
    readback_text: str,
    requested_by: str,
    now: str,
) -> dict[str, Any]:
    normalized = _normalize(readback_text)
    phrase_results = [
        {
            "phrase": phrase,
            "present": phrase in normalized,
            "evidence_sha256": sha256_text(phrase if phrase in normalized else ""),
        }
        for phrase in REQUIRED_READBACK_PHRASES
    ]
    missing = [row["phrase"] for row in phrase_results if not row["present"]]
    return {
        "requested_by": requested_by,
        "readback_ref": readback_ref,
        "readback_present": bool(readback_ref and readback_text),
        "readback_text_sha256": sha256_text(normalized),
        "normalized_readback_sha256": sha256_text(normalized),
        "raw_readback_stored": False,
        "phrase_results": phrase_results,
        "required_phrases_present": not missing,
        "missing_required_phrases": missing,
        "created_at": now,
    }


def _required_gates(*, packet: dict[str, Any], readback: dict[str, Any]) -> dict[str, bool]:
    packet_validation = validate_semantic_hook_operator_approval_packet_record(packet) if packet else {
        "ok": False,
        "reason_codes": ["missing"],
    }
    return {
        "operator_packet_present": bool(packet),
        "operator_packet_ready": packet.get("status") == "ready_for_operator_review",
        "operator_packet_hash_current": packet_validation["ok"],
        "operator_packet_grants_no_authority": packet.get("approval_granted") is False
        and packet.get("live_install_allowed") is False
        and packet.get("hook_file_write_allowed") is False
        and packet.get("hook_trust_allowed") is False
        and packet.get("provider_hook_execution_allowed") is False,
        "readback_ref_present": bool(readback.get("readback_ref")),
        "readback_present": readback.get("readback_present") is True,
        "required_phrases_present": readback.get("required_phrases_present") is True,
        "raw_readback_not_stored": readback.get("raw_readback_stored") is False,
        "receipt_grants_no_authority": True,
    }


def _reason_codes(gates: dict[str, bool]) -> list[str]:
    reasons = [f"semantic_hook_operator_readback.{key}_missing" for key, ok in gates.items() if not ok]
    return sorted(set(reasons)) or ["semantic_hook_operator_readback.readback_verified"]


def _normalize(text: str) -> str:
    return " ".join(text.lower().replace(",", " ").replace(";", " ").replace(".", " ").split())
