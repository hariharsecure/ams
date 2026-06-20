from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from .doc_action_patch_preview import LIVE_BOUNDARIES as PATCH_PREVIEW_LIVE_BOUNDARIES
from .doc_action_patch_preview import validate_doc_action_patch_preview_record
from .models import hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore
from .workspace import repo_root


SCHEMA_VERSION = "ams.ams.doc_action_patch_readback_receipt.v0"
STATUSES = {"readback_verified", "blocked"}

REQUIRED_READBACK_PHRASES = [
    "i reviewed the doc action patch preview",
    "literal patches remain disabled",
    "source doc writes remain disabled",
    "source doc moves remain disabled",
    "source doc archives remain disabled",
    "generated surface rewrites remain disabled",
    "a later explicit approval is required",
]

LIVE_BOUNDARIES = {
    "approval_granted": False,
    "source_file_rewritten": False,
    "source_file_deleted": False,
    "source_file_moved": False,
    "archive_created": False,
    "generated_surface_rewritten": False,
    "preview_artifact_written": False,
    "raw_patch_stored": False,
    "raw_source_markdown_stored": False,
    "raw_readback_stored": False,
    "discord_call_performed": False,
    "terminal_attach_performed": False,
    "terminal_capture_performed": False,
    "terminal_injection_performed": False,
    "persistent_process_started": False,
    "provider_call_performed": False,
    "network_call_performed": False,
    "secret_stored": False,
}

AUTHORITY_FALSE_FIELDS = (
    "approval_granted",
    "live_execution_allowed",
    "source_file_write_allowed",
    "source_file_move_allowed",
    "source_file_delete_allowed",
    "archive_create_allowed",
    "generated_surface_rewrite_allowed",
    "literal_patch_store_allowed",
    "preview_artifact_write_allowed",
    "provider_call_allowed",
    "network_call_allowed",
)

EMPTY_ACTION_FIELDS = ("approval_actions", "execution_actions", "patch_actions")


class DocActionPatchReadbackReceiptStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        doc_action_patch_preview_id: str,
        readback_ref: str,
        readback_text: str,
        requested_by: str = "operator",
        source_root: str | Path | None = None,
        label: str = "manual-doc-action-patch-readback",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            patch_preview = (state.get("doc_action_patch_previews") or {}).get(doc_action_patch_preview_id)
            if not patch_preview:
                raise KeyError(f"doc action patch preview not found: {doc_action_patch_preview_id}")
            approval_packet = (state.get("doc_action_operator_approval_packets") or {}).get(
                patch_preview.get("doc_action_operator_approval_packet_id")
            )
            if not approval_packet:
                raise KeyError(
                    "doc action operator approval packet not found: "
                    f"{patch_preview.get('doc_action_operator_approval_packet_id')}"
                )
            execution_plan = (state.get("doc_action_execution_plans") or {}).get(
                patch_preview.get("doc_action_execution_plan_id")
            )
            if not execution_plan:
                raise KeyError(f"doc action execution plan not found: {patch_preview.get('doc_action_execution_plan_id')}")
            record = build_doc_action_patch_readback_receipt(
                patch_preview=patch_preview,
                approval_packet=approval_packet,
                execution_plan=execution_plan,
                readback_ref=readback_ref,
                readback_text=readback_text,
                requested_by=requested_by,
                source_root=source_root,
                label=label,
            )
            receipt_id = record["doc_action_patch_readback_receipt_id"]
            state.setdefault("doc_action_patch_readback_receipts", {})[receipt_id] = record
            state.setdefault("indexes", {}).setdefault("doc_action_patch_readback_receipt_ids", {})[
                receipt_id
            ] = receipt_id
            return deepcopy(record)


def build_doc_action_patch_readback_receipt(
    *,
    patch_preview: dict[str, Any],
    approval_packet: dict[str, Any],
    execution_plan: dict[str, Any],
    readback_ref: str,
    readback_text: str,
    requested_by: str = "operator",
    source_root: str | Path | None = None,
    label: str = "manual-doc-action-patch-readback",
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
    required_gates = _required_gates(
        patch_preview=patch_preview,
        approval_packet=approval_packet,
        execution_plan=execution_plan,
        readback=readback,
    )
    status = _status(required_gates)
    reason_codes = _reason_codes(required_gates, status)
    record = {
        "schema_version": SCHEMA_VERSION,
        "doc_action_patch_readback_receipt_id": stable_id(
            "docpatchreadback",
            label,
            patch_preview.get("doc_action_patch_preview_id"),
            patch_preview.get("doc_action_patch_preview_sha256"),
            readback.get("readback_text_sha256"),
            now,
        ),
        "label": label,
        "source_root": str(root),
        "doc_action_patch_preview_id": patch_preview.get("doc_action_patch_preview_id"),
        "doc_action_patch_preview_sha256": patch_preview.get("doc_action_patch_preview_sha256"),
        "doc_action_operator_approval_packet_id": patch_preview.get("doc_action_operator_approval_packet_id"),
        "doc_action_operator_approval_packet_sha256": patch_preview.get(
            "doc_action_operator_approval_packet_sha256"
        ),
        "doc_action_execution_plan_id": patch_preview.get("doc_action_execution_plan_id"),
        "doc_action_execution_plan_sha256": patch_preview.get("doc_action_execution_plan_sha256"),
        "source_doc_retirement_plan_id": patch_preview.get("source_doc_retirement_plan_id"),
        "source_doc_retirement_plan_sha256": patch_preview.get("source_doc_retirement_plan_sha256"),
        "readback": readback,
        "required_readback_phrases": list(REQUIRED_READBACK_PHRASES),
        "required_gates": required_gates,
        "receipt_verifies_readback_only": True,
        "approval_granted": False,
        "live_execution_allowed": False,
        "source_file_write_allowed": False,
        "source_file_move_allowed": False,
        "source_file_delete_allowed": False,
        "archive_create_allowed": False,
        "generated_surface_rewrite_allowed": False,
        "literal_patch_store_allowed": False,
        "preview_artifact_write_allowed": False,
        "provider_call_allowed": False,
        "network_call_allowed": False,
        "approval_actions": [],
        "execution_actions": [],
        "patch_actions": [],
        "live_boundaries": dict(LIVE_BOUNDARIES),
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["doc_action_patch_readback_receipt_sha256"] = _hash_without(
        record,
        "doc_action_patch_readback_receipt_sha256",
    )
    return deepcopy(record)


def validate_doc_action_patch_readback_receipt_record(
    record: dict[str, Any],
    *,
    patch_preview: dict[str, Any] | None = None,
    approval_packet: dict[str, Any] | None = None,
    execution_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record(
            "doc_action_patch_readback_receipt.schema.json",
            record,
            location="doc_action_patch_readback_receipt",
        )
    except SchemaValidationError:
        reason_codes.append("doc_action_patch_readback.schema_invalid")
    expected_hash = record.get("doc_action_patch_readback_receipt_sha256")
    if expected_hash and expected_hash != _hash_without(record, "doc_action_patch_readback_receipt_sha256"):
        reason_codes.append("doc_action_patch_readback.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("doc_action_patch_readback.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("doc_action_patch_readback.status_invalid")
    if record.get("receipt_verifies_readback_only") is not True:
        reason_codes.append("doc_action_patch_readback.receipt_verifies_readback_only_not_true")
    for key, expected in LIVE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"doc_action_patch_readback.{key}_not_false")
    for key in AUTHORITY_FALSE_FIELDS:
        if record.get(key) is not False:
            reason_codes.append(f"doc_action_patch_readback.{key}_not_false")
    for key in EMPTY_ACTION_FIELDS:
        if record.get(key) != []:
            reason_codes.append(f"doc_action_patch_readback.{key}_not_empty")
    _validate_readback(record, reason_codes)
    if patch_preview is None:
        reason_codes.append("doc_action_patch_readback.patch_preview_missing")
    else:
        if record.get("doc_action_patch_preview_id") != patch_preview.get("doc_action_patch_preview_id"):
            reason_codes.append("doc_action_patch_readback.patch_preview_id_mismatch")
        if record.get("doc_action_patch_preview_sha256") != patch_preview.get("doc_action_patch_preview_sha256"):
            reason_codes.append("doc_action_patch_readback.patch_preview_hash_mismatch")
        for key in (
            "doc_action_operator_approval_packet_id",
            "doc_action_operator_approval_packet_sha256",
            "doc_action_execution_plan_id",
            "doc_action_execution_plan_sha256",
            "source_doc_retirement_plan_id",
            "source_doc_retirement_plan_sha256",
        ):
            if record.get(key) != patch_preview.get(key):
                reason_codes.append(f"doc_action_patch_readback.{key}_mismatch")
        preview_validation = validate_doc_action_patch_preview_record(
            patch_preview,
            approval_packet=approval_packet,
            execution_plan=execution_plan,
        )
        if not preview_validation["ok"]:
            reason_codes.extend(
                f"doc_action_patch_readback.patch_preview:{reason}"
                for reason in preview_validation["reason_codes"]
            )
    readback = record.get("readback") or {}
    expected_gates = _required_gates(
        patch_preview=patch_preview or {},
        approval_packet=approval_packet or {},
        execution_plan=execution_plan or {},
        readback=readback,
    )
    if record.get("required_gates") != expected_gates:
        reason_codes.append("doc_action_patch_readback.required_gates_mismatch")
    expected_status = _status(expected_gates)
    if record.get("status") != expected_status:
        reason_codes.append("doc_action_patch_readback.status_mismatch")
    expected_reasons = _reason_codes(expected_gates, expected_status)
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("doc_action_patch_readback.reason_codes_mismatch")
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


def _validate_readback(record: dict[str, Any], reason_codes: list[str]) -> None:
    readback = record.get("readback") or {}
    if readback.get("raw_readback_stored") is not False:
        reason_codes.append("doc_action_patch_readback.raw_readback_stored_not_false")
    if readback.get("readback_text_sha256") != readback.get("normalized_readback_sha256"):
        reason_codes.append("doc_action_patch_readback.readback_hash_mismatch")
    if record.get("required_readback_phrases") != REQUIRED_READBACK_PHRASES:
        reason_codes.append("doc_action_patch_readback.required_readback_phrases_mismatch")
    phrase_results = readback.get("phrase_results") or []
    if len(phrase_results) != len(REQUIRED_READBACK_PHRASES):
        reason_codes.append("doc_action_patch_readback.phrase_results_count_mismatch")
    present_by_phrase: dict[str, bool] = {}
    for phrase in REQUIRED_READBACK_PHRASES:
        matches = [row for row in phrase_results if isinstance(row, dict) and row.get("phrase") == phrase]
        if len(matches) != 1:
            reason_codes.append(f"doc_action_patch_readback.phrase_result_missing:{phrase}")
            continue
        row = matches[0]
        present = row.get("present")
        if not isinstance(present, bool):
            reason_codes.append(f"doc_action_patch_readback.phrase_present_invalid:{phrase}")
            continue
        present_by_phrase[phrase] = present
        expected_evidence = sha256_text(phrase if present else "")
        if row.get("evidence_sha256") != expected_evidence:
            reason_codes.append(f"doc_action_patch_readback.phrase_evidence_mismatch:{phrase}")
    missing = [phrase for phrase in REQUIRED_READBACK_PHRASES if present_by_phrase.get(phrase) is not True]
    if missing != readback.get("missing_required_phrases"):
        reason_codes.append("doc_action_patch_readback.missing_required_phrases_mismatch")
    if readback.get("required_phrases_present") is not (not missing):
        reason_codes.append("doc_action_patch_readback.required_phrases_present_mismatch")


def _required_gates(
    *,
    patch_preview: dict[str, Any],
    approval_packet: dict[str, Any],
    execution_plan: dict[str, Any],
    readback: dict[str, Any],
) -> dict[str, bool]:
    preview_validation = (
        validate_doc_action_patch_preview_record(
            patch_preview,
            approval_packet=approval_packet,
            execution_plan=execution_plan,
        )
        if patch_preview
        else {"ok": False}
    )
    return {
        "patch_preview_present": bool(patch_preview.get("doc_action_patch_preview_id")),
        "patch_preview_ready_for_review": patch_preview.get("status") == "ready_for_review",
        "patch_preview_hash_current": preview_validation["ok"],
        "patch_preview_grants_no_authority": _patch_preview_grants_no_authority(patch_preview),
        "patch_summary_present": bool((patch_preview.get("patch_summary") or {}).get("patch_count")),
        "patches_present": bool(patch_preview.get("patch_previews")),
        "readback_ref_present": bool(readback.get("readback_ref")),
        "readback_present": readback.get("readback_present") is True,
        "required_phrases_present": readback.get("required_phrases_present") is True,
        "raw_readback_not_stored": readback.get("raw_readback_stored") is False,
        "receipt_grants_no_authority": True,
    }


def _patch_preview_grants_no_authority(patch_preview: dict[str, Any]) -> bool:
    policy = patch_preview.get("policy") or {}
    live = patch_preview.get("live_boundaries") or {}
    return (
        policy.get("preview_only") is True
        and policy.get("operator_review_required") is True
        and policy.get("literal_patch_stored") is False
        and policy.get("raw_source_markdown_stored") is False
        and policy.get("preview_artifact_write_allowed") is False
        and policy.get("source_file_write_allowed") is False
        and policy.get("archive_create_allowed") is False
        and policy.get("generated_surface_rewrite_allowed") is False
        and bool(live)
        and all(live.get(key) is expected for key, expected in PATCH_PREVIEW_LIVE_BOUNDARIES.items())
    )


def _status(required_gates: dict[str, bool]) -> str:
    return "readback_verified" if required_gates and all(required_gates.values()) else "blocked"


def _reason_codes(required_gates: dict[str, bool], status: str) -> list[str]:
    if status == "readback_verified":
        return ["doc_action_patch_readback.readback_verified"]
    missing = [key for key, value in sorted(required_gates.items()) if value is not True]
    return [f"doc_action_patch_readback.gate_failed:{key}" for key in missing] or [
        "doc_action_patch_readback.blocked"
    ]


def _normalize(text: str) -> str:
    return " ".join(text.lower().replace(",", " ").replace(";", " ").replace(".", " ").split())
