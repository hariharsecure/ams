from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from .doc_action_execution import validate_doc_action_execution_plan_record
from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore
from .workspace import repo_root


SCHEMA_VERSION = "ams.ams_codex.doc_action_operator_approval_packet.v0"
STATUSES = {"ready_for_operator_review", "blocked"}

REQUIRED_REVIEW_STEPS = [
    "review_source_doc_retirement_plan",
    "review_selected_doc_actions",
    "review_source_file_hashes",
    "review_preview_operation_hashes",
    "confirm_no_live_doc_authority_granted",
    "confirm_future_executor_must_recheck_source_hashes",
]

REQUIRED_READBACK_PHRASES = [
    "i reviewed the doc action execution plan",
    "doc writes remain disabled",
    "doc moves remain disabled",
    "doc archives remain disabled",
    "a later explicit approval is required",
]

LIVE_BOUNDARIES = {
    "approval_granted": False,
    "file_rewritten": False,
    "file_deleted": False,
    "file_moved": False,
    "archive_created": False,
    "generated_surface_rewritten": False,
    "discord_call_performed": False,
    "terminal_attach_performed": False,
    "terminal_capture_performed": False,
    "terminal_injection_performed": False,
    "persistent_process_started": False,
    "provider_call_performed": False,
    "network_call_performed": False,
    "raw_readback_stored": False,
    "raw_markdown_stored": False,
    "secret_stored": False,
}


class DocActionOperatorApprovalPacketStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        doc_action_execution_plan_id: str,
        source_root: str | Path | None = None,
        label: str = "manual-doc-action-operator-approval",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            execution_plan = (state.get("doc_action_execution_plans") or {}).get(doc_action_execution_plan_id)
            if not execution_plan:
                raise KeyError(f"doc action execution plan not found: {doc_action_execution_plan_id}")
            record = build_doc_action_operator_approval_packet(
                execution_plan=execution_plan,
                source_root=source_root,
                label=label,
            )
            packet_id = record["doc_action_operator_approval_packet_id"]
            state.setdefault("doc_action_operator_approval_packets", {})[packet_id] = record
            state.setdefault("indexes", {}).setdefault("doc_action_operator_approval_packet_ids", {})[
                packet_id
            ] = packet_id
            return deepcopy(record)


def build_doc_action_operator_approval_packet(
    *,
    execution_plan: dict[str, Any],
    source_root: str | Path | None = None,
    label: str = "manual-doc-action-operator-approval",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False) if source_root else repo_root()
    plan_summary = _plan_summary(execution_plan)
    approval_request = _approval_request()
    required_gates = _required_gates(plan_summary=plan_summary, execution_plan=execution_plan)
    status = _status(required_gates)
    reason_codes = _reason_codes(required_gates, status)
    source_plan_ref = execution_plan.get("source_plan_ref") or {}
    record = {
        "schema_version": SCHEMA_VERSION,
        "doc_action_operator_approval_packet_id": stable_id(
            "docopapproval",
            label,
            execution_plan.get("doc_action_execution_plan_id"),
            execution_plan.get("doc_action_execution_plan_sha256"),
            plan_summary,
            now,
        ),
        "label": label,
        "source_root": str(root),
        "doc_action_execution_plan_id": execution_plan.get("doc_action_execution_plan_id"),
        "doc_action_execution_plan_sha256": execution_plan.get("doc_action_execution_plan_sha256"),
        "source_doc_retirement_plan_id": source_plan_ref.get("doc_retirement_plan_id"),
        "source_doc_retirement_plan_sha256": source_plan_ref.get("doc_retirement_plan_sha256"),
        "plan_summary": plan_summary,
        "approval_request": approval_request,
        "required_gates": required_gates,
        "approval_granted": False,
        "live_execution_allowed": False,
        "file_rewrite_allowed": False,
        "file_move_allowed": False,
        "file_delete_allowed": False,
        "archive_create_allowed": False,
        "generated_surface_rewrite_allowed": False,
        "approval_actions": [],
        "execution_actions": [],
        "live_boundaries": dict(LIVE_BOUNDARIES),
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["doc_action_operator_approval_packet_sha256"] = _hash_without(
        record,
        "doc_action_operator_approval_packet_sha256",
    )
    return deepcopy(record)


def validate_doc_action_operator_approval_packet_record(
    record: dict[str, Any],
    *,
    execution_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record(
            "doc_action_operator_approval_packet.schema.json",
            record,
            location="doc_action_operator_approval_packet",
        )
    except SchemaValidationError:
        reason_codes.append("doc_action_operator_approval.schema_invalid")
    expected_hash = record.get("doc_action_operator_approval_packet_sha256")
    if expected_hash and expected_hash != _hash_without(record, "doc_action_operator_approval_packet_sha256"):
        reason_codes.append("doc_action_operator_approval.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("doc_action_operator_approval.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("doc_action_operator_approval.status_invalid")
    for key, expected in LIVE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"doc_action_operator_approval.{key}_not_false")
    for key in (
        "approval_granted",
        "live_execution_allowed",
        "file_rewrite_allowed",
        "file_move_allowed",
        "file_delete_allowed",
        "archive_create_allowed",
        "generated_surface_rewrite_allowed",
    ):
        if record.get(key) is not False:
            reason_codes.append(f"doc_action_operator_approval.{key}_not_false")
    for key in ("approval_actions", "execution_actions"):
        if record.get(key) != []:
            reason_codes.append(f"doc_action_operator_approval.{key}_not_empty")
    approval_request = record.get("approval_request") or {}
    if approval_request.get("required_review_steps") != REQUIRED_REVIEW_STEPS:
        reason_codes.append("doc_action_operator_approval.required_review_steps_mismatch")
    if approval_request.get("required_readback_phrases") != REQUIRED_READBACK_PHRASES:
        reason_codes.append("doc_action_operator_approval.required_readback_phrases_mismatch")
    for key in ("operator_readback_captured", "raw_readback_stored", "approval_granted_by_readback"):
        if approval_request.get(key) is not False:
            reason_codes.append(f"doc_action_operator_approval.approval_request_{key}_not_false")
    required_gates = record.get("required_gates") or {}
    expected_status = _status(required_gates)
    if record.get("status") != expected_status:
        reason_codes.append("doc_action_operator_approval.status_mismatch")
    expected_reasons = _reason_codes(required_gates, expected_status)
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("doc_action_operator_approval.reason_codes_mismatch")
    if execution_plan is None:
        reason_codes.append("doc_action_operator_approval.execution_plan_missing")
    else:
        source_validation = validate_doc_action_execution_plan_record(execution_plan)
        if not source_validation["ok"]:
            reason_codes.append("doc_action_operator_approval.execution_plan_invalid")
        if execution_plan.get("doc_action_execution_plan_id") != record.get("doc_action_execution_plan_id"):
            reason_codes.append("doc_action_operator_approval.execution_plan_id_mismatch")
        if execution_plan.get("doc_action_execution_plan_sha256") != record.get("doc_action_execution_plan_sha256"):
            reason_codes.append("doc_action_operator_approval.execution_plan_hash_mismatch")
        source_plan_ref = execution_plan.get("source_plan_ref") or {}
        if source_plan_ref.get("doc_retirement_plan_id") != record.get("source_doc_retirement_plan_id"):
            reason_codes.append("doc_action_operator_approval.source_doc_retirement_plan_id_mismatch")
        if source_plan_ref.get("doc_retirement_plan_sha256") != record.get("source_doc_retirement_plan_sha256"):
            reason_codes.append("doc_action_operator_approval.source_doc_retirement_plan_hash_mismatch")
        expected_summary = _plan_summary(execution_plan)
        if record.get("plan_summary") != expected_summary:
            reason_codes.append("doc_action_operator_approval.plan_summary_mismatch")
        expected_gates = _required_gates(plan_summary=expected_summary, execution_plan=execution_plan)
        if record.get("required_gates") != expected_gates:
            reason_codes.append("doc_action_operator_approval.required_gates_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _approval_request() -> dict[str, Any]:
    return {
        "required_review_steps": REQUIRED_REVIEW_STEPS,
        "required_readback_phrases": REQUIRED_READBACK_PHRASES,
        "operator_readback_captured": False,
        "raw_readback_stored": False,
        "approval_granted_by_readback": False,
    }


def _plan_summary(execution_plan: dict[str, Any]) -> dict[str, Any]:
    selected = [action for action in execution_plan.get("selected_actions") or [] if isinstance(action, dict)]
    selected_paths = sorted(str(action.get("source_path") or "") for action in selected)
    preview_hashes = sorted(str(action.get("preview_sha256") or "") for action in selected)
    source_hashes = sorted(str((action.get("source_ref") or {}).get("sha256") or "") for action in selected)
    selected_action_set = [
        {
            "action_id": action.get("action_id"),
            "source_path": action.get("source_path"),
            "action_kind": action.get("action_kind"),
            "target_surface": action.get("target_surface"),
            "planned_operation": action.get("planned_operation"),
            "preview_sha256": action.get("preview_sha256"),
            "source_sha256": (action.get("source_ref") or {}).get("sha256"),
        }
        for action in selected
    ]
    return {
        "selected_action_count": len(selected),
        "skipped_action_count": int(execution_plan.get("skipped_action_count", 0) or 0),
        "selected_paths": selected_paths,
        "selected_action_set_sha256": sha256_text(canonical_json(selected_action_set)),
        "preview_hashes_sha256": sha256_text(canonical_json(preview_hashes)),
        "source_hashes_sha256": sha256_text(canonical_json(source_hashes)),
        "source_hashes_captured": bool(selected) and all(bool(value) for value in source_hashes),
        "preview_hashes_present": bool(selected) and all(value.startswith("sha256:") for value in preview_hashes),
        "plan_status": execution_plan.get("status"),
        "plan_live_execution_allowed": bool((execution_plan.get("readiness") or {}).get("live_execution_allowed")),
        "plan_operator_approval_granted": bool((execution_plan.get("readiness") or {}).get("operator_approval_granted")),
        "raw_content_stored": any(action.get("raw_content_stored") is not False for action in selected),
    }


def _required_gates(*, plan_summary: dict[str, Any], execution_plan: dict[str, Any]) -> dict[str, bool]:
    policy = execution_plan.get("policy") or {}
    return {
        "execution_plan_present": bool(execution_plan.get("doc_action_execution_plan_id")),
        "execution_plan_hash_present": bool(execution_plan.get("doc_action_execution_plan_sha256")),
        "source_doc_retirement_plan_ref_present": bool((execution_plan.get("source_plan_ref") or {}).get("doc_retirement_plan_id")),
        "source_doc_retirement_plan_hash_present": bool(
            (execution_plan.get("source_plan_ref") or {}).get("doc_retirement_plan_sha256")
        ),
        "selected_actions_present": int(plan_summary.get("selected_action_count", 0) or 0) > 0,
        "source_hashes_captured": plan_summary.get("source_hashes_captured") is True,
        "preview_hashes_present": plan_summary.get("preview_hashes_present") is True,
        "execution_plan_preview_only": policy.get("preview_only") is True,
        "execution_plan_write_disabled": policy.get("write_allowed") is False,
        "execution_plan_delete_move_disabled": (
            policy.get("delete_or_move_allowed") is False
            and policy.get("live_execution_allowed") is False
        ),
        "execution_plan_operator_approval_not_granted": policy.get("approval_granted") is False,
        "execution_plan_live_execution_not_allowed": plan_summary.get("plan_live_execution_allowed") is False,
        "raw_content_not_stored": plan_summary.get("raw_content_stored") is False,
    }


def _status(required_gates: dict[str, bool]) -> str:
    return "ready_for_operator_review" if required_gates and all(required_gates.values()) else "blocked"


def _reason_codes(required_gates: dict[str, bool], status: str) -> list[str]:
    if status == "ready_for_operator_review":
        return ["doc_action_operator_approval.ready_for_operator_review"]
    missing = [key for key, value in sorted(required_gates.items()) if value is not True]
    return [f"doc_action_operator_approval.gate_failed:{key}" for key in missing] or [
        "doc_action_operator_approval.blocked"
    ]
