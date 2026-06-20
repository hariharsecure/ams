from __future__ import annotations

from copy import deepcopy
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from .architecture_audit import validate_architecture_audit_record
from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .store import JsonStore


ARCHITECTURE_SCOPED_PATTERNS = (
    "ams_codex/*.py",
    "schemas/*.json",
    "schemas/*.schema.json",
)
DECISIONS = {"allow", "defer", "deny"}


class ArchitectureGateStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        subject_kind: str,
        subject_id: str,
        paths: list[str],
        architecture_audit_id: str | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            audit = None
            if architecture_audit_id:
                audit = (state.get("architecture_audits") or {}).get(architecture_audit_id)
                if not isinstance(audit, dict):
                    raise KeyError(f"unknown architecture_audit_id: {architecture_audit_id}")
            record = build_architecture_gate_review(
                subject_kind=subject_kind,
                subject_id=subject_id,
                paths=paths,
                architecture_audit=audit,
            )
            validation = validate_architecture_gate_review_record(record, state=state)
            if not validation["ok"]:
                raise ValueError("; ".join(validation["reason_codes"]))
            gate_id = record["architecture_gate_review_id"]
            state.setdefault("architecture_gate_reviews", {})[gate_id] = record
            state.setdefault("indexes", {}).setdefault("architecture_gate_review_ids", {})[gate_id] = gate_id
        return deepcopy(record)


def build_architecture_gate_review(
    *,
    subject_kind: str,
    subject_id: str,
    paths: list[str],
    architecture_audit: dict[str, Any] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    normalized_paths = [_normalize_rel(path) for path in paths]
    scoped_paths = architecture_scoped_paths(normalized_paths)
    required = bool(scoped_paths)
    decision, reason_codes = _decision_and_reasons(required=required, architecture_audit=architecture_audit)
    record = {
        "schema_version": "ams.ams_codex.architecture_gate_review.v0",
        "architecture_gate_review_id": stable_id(
            "archgate",
            subject_kind,
            subject_id,
            normalized_paths,
            (architecture_audit or {}).get("architecture_audit_id"),
            decision,
            now,
        ),
        "subject_kind": subject_kind,
        "subject_id": subject_id,
        "architecture_audit_id": (architecture_audit or {}).get("architecture_audit_id"),
        "architecture_audit_sha256": (architecture_audit or {}).get("architecture_audit_sha256"),
        "paths": normalized_paths,
        "scoped_paths": scoped_paths,
        "required": required,
        "decision": decision,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["gate_sha256"] = _hash_without(record, "gate_sha256")
    return deepcopy(record)


def validate_architecture_gate_review_record(record: dict[str, Any], *, state: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    expected_hash = record.get("gate_sha256")
    if expected_hash and expected_hash != _hash_without(record, "gate_sha256"):
        reason_codes.append("architecture_gate.hash_mismatch")
    if record.get("decision") not in DECISIONS:
        reason_codes.append("architecture_gate.decision_invalid")
    if not record.get("subject_kind") or not record.get("subject_id"):
        reason_codes.append("architecture_gate.subject_missing")
    paths = list(record.get("paths") or [])
    scoped_paths = architecture_scoped_paths(paths)
    if sorted(record.get("scoped_paths") or []) != sorted(scoped_paths):
        reason_codes.append("architecture_gate.scoped_paths_mismatch")
    if bool(record.get("required")) != bool(scoped_paths):
        reason_codes.append("architecture_gate.required_mismatch")
    audit_id = record.get("architecture_audit_id")
    audit = None
    if audit_id:
        audit = (state.get("architecture_audits") or {}).get(audit_id)
        if not isinstance(audit, dict):
            reason_codes.append("architecture_gate.audit_missing")
        else:
            if audit.get("architecture_audit_sha256") != record.get("architecture_audit_sha256"):
                reason_codes.append("architecture_gate.audit_hash_mismatch")
            audit_validation = validate_architecture_audit_record(audit)
            if not audit_validation["ok"]:
                reason_codes.append("architecture_gate.audit_invalid")
    expected_decision, expected_reasons = _decision_and_reasons(
        required=bool(scoped_paths),
        architecture_audit=audit,
    )
    if record.get("decision") != expected_decision:
        reason_codes.append("architecture_gate.decision_reason_mismatch")
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("architecture_gate.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": reason_codes}


def architecture_gate_result_for_request(
    state: dict[str, Any],
    *,
    task_run_id: str,
    request: dict[str, Any],
) -> dict[str, Any]:
    paths = [_normalize_rel(path) for path in (request.get("paths") or [])]
    scoped_paths = architecture_scoped_paths(paths)
    if not scoped_paths:
        return {"ok": True, "required": False, "reason_code": "architecture_gate.not_required"}
    gate_id = request.get("architecture_gate_review_id")
    if not gate_id:
        return {
            "ok": False,
            "required": True,
            "reason_code": "dispatch.architecture_gate_required",
            "scoped_paths": scoped_paths,
        }
    gate = (state.get("architecture_gate_reviews") or {}).get(gate_id)
    if not isinstance(gate, dict):
        return {
            "ok": False,
            "required": True,
            "reason_code": "dispatch.architecture_gate_missing",
            "architecture_gate_review_id": gate_id,
            "scoped_paths": scoped_paths,
        }
    validation = validate_architecture_gate_review_record(gate, state=state)
    if not validation["ok"]:
        return {
            "ok": False,
            "required": True,
            "reason_code": "dispatch.architecture_gate_invalid",
            "architecture_gate_review_id": gate_id,
            "reason_codes": validation["reason_codes"],
            "scoped_paths": scoped_paths,
        }
    if gate.get("subject_kind") != "task_run" or gate.get("subject_id") != task_run_id:
        return {
            "ok": False,
            "required": True,
            "reason_code": "dispatch.architecture_gate_subject_mismatch",
            "architecture_gate_review_id": gate_id,
            "scoped_paths": scoped_paths,
        }
    if sorted(gate.get("scoped_paths") or []) != sorted(scoped_paths):
        return {
            "ok": False,
            "required": True,
            "reason_code": "dispatch.architecture_gate_scope_mismatch",
            "architecture_gate_review_id": gate_id,
            "scoped_paths": scoped_paths,
        }
    if gate.get("decision") == "deny":
        return {
            "ok": False,
            "required": True,
            "reason_code": "dispatch.architecture_gate_denied",
            "architecture_gate_review_id": gate_id,
            "scoped_paths": scoped_paths,
            "architecture_reason_codes": list(gate.get("reason_codes") or []),
        }
    return {
        "ok": True,
        "required": True,
        "reason_code": "architecture_gate.reviewed",
        "architecture_gate_review_id": gate_id,
        "decision": gate.get("decision"),
        "scoped_paths": scoped_paths,
    }


def architecture_scoped_paths(paths: list[str]) -> list[str]:
    scoped = []
    for path in paths:
        rel = _normalize_rel(path)
        if any(fnmatch(rel, pattern) for pattern in ARCHITECTURE_SCOPED_PATTERNS):
            scoped.append(rel)
    return sorted(set(scoped))


def _decision_and_reasons(
    *,
    required: bool,
    architecture_audit: dict[str, Any] | None,
) -> tuple[str, list[str]]:
    if not required:
        return "allow", ["architecture_gate.not_required"]
    if not architecture_audit:
        return "defer", ["architecture_gate.audit_required"]
    status = str(architecture_audit.get("status") or "defer")
    audit_codes = list(architecture_audit.get("reason_codes") or [])
    if status == "deny":
        return "deny", ["architecture_gate.audit_denied", *audit_codes]
    if status == "defer":
        return "defer", ["architecture_gate.audit_deferred", *audit_codes]
    return "allow", ["architecture_gate.audit_allowed", *audit_codes]


def _normalize_rel(path: str) -> str:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate.name if len(candidate.parts) == 1 else "/".join(candidate.parts[-2:])
    return candidate.as_posix().lstrip("./")
