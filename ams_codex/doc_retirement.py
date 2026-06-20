from __future__ import annotations

from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any

from .markdown_governance import build_markdown_audit
from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore


SCHEMA_VERSION = "ams.ams_codex.doc_retirement_plan.v0"
STATUSES = {"allow", "defer", "deny"}
CONTROL_DOC_LINE_BUDGET = 900
SESSION_START_LINE_BUDGET = 220
GENERATED_STATUS_LINE_BUDGET = 160
LIVE_BOUNDARIES = {
    "file_deleted": False,
    "file_moved": False,
    "file_rewritten": False,
    "raw_markdown_stored": False,
    "raw_session_content_stored": False,
    "prompt_text_stored": False,
    "transcript_text_stored": False,
    "network_call_performed": False,
}
RESEARCH_BASIS = [
    {
        "lens": "documentation_architecture",
        "source": "Diataxis documentation framework",
        "url": "https://diataxis.fr/",
    },
    {
        "lens": "readme_scope",
        "source": "GitHub Docs: About READMEs",
        "url": "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes",
    },
    {
        "lens": "requirement_language",
        "source": "RFC 2119 and RFC 8174 BCP 14 requirement keywords",
        "url": "https://www.rfc-editor.org/rfc/rfc2119",
    },
    {
        "lens": "generated_artifact_risk",
        "source": "OpenSSF Scorecard check documentation",
        "url": "https://github.com/ossf/scorecard/blob/main/docs/checks.md",
    },
]


class DocRetirementPlanStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        source_root: str | Path,
        label: str = "manual-doc-retirement-plan",
        include_local_session_metadata: bool = False,
        session_window_days: int = 92,
    ) -> dict[str, Any]:
        record = build_doc_retirement_plan(
            source_root=source_root,
            label=label,
            include_local_session_metadata=include_local_session_metadata,
            session_window_days=session_window_days,
        )
        with self.store.locked() as state:
            plan_id = record["doc_retirement_plan_id"]
            state.setdefault("doc_retirement_plans", {})[plan_id] = record
            state.setdefault("indexes", {}).setdefault("doc_retirement_plan_ids", {})[plan_id] = plan_id
            return deepcopy(record)


def build_doc_retirement_plan(
    *,
    source_root: str | Path,
    label: str = "manual-doc-retirement-plan",
    include_local_session_metadata: bool = False,
    session_window_days: int = 92,
    exclude_relative_paths: list[str] | tuple[str, ...] | set[str] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    if session_window_days < 1:
        raise ValueError("session_window_days must be >= 1")
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False)
    audit = build_markdown_audit(
        source_root=root,
        label=f"{label}-markdown",
        include_local_session_metadata=include_local_session_metadata,
        session_window_days=session_window_days,
        exclude_relative_paths=exclude_relative_paths,
        now=now,
    )
    control_doc_actions = _control_doc_actions(audit)
    metadata_actions = _metadata_actions(audit)
    structure_actions = _structure_actions(audit)
    generated_status = _generated_status(audit)
    decision_actions = control_doc_actions + metadata_actions + structure_actions
    action_summary = _action_summary(decision_actions)
    status = _status(audit, decision_actions)
    reason_codes = _reason_codes(audit, decision_actions, status)
    record = {
        "schema_version": SCHEMA_VERSION,
        "doc_retirement_plan_id": stable_id(
            "docplan",
            str(root),
            label,
            audit["markdown_snapshot_sha256"],
            action_summary,
            now,
        ),
        "label": label,
        "source_root": str(root),
        "research_basis": RESEARCH_BASIS,
        "policy": {
            "control_doc_line_budget": CONTROL_DOC_LINE_BUDGET,
            "session_start_line_budget": SESSION_START_LINE_BUDGET,
            "generated_status_line_budget": GENERATED_STATUS_LINE_BUDGET,
            "raw_markdown_stored": False,
            "raw_session_content_stored": False,
            "prompt_text_stored": False,
            "transcript_text_stored": False,
            "delete_or_move_allowed": False,
            "generated_status_required": True,
            "relative_links_required": True,
            "bcp14_keywords_reserved_for_contracts": True,
        },
        "live_boundaries": dict(LIVE_BOUNDARIES),
        "markdown_audit_ref": {
            "markdown_audit_id": audit["markdown_audit_id"],
            "markdown_audit_sha256": audit["markdown_audit_sha256"],
            "status": audit["status"],
            "reason_codes": audit["reason_codes"],
            "markdown_snapshot_sha256": audit["markdown_snapshot_sha256"],
        },
        "generated_status": generated_status,
        "decision_actions": decision_actions,
        "action_summary": action_summary,
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["doc_retirement_plan_sha256"] = _hash_without(record, "doc_retirement_plan_sha256")
    return deepcopy(record)


def validate_doc_retirement_plan_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("doc_retirement_plan.schema.json", record, location="doc_retirement_plan")
    except SchemaValidationError:
        reason_codes.append("doc_retirement_plan.schema_invalid")
    expected_hash = record.get("doc_retirement_plan_sha256")
    if expected_hash and expected_hash != _hash_without(record, "doc_retirement_plan_sha256"):
        reason_codes.append("doc_retirement_plan.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("doc_retirement_plan.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("doc_retirement_plan.status_invalid")
    for key, expected in LIVE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"doc_retirement_plan.{key}_not_false")
    policy = record.get("policy") or {}
    for key in ("raw_markdown_stored", "raw_session_content_stored", "prompt_text_stored", "transcript_text_stored"):
        if policy.get(key) is not False:
            reason_codes.append(f"doc_retirement_plan.policy_{key}_not_false")
    generated_status = record.get("generated_status") or {}
    if generated_status.get("raw_content_stored") is not False:
        reason_codes.append("doc_retirement_plan.generated_status_raw_content_not_false")
    actions = record.get("decision_actions") or []
    expected_summary = _action_summary(actions)
    if record.get("action_summary") != expected_summary:
        reason_codes.append("doc_retirement_plan.action_summary_mismatch")
    expected_status = _status_from_record(record, actions)
    if record.get("status") != expected_status:
        reason_codes.append("doc_retirement_plan.status_mismatch")
    expected_reasons = _reason_codes_from_record(record, actions, expected_status)
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("doc_retirement_plan.reason_codes_mismatch")
    if record.get("status") == "allow" and actions:
        reason_codes.append("doc_retirement_plan.allow_with_actions")
    action_ids = [action.get("action_id") for action in actions if isinstance(action, dict)]
    if len(action_ids) != len(set(action_ids)):
        reason_codes.append("doc_retirement_plan.duplicate_action_id")
    for action in actions:
        if not isinstance(action, dict):
            reason_codes.append("doc_retirement_plan.action_not_object")
            continue
        if action.get("raw_content_stored") is not False:
            reason_codes.append("doc_retirement_plan.action_raw_content_not_false")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _control_doc_actions(audit: dict[str, Any]) -> list[dict[str, Any]]:
    by_path = {summary["path"]: summary for summary in audit.get("file_summaries") or []}
    oversized_paths = {item["path"] for item in audit.get("oversized_files") or []}
    actions: list[dict[str, Any]] = []
    for path in (audit.get("authority_index") or {}).get("control_docs") or []:
        summary = by_path.get(path)
        if not summary:
            continue
        line_count = int(summary.get("line_count", 0) or 0)
        if path in oversized_paths or line_count > CONTROL_DOC_LINE_BUDGET:
            if path == "STATUS.md":
                action_kind = "replace_manual_status_with_generated_snapshot"
                target_surface = "GENERATED_STATUS.md"
            elif path == "MILESTONES.md":
                action_kind = "split_milestone_history_from_session_surface"
                target_surface = "docs/archive/MILESTONES.history.md"
            elif path == "README.md":
                action_kind = "keep_readme_as_orientation_only"
                target_surface = "README.md plus generated reference links"
            else:
                action_kind = "split_control_doc"
                target_surface = "docs/archive/"
            actions.append(
                _action(
                    source_path=path,
                    action_kind=action_kind,
                    severity="high",
                    reason="control_doc_oversized",
                    target_surface=target_surface,
                    details={
                        "line_count": line_count,
                        "line_budget": CONTROL_DOC_LINE_BUDGET,
                        "sha256": summary.get("sha256"),
                    },
                )
            )
    return actions


def _metadata_actions(audit: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        _action(
            source_path=gap["path"],
            action_kind="add_machine_readable_metadata",
            severity="medium",
            reason=f"metadata_gap:{gap['field']}",
            target_surface=gap["path"],
            details={"field": gap["field"]},
        )
        for gap in audit.get("metadata_gaps") or []
    ]


def _structure_actions(audit: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        _action(
            source_path=gap["path"],
            action_kind="add_required_doc_section",
            severity="medium",
            reason=f"structure_gap:{gap['field']}",
            target_surface=gap["path"],
            details={"field": gap["field"]},
        )
        for gap in audit.get("structure_gaps") or []
    ]


def _generated_status(audit: dict[str, Any]) -> dict[str, Any]:
    return {
        "recommended_path": "GENERATED_STATUS.md",
        "line_budget": GENERATED_STATUS_LINE_BUDGET,
        "source_record_kind": "doc_retirement_plan",
        "source_markdown_audit_id": audit["markdown_audit_id"],
        "source_markdown_audit_sha256": audit["markdown_audit_sha256"],
        "latest_milestone_doc": (audit.get("authority_index") or {}).get("latest_milestone_doc"),
        "markdown_file_count": audit.get("markdown_file_count"),
        "total_line_count": audit.get("total_line_count"),
        "metadata_gap_count": len(audit.get("metadata_gaps") or []),
        "structure_gap_count": len(audit.get("structure_gaps") or []),
        "oversized_file_count": len(audit.get("oversized_files") or []),
        "role_counts": audit.get("role_counts") or {},
        "session_metadata_included": bool((audit.get("session_metadata") or {}).get("included")),
        "excluded_paths": (audit.get("policy") or {}).get("excluded_paths") or [],
        "raw_content_stored": False,
    }


def _action(
    *,
    source_path: str,
    action_kind: str,
    severity: str,
    reason: str,
    target_surface: str,
    details: dict[str, Any],
) -> dict[str, Any]:
    return {
        "action_id": stable_id("docact", source_path, action_kind, reason, target_surface),
        "source_path": source_path,
        "action_kind": action_kind,
        "severity": severity,
        "reason": reason,
        "target_surface": target_surface,
        "operator_review_required": True,
        "raw_content_stored": False,
        "details": details,
    }


def _action_summary(actions: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "action_count": len(actions),
        "by_kind": dict(Counter(str(action.get("action_kind")) for action in actions)),
        "by_severity": dict(Counter(str(action.get("severity")) for action in actions)),
        "operator_review_required_count": sum(1 for action in actions if action.get("operator_review_required") is True),
    }


def _status(audit: dict[str, Any], actions: list[dict[str, Any]]) -> str:
    if audit.get("status") == "deny":
        return "deny"
    if actions or audit.get("status") != "allow":
        return "defer"
    return "allow"


def _status_from_record(record: dict[str, Any], actions: list[dict[str, Any]]) -> str:
    audit_ref = record.get("markdown_audit_ref") or {}
    if audit_ref.get("status") == "deny":
        return "deny"
    if actions or audit_ref.get("status") != "allow":
        return "defer"
    return "allow"


def _reason_codes(audit: dict[str, Any], actions: list[dict[str, Any]], status: str) -> list[str]:
    if status == "allow":
        return ["doc_retirement_plan.allow"]
    reasons = []
    if audit.get("status") != "allow":
        reasons.append("doc_retirement_plan.markdown_audit_defer")
    reasons.extend(_action_reason_codes(actions))
    return sorted(set(reasons)) or ["doc_retirement_plan.defer"]


def _reason_codes_from_record(record: dict[str, Any], actions: list[dict[str, Any]], status: str) -> list[str]:
    if status == "allow":
        return ["doc_retirement_plan.allow"]
    reasons = []
    if (record.get("markdown_audit_ref") or {}).get("status") != "allow":
        reasons.append("doc_retirement_plan.markdown_audit_defer")
    reasons.extend(_action_reason_codes(actions))
    return sorted(set(reasons)) or ["doc_retirement_plan.defer"]


def _action_reason_codes(actions: list[dict[str, Any]]) -> list[str]:
    reasons = []
    by_kind = {action.get("action_kind") for action in actions}
    if any(action.get("reason") == "control_doc_oversized" for action in actions):
        reasons.append("doc_retirement_plan.oversized_control_docs")
    if "add_machine_readable_metadata" in by_kind:
        reasons.append("doc_retirement_plan.metadata_gaps")
    if "add_required_doc_section" in by_kind:
        reasons.append("doc_retirement_plan.structure_gaps")
    return reasons
