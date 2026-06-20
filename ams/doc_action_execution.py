from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any

from .doc_retirement import build_doc_retirement_plan
from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore


SCHEMA_VERSION = "ams.ams.doc_action_execution_plan.v0"
STATUSES = {"allow", "defer", "deny"}
DEFAULT_MAX_ACTIONS = 3
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
LIVE_BOUNDARIES = {
    "file_rewritten": False,
    "file_deleted": False,
    "file_moved": False,
    "archive_created": False,
    "generated_surface_rewritten": False,
    "raw_markdown_stored": False,
    "network_call_performed": False,
    "provider_call_performed": False,
    "discord_call_performed": False,
    "terminal_attach_performed": False,
}
OPERATION_BY_KIND = {
    "replace_manual_status_with_generated_snapshot": "replace_with_generated_surface_preview",
    "split_milestone_history_from_session_surface": "split_archive_preview",
    "keep_readme_as_orientation_only": "trim_orientation_preview",
    "split_control_doc": "split_archive_preview",
    "add_machine_readable_metadata": "metadata_patch_preview",
    "add_required_doc_section": "section_patch_preview",
}
RESEARCH_BASIS = [
    {
        "lens": "change_control",
        "source": "NIST SP 800-128 configuration change control",
        "url": "https://csrc.nist.gov/pubs/sp/800/128/final",
    },
    {
        "lens": "documentation_architecture",
        "source": "Diataxis documentation framework",
        "url": "https://diataxis.fr/",
    },
    {
        "lens": "secure_supply_chain",
        "source": "SLSA provenance and hermetic build guidance",
        "url": "https://slsa.dev/spec/v1.1/requirements",
    },
]


class DocActionExecutionPlanStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        source_root: str | Path,
        label: str = "manual-doc-action-execution-plan",
        include_local_session_metadata: bool = False,
        session_window_days: int = 92,
        max_actions: int = DEFAULT_MAX_ACTIONS,
        action_kinds: list[str] | tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        source_plan = build_doc_retirement_plan(
            source_root=source_root,
            label=f"{label}-source-doc-plan",
            include_local_session_metadata=include_local_session_metadata,
            session_window_days=session_window_days,
        )
        record = build_doc_action_execution_plan(
            source_plan=source_plan,
            label=label,
            max_actions=max_actions,
            action_kinds=action_kinds,
        )
        with self.store.locked() as state:
            source_plan_id = source_plan["doc_retirement_plan_id"]
            plan_id = record["doc_action_execution_plan_id"]
            state.setdefault("doc_retirement_plans", {})[source_plan_id] = source_plan
            state.setdefault("indexes", {}).setdefault("doc_retirement_plan_ids", {})[source_plan_id] = source_plan_id
            state.setdefault("doc_action_execution_plans", {})[plan_id] = record
            state.setdefault("indexes", {}).setdefault("doc_action_execution_plan_ids", {})[plan_id] = plan_id
            return deepcopy(record)


def build_doc_action_execution_plan(
    *,
    source_plan: dict[str, Any],
    label: str = "manual-doc-action-execution-plan",
    max_actions: int = DEFAULT_MAX_ACTIONS,
    action_kinds: list[str] | tuple[str, ...] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    if max_actions < 1:
        raise ValueError("max_actions must be >= 1")
    now = now or utc_now()
    kinds = _unique_sorted([str(kind) for kind in (action_kinds or []) if str(kind)])
    selected = _select_actions(source_plan, max_actions=max_actions, action_kinds=kinds)
    action_summary = _action_summary(selected)
    source_plan_ref = _source_plan_ref(source_plan)
    readiness = _readiness(source_plan_ref=source_plan_ref, selected_actions=selected)
    status = _status(source_plan_ref=source_plan_ref, selected_actions=selected)
    reason_codes = _reason_codes(source_plan_ref=source_plan_ref, selected_actions=selected, status=status)
    record = {
        "schema_version": SCHEMA_VERSION,
        "doc_action_execution_plan_id": stable_id(
            "docexec",
            source_plan_ref,
            action_summary,
            kinds,
            max_actions,
            label,
            now,
        ),
        "label": label,
        "source_root": source_plan.get("source_root"),
        "research_basis": RESEARCH_BASIS,
        "policy": {
            "preview_only": True,
            "max_actions": max_actions,
            "action_kinds": kinds,
            "operator_review_required": True,
            "approval_granted": False,
            "live_execution_allowed": False,
            "raw_markdown_stored": False,
            "delete_or_move_allowed": False,
            "write_allowed": False,
            "source_hash_match_required": True,
        },
        "live_boundaries": dict(LIVE_BOUNDARIES),
        "source_plan_ref": source_plan_ref,
        "selected_actions": selected,
        "skipped_action_count": max(0, int(source_plan_ref["action_count"]) - len(selected)),
        "action_summary": action_summary,
        "readiness": readiness,
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["doc_action_execution_plan_sha256"] = _hash_without(record, "doc_action_execution_plan_sha256")
    return deepcopy(record)


def validate_doc_action_execution_plan_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("doc_action_execution_plan.schema.json", record, location="doc_action_execution_plan")
    except SchemaValidationError:
        reason_codes.append("doc_action_execution_plan.schema_invalid")
    expected_hash = record.get("doc_action_execution_plan_sha256")
    if expected_hash and expected_hash != _hash_without(record, "doc_action_execution_plan_sha256"):
        reason_codes.append("doc_action_execution_plan.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("doc_action_execution_plan.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("doc_action_execution_plan.status_invalid")
    for key, expected in LIVE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"doc_action_execution_plan.{key}_not_false")
    policy = record.get("policy") or {}
    for key in ("preview_only", "operator_review_required", "source_hash_match_required"):
        if policy.get(key) is not True:
            reason_codes.append(f"doc_action_execution_plan.policy_{key}_not_true")
    for key in ("approval_granted", "live_execution_allowed", "raw_markdown_stored", "delete_or_move_allowed", "write_allowed"):
        if policy.get(key) is not False:
            reason_codes.append(f"doc_action_execution_plan.policy_{key}_not_false")
    selected = record.get("selected_actions") or []
    expected_summary = _action_summary(selected)
    if record.get("action_summary") != expected_summary:
        reason_codes.append("doc_action_execution_plan.action_summary_mismatch")
    source_plan_ref = record.get("source_plan_ref") or {}
    expected_status = _status(source_plan_ref=source_plan_ref, selected_actions=selected)
    if record.get("status") != expected_status:
        reason_codes.append("doc_action_execution_plan.status_mismatch")
    expected_reasons = _reason_codes(source_plan_ref=source_plan_ref, selected_actions=selected, status=expected_status)
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("doc_action_execution_plan.reason_codes_mismatch")
    expected_readiness = _readiness(source_plan_ref=source_plan_ref, selected_actions=selected)
    if record.get("readiness") != expected_readiness:
        reason_codes.append("doc_action_execution_plan.readiness_mismatch")
    expected_skipped = max(0, int(source_plan_ref.get("action_count", 0) or 0) - len(selected))
    if record.get("skipped_action_count") != expected_skipped:
        reason_codes.append("doc_action_execution_plan.skipped_action_count_mismatch")
    action_ids = [action.get("action_id") for action in selected if isinstance(action, dict)]
    if len(action_ids) != len(set(action_ids)):
        reason_codes.append("doc_action_execution_plan.duplicate_action_id")
    for action in selected:
        if not isinstance(action, dict):
            reason_codes.append("doc_action_execution_plan.action_not_object")
            continue
        if action.get("raw_content_stored") is not False:
            reason_codes.append("doc_action_execution_plan.action_raw_content_not_false")
        if action.get("preview_only") is not True:
            reason_codes.append("doc_action_execution_plan.action_preview_only_not_true")
        if action.get("live_boundary") is not False:
            reason_codes.append("doc_action_execution_plan.action_live_boundary_not_false")
        source_ref = action.get("source_ref") or {}
        if source_ref.get("under_source_root") is not True:
            reason_codes.append(f"doc_action_execution_plan.source_ref_outside_root:{action.get('action_id')}")
        if source_ref.get("exists") is not True:
            reason_codes.append(f"doc_action_execution_plan.source_ref_missing:{action.get('action_id')}")
        if not source_ref.get("sha256"):
            reason_codes.append(f"doc_action_execution_plan.source_ref_hash_missing:{action.get('action_id')}")
        expected_preview = _preview_sha256(action)
        if action.get("preview_sha256") != expected_preview:
            reason_codes.append(f"doc_action_execution_plan.preview_hash_mismatch:{action.get('action_id')}")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def validate_doc_action_execution_plan_against_source(
    record: dict[str, Any],
    source_plan: dict[str, Any] | None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    ref = record.get("source_plan_ref") or {}
    if source_plan is None:
        reason_codes.append("doc_action_execution_plan.source_plan_missing")
        return {"ok": False, "reason_codes": reason_codes}
    if source_plan.get("doc_retirement_plan_id") != ref.get("doc_retirement_plan_id"):
        reason_codes.append("doc_action_execution_plan.source_plan_id_mismatch")
    if source_plan.get("doc_retirement_plan_sha256") != ref.get("doc_retirement_plan_sha256"):
        reason_codes.append("doc_action_execution_plan.source_plan_hash_mismatch")
    source_actions = {
        action.get("action_id"): action
        for action in source_plan.get("decision_actions") or []
        if isinstance(action, dict)
    }
    for action in record.get("selected_actions") or []:
        action_id = action.get("action_id") if isinstance(action, dict) else None
        source_action = source_actions.get(action_id)
        if source_action is None:
            reason_codes.append(f"doc_action_execution_plan.source_action_missing:{action_id}")
            continue
        for field in ("source_path", "action_kind", "severity", "reason", "target_surface"):
            if action.get(field) != source_action.get(field):
                reason_codes.append(f"doc_action_execution_plan.source_action_{field}_mismatch:{action_id}")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _select_actions(
    source_plan: dict[str, Any],
    *,
    max_actions: int,
    action_kinds: list[str],
) -> list[dict[str, Any]]:
    root = Path(str(source_plan.get("source_root") or "")).expanduser().resolve(strict=False)
    actions = [
        action for action in (source_plan.get("decision_actions") or [])
        if isinstance(action, dict) and (not action_kinds or action.get("action_kind") in action_kinds)
    ]
    actions = sorted(
        actions,
        key=lambda action: (
            SEVERITY_ORDER.get(str(action.get("severity") or ""), 9),
            str(action.get("source_path") or ""),
            str(action.get("action_kind") or ""),
            str(action.get("action_id") or ""),
        ),
    )
    return [_execution_action(root, action) for action in actions[:max_actions]]


def _execution_action(root: Path, action: dict[str, Any]) -> dict[str, Any]:
    source_ref = _source_ref(root, str(action.get("source_path") or ""))
    normalized = {
        "action_id": action.get("action_id"),
        "source_path": action.get("source_path"),
        "action_kind": action.get("action_kind"),
        "severity": action.get("severity"),
        "reason": action.get("reason"),
        "target_surface": action.get("target_surface"),
        "planned_operation": OPERATION_BY_KIND.get(str(action.get("action_kind") or ""), "manual_review_preview"),
        "source_ref": source_ref,
        "operator_review_required": True,
        "preview_only": True,
        "live_boundary": False,
        "raw_content_stored": False,
        "details": {
            "source_plan_details_sha256": sha256_text(canonical_json(action.get("details") or {})),
            "future_executor_must_recheck_source_sha256": True,
        },
    }
    normalized["preview_sha256"] = _preview_sha256(normalized)
    return normalized


def _source_ref(root: Path, relative_path: str) -> dict[str, Any]:
    safe_rel = relative_path.strip("/")
    path = (root / safe_rel).resolve(strict=False)
    under_root = _path_under_root(path, root)
    is_file = under_root and path.is_file()
    size_bytes = path.stat().st_size if is_file else None
    sha256 = _file_sha256(path) if is_file else None
    line_count = _line_count(path) if is_file else None
    return {
        "path": relative_path,
        "exists": bool(is_file),
        "under_source_root": bool(under_root),
        "sha256": sha256,
        "line_count": line_count,
        "size_bytes": size_bytes,
        "raw_content_stored": False,
    }


def _source_plan_ref(source_plan: dict[str, Any]) -> dict[str, Any]:
    action_summary = source_plan.get("action_summary") or {}
    return {
        "doc_retirement_plan_id": source_plan.get("doc_retirement_plan_id"),
        "doc_retirement_plan_sha256": source_plan.get("doc_retirement_plan_sha256"),
        "status": source_plan.get("status"),
        "reason_codes": source_plan.get("reason_codes") or [],
        "markdown_snapshot_sha256": (source_plan.get("markdown_audit_ref") or {}).get("markdown_snapshot_sha256"),
        "action_count": int(action_summary.get("action_count", 0) or 0),
    }


def _readiness(*, source_plan_ref: dict[str, Any], selected_actions: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "source_plan_allows_live_execution": source_plan_ref.get("status") == "allow",
        "selected_action_count": len(selected_actions),
        "operator_approval_granted": False,
        "source_hashes_captured": all((action.get("source_ref") or {}).get("sha256") for action in selected_actions),
        "live_execution_allowed": False,
    }


def _status(*, source_plan_ref: dict[str, Any], selected_actions: list[dict[str, Any]]) -> str:
    if source_plan_ref.get("status") == "deny":
        return "deny"
    if selected_actions or int(source_plan_ref.get("action_count", 0) or 0) > 0:
        return "defer"
    return "allow"


def _reason_codes(*, source_plan_ref: dict[str, Any], selected_actions: list[dict[str, Any]], status: str) -> list[str]:
    if status == "allow":
        return ["doc_action_execution_plan.allow"]
    if status == "deny":
        return ["doc_action_execution_plan.source_plan_deny"]
    reasons = ["doc_action_execution_plan.operator_review_required", "doc_action_execution_plan.preview_only"]
    if source_plan_ref.get("status") == "defer":
        reasons.append("doc_action_execution_plan.source_plan_defer")
    if not selected_actions:
        reasons.append("doc_action_execution_plan.no_actions_selected")
    if any(action.get("severity") in {"critical", "high"} for action in selected_actions):
        reasons.append("doc_action_execution_plan.high_priority_actions_selected")
    return sorted(set(reasons))


def _action_summary(actions: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "action_count": len(actions),
        "by_kind": dict(Counter(str(action.get("action_kind")) for action in actions)),
        "by_severity": dict(Counter(str(action.get("severity")) for action in actions)),
        "operator_review_required_count": sum(1 for action in actions if action.get("operator_review_required") is True),
    }


def _preview_sha256(action: dict[str, Any]) -> str:
    material = {
        "action_id": action.get("action_id"),
        "source_path": action.get("source_path"),
        "action_kind": action.get("action_kind"),
        "target_surface": action.get("target_surface"),
        "planned_operation": action.get("planned_operation"),
        "source_ref": action.get("source_ref"),
        "operator_review_required": action.get("operator_review_required"),
        "preview_only": action.get("preview_only"),
        "live_boundary": action.get("live_boundary"),
        "raw_content_stored": action.get("raw_content_stored"),
        "details": action.get("details"),
    }
    return sha256_text(canonical_json(material))


def _file_sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _line_count(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    return text.count("\n") + (0 if text.endswith("\n") or text == "" else 1)


def _path_under_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _unique_sorted(values: list[str]) -> list[str]:
    return sorted(set(values))
