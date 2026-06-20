from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore
from .workspace import repo_root


SCHEMA_VERSION = "ams.ams_codex.semantic_hook_install_plan.v0"
STATUSES = {"ready_for_operator_review", "defer", "deny"}

LIVE_BOUNDARIES = {
    "hook_file_written": False,
    "hook_installed": False,
    "hook_trusted": False,
    "provider_hook_executed": False,
    "discord_call_performed": False,
    "terminal_attach_performed": False,
    "terminal_capture_performed": False,
    "terminal_injection_performed": False,
    "persistent_process_started": False,
    "provider_call_performed": False,
    "embedding_call_performed": False,
    "vector_write_performed": False,
    "network_call_performed": False,
    "raw_content_stored": False,
    "secret_stored": False,
}

RESEARCH_BASIS = [
    {
        "lens": "codex_hooks_trust",
        "source": "OpenAI Codex manual: review and trust hooks",
        "url": "https://developers.openai.com/codex/hooks.md",
    },
    {
        "lens": "codex_hooks_locations",
        "source": "OpenAI Codex manual: hook discovery locations",
        "url": "https://developers.openai.com/codex/hooks.md",
    },
    {
        "lens": "ams_signed_package",
        "source": "AMS MILESTONE-2 signed package manifest boundary",
        "url": "file:MILESTONE_2_SIGNED_PACKAGE_MANIFEST.md",
    },
]


class SemanticHookInstallPlanStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        semantic_hook_run_id: str,
        source_root: str | Path | None = None,
        label: str = "manual-semantic-hook-install-plan",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            hook_run = (state.get("semantic_hook_runs") or {}).get(semantic_hook_run_id)
            if not hook_run:
                raise KeyError(f"semantic hook run not found: {semantic_hook_run_id}")
            hook_records = [
                record
                for record in (state.get("semantic_hook_records") or {}).values()
                if record.get("semantic_hook_run_id") == semantic_hook_run_id
            ]
            record = build_semantic_hook_install_plan(
                semantic_hook_run=hook_run,
                semantic_hook_records=hook_records,
                source_root=source_root,
                label=label,
            )
            plan_id = record["semantic_hook_install_plan_id"]
            state.setdefault("semantic_hook_install_plans", {})[plan_id] = record
            state.setdefault("indexes", {}).setdefault("semantic_hook_install_plan_ids", {})[plan_id] = plan_id
            return deepcopy(record)


def build_semantic_hook_install_plan(
    *,
    semantic_hook_run: dict[str, Any],
    semantic_hook_records: list[dict[str, Any]],
    source_root: str | Path | None = None,
    label: str = "manual-semantic-hook-install-plan",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False) if source_root else repo_root()
    hook_run_id = semantic_hook_run.get("semantic_hook_run_id")
    codex_preview = semantic_hook_run.get("codex_hook_config_preview") or {}
    claude_preview = semantic_hook_run.get("claude_hook_contract_preview") or {}
    codex_preview_sha = sha256_text(canonical_json(codex_preview))
    claude_preview_sha = sha256_text(canonical_json(claude_preview))
    hook_records_sorted = sorted(semantic_hook_records, key=lambda item: item.get("semantic_hook_record_id", ""))
    hook_record_set_sha = sha256_text(
        canonical_json(
            [
                {
                    "semantic_hook_record_id": item.get("semantic_hook_record_id"),
                    "semantic_hook_record_sha256": item.get("semantic_hook_record_sha256"),
                    "record_family": item.get("record_family"),
                }
                for item in hook_records_sorted
            ]
        )
    )
    install_targets = _install_targets(root=root, codex_preview_sha=codex_preview_sha, claude_preview_sha=claude_preview_sha)
    readiness = _readiness(semantic_hook_run=semantic_hook_run, hook_records=hook_records_sorted)
    status = _status(readiness)
    reason_codes = _reason_codes(status, readiness)
    record = {
        "schema_version": SCHEMA_VERSION,
        "semantic_hook_install_plan_id": stable_id(
            "semhookinstall",
            label,
            hook_run_id,
            semantic_hook_run.get("semantic_hook_run_sha256"),
            codex_preview_sha,
            claude_preview_sha,
            hook_record_set_sha,
            now,
        ),
        "label": label,
        "source_root": str(root),
        "semantic_hook_run_id": hook_run_id,
        "semantic_hook_run_sha256": semantic_hook_run.get("semantic_hook_run_sha256"),
        "semantic_oracle_review_id": semantic_hook_run.get("semantic_oracle_review_id"),
        "semantic_gap_remaining_count": int((semantic_hook_run.get("coverage") or {}).get("semantic_gap_remaining_count") or 0),
        "covered_hook_count": int((semantic_hook_run.get("coverage") or {}).get("covered_hook_count") or 0),
        "covered_record_family_count": int((semantic_hook_run.get("coverage") or {}).get("covered_record_family_count") or 0),
        "semantic_hook_record_count": len(hook_records_sorted),
        "semantic_hook_record_set_sha256": hook_record_set_sha,
        "codex_hook_config_preview_sha256": codex_preview_sha,
        "claude_hook_contract_preview_sha256": claude_preview_sha,
        "install_targets": install_targets,
        "trust_review_plan": _trust_review_plan(codex_preview_sha=codex_preview_sha, claude_preview_sha=claude_preview_sha),
        "signing_requirements": _signing_requirements(),
        "rollback_plan": _rollback_plan(),
        "operator_approval": {
            "required": True,
            "approval_granted": False,
            "approval_id": None,
            "reason_code": "semantic_hook_install.operator_approval_required",
        },
        "readiness": readiness,
        "research_basis": RESEARCH_BASIS,
        "live_boundaries": dict(LIVE_BOUNDARIES),
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["semantic_hook_install_plan_sha256"] = _hash_without(record, "semantic_hook_install_plan_sha256")
    return deepcopy(record)


def validate_semantic_hook_install_plan_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("semantic_hook_install_plan.schema.json", record, location="semantic_hook_install_plan")
    except SchemaValidationError:
        reason_codes.append("semantic_hook_install_plan.schema_invalid")
    expected_hash = record.get("semantic_hook_install_plan_sha256")
    if expected_hash and expected_hash != _hash_without(record, "semantic_hook_install_plan_sha256"):
        reason_codes.append("semantic_hook_install_plan.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("semantic_hook_install_plan.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("semantic_hook_install_plan.status_invalid")
    for key, expected in LIVE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"semantic_hook_install_plan.{key}_not_false")
    for target in record.get("install_targets") or []:
        if target.get("write_performed") is not False:
            reason_codes.append("semantic_hook_install_plan.target_write_performed_not_false")
        if target.get("installed") is not False:
            reason_codes.append("semantic_hook_install_plan.target_installed_not_false")
    approval = record.get("operator_approval") or {}
    if approval.get("approval_granted") is not False:
        reason_codes.append("semantic_hook_install_plan.approval_granted_not_false")
    expected_status = _status(record.get("readiness") or {})
    if record.get("status") != expected_status:
        reason_codes.append("semantic_hook_install_plan.status_reason_mismatch")
    if sorted(record.get("reason_codes") or []) != sorted(_reason_codes(expected_status, record.get("readiness") or {})):
        reason_codes.append("semantic_hook_install_plan.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _install_targets(root: Path, codex_preview_sha: str, claude_preview_sha: str) -> list[dict[str, Any]]:
    return [
        {
            "target": "codex_user_hooks_json",
            "path": "~/.codex/hooks.json",
            "config_sha256": codex_preview_sha,
            "write_performed": False,
            "installed": False,
            "trust_review_required": True,
            "rollback_required": True,
        },
        {
            "target": "codex_project_hooks_json",
            "path": str(root / ".codex" / "hooks.json"),
            "config_sha256": codex_preview_sha,
            "write_performed": False,
            "installed": False,
            "trust_review_required": True,
            "rollback_required": True,
        },
        {
            "target": "claude_hook_contract",
            "path": str(root / ".claude" / "hooks.json"),
            "config_sha256": claude_preview_sha,
            "write_performed": False,
            "installed": False,
            "trust_review_required": True,
            "rollback_required": True,
        },
    ]


def _trust_review_plan(*, codex_preview_sha: str, claude_preview_sha: str) -> list[dict[str, Any]]:
    return [
        {
            "surface": "codex",
            "review_command": "/hooks",
            "review_required": True,
            "trusted": False,
            "config_sha256": codex_preview_sha,
        },
        {
            "surface": "claude",
            "review_command": "operator-reviewed Claude hook contract",
            "review_required": True,
            "trusted": False,
            "config_sha256": claude_preview_sha,
        },
    ]


def _signing_requirements() -> dict[str, Any]:
    return {
        "signed_package_required": True,
        "pinned_signer_required": True,
        "verified_signed_package_present": False,
        "reason_code": "semantic_hook_install.signed_package_required_before_install",
    }


def _rollback_plan() -> list[dict[str, Any]]:
    return [
        {"step": "backup_existing_hook_files", "required": True, "completed": False},
        {"step": "write_new_hooks_with_no_egress_mode", "required": True, "completed": False},
        {"step": "verify_hooks_listed_but_not_trusted", "required": True, "completed": False},
        {"step": "restore_previous_hook_files_on_failure", "required": True, "completed": False},
    ]


def _readiness(*, semantic_hook_run: dict[str, Any], hook_records: list[dict[str, Any]]) -> dict[str, Any]:
    coverage = semantic_hook_run.get("coverage") or {}
    hook_run_ok = semantic_hook_run.get("status") == "allow"
    semantic_gap_remaining = int(coverage.get("semantic_gap_remaining_count") or 0)
    expected_record_count = int(coverage.get("required_record_family_count") or 0)
    actual_record_count = len(hook_records)
    return {
        "semantic_hook_run_allow": hook_run_ok,
        "semantic_gap_remaining_count": semantic_gap_remaining,
        "expected_hook_record_count": expected_record_count,
        "actual_hook_record_count": actual_record_count,
        "hook_record_count_ok": expected_record_count == actual_record_count,
        "signed_package_verified": False,
        "operator_approval_granted": False,
        "live_install_allowed": False,
    }


def _status(readiness: dict[str, Any]) -> str:
    if not readiness.get("semantic_hook_run_allow"):
        return "deny"
    if int(readiness.get("semantic_gap_remaining_count") or 0) != 0:
        return "deny"
    if not readiness.get("hook_record_count_ok"):
        return "deny"
    return "ready_for_operator_review"


def _reason_codes(status: str, readiness: dict[str, Any]) -> list[str]:
    reasons: list[str] = [
        "semantic_hook_install.no_live_boundaries",
        "semantic_hook_install.operator_approval_required",
        "semantic_hook_install.signed_package_required_before_install",
        "semantic_hook_install.trust_review_required",
    ]
    if not readiness.get("semantic_hook_run_allow"):
        reasons.append("semantic_hook_install.semantic_hook_run_not_allow")
    if int(readiness.get("semantic_gap_remaining_count") or 0) != 0:
        reasons.append("semantic_hook_install.semantic_gaps_remaining")
    if not readiness.get("hook_record_count_ok"):
        reasons.append("semantic_hook_install.hook_record_count_mismatch")
    if status == "ready_for_operator_review":
        reasons.append("semantic_hook_install.ready_for_operator_review")
    elif status == "deny":
        reasons.append("semantic_hook_install.denied")
    else:
        reasons.append("semantic_hook_install.defer")
    return sorted(set(reasons))
