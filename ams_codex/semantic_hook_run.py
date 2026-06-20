from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore
from .workspace import repo_root


SCHEMA_VERSION = "ams.ams_codex.semantic_hook_run.v0"
STATUSES = {"allow", "defer", "deny"}
RUNNER_MODES = {"sandbox_simulated"}

LIVE_BOUNDARIES = {
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
    "hook_installed": False,
    "hook_command_executed_by_provider": False,
}

HOOK_MATCHERS = {
    "PostCompact": "manual|auto",
    "PreCompact": "manual|auto",
    "SessionStart": "startup|resume|clear|compact",
    "Stop": "",
    "UserPromptSubmit": "",
}

RECORD_FAMILY_TO_HOOKS = {
    "attention_signal": ["UserPromptSubmit", "Stop"],
    "capability_admission": ["UserPromptSubmit"],
    "counterfactual_retrieval_check": ["UserPromptSubmit"],
    "egress_gate": ["UserPromptSubmit", "Stop"],
    "generated_status_snapshot": ["SessionStart", "UserPromptSubmit"],
    "manager_intervention": ["Stop", "UserPromptSubmit"],
    "manager_readback_settlement": ["Stop"],
    "rag_taint_label": ["UserPromptSubmit"],
    "resume_epoch": ["PostCompact", "SessionStart"],
    "summary_checkpoint": ["PreCompact", "PostCompact"],
    "work_mode_decision": ["SessionStart", "UserPromptSubmit"],
}

RECORD_FAMILY_PURPOSES = {
    "attention_signal": "Classify important/urgent source signals before the worker drifts.",
    "capability_admission": "Bind requested tool/path authority before execution.",
    "counterfactual_retrieval_check": "Compare retrieved context against a null/reference path for taint-sensitive work.",
    "egress_gate": "Require AMS approval before any user-visible or network egress.",
    "generated_status_snapshot": "Use generated authority state instead of model memory for status claims.",
    "manager_intervention": "Create manager reminders for attention-loss and digression risks.",
    "manager_readback_settlement": "Require target-agent readback before clearing manager interventions.",
    "rag_taint_label": "Mark retrieved/source refs with taint labels before they influence action.",
    "resume_epoch": "Record session/compaction epoch so resume cannot silently use stale context.",
    "summary_checkpoint": "Force a compact structured checkpoint before compaction-sensitive work proceeds.",
    "work_mode_decision": "Classify whether the request needs session-isolation, cleanup, both, or standard checks.",
}

RESEARCH_BASIS = [
    {
        "lens": "codex_hooks",
        "source": "OpenAI Codex manual: Hooks",
        "url": "https://developers.openai.com/codex/hooks.md",
    },
    {
        "lens": "codex_app_server",
        "source": "OpenAI Codex manual: App Server lifecycle",
        "url": "https://developers.openai.com/codex/app-server.md",
    },
    {
        "lens": "prompt_injection_eval",
        "source": "AgentDojo prompt-injection evaluation",
        "url": "https://arxiv.org/abs/2406.13352",
    },
    {
        "lens": "agentic_security",
        "source": "OWASP Agentic Security Initiative",
        "url": "https://genai.owasp.org/initiatives/agentic-security-initiative/",
    },
]


class SemanticHookRunStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        semantic_oracle_review_id: str,
        source_root: str | Path | None = None,
        label: str = "manual-semantic-hook-run",
        runner_mode: str = "sandbox_simulated",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            review = (state.get("semantic_oracle_reviews") or {}).get(semantic_oracle_review_id)
            if not review:
                raise KeyError(f"semantic oracle review not found: {semantic_oracle_review_id}")
            record, hook_records = build_semantic_hook_run(
                semantic_oracle_review=review,
                source_root=source_root,
                label=label,
                runner_mode=runner_mode,
            )
            run_id = record["semantic_hook_run_id"]
            for hook_record in hook_records:
                hook_record_id = hook_record["semantic_hook_record_id"]
                state.setdefault("semantic_hook_records", {})[hook_record_id] = hook_record
                state.setdefault("indexes", {}).setdefault("semantic_hook_record_ids", {})[hook_record_id] = hook_record_id
            state.setdefault("semantic_hook_runs", {})[run_id] = record
            state.setdefault("indexes", {}).setdefault("semantic_hook_run_ids", {})[run_id] = run_id
            return deepcopy(record)


def build_semantic_hook_run(
    *,
    semantic_oracle_review: dict[str, Any],
    source_root: str | Path | None = None,
    label: str = "manual-semantic-hook-run",
    runner_mode: str = "sandbox_simulated",
    now: str | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if runner_mode not in RUNNER_MODES:
        raise ValueError(f"unsupported semantic hook runner mode: {runner_mode}")
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False) if source_root else repo_root()
    contract = semantic_oracle_review.get("hook_shim_contract") or {}
    required_hooks = sorted(str(item) for item in contract.get("required_hooks") or [])
    required_records = sorted(str(item) for item in contract.get("required_records") or [])
    metrics = semantic_oracle_review.get("metrics") or {}
    semantic_gap_count = int(metrics.get("semantic_gap_count") or 0)
    semantic_matched_count = int(metrics.get("semantic_matched_scenario_count") or 0)
    run_id = stable_id(
        "semhook",
        label,
        semantic_oracle_review.get("semantic_oracle_review_id"),
        semantic_oracle_review.get("semantic_oracle_review_sha256"),
        required_hooks,
        required_records,
        semantic_gap_count,
        now,
    )
    hook_receipts = _hook_receipts(
        run_id=run_id,
        required_hooks=required_hooks,
        required_records=required_records,
        semantic_oracle_review=semantic_oracle_review,
    )
    hook_records = _semantic_hook_records(
        run_id=run_id,
        semantic_oracle_review=semantic_oracle_review,
        required_records=required_records,
        required_hooks=required_hooks,
        semantic_gap_count=semantic_gap_count,
        now=now,
    )
    record_family_receipts = _record_family_receipts(
        hook_records=hook_records,
        required_records=required_records,
        required_hooks=required_hooks,
        semantic_gap_count=semantic_gap_count,
    )
    coverage = _coverage(
        semantic_gap_count=semantic_gap_count,
        semantic_matched_count=semantic_matched_count,
        required_hooks=required_hooks,
        required_records=required_records,
        hook_receipts=hook_receipts,
        record_family_receipts=record_family_receipts,
    )
    status = _status(coverage)
    reason_codes = _reason_codes(status, coverage)
    record = {
        "schema_version": SCHEMA_VERSION,
        "semantic_hook_run_id": run_id,
        "label": label,
        "source_root": str(root),
        "runner_mode": runner_mode,
        "semantic_oracle_review_id": semantic_oracle_review.get("semantic_oracle_review_id"),
        "semantic_oracle_review_sha256": semantic_oracle_review.get("semantic_oracle_review_sha256"),
        "simulation_sweep_id": semantic_oracle_review.get("simulation_sweep_id"),
        "simulation_sweep_sha256": semantic_oracle_review.get("simulation_sweep_sha256"),
        "hook_contract_sha256": sha256_text(canonical_json(contract)),
        "required_hooks": required_hooks,
        "required_record_families": required_records,
        "hook_event_receipts": hook_receipts,
        "record_family_receipts": record_family_receipts,
        "coverage": coverage,
        "codex_hook_config_preview": _codex_hook_config_preview(required_hooks),
        "claude_hook_contract_preview": _claude_hook_contract_preview(required_hooks),
        "research_basis": RESEARCH_BASIS,
        "live_boundaries": dict(LIVE_BOUNDARIES),
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["semantic_hook_run_sha256"] = _hash_without(record, "semantic_hook_run_sha256")
    return deepcopy(record), deepcopy(hook_records)


def validate_semantic_hook_record_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("semantic_hook_record.schema.json", record, location="semantic_hook_record")
    except SchemaValidationError:
        reason_codes.append("semantic_hook_record.schema_invalid")
    expected_hash = record.get("semantic_hook_record_sha256")
    if expected_hash and expected_hash != _hash_without(record, "semantic_hook_record_sha256"):
        reason_codes.append("semantic_hook_record.hash_mismatch")
    if record.get("schema_version") != "ams.ams_codex.semantic_hook_record.v0":
        reason_codes.append("semantic_hook_record.schema_version_invalid")
    if record.get("status") != "recorded":
        reason_codes.append("semantic_hook_record.status_invalid")
    if record.get("raw_payload_stored") is not False:
        reason_codes.append("semantic_hook_record.raw_payload_not_false")
    for key, expected in LIVE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"semantic_hook_record.{key}_not_false")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def validate_semantic_hook_run_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("semantic_hook_run.schema.json", record, location="semantic_hook_run")
    except SchemaValidationError:
        reason_codes.append("semantic_hook_run.schema_invalid")
    expected_hash = record.get("semantic_hook_run_sha256")
    if expected_hash and expected_hash != _hash_without(record, "semantic_hook_run_sha256"):
        reason_codes.append("semantic_hook_run.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("semantic_hook_run.schema_version_invalid")
    if record.get("runner_mode") not in RUNNER_MODES:
        reason_codes.append("semantic_hook_run.runner_mode_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("semantic_hook_run.status_invalid")
    for key, expected in LIVE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"semantic_hook_run.{key}_not_false")

    required_hooks = sorted(record.get("required_hooks") or [])
    required_records = sorted(record.get("required_record_families") or [])
    hook_receipts = record.get("hook_event_receipts") or []
    record_receipts = record.get("record_family_receipts") or []
    hook_names = sorted({item.get("hook_event") for item in hook_receipts})
    record_names = sorted({item.get("record_family") for item in record_receipts})
    coverage = record.get("coverage") or {}
    missing_hooks = sorted(set(required_hooks) - set(hook_names))
    missing_records = sorted(set(required_records) - set(record_names))

    if missing_hooks != sorted(coverage.get("missing_hooks") or []):
        reason_codes.append("semantic_hook_run.missing_hooks_mismatch")
    if missing_records != sorted(coverage.get("missing_record_families") or []):
        reason_codes.append("semantic_hook_run.missing_records_mismatch")
    if coverage.get("required_hook_count") != len(required_hooks):
        reason_codes.append("semantic_hook_run.required_hook_count_mismatch")
    if coverage.get("covered_hook_count") != len(set(hook_names) & set(required_hooks)):
        reason_codes.append("semantic_hook_run.covered_hook_count_mismatch")
    if coverage.get("required_record_family_count") != len(required_records):
        reason_codes.append("semantic_hook_run.required_record_count_mismatch")
    if coverage.get("covered_record_family_count") != len(set(record_names) & set(required_records)):
        reason_codes.append("semantic_hook_run.covered_record_count_mismatch")
    semantic_gap_count = int(coverage.get("semantic_gap_input_count") or 0)
    if coverage.get("semantic_gap_covered_count") != (0 if (missing_hooks or missing_records) else semantic_gap_count):
        reason_codes.append("semantic_hook_run.semantic_gap_coverage_mismatch")
    for receipt in hook_receipts:
        if receipt.get("hook_installed") is not False:
            reason_codes.append("semantic_hook_run.hook_receipt_installed_not_false")
        if receipt.get("provider_executed") is not False:
            reason_codes.append("semantic_hook_run.hook_receipt_provider_executed_not_false")
        if receipt.get("status") != "recorded":
            reason_codes.append("semantic_hook_run.hook_receipt_status_invalid")
    for receipt in record_receipts:
        if receipt.get("raw_payload_stored") is not False:
            reason_codes.append("semantic_hook_run.record_receipt_raw_payload_not_false")
        if receipt.get("coverage_semantic_gap_count") != semantic_gap_count:
            reason_codes.append("semantic_hook_run.record_receipt_gap_count_mismatch")

    expected_status = _status(coverage)
    if record.get("status") != expected_status:
        reason_codes.append("semantic_hook_run.status_reason_mismatch")
    if sorted(record.get("reason_codes") or []) != sorted(_reason_codes(expected_status, coverage)):
        reason_codes.append("semantic_hook_run.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _hook_receipts(
    *,
    run_id: str,
    required_hooks: list[str],
    required_records: list[str],
    semantic_oracle_review: dict[str, Any],
) -> list[dict[str, Any]]:
    receipts: list[dict[str, Any]] = []
    review_ref = f"ams://semantic-oracle-review/{semantic_oracle_review.get('semantic_oracle_review_id')}"
    for hook in required_hooks:
        produced_records = [
            family
            for family in required_records
            if hook in RECORD_FAMILY_TO_HOOKS.get(family, []) or not RECORD_FAMILY_TO_HOOKS.get(family)
        ]
        payload = {
            "hook_event": hook,
            "runner_mode": "sandbox_simulated",
            "review_ref": review_ref,
            "produced_record_families": produced_records,
        }
        receipts.append(
            {
                "hook_event": hook,
                "matcher": HOOK_MATCHERS.get(hook, ""),
                "turn_scope": hook not in {"SessionStart"},
                "thread_scope": hook == "SessionStart",
                "source_ref": review_ref,
                "produced_record_families": produced_records,
                "hook_installed": False,
                "provider_executed": False,
                "raw_input_stored": False,
                "receipt_sha256": sha256_text(canonical_json(payload)),
                "status": "recorded",
                "reason_code": f"semantic_hook_run.{hook}.sandbox_receipt",
            }
        )
    return receipts


def _record_family_receipts(
    *,
    hook_records: list[dict[str, Any]],
    required_records: list[str],
    required_hooks: list[str],
    semantic_gap_count: int,
) -> list[dict[str, Any]]:
    receipts: list[dict[str, Any]] = []
    records_by_family = {record["record_family"]: record for record in hook_records}
    for family in required_records:
        hook_record = records_by_family[family]
        source_hooks = [hook for hook in RECORD_FAMILY_TO_HOOKS.get(family, []) if hook in required_hooks]
        if not source_hooks and required_hooks:
            source_hooks = [required_hooks[0]]
        receipts.append(
            {
                "record_family": family,
                "source_hooks": source_hooks,
                "semantic_hook_record_id": hook_record["semantic_hook_record_id"],
                "semantic_hook_record_sha256": hook_record["semantic_hook_record_sha256"],
                "stored_record_ref": f"ams://semantic-hook-record/{hook_record['semantic_hook_record_id']}",
                "raw_payload_stored": False,
                "coverage_semantic_gap_count": semantic_gap_count,
                "purpose": hook_record["purpose"],
                "status": "recorded",
                "reason_code": f"semantic_hook_run.{family}.receipt_recorded",
            }
        )
    return receipts


def _semantic_hook_records(
    *,
    run_id: str,
    semantic_oracle_review: dict[str, Any],
    required_records: list[str],
    required_hooks: list[str],
    semantic_gap_count: int,
    now: str,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for family in required_records:
        source_hooks = [hook for hook in RECORD_FAMILY_TO_HOOKS.get(family, []) if hook in required_hooks]
        if not source_hooks and required_hooks:
            source_hooks = [required_hooks[0]]
        payload_shape = {
            "record_family": family,
            "source_hooks": source_hooks,
            "fields": [
                "source_ref",
                "source_sha256",
                "semantic_gap_ids_or_count",
                "authority_state",
                "no_raw_content",
            ],
        }
        record = {
            "schema_version": "ams.ams_codex.semantic_hook_record.v0",
            "semantic_hook_record_id": stable_id(
                "semhookrec",
                run_id,
                semantic_oracle_review.get("semantic_oracle_review_id"),
                family,
                source_hooks,
                semantic_gap_count,
            ),
            "semantic_hook_run_id": run_id,
            "semantic_oracle_review_id": semantic_oracle_review.get("semantic_oracle_review_id"),
            "semantic_oracle_review_sha256": semantic_oracle_review.get("semantic_oracle_review_sha256"),
            "simulation_sweep_id": semantic_oracle_review.get("simulation_sweep_id"),
            "record_family": family,
            "source_hooks": source_hooks,
            "coverage_semantic_gap_count": semantic_gap_count,
            "purpose": RECORD_FAMILY_PURPOSES.get(family, "Semantic hook-run record family receipt."),
            "payload_shape_sha256": sha256_text(canonical_json(payload_shape)),
            "raw_payload_stored": False,
            "live_boundaries": dict(LIVE_BOUNDARIES),
            "status": "recorded",
            "reason_codes": [f"semantic_hook_record.{family}.recorded"],
            "created_at": now,
        }
        record["semantic_hook_record_sha256"] = _hash_without(record, "semantic_hook_record_sha256")
        records.append(record)
    return records


def _coverage(
    *,
    semantic_gap_count: int,
    semantic_matched_count: int,
    required_hooks: list[str],
    required_records: list[str],
    hook_receipts: list[dict[str, Any]],
    record_family_receipts: list[dict[str, Any]],
) -> dict[str, Any]:
    covered_hooks = sorted({item["hook_event"] for item in hook_receipts if item.get("status") == "recorded"})
    covered_records = sorted(
        {item["record_family"] for item in record_family_receipts if item.get("status") == "recorded"}
    )
    missing_hooks = sorted(set(required_hooks) - set(covered_hooks))
    missing_records = sorted(set(required_records) - set(covered_records))
    semantic_gap_covered_count = 0 if (missing_hooks or missing_records) else semantic_gap_count
    return {
        "semantic_matched_scenario_count": semantic_matched_count,
        "semantic_gap_input_count": semantic_gap_count,
        "semantic_gap_covered_count": semantic_gap_covered_count,
        "semantic_gap_remaining_count": max(semantic_gap_count - semantic_gap_covered_count, 0),
        "coverage_rate": round(semantic_gap_covered_count / semantic_gap_count, 4) if semantic_gap_count else 1.0,
        "required_hook_count": len(required_hooks),
        "covered_hook_count": len(set(covered_hooks) & set(required_hooks)),
        "missing_hooks": missing_hooks,
        "required_record_family_count": len(required_records),
        "covered_record_family_count": len(set(covered_records) & set(required_records)),
        "missing_record_families": missing_records,
        "hook_event_receipt_count": len(hook_receipts),
        "record_family_receipt_count": len(record_family_receipts),
    }


def _status(coverage: dict[str, Any]) -> str:
    if int(coverage.get("required_hook_count") or 0) < 1:
        return "deny"
    if coverage.get("missing_hooks") or coverage.get("missing_record_families"):
        return "defer"
    if int(coverage.get("semantic_gap_remaining_count") or 0) > 0:
        return "defer"
    return "allow"


def _reason_codes(status: str, coverage: dict[str, Any]) -> list[str]:
    reasons: list[str] = ["semantic_hook_run.no_live_boundaries"]
    if int(coverage.get("required_hook_count") or 0) < 1:
        reasons.append("semantic_hook_run.no_required_hooks")
    if coverage.get("missing_hooks"):
        reasons.append("semantic_hook_run.missing_hooks")
    if coverage.get("missing_record_families"):
        reasons.append("semantic_hook_run.missing_record_families")
    if int(coverage.get("semantic_gap_remaining_count") or 0) > 0:
        reasons.append("semantic_hook_run.semantic_gaps_remaining")
    if status == "allow":
        reasons.append("semantic_hook_run.local_contract_covered")
    elif status == "defer":
        reasons.append("semantic_hook_run.operator_review_required")
    else:
        reasons.append("semantic_hook_run.denied")
    return sorted(set(reasons))


def _codex_hook_config_preview(required_hooks: list[str]) -> dict[str, Any]:
    hooks: dict[str, Any] = {}
    for hook in required_hooks:
        entry: dict[str, Any] = {
            "hooks": [
                {
                    "type": "command",
                    "command": "python3 -m ams_codex.cli semantic-hook-run --semantic-oracle-review-id <review-id>",
                    "statusMessage": "Recording AMS semantic hook receipt",
                }
            ]
        }
        matcher = HOOK_MATCHERS.get(hook)
        if matcher:
            entry["matcher"] = matcher
        hooks[hook] = [entry]
    return {
        "format": "hooks.json-preview",
        "installed": False,
        "trust_required_before_live_use": True,
        "hooks": hooks,
    }


def _claude_hook_contract_preview(required_hooks: list[str]) -> dict[str, Any]:
    return {
        "format": "agent-sdk-hook-contract-preview",
        "installed": False,
        "required_lifecycle_events": required_hooks,
        "notes": "Preview only; no Claude hook file or provider process is started.",
    }
