from __future__ import annotations

from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
from typing import Any

from .durability import fsync_dir, fsync_path
from .models import hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore
from .workspace import repo_root


SCHEMA_VERSION = "ams.ams.semantic_oracle_review.v0"
STATUSES = {"allow", "defer", "deny"}
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
}

RESEARCH_BASIS = [
    {
        "lens": "semantic_eval",
        "source": "AgentDojo prompt-injection evaluation",
        "url": "https://arxiv.org/abs/2406.13352",
    },
    {
        "lens": "agentic_security",
        "source": "OWASP Agentic Security Initiative",
        "url": "https://genai.owasp.org/initiatives/agentic-security-initiative/",
    },
    {
        "lens": "multi_agent_failures",
        "source": "Why Do Multi-Agent LLM Systems Fail?",
        "url": "https://arxiv.org/abs/2503.13657",
    },
    {
        "lens": "codex_lifecycle",
        "source": "OpenAI Codex hooks documentation",
        "url": "https://developers.openai.com/codex/hooks.md",
    },
]

SEMANTIC_RULES = (
    {
        "rule_id": "semantic.prompt_injection_trace_required",
        "fault": "prompt_injection",
        "required_features": ["capability_policy", "rag_taint_boundary", "egress_gate", "replay_oracle"],
        "required_hooks": ["UserPromptSubmit"],
        "required_records": ["attention_signal", "rag_taint_label", "capability_admission", "egress_gate"],
        "closes_research_need": "semantic_oracle_for_unrecorded_agent_failures",
    },
    {
        "rule_id": "semantic.attention_drop_rescue_required",
        "fault": "attention_drop",
        "required_features": ["attention_router", "manager_intervention", "replay_oracle"],
        "required_hooks": ["UserPromptSubmit", "Stop"],
        "required_records": ["attention_signal", "manager_intervention", "manager_readback_settlement"],
        "closes_research_need": "semantic_oracle_for_unrecorded_agent_failures",
    },
    {
        "rule_id": "semantic.stale_context_epoch_required",
        "fault": "stale_context",
        "required_features": ["session_registry", "checkpoint_compaction", "replay_oracle"],
        "required_hooks": ["PreCompact", "PostCompact", "SessionStart"],
        "required_records": ["work_mode_decision", "summary_checkpoint", "resume_epoch"],
        "closes_research_need": "resume_epoch_and_surface_binding_reconciliation",
    },
    {
        "rule_id": "semantic.missing_checkpoint_forbidden",
        "fault": "missing_checkpoint",
        "required_features": ["checkpoint_compaction", "replay_oracle"],
        "required_hooks": ["PreCompact"],
        "required_records": ["summary_checkpoint", "work_mode_decision"],
        "closes_research_need": "precompact_checkpoint_forced_lifecycle_hook",
    },
    {
        "rule_id": "semantic.rag_taint_counterfactual_required",
        "fault": "rag_taint",
        "required_features": ["rag_taint_boundary"],
        "required_hooks": ["UserPromptSubmit"],
        "required_records": ["rag_taint_label", "counterfactual_retrieval_check"],
        "closes_research_need": "causal_taint_and_counterfactual_retrieval",
    },
    {
        "rule_id": "semantic.status_truth_source_required",
        "fault": "hallucinated_status",
        "required_features": ["work_mode_decision", "docs_governance"],
        "required_hooks": ["UserPromptSubmit", "SessionStart"],
        "required_records": ["generated_status_snapshot", "work_mode_decision"],
        "closes_research_need": "generated_status_truth_source",
    },
)


class SemanticOracleReviewStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        simulation_sweep_id: str,
        source_root: str | Path | None = None,
        output_path: str | Path | None = None,
        label: str = "manual-semantic-oracle-review",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            sweep = (state.get("simulation_sweeps") or {}).get(simulation_sweep_id)
            if not sweep:
                raise KeyError(f"simulation sweep not found: {simulation_sweep_id}")
            record = build_semantic_oracle_review(
                sweep=sweep,
                source_root=source_root,
                output_path=output_path,
                label=label,
            )
            review_id = record["semantic_oracle_review_id"]
            state.setdefault("semantic_oracle_reviews", {})[review_id] = record
            state.setdefault("indexes", {}).setdefault("semantic_oracle_review_ids", {})[review_id] = review_id
            return deepcopy(record)


def build_semantic_oracle_review(
    *,
    sweep: dict[str, Any],
    source_root: str | Path | None = None,
    output_path: str | Path | None = None,
    label: str = "manual-semantic-oracle-review",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False) if source_root else repo_root()
    scenario_artifact = _scenario_artifact(sweep)
    rows = _load_jsonl(Path(scenario_artifact["path"]))
    rule_results = [_evaluate_rule(rule, rows) for rule in SEMANTIC_RULES]
    metrics = _metrics(rows, rule_results)
    status = _status(metrics)
    reason_codes = _reason_codes(status, metrics)
    output = Path(output_path).expanduser().resolve(strict=False) if output_path else Path(sweep["simulation_area"]) / "semantic_oracle_review.json"
    hook_shim_contract = _hook_shim_contract(rule_results)

    record = {
        "schema_version": SCHEMA_VERSION,
        "semantic_oracle_review_id": stable_id(
            "semoracle",
            label,
            sweep.get("simulation_sweep_id"),
            sweep.get("simulation_sweep_sha256"),
            metrics["semantic_gap_count"],
            now,
        ),
        "label": label,
        "source_root": str(root),
        "simulation_sweep_id": sweep.get("simulation_sweep_id"),
        "simulation_sweep_sha256": sweep.get("simulation_sweep_sha256"),
        "scenario_artifact": scenario_artifact,
        "reviewed_scenario_count": len(rows),
        "semantic_rules": list(SEMANTIC_RULES),
        "rule_results": rule_results,
        "hook_shim_contract": hook_shim_contract,
        "metrics": metrics,
        "research_basis": RESEARCH_BASIS,
        "live_boundaries": dict(LIVE_BOUNDARIES),
        "artifacts": [
            {"path": str(output), "kind": "semantic_oracle_review_json", "sha256": None},
        ],
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["semantic_oracle_review_sha256"] = _hash_without(record, "semantic_oracle_review_sha256")
    _write_json(output, _summary(record))
    record["artifacts"][0] = _artifact_ref(output, "semantic_oracle_review_json")
    record["semantic_oracle_review_sha256"] = _hash_without(record, "semantic_oracle_review_sha256")
    return deepcopy(record)


def validate_semantic_oracle_review_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("semantic_oracle_review.schema.json", record, location="semantic_oracle_review")
    except SchemaValidationError:
        reason_codes.append("semantic_oracle_review.schema_invalid")
    expected_hash = record.get("semantic_oracle_review_sha256")
    if expected_hash and expected_hash != _hash_without(record, "semantic_oracle_review_sha256"):
        reason_codes.append("semantic_oracle_review.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("semantic_oracle_review.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("semantic_oracle_review.status_invalid")
    for key, expected in LIVE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"semantic_oracle_review.{key}_not_false")
    metrics = record.get("metrics") or {}
    if metrics.get("reviewed_scenario_count") != record.get("reviewed_scenario_count"):
        reason_codes.append("semantic_oracle_review.metrics_count_mismatch")
    expected_status = _status(metrics)
    if record.get("status") != expected_status:
        reason_codes.append("semantic_oracle_review.status_reason_mismatch")
    if sorted(record.get("reason_codes") or []) != sorted(_reason_codes(expected_status, metrics)):
        reason_codes.append("semantic_oracle_review.reason_codes_mismatch")
    hook = record.get("hook_shim_contract") or {}
    if hook.get("live_installed") is not False:
        reason_codes.append("semantic_oracle_review.hook_live_installed")
    if hook.get("enforcement_mode") != "contract_only":
        reason_codes.append("semantic_oracle_review.hook_enforcement_mode_invalid")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _scenario_artifact(sweep: dict[str, Any]) -> dict[str, Any]:
    for artifact in sweep.get("artifacts") or []:
        if artifact.get("kind") == "scenario_results_jsonl":
            return dict(artifact)
    raise ValueError("simulation sweep has no scenario_results_jsonl artifact")


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                item = json.loads(line)
                if isinstance(item, dict):
                    rows.append(item)
    return rows


def _evaluate_rule(rule: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    matched = [row for row in rows if (row.get("dimensions") or {}).get("fault") == rule["fault"]]
    detected = []
    covered = 0
    for row in matched:
        reactions = {item.get("feature"): item for item in row.get("feature_reactions") or []}
        missing_features = [feature for feature in rule["required_features"] if feature not in reactions]
        weak_features = [
            feature
            for feature in rule["required_features"]
            if int((reactions.get(feature) or {}).get("score", 0)) < 90
        ]
        if missing_features or weak_features:
            detected.append(
                {
                    "scenario_id": row.get("scenario_id"),
                    "missing_features": missing_features,
                    "weak_features": weak_features,
                    "required_records": rule["required_records"],
                }
            )
        else:
            covered += 1
    return {
        "rule_id": rule["rule_id"],
        "fault": rule["fault"],
        "matched_scenarios": len(matched),
        "covered_scenarios": covered,
        "semantic_gap_count": len(detected),
        "sample_gaps": detected[:12],
        "status": "allow" if not detected else "defer",
        "required_hooks": rule["required_hooks"],
        "required_records": rule["required_records"],
        "closes_research_need": rule["closes_research_need"],
    }


def _hook_shim_contract(rule_results: list[dict[str, Any]]) -> dict[str, Any]:
    hooks = sorted({hook for result in rule_results for hook in result.get("required_hooks", [])})
    records = sorted({record for result in rule_results for record in result.get("required_records", [])})
    return {
        "enforcement_mode": "contract_only",
        "live_installed": False,
        "required_hooks": hooks,
        "required_records": records,
        "preflight_commands": [
            "python3 -m ams.cli work-mode-decision --changed-path ams/session_registry.py",
            "python3 -m ams.cli semantic-oracle-review --simulation-sweep-id <sweep-id>",
        ],
        "reason_code": "semantic_oracle_review.hook_shim_contract_only",
    }


def _metrics(rows: list[dict[str, Any]], rule_results: list[dict[str, Any]]) -> dict[str, Any]:
    by_fault = Counter((row.get("dimensions") or {}).get("fault", "unknown") for row in rows)
    gap_count = sum(int(result["semantic_gap_count"]) for result in rule_results)
    matched_count = sum(int(result["matched_scenarios"]) for result in rule_results)
    covered_count = sum(int(result["covered_scenarios"]) for result in rule_results)
    return {
        "reviewed_scenario_count": len(rows),
        "reviewed_fault_distribution": dict(by_fault),
        "semantic_rule_count": len(rule_results),
        "semantic_matched_scenario_count": matched_count,
        "semantic_covered_scenario_count": covered_count,
        "semantic_gap_count": gap_count,
        "semantic_gap_rate": round(gap_count / matched_count, 4) if matched_count else 0.0,
        "hook_required_count": len({hook for result in rule_results for hook in result.get("required_hooks", [])}),
        "record_requirement_count": len({record for result in rule_results for record in result.get("required_records", [])}),
    }


def _status(metrics: dict[str, Any]) -> str:
    if int(metrics.get("reviewed_scenario_count") or 0) < 1000:
        return "deny"
    if int(metrics.get("semantic_gap_count") or 0) > 0:
        return "defer"
    return "allow"


def _reason_codes(status: str, metrics: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if int(metrics.get("reviewed_scenario_count") or 0) < 1000:
        reasons.append("semantic_oracle_review.scenario_count_below_1000")
    if int(metrics.get("semantic_gap_count") or 0) > 0:
        reasons.append("semantic_oracle_review.semantic_gaps_found")
    if status == "allow":
        reasons.append("semantic_oracle_review.passed")
    elif status == "defer":
        reasons.append("semantic_oracle_review.operator_review_required")
    else:
        reasons.append("semantic_oracle_review.denied")
    return sorted(set(reasons))


def _summary(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "semantic_oracle_review_id": record["semantic_oracle_review_id"],
        "simulation_sweep_id": record["simulation_sweep_id"],
        "status": record["status"],
        "reason_codes": record["reason_codes"],
        "metrics": record["metrics"],
        "hook_shim_contract": record["hook_shim_contract"],
        "rule_results": record["rule_results"],
    }


def _artifact_ref(path: Path, kind: str) -> dict[str, Any]:
    return {
        "path": str(path),
        "kind": kind,
        "sha256": sha256_text(path.read_text(encoding="utf-8")),
    }


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    fsync_path(path)
    fsync_dir(path.parent)
