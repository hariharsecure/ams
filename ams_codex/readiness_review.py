from __future__ import annotations

from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any

from .architecture_audit import build_architecture_audit
from .markdown_governance import build_markdown_audit
from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore


SCHEMA_VERSION = "ams.ams_codex.readiness_review.v0"
STATUSES = {"allow", "defer", "deny"}
SCORE_MAX = 4
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
}
RESEARCH_BASIS = [
    {
        "lens": "ai_risk_management",
        "source": "NIST AI RMF 1.0 and Generative AI Profile",
        "url": "https://www.nist.gov/itl/ai-risk-management-framework",
    },
    {
        "lens": "secure_software",
        "source": "NIST SP 800-218 SSDF",
        "url": "https://csrc.nist.gov/pubs/sp/800/218/final",
    },
    {
        "lens": "llm_security",
        "source": "OWASP Top 10 for LLM Applications 2025",
        "url": "https://genai.owasp.org/llm-top-10/",
    },
    {
        "lens": "supply_chain",
        "source": "SLSA provenance and isolation requirements",
        "url": "https://slsa.dev/spec/v1.1/requirements",
    },
    {
        "lens": "operations",
        "source": "Google SRE monitoring distributed systems",
        "url": "https://sre.google/sre-book/monitoring-distributed-systems/",
    },
    {
        "lens": "durable_execution",
        "source": "Temporal durable execution model",
        "url": "https://docs.temporal.io/temporal",
    },
]


class ReadinessReviewStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        source_root: str | Path,
        label: str = "manual-readiness-review",
        include_local_session_metadata: bool = False,
        session_window_days: int = 92,
    ) -> dict[str, Any]:
        record = build_readiness_review(
            source_root=source_root,
            label=label,
            include_local_session_metadata=include_local_session_metadata,
            session_window_days=session_window_days,
        )
        with self.store.locked() as state:
            review_id = record["readiness_review_id"]
            state.setdefault("readiness_reviews", {})[review_id] = record
            state.setdefault("indexes", {}).setdefault("readiness_review_ids", {})[review_id] = review_id
            return deepcopy(record)


def build_readiness_review(
    *,
    source_root: str | Path,
    label: str = "manual-readiness-review",
    include_local_session_metadata: bool = False,
    session_window_days: int = 92,
    now: str | None = None,
) -> dict[str, Any]:
    root = Path(source_root).expanduser().resolve(strict=False)
    now = now or utc_now()
    markdown = build_markdown_audit(
        source_root=root,
        label=f"{label}-markdown",
        include_local_session_metadata=include_local_session_metadata,
        session_window_days=session_window_days,
        now=now,
    )
    architecture = build_architecture_audit(source_root=root, package_name="ams_codex", now=now)
    repo_evidence = _repo_evidence(root)
    dimensions = _dimensions(root=root, markdown=markdown, architecture=architecture, repo=repo_evidence)
    priority_actions = _priority_actions(dimensions)
    score = _score(dimensions)
    status = _status(dimensions)
    reason_codes = _reason_codes(dimensions, status)
    record = {
        "schema_version": SCHEMA_VERSION,
        "readiness_review_id": stable_id(
            "readyrev",
            str(root),
            label,
            markdown["markdown_snapshot_sha256"],
            architecture["source_snapshot_sha256"],
            score,
            now,
        ),
        "label": label,
        "source_root": str(root),
        "review_scope": "local_preproduction",
        "research_basis": RESEARCH_BASIS,
        "live_boundaries": dict(LIVE_BOUNDARIES),
        "evidence_summary": {
            "repo": repo_evidence,
            "markdown": _markdown_summary(markdown),
            "architecture": _architecture_summary(architecture),
        },
        "dimensions": dimensions,
        "score": score,
        "priority_actions": priority_actions,
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["readiness_review_sha256"] = _hash_without(record, "readiness_review_sha256")
    return deepcopy(record)


def validate_readiness_review_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("readiness_review.schema.json", record, location="readiness_review")
    except SchemaValidationError:
        reason_codes.append("readiness_review.schema_invalid")
    expected_hash = record.get("readiness_review_sha256")
    if expected_hash and expected_hash != _hash_without(record, "readiness_review_sha256"):
        reason_codes.append("readiness_review.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("readiness_review.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("readiness_review.status_invalid")
    for key, expected in LIVE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"readiness_review.{key}_not_false")
    dimensions = record.get("dimensions") or []
    expected_score = _score(dimensions)
    if record.get("score") != expected_score:
        reason_codes.append("readiness_review.score_mismatch")
    expected_status = _status(dimensions)
    if record.get("status") != expected_status:
        reason_codes.append("readiness_review.status_mismatch")
    expected_reasons = _reason_codes(dimensions, expected_status)
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("readiness_review.reason_codes_mismatch")
    dimension_ids = [dimension.get("dimension_id") for dimension in dimensions if isinstance(dimension, dict)]
    if len(dimension_ids) != len(set(dimension_ids)):
        reason_codes.append("readiness_review.duplicate_dimension_id")
    for dimension in dimensions:
        if not isinstance(dimension, dict):
            reason_codes.append("readiness_review.dimension_not_object")
            continue
        if dimension.get("status") == "allow" and dimension.get("gaps"):
            reason_codes.append(f"readiness_review.allow_with_gaps:{dimension.get('dimension_id')}")
        if int(dimension.get("score", 0) or 0) > SCORE_MAX:
            reason_codes.append(f"readiness_review.score_above_max:{dimension.get('dimension_id')}")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _repo_evidence(root: Path) -> dict[str, Any]:
    required_files = [
        "AGENTS.md",
        "CLAUDE.md",
        "STATUS.md",
        "MAP.md",
        "MILESTONES.md",
        "AMS_100_PERCENT_PLAN.md",
        "ams_codex/store.py",
        "ams_codex/replay.py",
        "ams_codex/replay_oracle.py",
        "ams_codex/schema_validation.py",
        "ams_codex/dispatch.py",
        "ams_codex/signed_policy.py",
        "ams_codex/package_manifest.py",
        "ams_codex/capability_policy.py",
        "ams_codex/resource_policy.py",
        "ams_codex/markdown_governance.py",
        "schemas/markdown_audit.schema.json",
    ]
    milestone_docs = sorted((path.name for path in root.glob("MILESTONE_*.md") if path.is_file()), key=_milestone_sort_key)
    package_files = sorted((root / "ams_codex").glob("*.py")) if (root / "ams_codex").exists() else []
    tests = sorted((root / "tests").glob("test_*.py")) if (root / "tests").exists() else []
    missing = [path for path in required_files if not (root / path).exists()]
    return {
        "required_file_count": len(required_files),
        "missing_required_files": missing,
        "milestone_doc_count": len(milestone_docs),
        "latest_milestone_doc": milestone_docs[-1] if milestone_docs else None,
        "python_module_count": len(package_files),
        "test_file_count": len(tests),
        "live_runner_files_present": _files_present(
            root,
            [
                "ams_codex/discord_canary.py",
                "ams_codex/discord_canary_receipt.py",
                "ams_codex/terminal_source.py",
                "ams_codex/resource_telemetry.py",
                "ams_codex/shadow_approval.py",
            ],
        ),
    }


def _markdown_summary(markdown: dict[str, Any]) -> dict[str, Any]:
    session = markdown.get("session_metadata") or {}
    return {
        "status": markdown.get("status"),
        "reason_codes": markdown.get("reason_codes") or [],
        "file_count": markdown.get("markdown_file_count"),
        "total_line_count": markdown.get("total_line_count"),
        "metadata_gap_count": len(markdown.get("metadata_gaps") or []),
        "structure_gap_count": len(markdown.get("structure_gaps") or []),
        "oversized_file_count": len(markdown.get("oversized_files") or []),
        "latest_milestone_doc": (markdown.get("authority_index") or {}).get("latest_milestone_doc"),
        "session_metadata_included": bool(session.get("included")),
        "raw_content_stored": False,
    }


def _architecture_summary(architecture: dict[str, Any]) -> dict[str, Any]:
    metrics = architecture.get("metrics") or {}
    return {
        "status": architecture.get("status"),
        "reason_codes": architecture.get("reason_codes") or [],
        "file_count": architecture.get("file_count"),
        "line_count": architecture.get("line_count"),
        "cycle_count": ((metrics.get("acyclicity") or {}).get("cycle_count")),
        "max_import_depth": ((metrics.get("depth") or {}).get("max_import_depth")),
        "duplicate_function_group_count": ((metrics.get("redundancy") or {}).get("duplicate_function_group_count")),
        "same_area_edge_ratio": ((metrics.get("modularity") or {}).get("same_area_edge_ratio")),
    }


def _dimensions(
    *,
    root: Path,
    markdown: dict[str, Any],
    architecture: dict[str, Any],
    repo: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        _authority_kernel_dimension(root, repo),
        _context_docs_dimension(markdown),
        _architecture_dimension(architecture),
        _security_supply_chain_dimension(root),
        _llm_security_dimension(root),
        _live_ops_dimension(root),
        _resource_dimension(root),
        _rag_dimension(root),
        _multi_agent_dimension(root),
        _cyber_physical_dimension(root),
    ]


def _authority_kernel_dimension(root: Path, repo: dict[str, Any]) -> dict[str, Any]:
    gaps: list[dict[str, Any]] = []
    if repo.get("missing_required_files"):
        gaps.append(_gap("authority.missing_required_files", "high", "Required AMS authority files are missing.", "MILESTONE-34"))
    if not (root / "ams_codex/shadow_approval.py").exists():
        gaps.append(_gap("authority.shadow_approval_missing", "high", "No explicit shadow approval packet contract.", "MILESTONE-34"))
    gaps.append(
        _gap(
            "authority.production_gate_artifact_missing",
            "high",
            "The signed authority production gate artifact is still not imported or verified.",
            "M10",
        )
    )
    return _dimension(
        "authority_kernel",
        score=3 if len(gaps) == 1 else 2,
        strengths=[
            "Store locks, revision checks, schema validation, replay, replay oracle, dispatch envelopes, signed policy, package manifest, and approval packets exist locally.",
            "Live-boundary records remain inert until explicit approval.",
        ],
        gaps=gaps,
        evidence_refs=["ams_codex/store.py", "ams_codex/replay.py", "ams_codex/dispatch.py", "ams_codex/shadow_approval.py"],
    )


def _context_docs_dimension(markdown: dict[str, Any]) -> dict[str, Any]:
    gaps: list[dict[str, Any]] = []
    summary = _markdown_summary(markdown)
    if markdown.get("status") != "allow":
        gaps.append(
            _gap(
                "context.markdown_defer",
                "high",
                "Markdown/session audit is still defer, so doc drift is a promotion blocker.",
                "MILESTONE-34",
                details=summary,
            )
        )
    return _dimension(
        "context_docs_memory",
        score=2 if gaps else 4,
        strengths=[
            "AGENTS.md and CLAUDE.md are compact session-start rules.",
            "Markdown audit stores hashes/counts/booleans only and excludes raw prompts/transcripts.",
        ],
        gaps=gaps,
        evidence_refs=["AGENTS.md", "CLAUDE.md", "MILESTONE_32_MARKDOWN_SESSION_GOVERNANCE.md"],
    )


def _architecture_dimension(architecture: dict[str, Any]) -> dict[str, Any]:
    summary = _architecture_summary(architecture)
    gaps: list[dict[str, Any]] = []
    if architecture.get("status") == "deny":
        gaps.append(_gap("architecture.deny", "critical", "Architecture audit denies promotion.", "MILESTONE-35", details=summary))
    elif architecture.get("status") != "allow":
        gaps.append(_gap("architecture.defer", "high", "Architecture audit has unresolved maintainability debt.", "MILESTONE-35", details=summary))
    return _dimension(
        "architecture_modularity",
        score=1 if architecture.get("status") == "deny" else 2 if gaps else 4,
        strengths=["Python AST architecture audit exists and is replay-protected."],
        gaps=gaps,
        evidence_refs=["ams_codex/architecture_audit.py", "schemas/architecture_audit.schema.json"],
    )


def _security_supply_chain_dimension(root: Path) -> dict[str, Any]:
    gaps = [
        _gap(
            "supply_chain.isolated_builder_missing",
            "high",
            "Local workstation provenance is not equivalent to an isolated signed build platform.",
            "MILESTONE-36",
        ),
        _gap(
            "supply_chain.multi_machine_conformance_missing",
            "medium",
            "No signed multi-machine conformance pack has been exchanged with the authority peer.",
            "MILESTONE-36",
        ),
    ]
    return _dimension(
        "security_supply_chain",
        score=2,
        strengths=[
            "Signed policy and signed package manifest contracts exist locally.",
            "Provider auth preflight stores env-name presence only, not secrets.",
        ],
        gaps=gaps,
        evidence_refs=["ams_codex/signed_policy.py", "ams_codex/package_manifest.py", "ams_codex/provider_auth.py"],
    )


def _llm_security_dimension(root: Path) -> dict[str, Any]:
    gaps = [
        _gap(
            "llm_security.red_team_suite_missing",
            "medium",
            "No OWASP-style prompt injection/excessive agency/vector weakness red-team suite is wired into conformance.",
            "MILESTONE-37",
        )
    ]
    return _dimension(
        "llm_security",
        score=3,
        strengths=[
            "Capability policy, egress denial, source-packet hashing, RAG taint labels, and manager readback settlement address major agent-risk classes.",
        ],
        gaps=gaps,
        evidence_refs=["ams_codex/capability_policy.py", "ams_codex/rag_retrieval_query.py", "ams_codex/manager_intervention.py"],
    )


def _live_ops_dimension(root: Path) -> dict[str, Any]:
    gaps = [
        _gap("live_ops.no_live_canary", "high", "Discord canary send is planned but not executed under approval.", "M10-0"),
        _gap("live_ops.no_terminal_adapter", "medium", "Terminal/tmux source packets exist, but no approved live adapter is running.", "M10-1"),
        _gap("live_ops.no_slo_or_pager_policy", "medium", "No SLO/alert policy defines which AMS failures interrupt humans.", "MILESTONE-38"),
    ]
    return _dimension(
        "live_ops_observability",
        score=2,
        strengths=[
            "Backup/restore drill, conformance pack, canary plan/receipt, terminal source packet, and resource telemetry records exist locally.",
        ],
        gaps=gaps,
        evidence_refs=["ams_codex/backup_restore.py", "ams_codex/conformance_pack.py", "ams_codex/discord_canary.py", "ams_codex/terminal_source.py"],
    )


def _resource_dimension(root: Path) -> dict[str, Any]:
    gaps = [
        _gap("resource.live_enforcement_missing", "medium", "Resource telemetry is local evidence, not live throttling or automatic checkpointing.", "MILESTONE-39"),
        _gap("resource.local_model_profiles_missing", "medium", "Local model provider profiles and resource classes are not yet formalized.", "MILESTONE-39"),
    ]
    return _dimension(
        "resource_management",
        score=2,
        strengths=["Resource policy, claims, and telemetry settlement records exist with no raw log/token storage."],
        gaps=gaps,
        evidence_refs=["ams_codex/resource_policy.py", "ams_codex/resource_claim.py", "ams_codex/resource_telemetry.py"],
    )


def _rag_dimension(root: Path) -> dict[str, Any]:
    gaps = [
        _gap("rag.vector_backend_missing", "medium", "HNSW/research_rag vector provider contract is not implemented.", "MILESTONE-40"),
        _gap("rag.retrieval_eval_missing", "medium", "Retrieval quality metrics are not yet part of the conformance gate.", "MILESTONE-40"),
    ]
    return _dimension(
        "rag_and_knowledge",
        score=2,
        strengths=[
            "RAG index plans, embedding jobs, provider auth, embedding receipts, retrieval queries, taint labels, and artifact quarantine exist as hash-only ledgers.",
        ],
        gaps=gaps,
        evidence_refs=["ams_codex/rag_index_plan.py", "ams_codex/rag_embedding_job.py", "ams_codex/rag_retrieval_query.py"],
    )


def _multi_agent_dimension(root: Path) -> dict[str, Any]:
    gaps = [
        _gap("agents.claude_real_smoke_missing", "medium", "Real Claude model turn remains unverified on this machine.", "MILESTONE-41"),
        _gap("agents.vendor_diverse_verifier_missing", "medium", "Vendor-diverse verifier quorum is planned but not enforced.", "MILESTONE-41"),
    ]
    return _dimension(
        "multi_agent_reliability",
        score=2,
        strengths=[
            "Fake-agent memory trials, real Codex smoke evidence, provider bindings, and manager intervention/settlement records exist.",
        ],
        gaps=gaps,
        evidence_refs=["ams_codex/agent_memory_sim.py", "ams_codex/real_agent_trial.py", "ams_codex/intervention_settlement.py"],
    )


def _cyber_physical_dimension(root: Path) -> dict[str, Any]:
    gaps = [
        _gap("farm.source_packet_ledger_missing", "high", "No farm source-packet/device registry/flock-cycle ledger exists yet.", "MILESTONE-42"),
        _gap("farm.control_receipt_missing", "critical", "No signed human-approved control proposal/approval/receipt path exists for actuators.", "MILESTONE-42"),
    ]
    return _dimension(
        "cyber_physical_safety",
        score=1,
        strengths=["Farm animal-welfare and cyber-physical attention domains exist, with P0 no-water routing coverage."],
        gaps=gaps,
        evidence_refs=["MILESTONE_31_POULTRY_AI_AMS_ARCHITECTURE.md", "ams_codex/attention_router.py"],
    )


def _dimension(
    dimension_id: str,
    *,
    score: int,
    strengths: list[str],
    gaps: list[dict[str, Any]],
    evidence_refs: list[str],
) -> dict[str, Any]:
    status = "allow" if not gaps and score >= SCORE_MAX else "defer"
    reasons = [f"readiness.{dimension_id}.{gap['gap_id'].split('.', 1)[-1]}" for gap in gaps] or [f"readiness.{dimension_id}.ok"]
    return {
        "dimension_id": dimension_id,
        "status": status,
        "score": int(score),
        "target_score": SCORE_MAX,
        "strengths": strengths,
        "gaps": gaps,
        "evidence_refs": evidence_refs,
        "reason_codes": reasons,
    }


def _gap(
    gap_id: str,
    severity: str,
    summary: str,
    fix_milestone: str,
    *,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "gap_id": gap_id,
        "severity": severity,
        "summary": summary,
        "fix_milestone": fix_milestone,
        "details": details or {},
    }


def _priority_actions(dimensions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    actions: list[dict[str, Any]] = []
    for dimension in dimensions:
        for gap in dimension.get("gaps") or []:
            actions.append(
                {
                    "priority": 0,
                    "dimension_id": dimension["dimension_id"],
                    "gap_id": gap["gap_id"],
                    "severity": gap["severity"],
                    "fix_milestone": gap["fix_milestone"],
                    "summary": gap["summary"],
                }
            )
    actions.sort(key=lambda item: (severity_rank.get(item["severity"], 9), item["fix_milestone"], item["gap_id"]))
    for index, action in enumerate(actions, start=1):
        action["priority"] = index
    return actions[:12]


def _score(dimensions: list[dict[str, Any]]) -> dict[str, Any]:
    scores = [int(dimension.get("score", 0) or 0) for dimension in dimensions]
    status_counts = dict(Counter(str(dimension.get("status")) for dimension in dimensions))
    total = sum(scores)
    maximum = len(scores) * SCORE_MAX
    return {
        "score_total": total,
        "score_max": maximum,
        "score_percent": round((total / maximum) * 100, 2) if maximum else 0.0,
        "dimension_count": len(scores),
        "status_counts": status_counts,
    }


def _status(dimensions: list[dict[str, Any]]) -> str:
    statuses = {str(dimension.get("status")) for dimension in dimensions}
    if "deny" in statuses:
        return "deny"
    if statuses == {"allow"}:
        return "allow"
    return "defer"


def _reason_codes(dimensions: list[dict[str, Any]], status: str) -> list[str]:
    if status == "allow":
        return ["readiness_review.allow"]
    reasons = []
    for dimension in dimensions:
        if dimension.get("status") != "allow":
            reasons.append(f"readiness_review.{dimension.get('dimension_id')}_{dimension.get('status')}")
    return sorted(set(reasons)) or ["readiness_review.defer"]


def _files_present(root: Path, paths: list[str]) -> dict[str, bool]:
    return {path: (root / path).exists() for path in paths}


def _milestone_sort_key(name: str) -> tuple[int, int, str]:
    stem = Path(name).stem
    parts = stem.split("_")
    if len(parts) < 2 or parts[0] != "MILESTONE":
        return (0, 0, name)
    try:
        minor = int(parts[1])
    except ValueError:
        return (0, 0, name)
    return (0, minor, name)
