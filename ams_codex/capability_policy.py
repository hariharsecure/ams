from __future__ import annotations

from copy import deepcopy
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from .models import stable_id, utc_now
from .policy_common import normalize_path, path_under, policy_hash
from .policy_templates import load_example_policy
from .workspace import workspace_root


def _relative_to_workspace(path: str, roots: list[str]) -> str:
    if not roots:
        return path
    root_path = normalize_path(roots[0])
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = Path(root_path) / candidate
    normalized = normalize_path(str(candidate))
    for root in roots:
        normalized_root = normalize_path(root)
        prefix = normalized_root.rstrip("/") + "/"
        if normalized == normalized_root:
            return "."
        if normalized.startswith(prefix):
            return normalized[len(prefix) :]
    return normalized


def _matches_any(value: str, patterns: list[str]) -> bool:
    return any(fnmatch(value, pattern) for pattern in patterns)


def build_default_capability_policy() -> dict[str, Any]:
    try:
        policy = load_example_policy("capability_policy.default.json")
    except FileNotFoundError:
        root = workspace_root()
    else:
        policy.pop("policy_sha256", None)
        policy["policy_sha256"] = policy_hash(policy)
        return policy

    policy: dict[str, Any] = {
        "schema_version": "ams.ams_codex.capability_policy.v0",
        "capability_policy_id": stable_id("cappol", "local-default", "v0"),
        "name": "local-default-capability-policy",
        "scope": {
            "workspace_roots": [root],
            "default_egress": "deny",
        },
        "tiers": [
            {
                "tier": "observer",
                "allowed_actions": ["read"],
                "writable_globs": [],
                "allowed_tools": ["Read", "ShellReadOnly"],
                "denied_tools": ["Edit", "ApplyPatch", "network.post", "discord_client.send"],
                "allowed_egress_modes": ["none"],
            },
            {
                "tier": "verifier",
                "allowed_actions": ["read", "test"],
                "writable_globs": [],
                "allowed_tools": ["Read", "ShellReadOnly", "Tests"],
                "denied_tools": ["Edit", "ApplyPatch", "network.post", "discord_client.send"],
                "allowed_egress_modes": ["none"],
            },
            {
                "tier": "builder",
                "allowed_actions": ["read", "write", "test"],
                "writable_globs": [
                    "README.md",
                    "MAP.md",
                    "MILESTONES.md",
                    "STATUS.md",
                    "NEW_CODEX_SESSION.md",
                    "*.md",
                    "notes/**",
                    "tests/**",
                    "examples/*.json",
                    "schemas/*.schema.json",
                    "ams_codex/*.py",
                ],
                "allowed_tools": ["Read", "Edit", "ApplyPatch", "ShellReadOnly", "Tests"],
                "denied_tools": ["network.post", "discord_client.send", "launchd.write", "git.push"],
                "allowed_egress_modes": ["none", "ams_outbox"],
            },
            {
                "tier": "maintainer",
                "allowed_actions": ["read", "write", "test", "policy_change"],
                "writable_globs": ["*"],
                "allowed_tools": ["Read", "Edit", "ApplyPatch", "ShellReadOnly", "Tests"],
                "denied_tools": ["network.post", "discord_client.send", "launchd.write", "git.push"],
                "allowed_egress_modes": ["none", "ams_outbox"],
            },
            {
                "tier": "signed_maintainer",
                "allowed_actions": ["read", "write", "test", "policy_change", "egress"],
                "writable_globs": ["*"],
                "allowed_tools": ["Read", "Edit", "ApplyPatch", "ShellReadOnly", "Tests", "EgressOutbox"],
                "denied_tools": ["network.post", "discord_client.send", "launchd.write", "git.push"],
                "allowed_egress_modes": ["none", "ams_outbox"],
            },
        ],
        "protected_path_rules": [
            {
                "rule_id": "secrets-never-agent-readable-or-writable",
                "category": "secret",
                "patterns": [
                    ".env",
                    ".env.*",
                    "**/.env",
                    "**/.env.*",
                    "**/*.pem",
                    "**/*.key",
                    "*.pem",
                    "*.key",
                    "*token*",
                    "*secret*",
                    "**/*token*",
                    "**/*secret*",
                    "**/secrets/**",
                    ".ssh/**",
                ],
                "actions": ["read", "write", "execute", "policy_change"],
                "decision": "deny",
                "reason_code": "capability.secret_path_denied",
            },
            {
                "rule_id": "vcs-internals-denied",
                "category": "vcs_internal",
                "patterns": [".git/**", ".git", ".gitmodules"],
                "actions": ["read", "write", "execute", "policy_change"],
                "decision": "deny",
                "reason_code": "capability.vcs_internal_denied",
            },
            {
                "rule_id": "ams-authority-requires-review",
                "category": "ams_authority",
                "patterns": [
                    "ams_codex/store.py",
                    "ams_codex/replay.py",
                    "ams_codex/replay_oracle.py",
                    "ams_codex/schema_validation.py",
                    "ams_codex/agent_memory_sim.py",
                    "ams_codex/real_agent_trial.py",
                    "ams_codex/work_mode_decision.py",
                    "ams_codex/doc_action_execution.py",
                    "ams_codex/doc_action_operator_approval.py",
                    "ams_codex/doc_action_patch_preview.py",
                    "ams_codex/doc_action_patch_readback.py",
                    "ams_codex/doc_action_patch_artifact.py",
                    "ams_codex/doc_action_patch_artifact_approval.py",
                    "ams_codex/doc_action_patch_dry_run.py",
                    "ams_codex/doc_action_patch_dry_run_readback.py",
                    "ams_codex/doc_action_patch_live_execution_approval.py",
                    "ams_codex/doc_action_patch_executor_preflight.py",
                    "ams_codex/doc_action_patch_apply_boundary.py",
                    "ams_codex/doc_action_patch_apply_acceptance.py",
                    "ams_codex/simulation_sweep.py",
                    "ams_codex/ams_emulation.py",
                    "ams_codex/semantic_oracle_review.py",
                    "ams_codex/semantic_hook_run.py",
                    "ams_codex/semantic_hook_install_plan.py",
                    "ams_codex/semantic_hook_approval.py",
                    "ams_codex/semantic_hook_target_snapshot.py",
                    "ams_codex/semantic_hook_install_transaction.py",
                    "ams_codex/semantic_hook_operator_approval.py",
                    "ams_codex/semantic_hook_operator_readback.py",
                    "ams_codex/attention_router.py",
                    "ams_codex/manager_intervention.py",
                    "ams_codex/intervention_delivery.py",
                    "ams_codex/intervention_settlement.py",
                    "ams_codex/architecture_audit.py",
                    "ams_codex/architecture_gate.py",
                    "ams_codex/rag_index_plan.py",
                    "ams_codex/artifact_quarantine.py",
                    "ams_codex/rag_embedding_job.py",
                    "ams_codex/rag_local_vector_trial.py",
                    "ams_codex/gate_adapter.py",
                    "ams_codex/resource_enforcement.py",
                    "ams_codex/resource_policy.py",
                    "ams_codex/shareability_bundle.py",
                    "ams_codex/shareability_receiver.py",
                    "ams_codex/capability_policy.py",
                    "ams_codex/definition_registry.py",
                    "ams_codex/package_manifest.py",
                    "ams_codex/runner_boundary.py",
                    "ams_codex/install_preflight.py",
                    "ams_codex/shadow_readiness.py",
                    "ams_codex/shadow_launch.py",
                    "ams_codex/shadow_runner.py",
                    "ams_codex/surface_bindings.py",
                    "ams_codex/surface_promise.py",
                    "ams_codex/cli.py",
                    "schemas/*definition*.json",
                    "schemas/*surface*.json",
                    "schemas/*package*.json",
                    "schemas/*policy*.json",
                    "schemas/*verdict*.json",
                    "schemas/manager_intervention.schema.json",
                    "schemas/manager_intervention_delivery.schema.json",
                    "schemas/manager_intervention_settlement.schema.json",
                    "schemas/architecture_audit.schema.json",
                    "schemas/architecture_gate_review.schema.json",
                    "schemas/work_mode_decision.schema.json",
                    "schemas/doc_action_execution_plan.schema.json",
                    "schemas/doc_action_operator_approval_packet.schema.json",
                    "schemas/doc_action_patch_preview.schema.json",
                    "schemas/doc_action_patch_readback_receipt.schema.json",
                    "schemas/doc_action_patch_artifact_receipt.schema.json",
                    "schemas/doc_action_patch_artifact_approval_packet.schema.json",
                    "schemas/doc_action_patch_dry_run_plan.schema.json",
                    "schemas/doc_action_patch_dry_run_readback_receipt.schema.json",
                    "schemas/doc_action_patch_live_execution_approval_packet.schema.json",
                    "schemas/doc_action_patch_executor_preflight.schema.json",
                    "schemas/doc_action_patch_apply_boundary_packet.schema.json",
                    "schemas/doc_action_patch_apply_acceptance_packet.schema.json",
                    "schemas/simulation_sweep.schema.json",
                    "schemas/ams_emulation_trial.schema.json",
                    "schemas/semantic_oracle_review.schema.json",
                    "schemas/semantic_hook_record.schema.json",
                    "schemas/semantic_hook_run.schema.json",
                    "schemas/semantic_hook_install_plan.schema.json",
                    "schemas/semantic_hook_approval_binding.schema.json",
                    "schemas/semantic_hook_target_snapshot.schema.json",
                    "schemas/semantic_hook_install_transaction.schema.json",
                    "schemas/semantic_hook_operator_approval_packet.schema.json",
                    "schemas/semantic_hook_operator_readback_receipt.schema.json",
                    "schemas/rag_index_plan.schema.json",
                    "schemas/downloaded_artifact_quarantine.schema.json",
                    "schemas/rag_embedding_job.schema.json",
                    "schemas/rag_local_vector_trial.schema.json",
                    "schemas/resource_enforcement_trial.schema.json",
                    "schemas/shareability_bundle.schema.json",
                    "schemas/shareability_receiver_trial.schema.json",
                    "examples/*definition*.json",
                    "examples/*package*.json",
                    "examples/*policy*.json",
                    "data/*.json",
                ],
                "actions": ["write", "policy_change"],
                "decision": "defer",
                "reason_code": "capability.ams_authority_requires_review",
            },
            {
                "rule_id": "supply-chain-requires-review",
                "category": "supply_chain",
                "patterns": [
                    "pyproject.toml",
                    "requirements*.txt",
                    "uv.lock",
                    "poetry.lock",
                    "package.json",
                    "package-lock.json",
                    "pnpm-lock.yaml",
                    "yarn.lock",
                    ".github/**",
                    "CODEOWNERS",
                    ".pre-commit-config.yaml",
                ],
                "actions": ["write", "execute", "policy_change"],
                "decision": "defer",
                "reason_code": "capability.supply_chain_requires_review",
            },
            {
                "rule_id": "service-and-daemon-requires-review",
                "category": "service_control",
                "patterns": ["*.plist", "launchd/**", "scripts/install*", "scripts/*daemon*"],
                "actions": ["write", "execute", "policy_change"],
                "decision": "defer",
                "reason_code": "capability.service_control_requires_review",
            },
        ],
        "review_requirements": {
            "protected_change_requires": [
                "change_request_id",
                "admission_review_id",
                "signed_policy_sha256",
            ],
            "untrusted_repo_content_default": "read_or_patch_only",
            "live_mode_requires_signed_policy": True,
        },
        "created_at": "2026-06-09T00:00:00Z",
    }
    policy["scope"]["workspace_roots"] = [root]
    policy["policy_sha256"] = policy_hash(policy)
    return policy


def find_tier(policy: dict[str, Any], tier_name: str) -> dict[str, Any] | None:
    for tier in policy.get("tiers") or []:
        if tier.get("tier") == tier_name:
            return deepcopy(tier)
    return None


def build_capability_request(
    *,
    actor: str = "agent:agent_b",
    tier: str = "builder",
    action: str = "write",
    paths: list[str] | None = None,
    tools: list[str] | None = None,
    egress_mode: str = "none",
    change_request_id: str | None = None,
    admission_review_id: str | None = None,
    signed_policy_sha256: str | None = None,
    architecture_gate_review_id: str | None = None,
    architecture_audit_id: str | None = None,
    architecture_audit_sha256: str | None = None,
    blast_radius_review_id: str | None = None,
    blast_radius_review_sha256: str | None = None,
) -> dict[str, Any]:
    request = {
        "schema_version": "ams.ams_codex.capability_request.v0",
        "actor": actor,
        "tier": tier,
        "action": action,
        "paths": paths or [],
        "tools": tools or [],
        "egress_mode": egress_mode,
        "change_request_id": change_request_id,
        "admission_review_id": admission_review_id,
        "signed_policy_sha256": signed_policy_sha256,
        "architecture_gate_review_id": architecture_gate_review_id,
        "architecture_audit_id": architecture_audit_id,
        "architecture_audit_sha256": architecture_audit_sha256,
        "blast_radius_review_id": blast_radius_review_id,
        "blast_radius_review_sha256": blast_radius_review_sha256,
        "created_at": utc_now(),
    }
    request["capability_request_id"] = stable_id(
        "capreq",
        actor,
        tier,
        action,
        request["paths"],
        request["tools"],
        egress_mode,
        change_request_id,
        admission_review_id,
        signed_policy_sha256,
        architecture_gate_review_id,
        architecture_audit_id,
        architecture_audit_sha256,
        blast_radius_review_id,
        blast_radius_review_sha256,
    )
    return request


def _review_requirements_met(request: dict[str, Any]) -> bool:
    return bool(
        request.get("change_request_id")
        and request.get("admission_review_id")
        and str(request.get("signed_policy_sha256") or "").startswith("sha256:")
    )


def evaluate_capability_request(
    request: dict[str, Any],
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    policy = deepcopy(policy or build_default_capability_policy())
    computed_policy_sha256 = policy_hash(policy)
    declared_policy_sha256 = policy.get("policy_sha256")
    policy_sha256 = declared_policy_sha256 or computed_policy_sha256
    tier_name = str(request.get("tier") or "")
    tier = find_tier(policy, tier_name)
    action = str(request.get("action") or "")
    roots = list(policy.get("scope", {}).get("workspace_roots") or [])
    reason_codes: list[str] = []
    denied_paths: list[str] = []
    deferred_paths: list[str] = []
    allowed_paths: list[str] = []
    deferred_rules: set[str] = set()
    errors: list[str] = []

    if declared_policy_sha256 and declared_policy_sha256 != computed_policy_sha256:
        errors.append("capability.policy_hash_mismatch")

    if not tier:
        errors.append("capability.unknown_tier")
    else:
        if action not in (tier.get("allowed_actions") or []):
            errors.append(f"capability.action_not_allowed:{action}")

        allowed_tools = set(tier.get("allowed_tools") or [])
        denied_tools = set(tier.get("denied_tools") or [])
        for tool in request.get("tools") or []:
            if tool in denied_tools:
                errors.append(f"capability.tool_denied:{tool}")
            elif "*" not in allowed_tools and tool not in allowed_tools:
                errors.append(f"capability.tool_not_allowed:{tool}")

        egress_mode = request.get("egress_mode") or "none"
        if egress_mode == "direct":
            errors.append("capability.direct_egress_denied")
        elif egress_mode not in (tier.get("allowed_egress_modes") or ["none"]):
            errors.append(f"capability.egress_mode_not_allowed:{egress_mode}")

    protected_review_allowed = tier_name == "signed_maintainer" and _review_requirements_met(request)
    writable_globs = (tier or {}).get("writable_globs") or []
    path_rules = policy.get("protected_path_rules") or []

    for path in request.get("paths") or []:
        rel = _relative_to_workspace(path, roots)
        if not roots:
            errors.append("capability.no_workspace_roots")
            denied_paths.append(path)
            continue
        path_for_check = path if Path(path).is_absolute() else str(Path(roots[0]) / path)
        if not path_under(path_for_check, roots):
            errors.append("capability.path_outside_workspace")
            denied_paths.append(path)
            continue

        rule_decision: str | None = None
        for rule in path_rules:
            if action not in (rule.get("actions") or []):
                continue
            if not _matches_any(rel, list(rule.get("patterns") or [])):
                continue
            code = str(rule.get("reason_code") or "capability.protected_path")
            if rule.get("decision") == "deny":
                errors.append(code)
                denied_paths.append(rel)
                rule_decision = "deny"
                break
            if rule.get("decision") == "defer":
                if protected_review_allowed:
                    reason_codes.append(f"capability.reviewed_protected_path:{rule.get('category')}")
                    rule_decision = "allow"
                else:
                    deferred_rules.add(code)
                    deferred_paths.append(rel)
                    rule_decision = "defer"
                break
        if rule_decision == "deny":
            continue
        if rule_decision == "defer":
            continue
        if action in {"write", "policy_change"} and tier:
            if "*" not in writable_globs and not _matches_any(rel, writable_globs):
                deferred_rules.add("capability.path_not_in_writable_allowlist")
                deferred_paths.append(rel)
                continue
        allowed_paths.append(rel)

    reason_codes = errors + sorted(deferred_rules) + reason_codes
    status = "allow"
    if errors:
        status = "deny"
    elif deferred_rules or deferred_paths:
        status = "defer"

    return {
        "schema_version": "ams.ams_codex.capability_verdict.v0",
        "capability_verdict_id": stable_id(
            "capv",
            request.get("capability_request_id"),
            policy.get("capability_policy_id"),
            status,
            reason_codes,
        ),
        "capability_request_id": request.get("capability_request_id"),
        "status": status,
        "policy_id": policy.get("capability_policy_id"),
        "policy_sha256": policy_sha256,
        "tier": tier_name,
        "action": action,
        "reason_codes": reason_codes,
        "allowed_paths": allowed_paths,
        "deferred_paths": sorted(set(deferred_paths)),
        "denied_paths": sorted(set(denied_paths)),
        "review_required": bool(deferred_paths or deferred_rules),
        "checked_at": utc_now(),
    }
