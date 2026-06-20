from __future__ import annotations

from copy import deepcopy
from fnmatch import fnmatch
from typing import Any

from .models import stable_id, utc_now
from .policy_common import path_under, policy_hash
from .policy_templates import load_example_policy
from .workspace import workspace_root


def build_default_resource_policy() -> dict[str, Any]:
    try:
        policy = load_example_policy("resource_policy.default.json")
    except FileNotFoundError:
        root = workspace_root()
    else:
        policy.pop("policy_sha256", None)
        policy["policy_sha256"] = policy_hash(policy)
        return policy

    policy = {
        "schema_version": "ams.ams.resource_policy.v0",
        "resource_policy_id": stable_id("respol", "local-default", "v0"),
        "name": "local-default-dry-run",
        "scope": {
            "install_id": "local-dry-run",
            "workspace_roots": [root],
            "default_egress": "deny",
        },
        "global_limits": {
            "max_concurrent_runs": 2,
            "max_daily_input_tokens": 1000000,
            "max_daily_output_tokens": 250000,
            "max_daily_usd": 25.0,
        },
        "provider_profiles": [
            {
                "profile_id": "codex-app-server-default",
                "provider": "openai_codex",
                "surface": "app-server",
                "model_pattern": "*",
                "max_concurrent_runs": 1,
                "max_context_tokens": 200000,
                "max_input_tokens_per_run": 50000,
                "max_output_tokens_per_run": 12000,
                "max_runtime_seconds": 3600,
                "local_resources": {"cpu_cores": 1, "memory_mb": 2048, "gpu_memory_mb": 0},
                "allowed_cwd_roots": [root],
                "allowed_tools": ["Read", "Edit", "ApplyPatch", "ShellReadOnly", "Tests"],
                "denied_tools": ["discord_client.send", "network.post", "launchd.write"],
                "egress_modes": ["none", "ams_outbox"],
                "data_classes": ["public", "project", "hash_refs"],
            },
            {
                "profile_id": "claude-agent-sdk-verifier",
                "provider": "anthropic_claude",
                "surface": "agent-sdk",
                "model_pattern": "*",
                "max_concurrent_runs": 1,
                "max_context_tokens": 200000,
                "max_input_tokens_per_run": 50000,
                "max_output_tokens_per_run": 12000,
                "max_runtime_seconds": 2400,
                "local_resources": {"cpu_cores": 1, "memory_mb": 2048, "gpu_memory_mb": 0},
                "allowed_cwd_roots": [root],
                "allowed_tools": ["Read", "ShellReadOnly", "Tests"],
                "denied_tools": ["Edit", "ApplyPatch", "discord_client.send", "network.post"],
                "egress_modes": ["none"],
                "data_classes": ["public", "project", "hash_refs"],
            },
            {
                "profile_id": "local-ollama-default",
                "provider": "local_ollama",
                "surface": "ollama-api",
                "model_pattern": "*",
                "max_concurrent_runs": 1,
                "max_context_tokens": 32768,
                "max_input_tokens_per_run": 12000,
                "max_output_tokens_per_run": 4000,
                "max_runtime_seconds": 900,
                "local_resources": {"cpu_cores": 4, "memory_mb": 16384, "gpu_memory_mb": 8192},
                "allowed_cwd_roots": [root],
                "allowed_tools": ["Read", "ShellReadOnly"],
                "denied_tools": ["Edit", "ApplyPatch", "discord_client.send", "network.post"],
                "egress_modes": ["none"],
                "data_classes": ["public", "project", "hash_refs"],
            },
            {
                "profile_id": "local-openai-compatible-default",
                "provider": "local_openai_compatible",
                "surface": "openai-compatible",
                "model_pattern": "*",
                "max_concurrent_runs": 1,
                "max_context_tokens": 65536,
                "max_input_tokens_per_run": 16000,
                "max_output_tokens_per_run": 6000,
                "max_runtime_seconds": 1200,
                "local_resources": {"cpu_cores": 4, "memory_mb": 24576, "gpu_memory_mb": 12288},
                "allowed_cwd_roots": [root],
                "allowed_tools": ["Read", "ShellReadOnly"],
                "denied_tools": ["Edit", "ApplyPatch", "discord_client.send", "network.post"],
                "egress_modes": ["none"],
                "data_classes": ["public", "project", "hash_refs"],
            },
        ],
        "status_cadence": {
            "min_seconds_between_status_posts": 300,
            "prefer_edit_existing_status": True,
            "max_public_status_per_hour": 4,
        },
        "created_at": "2026-06-09T00:00:00Z",
    }
    policy["policy_sha256"] = policy_hash(policy)
    return policy


def find_provider_profile(policy: dict[str, Any], task_run: dict[str, Any]) -> dict[str, Any] | None:
    provider = task_run.get("provider")
    surface = task_run.get("provider_surface")
    model = task_run.get("model") or ""
    for profile in policy.get("provider_profiles") or []:
        if profile.get("provider") != provider:
            continue
        if profile.get("surface") != surface:
            continue
        if not fnmatch(model, profile.get("model_pattern") or "*"):
            continue
        return deepcopy(profile)
    return None


def evaluate_task_run(
    task_run: dict[str, Any],
    policy: dict[str, Any] | None = None,
    *,
    current_usage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    policy = deepcopy(policy or build_default_resource_policy())
    current_usage = current_usage or {}
    errors: list[str] = []
    defers: list[str] = []
    warnings: list[str] = []
    profile = find_provider_profile(policy, task_run)
    policy_sha256 = policy.get("policy_sha256") or policy_hash(policy)

    if not profile:
        errors.append("resource.unknown_provider_profile")
    else:
        cwd = task_run.get("cwd") or ""
        allowed_roots = profile.get("allowed_cwd_roots") or policy.get("scope", {}).get("workspace_roots") or []
        if not cwd or not path_under(cwd, allowed_roots):
            errors.append("resource.cwd_outside_allowed_roots")

        requested_tools = list(task_run.get("tool_scope") or task_run.get("allowed_tools") or [])
        denied_tools = set(profile.get("denied_tools") or [])
        allowed_tools = set(profile.get("allowed_tools") or [])
        for tool in requested_tools:
            if tool in denied_tools:
                errors.append(f"resource.tool_denied:{tool}")
            elif "*" not in allowed_tools and tool not in allowed_tools:
                errors.append(f"resource.tool_not_allowed:{tool}")

        input_tokens = int(current_usage.get("requested_input_tokens", task_run.get("input_tokens") or 0) or 0)
        output_tokens = int(current_usage.get("requested_output_tokens", task_run.get("output_tokens") or 0) or 0)
        if input_tokens > int(profile.get("max_input_tokens_per_run") or 0):
            errors.append("resource.input_tokens_over_limit")
        if output_tokens > int(profile.get("max_output_tokens_per_run") or 0):
            errors.append("resource.output_tokens_over_limit")
        if input_tokens + output_tokens > int(profile.get("max_context_tokens") or 0):
            errors.append("resource.context_tokens_over_limit")

        provider_key = f"{profile.get('provider')}:{profile.get('surface')}"
        active_by_provider = current_usage.get("active_runs_by_provider") or {}
        if int(active_by_provider.get(provider_key, 0) or 0) >= int(profile.get("max_concurrent_runs") or 1):
            defers.append("resource.provider_concurrency_full")
        if int(current_usage.get("active_runs_global", 0) or 0) >= int(policy.get("global_limits", {}).get("max_concurrent_runs") or 1):
            defers.append("resource.global_concurrency_full")

        local_resources = profile.get("local_resources") or {}
        available = current_usage.get("available_local_resources") or {}
        for key in ("cpu_cores", "memory_mb", "gpu_memory_mb"):
            needed = int(local_resources.get(key, 0) or 0)
            if key in available and int(available.get(key, 0) or 0) < needed:
                defers.append(f"resource.insufficient_{key}")

        if task_run.get("delivery_status") not in (None, "not_requested"):
            if "ams_outbox" not in profile.get("egress_modes", []):
                errors.append("resource.egress_not_allowed_for_profile")
        if str(task_run.get("action") or "").startswith("discord_"):
            errors.append("resource.direct_discord_action_denied")

        if not task_run.get("lease_id"):
            warnings.append("resource.no_lease_snapshot")
        if not task_run.get("input_context_sha256"):
            errors.append("resource.missing_context_hash")

    status = "allow"
    if errors:
        status = "deny"
    elif defers:
        status = "defer"

    verdict = {
        "resource_verdict_id": stable_id(
            "resv",
            task_run.get("task_run_id"),
            policy.get("resource_policy_id"),
            status,
            errors,
            defers,
        ),
        "task_run_id": task_run.get("task_run_id"),
        "status": status,
        "policy_id": policy.get("resource_policy_id"),
        "policy_sha256": policy_sha256,
        "provider_profile_id": (profile or {}).get("profile_id"),
        "reason_codes": errors + defers + warnings,
        "limits": deepcopy(profile or {}),
        "checked_at": utc_now(),
    }
    return verdict
