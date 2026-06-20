from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import canonical_json, iso_after, sha256_text, stable_id, utc_now
from .resource_policy import build_default_resource_policy, evaluate_task_run
from .store import JsonStore


CLAIM_STATES = {"reserved", "active", "released", "expired"}


def _claim_hash(claim: dict[str, Any]) -> str:
    material = dict(claim)
    material.pop("claim_sha256", None)
    return sha256_text(canonical_json(material))


def build_resource_claim(
    task_run: dict[str, Any],
    resource_verdict: dict[str, Any],
    *,
    ttl_seconds: int = 3600,
) -> dict[str, Any]:
    if resource_verdict.get("status") != "allow":
        raise ValueError("cannot reserve resources without allow verdict")
    limits = resource_verdict.get("limits") or {}
    local_resources = limits.get("local_resources") or {}
    now = utc_now()
    claim = {
        "schema_version": "ams.ams_codex.resource_claim.v0",
        "resource_claim_id": stable_id(
            "resclaim",
            task_run.get("task_run_id"),
            resource_verdict.get("resource_verdict_id"),
            task_run.get("idempotency_key"),
        ),
        "task_run_id": task_run.get("task_run_id"),
        "session_id": task_run.get("session_id"),
        "policy_id": resource_verdict.get("policy_id"),
        "policy_sha256": resource_verdict.get("policy_sha256"),
        "resource_verdict_id": resource_verdict.get("resource_verdict_id"),
        "provider_profile_id": resource_verdict.get("provider_profile_id"),
        "state": "reserved",
        "holder": task_run.get("actor"),
        "idempotency_key": task_run.get("idempotency_key"),
        "reserved": {
            "cpu_cores": int(local_resources.get("cpu_cores", 0) or 0),
            "memory_mb": int(local_resources.get("memory_mb", 0) or 0),
            "gpu_memory_mb": int(local_resources.get("gpu_memory_mb", 0) or 0),
            "max_input_tokens": int(limits.get("max_input_tokens_per_run", 0) or 0),
            "max_output_tokens": int(limits.get("max_output_tokens_per_run", 0) or 0),
            "max_runtime_seconds": int(limits.get("max_runtime_seconds", 0) or 0),
            "concurrency_units": 1,
        },
        "created_at": now,
        "updated_at": now,
        "expires_at": iso_after(ttl_seconds),
        "released_at": None,
    }
    claim["claim_sha256"] = _claim_hash(claim)
    return claim


def transition_resource_claim(claim: dict[str, Any], state: str) -> dict[str, Any]:
    if state not in CLAIM_STATES:
        raise ValueError(f"invalid resource claim state: {state}")
    updated = deepcopy(claim)
    updated["state"] = state
    updated["updated_at"] = utc_now()
    if state in {"released", "expired"}:
        updated["released_at"] = updated["updated_at"]
    updated["claim_sha256"] = _claim_hash(updated)
    return updated


def settle_claims_for_run_in_state(state: dict[str, Any], task_run_id: str) -> list[dict[str, Any]]:
    settled: list[dict[str, Any]] = []
    claims = state.setdefault("resource_claims", {})
    for claim_id, claim in list(claims.items()):
        if claim.get("task_run_id") != task_run_id:
            continue
        if claim.get("state") not in {"reserved", "active"}:
            continue
        updated = transition_resource_claim(claim, "released")
        claims[claim_id] = updated
        settled.append(deepcopy(updated))
    return settled


class ResourceClaimStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def reserve(
        self,
        task_run_id: str,
        *,
        policy: dict[str, Any] | None = None,
        current_usage: dict[str, Any] | None = None,
        ttl_seconds: int = 3600,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            task_run = state.get("task_runs", {}).get(task_run_id)
            if not task_run:
                raise KeyError(f"unknown task_run_id: {task_run_id}")
            policy = policy or build_default_resource_policy()
            verdict = evaluate_task_run(task_run, policy, current_usage=current_usage)
            if verdict["status"] != "allow":
                return {"reserved": False, "verdict": verdict, "claim": None}
            claim = build_resource_claim(task_run, verdict, ttl_seconds=ttl_seconds)
            state.setdefault("resource_claims", {})[claim["resource_claim_id"]] = claim
        return {"reserved": True, "verdict": verdict, "claim": deepcopy(claim)}

    def transition(self, resource_claim_id: str, state_name: str) -> dict[str, Any]:
        with self.store.locked() as state:
            claim = state.get("resource_claims", {}).get(resource_claim_id)
            if not claim:
                raise KeyError(f"unknown resource_claim_id: {resource_claim_id}")
            updated = transition_resource_claim(claim, state_name)
            state.setdefault("resource_claims", {})[resource_claim_id] = updated
        return deepcopy(updated)
