from __future__ import annotations

from copy import deepcopy
from typing import Any

from .replay import replay_check
from .store import JsonStore


CRITICAL_COLLECTIONS = (
    "sessions",
    "events",
    "contexts",
    "checkpoints",
    "task_runs",
    "run_events",
    "ams_events",
    "admission_reviews",
    "resource_claims",
    "resource_telemetry_samples",
    "resource_enforcement_trials",
    "shareability_bundles",
    "shareability_receiver_trials",
    "tool_definitions",
    "surface_definitions",
    "runtime_surfaces",
    "surface_bindings",
    "surface_promises",
    "shadow_launch_plans",
    "shadow_runner_transactions",
    "attention_signals",
    "manager_interventions",
    "manager_intervention_deliveries",
    "manager_intervention_settlements",
    "architecture_audits",
    "architecture_gate_reviews",
    "rag_index_plans",
    "downloaded_artifact_quarantines",
    "rag_embedding_jobs",
    "provider_auth_preflights",
    "rag_embedding_receipts",
    "rag_retrieval_queries",
    "rag_local_vector_trials",
    "agent_memory_trials",
    "memory_claims",
    "memory_promotion_reviews",
    "memory_supersession_records",
    "memory_conflict_records",
    "real_agent_trials",
    "real_agent_system_trials",
    "provider_results",
    "incident_packets",
    "outbox_items",
    "outbox_receipts",
    "store_backup_drills",
    "runner_dry_run_parities",
    "shadow_approval_packets",
    "discord_source_packets",
    "discord_canary_send_plans",
    "discord_canary_receipts",
    "terminal_source_packets",
    "conformance_packs",
    "markdown_audits",
    "readiness_reviews",
    "doc_retirement_plans",
    "doc_action_execution_plans",
    "doc_action_operator_approval_packets",
    "doc_action_patch_previews",
    "doc_action_patch_readback_receipts",
    "doc_action_patch_artifact_receipts",
    "doc_action_patch_artifact_approval_packets",
    "doc_action_patch_dry_run_plans",
    "doc_action_patch_dry_run_readback_receipts",
    "doc_action_patch_live_execution_approval_packets",
    "doc_action_patch_executor_preflights",
    "doc_action_patch_apply_boundary_packets",
    "doc_action_patch_apply_acceptance_packets",
    "source_write_executor_preflights",
    "source_write_backup_preimage_receipts",
    "source_write_executor_leases",
    "generated_status_snapshots",
    "session_start_briefs",
    "markdown_authority_indexes",
    "markdown_authority_entries",
    "codebase_spider_graph_snapshots",
    "codebase_graph_nodes",
    "codebase_graph_edges",
    "codebase_graph_query_receipts",
    "blast_radius_reviews",
    "work_mode_decisions",
    "simulation_sweeps",
    "ams_emulation_trials",
    "semantic_oracle_reviews",
    "semantic_hook_records",
    "semantic_hook_runs",
    "semantic_hook_install_plans",
    "semantic_hook_approval_bindings",
    "semantic_hook_target_snapshots",
    "semantic_hook_install_transactions",
    "semantic_hook_operator_approval_packets",
    "semantic_hook_operator_readback_receipts",
)

HASH_FIELDS = {
    "checkpoints": "checkpoint_sha256",
    "run_events": "event_sha256",
    "ams_events": "event_sha256",
    "admission_reviews": "review_sha256",
    "resource_claims": "claim_sha256",
    "resource_telemetry_samples": "telemetry_sha256",
    "resource_enforcement_trials": "resource_enforcement_trial_sha256",
    "shareability_bundles": "shareability_bundle_sha256",
    "shareability_receiver_trials": "shareability_receiver_trial_sha256",
    "tool_definitions": "definition_sha256",
    "surface_definitions": "definition_sha256",
    "runtime_surfaces": "runtime_surface_sha256",
    "surface_bindings": "surface_binding_sha256",
    "surface_promises": "surface_promise_sha256",
    "shadow_launch_plans": "shadow_launch_plan_sha256",
    "shadow_runner_transactions": "shadow_runner_transaction_sha256",
    "attention_signals": "attention_signal_sha256",
    "manager_interventions": "manager_intervention_sha256",
    "manager_intervention_deliveries": "delivery_sha256",
    "manager_intervention_settlements": "settlement_sha256",
    "architecture_audits": "architecture_audit_sha256",
    "architecture_gate_reviews": "gate_sha256",
    "rag_index_plans": "plan_sha256",
    "downloaded_artifact_quarantines": "quarantine_sha256",
    "rag_embedding_jobs": "job_sha256",
    "provider_auth_preflights": "auth_preflight_sha256",
    "rag_embedding_receipts": "receipt_sha256",
    "rag_retrieval_queries": "retrieval_query_sha256",
    "rag_local_vector_trials": "rag_local_vector_trial_sha256",
    "agent_memory_trials": "trial_sha256",
    "memory_claims": "memory_claim_sha256",
    "memory_promotion_reviews": "memory_promotion_review_sha256",
    "memory_supersession_records": "memory_supersession_record_sha256",
    "memory_conflict_records": "memory_conflict_record_sha256",
    "real_agent_trials": "trial_sha256",
    "real_agent_system_trials": "real_agent_system_trial_sha256",
    "provider_results": "sha256",
    "incident_packets": "incident_sha256",
    "outbox_items": "outbox_sha256",
    "outbox_receipts": "receipt_sha256",
    "store_backup_drills": "drill_sha256",
    "runner_dry_run_parities": "parity_sha256",
    "shadow_approval_packets": "approval_packet_sha256",
    "discord_source_packets": "source_packet_sha256",
    "discord_canary_send_plans": "canary_send_plan_sha256",
    "discord_canary_receipts": "canary_receipt_sha256",
    "terminal_source_packets": "source_packet_sha256",
    "conformance_packs": "conformance_pack_sha256",
    "markdown_audits": "markdown_audit_sha256",
    "readiness_reviews": "readiness_review_sha256",
    "doc_retirement_plans": "doc_retirement_plan_sha256",
    "doc_action_execution_plans": "doc_action_execution_plan_sha256",
    "doc_action_operator_approval_packets": "doc_action_operator_approval_packet_sha256",
    "doc_action_patch_previews": "doc_action_patch_preview_sha256",
    "doc_action_patch_readback_receipts": "doc_action_patch_readback_receipt_sha256",
    "doc_action_patch_artifact_receipts": "doc_action_patch_artifact_receipt_sha256",
    "doc_action_patch_artifact_approval_packets": "doc_action_patch_artifact_approval_packet_sha256",
    "doc_action_patch_dry_run_plans": "doc_action_patch_dry_run_plan_sha256",
    "doc_action_patch_dry_run_readback_receipts": "doc_action_patch_dry_run_readback_receipt_sha256",
    "doc_action_patch_live_execution_approval_packets": "doc_action_patch_live_execution_approval_packet_sha256",
    "doc_action_patch_executor_preflights": "doc_action_patch_executor_preflight_sha256",
    "doc_action_patch_apply_boundary_packets": "doc_action_patch_apply_boundary_packet_sha256",
    "doc_action_patch_apply_acceptance_packets": "doc_action_patch_apply_acceptance_packet_sha256",
    "source_write_executor_preflights": "source_write_executor_preflight_sha256",
    "source_write_backup_preimage_receipts": "source_write_backup_preimage_receipt_sha256",
    "source_write_executor_leases": "source_write_executor_lease_sha256",
    "generated_status_snapshots": "generated_status_snapshot_sha256",
    "session_start_briefs": "session_start_brief_sha256",
    "markdown_authority_indexes": "markdown_authority_index_sha256",
    "markdown_authority_entries": "markdown_authority_entry_sha256",
    "codebase_spider_graph_snapshots": "codebase_spider_graph_snapshot_sha256",
    "codebase_graph_nodes": "codebase_graph_node_sha256",
    "codebase_graph_edges": "codebase_graph_edge_sha256",
    "codebase_graph_query_receipts": "codebase_graph_query_receipt_sha256",
    "blast_radius_reviews": "blast_radius_review_sha256",
    "work_mode_decisions": "work_mode_decision_sha256",
    "simulation_sweeps": "simulation_sweep_sha256",
    "ams_emulation_trials": "ams_emulation_trial_sha256",
    "semantic_oracle_reviews": "semantic_oracle_review_sha256",
    "semantic_hook_records": "semantic_hook_record_sha256",
    "semantic_hook_runs": "semantic_hook_run_sha256",
    "semantic_hook_install_plans": "semantic_hook_install_plan_sha256",
    "semantic_hook_approval_bindings": "semantic_hook_approval_binding_sha256",
    "semantic_hook_target_snapshots": "semantic_hook_target_snapshot_sha256",
    "semantic_hook_install_transactions": "semantic_hook_install_transaction_sha256",
    "semantic_hook_operator_approval_packets": "semantic_hook_operator_approval_packet_sha256",
    "semantic_hook_operator_readback_receipts": "semantic_hook_operator_readback_receipt_sha256",
}


DEFAULT_MAX_RECORDS_PER_COLLECTION = 5


def run_replay_oracle(
    state: dict[str, Any],
    *,
    exhaustive: bool = False,
    max_records_per_collection: int = DEFAULT_MAX_RECORDS_PER_COLLECTION,
) -> dict[str, Any]:
    baseline = replay_check(deepcopy(state))
    cases: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    max_records_per_collection = max(1, int(max_records_per_collection or DEFAULT_MAX_RECORDS_PER_COLLECTION))

    if baseline["ok"]:
        for collection in CRITICAL_COLLECTIONS:
            records = state.get(collection) or {}
            if not records:
                skipped.append({"attack": "delete_record", "collection": collection, "reason": "empty"})
                continue
            record_ids = _record_ids_for_attack(
                collection=collection,
                records=records,
                exhaustive=exhaustive,
                max_records_per_collection=max_records_per_collection,
                skipped=skipped,
                attack="delete_record",
            )
            for record_id in record_ids:
                if collection in {"tool_definitions", "surface_definitions"} and not _definition_is_referenced(
                    state,
                    collection,
                    record_id,
                ):
                    skipped.append(
                        {
                            "attack": "delete_record",
                            "collection": collection,
                            "record_id": record_id,
                            "reason": "definition not pinned by a task_run",
                        }
                    )
                    continue
                mutated = deepcopy(state)
                mutated.setdefault(collection, {}).pop(record_id, None)
                cases.append(_case("delete_record", collection, record_id, replay_check(mutated)))

        for collection, hash_field in HASH_FIELDS.items():
            records = state.get(collection) or {}
            if not records:
                skipped.append({"attack": "mutate_hashed_record", "collection": collection, "reason": "empty"})
                continue
            record_ids = _record_ids_for_attack(
                collection=collection,
                records=records,
                exhaustive=exhaustive,
                max_records_per_collection=max_records_per_collection,
                skipped=skipped,
                attack="mutate_hashed_record",
            )
            for record_id in record_ids:
                mutated = deepcopy(state)
                record = mutated.setdefault(collection, {}).get(record_id)
                if not isinstance(record, dict) or hash_field not in record:
                    skipped.append(
                        {
                            "attack": "mutate_hashed_record",
                            "collection": collection,
                            "record_id": record_id,
                            "reason": f"missing {hash_field}",
                        }
                    )
                    continue
                if not _mutate_record(record, skip_keys={hash_field}):
                    skipped.append(
                        {
                            "attack": "mutate_hashed_record",
                            "collection": collection,
                            "record_id": record_id,
                            "reason": "no mutable field",
                        }
                    )
                    continue
                cases.append(_case("mutate_hashed_record", collection, record_id, replay_check(mutated)))

        run_events = state.get("run_events") or {}
        if run_events:
            record_id = sorted(run_events)[0]
            mutated = deepcopy(state)
            mutated["run_events"][record_id]["sequence"] = int(
                mutated["run_events"][record_id].get("sequence", 0) or 0
            ) + 100
            cases.append(_case("bump_run_event_sequence", "run_events", record_id, replay_check(mutated)))
        else:
            skipped.append({"attack": "bump_run_event_sequence", "collection": "run_events", "reason": "empty"})

    misses = [case for case in cases if case["detected"] is False]
    return {
        "ok": baseline["ok"] and not misses,
        "baseline": baseline,
        "summary": {
            "cases": len(cases),
            "detected": len(cases) - len(misses),
            "missed": len(misses),
            "skipped": len(skipped),
            "exhaustive": exhaustive,
            "max_records_per_collection": None if exhaustive else max_records_per_collection,
        },
        "misses": misses,
        "cases": cases,
        "skipped": skipped,
        "unhashed_collections": [
            collection for collection in CRITICAL_COLLECTIONS
            if collection not in HASH_FIELDS and state.get(collection)
        ],
}


def _record_ids_for_attack(
    *,
    collection: str,
    records: dict[str, Any],
    exhaustive: bool,
    max_records_per_collection: int,
    skipped: list[dict[str, Any]],
    attack: str,
) -> list[str]:
    record_ids = sorted(records)
    if exhaustive or len(record_ids) <= max_records_per_collection:
        return record_ids
    selected = record_ids[:max_records_per_collection]
    skipped.append(
        {
            "attack": attack,
            "collection": collection,
            "reason": "sampled_out",
            "sampled_records": len(selected),
            "skipped_records": len(record_ids) - len(selected),
        }
    )
    return selected


def _case(attack: str, collection: str, record_id: str, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "attack": attack,
        "collection": collection,
        "record_id": record_id,
        "detected": not result["ok"],
        "errors": result["errors"][:6],
    }


def _definition_is_referenced(state: dict[str, Any], collection: str, record_id: str) -> bool:
    for task_run in (state.get("task_runs") or {}).values():
        if collection == "tool_definitions":
            for ref in task_run.get("tool_definition_refs") or []:
                if ref.get("definition_id") == record_id:
                    return True
        elif collection == "surface_definitions":
            ref = task_run.get("surface_definition_ref") or {}
            if ref.get("definition_id") == record_id:
                return True
    if collection == "surface_definitions":
        for binding in (state.get("runtime_surfaces") or {}).values():
            ref = binding.get("surface_definition_ref") or {}
            if ref.get("definition_id") == record_id:
                return True
    return False


def _mutate_record(record: dict[str, Any], *, skip_keys: set[str]) -> bool:
    for key in sorted(record):
        if key in skip_keys:
            continue
        value = record[key]
        mutated, new_value = _mutated_value(value)
        if mutated:
            record[key] = new_value
            return True
    return False


def _mutated_value(value: Any) -> tuple[bool, Any]:
    if isinstance(value, bool):
        return True, not value
    if isinstance(value, int) and not isinstance(value, bool):
        return True, value + 1
    if isinstance(value, float):
        return True, value + 1.0
    if isinstance(value, str):
        return True, value + "#tampered"
    if value is None:
        return True, "tampered"
    if isinstance(value, list):
        return True, list(value) + ["tampered"]
    if isinstance(value, dict):
        updated = deepcopy(value)
        updated["tampered"] = True
        return True, updated
    return False, value


class ReplayOracle:
    def __init__(
        self,
        store: JsonStore | None = None,
        *,
        exhaustive: bool = False,
        max_records_per_collection: int = DEFAULT_MAX_RECORDS_PER_COLLECTION,
    ) -> None:
        self.store = store or JsonStore()
        self.exhaustive = exhaustive
        self.max_records_per_collection = max_records_per_collection

    def check(
        self,
        *,
        exhaustive: bool | None = None,
        max_records_per_collection: int | None = None,
    ) -> dict[str, Any]:
        return run_replay_oracle(
            self.store.load(),
            exhaustive=self.exhaustive if exhaustive is None else exhaustive,
            max_records_per_collection=(
                self.max_records_per_collection
                if max_records_per_collection is None
                else max_records_per_collection
            ),
        )
