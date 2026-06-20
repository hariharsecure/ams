from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import fcntl
import json
import os
from pathlib import Path
from typing import Any

from .durability import fsync_dir, full_fsync
from .schema_validation import validate_state_records


DEFAULT_STORE = Path.home() / ".ams" / "stores" / "ams_codex_store.json"


def empty_state() -> dict[str, Any]:
    return {
        "schema": "ams.ams_codex.store.v0",
        "revision": 0,
        "sessions": {},
        "contexts": {},
        "checkpoints": {},
        "task_runs": {},
        "run_events": {},
        "ams_events": {},
        "admission_reviews": {},
        "resource_policies": {},
        "resource_claims": {},
        "resource_telemetry_samples": {},
        "resource_enforcement_trials": {},
        "shareability_bundles": {},
        "shareability_receiver_trials": {},
        "tool_definitions": {},
        "surface_definitions": {},
        "runtime_surfaces": {},
        "surface_bindings": {},
        "surface_promises": {},
        "shadow_launch_plans": {},
        "shadow_runner_transactions": {},
        "attention_signals": {},
        "manager_interventions": {},
        "manager_intervention_deliveries": {},
        "manager_intervention_settlements": {},
        "architecture_audits": {},
        "architecture_gate_reviews": {},
        "rag_index_plans": {},
        "downloaded_artifact_quarantines": {},
        "rag_embedding_jobs": {},
        "provider_auth_preflights": {},
        "rag_embedding_receipts": {},
        "rag_retrieval_queries": {},
        "rag_local_vector_trials": {},
        "agent_memory_trials": {},
        "memory_claims": {},
        "memory_promotion_reviews": {},
        "memory_supersession_records": {},
        "memory_conflict_records": {},
        "real_agent_trials": {},
        "real_agent_system_trials": {},
        "provider_results": {},
        "incident_packets": {},
        "outbox_items": {},
        "outbox_receipts": {},
        "store_backup_drills": {},
        "runner_dry_run_parities": {},
        "shadow_approval_packets": {},
        "discord_source_packets": {},
        "discord_canary_send_plans": {},
        "discord_canary_receipts": {},
        "terminal_source_packets": {},
        "conformance_packs": {},
        "markdown_audits": {},
        "readiness_reviews": {},
        "doc_retirement_plans": {},
        "doc_action_execution_plans": {},
        "doc_action_operator_approval_packets": {},
        "doc_action_patch_previews": {},
        "doc_action_patch_readback_receipts": {},
        "doc_action_patch_artifact_receipts": {},
        "doc_action_patch_artifact_approval_packets": {},
        "doc_action_patch_dry_run_plans": {},
        "doc_action_patch_dry_run_readback_receipts": {},
        "doc_action_patch_live_execution_approval_packets": {},
        "doc_action_patch_executor_preflights": {},
        "doc_action_patch_apply_boundary_packets": {},
        "doc_action_patch_apply_acceptance_packets": {},
        "source_write_executor_preflights": {},
        "source_write_backup_preimage_receipts": {},
        "source_write_executor_leases": {},
        "generated_status_snapshots": {},
        "session_start_briefs": {},
        "markdown_authority_indexes": {},
        "markdown_authority_entries": {},
        "codebase_spider_graph_snapshots": {},
        "codebase_graph_nodes": {},
        "codebase_graph_edges": {},
        "codebase_graph_query_receipts": {},
        "blast_radius_reviews": {},
        "work_mode_decisions": {},
        "simulation_sweeps": {},
        "ams_emulation_trials": {},
        "semantic_oracle_reviews": {},
        "semantic_hook_records": {},
        "semantic_hook_runs": {},
        "semantic_hook_install_plans": {},
        "semantic_hook_approval_bindings": {},
        "semantic_hook_target_snapshots": {},
        "semantic_hook_install_transactions": {},
        "semantic_hook_operator_approval_packets": {},
        "semantic_hook_operator_readback_receipts": {},
        "events": {},
        "indexes": {
            "root_to_session": {},
            "thread_to_session": {},
            "message_to_session": {},
            "attention_to_session": {},
            "content_to_session": {},
            "shadow_launch_plan_ids": {},
            "shadow_runner_transaction_ids": {},
            "attention_signal_ids": {},
            "source_ref_to_attention_signal": {},
            "content_to_attention_signal": {},
            "manager_intervention_ids": {},
            "manager_intervention_delivery_ids": {},
            "manager_intervention_settlement_ids": {},
            "architecture_audit_ids": {},
            "architecture_gate_review_ids": {},
            "rag_index_plan_ids": {},
            "downloaded_artifact_quarantine_ids": {},
            "rag_embedding_job_ids": {},
            "provider_auth_preflight_ids": {},
            "rag_embedding_receipt_ids": {},
            "rag_retrieval_query_ids": {},
            "rag_local_vector_trial_ids": {},
            "agent_memory_trial_ids": {},
            "memory_claim_ids": {},
            "memory_promotion_review_ids": {},
            "memory_supersession_record_ids": {},
            "memory_conflict_record_ids": {},
            "real_agent_trial_ids": {},
            "real_agent_system_trial_ids": {},
            "resource_telemetry_ids": {},
            "resource_claim_to_telemetry": {},
            "resource_enforcement_trial_ids": {},
            "shareability_bundle_ids": {},
            "shareability_receiver_trial_ids": {},
            "store_backup_drill_ids": {},
            "runner_dry_run_parity_ids": {},
            "shadow_approval_packet_ids": {},
            "discord_source_packet_ids": {},
            "source_ref_to_discord_source_packet": {},
            "discord_canary_send_plan_ids": {},
            "discord_canary_receipt_ids": {},
            "terminal_source_packet_ids": {},
            "source_ref_to_terminal_source_packet": {},
            "conformance_pack_ids": {},
            "markdown_audit_ids": {},
            "readiness_review_ids": {},
            "doc_retirement_plan_ids": {},
            "doc_action_execution_plan_ids": {},
            "doc_action_operator_approval_packet_ids": {},
            "doc_action_patch_preview_ids": {},
            "doc_action_patch_readback_receipt_ids": {},
            "doc_action_patch_artifact_receipt_ids": {},
            "doc_action_patch_artifact_approval_packet_ids": {},
            "doc_action_patch_dry_run_plan_ids": {},
            "doc_action_patch_dry_run_readback_receipt_ids": {},
            "doc_action_patch_live_execution_approval_packet_ids": {},
            "doc_action_patch_executor_preflight_ids": {},
            "doc_action_patch_apply_boundary_packet_ids": {},
            "doc_action_patch_apply_acceptance_packet_ids": {},
            "source_write_executor_preflight_ids": {},
            "source_write_backup_preimage_receipt_ids": {},
            "source_write_executor_lease_ids": {},
            "generated_status_snapshot_ids": {},
            "session_start_brief_ids": {},
            "markdown_authority_index_ids": {},
            "markdown_authority_entry_ids": {},
            "codebase_spider_graph_snapshot_ids": {},
            "codebase_graph_node_ids": {},
            "codebase_graph_edge_ids": {},
            "codebase_graph_query_receipt_ids": {},
            "blast_radius_review_ids": {},
            "work_mode_decision_ids": {},
            "simulation_sweep_ids": {},
            "ams_emulation_trial_ids": {},
            "semantic_oracle_review_ids": {},
            "semantic_hook_record_ids": {},
            "semantic_hook_run_ids": {},
            "semantic_hook_install_plan_ids": {},
            "semantic_hook_approval_binding_ids": {},
            "semantic_hook_target_snapshot_ids": {},
            "semantic_hook_install_transaction_ids": {},
            "semantic_hook_operator_approval_packet_ids": {},
            "semantic_hook_operator_readback_receipt_ids": {},
        },
    }


class StoreRevisionError(RuntimeError):
    pass


class JsonStore:
    def __init__(self, path: str | Path = DEFAULT_STORE, *, durable: bool = True) -> None:
        self.path = Path(path)
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        self.durable = durable

    def load(self) -> dict[str, Any]:
        return self._load_unlocked()

    def save(
        self,
        state: dict[str, Any],
        *,
        check_revision: bool = True,
        validate: bool = True,
    ) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock_file():
            current = self._load_unlocked()
            current_revision = int(current.get("revision", 0) or 0)
            expected_revision = int(state.get("revision", 0) or 0)
            if check_revision and expected_revision != current_revision:
                raise StoreRevisionError(
                    f"store revision changed: expected {expected_revision}, found {current_revision}"
                )
            next_state = deepcopy(state)
            next_state["revision"] = current_revision + 1
            if validate:
                validate_state_records(next_state)
            self._save_unlocked(next_state)
            state["revision"] = next_state["revision"]

    @contextmanager
    def locked(self, *, validate: bool = True):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock_file():
            state = self._load_unlocked()
            original_revision = int(state.get("revision", 0) or 0)
            yield state
            current = self._load_unlocked()
            current_revision = int(current.get("revision", 0) or 0)
            if current_revision != original_revision:
                raise StoreRevisionError(
                    f"store revision changed under lock: expected {original_revision}, found {current_revision}"
                )
            next_state = deepcopy(state)
            next_state["revision"] = original_revision + 1
            if validate:
                validate_state_records(next_state)
            self._save_unlocked(next_state)
            state["revision"] = next_state["revision"]

    @contextmanager
    def _lock_file(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield fh
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def _load_unlocked(self) -> dict[str, Any]:
        if not self.path.exists():
            return empty_state()
        with self.path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        state = empty_state()
        state.update(data)
        state["revision"] = int(state.get("revision", 0) or 0)
        state.setdefault("indexes", {}).update(data.get("indexes") or {})
        for key, value in empty_state()["indexes"].items():
            state["indexes"].setdefault(key, value.copy())
        return state

    def _save_unlocked(self, state: dict[str, Any]) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            if self.durable:
                os.fsync(fh.fileno())
                full_fsync(fh.fileno())
        tmp.replace(self.path)
        if self.durable:
            fsync_dir(self.path.parent)
