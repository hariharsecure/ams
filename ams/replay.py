from __future__ import annotations

from typing import Any

from .agent_memory_sim import validate_agent_memory_trial_record
from .ams_emulation import validate_ams_emulation_trial_record
from .architecture_audit import validate_architecture_audit_record
from .architecture_gate import validate_architecture_gate_review_record
from .artifact_quarantine import validate_downloaded_artifact_quarantine_record
from .attention_router import validate_attention_signal_record
from .backup_restore import validate_store_backup_drill_record
from .blast_radius import validate_blast_radius_review_record
from .codebase_spider_graph import (
    validate_codebase_graph_edge_record,
    validate_codebase_graph_node_record,
    validate_codebase_graph_query_receipt_record,
    validate_codebase_spider_graph_snapshot_record,
)
from .conformance_pack import validate_conformance_pack_record
from .definition_registry import validate_task_run_definition_pins, _record_hash
from .discord_canary import validate_discord_canary_send_plan_record
from .discord_canary_receipt import validate_discord_canary_receipt_record
from .discord_source import validate_discord_source_packet_record
from .doc_action_execution import (
    validate_doc_action_execution_plan_against_source,
    validate_doc_action_execution_plan_record,
)
from .doc_action_operator_approval import validate_doc_action_operator_approval_packet_record
from .doc_action_patch_preview import validate_doc_action_patch_preview_record
from .doc_action_patch_artifact import validate_doc_action_patch_artifact_receipt_record
from .doc_action_patch_artifact_approval import validate_doc_action_patch_artifact_approval_packet_record
from .doc_action_patch_dry_run import validate_doc_action_patch_dry_run_plan_record
from .doc_action_patch_dry_run_readback import validate_doc_action_patch_dry_run_readback_receipt_record
from .doc_action_patch_apply_acceptance import validate_doc_action_patch_apply_acceptance_packet_record
from .doc_action_patch_apply_boundary import validate_doc_action_patch_apply_boundary_packet_record
from .doc_action_patch_executor_preflight import validate_doc_action_patch_executor_preflight_record
from .doc_action_patch_live_execution_approval import validate_doc_action_patch_live_execution_approval_packet_record
from .doc_action_patch_readback import validate_doc_action_patch_readback_receipt_record
from .doc_retirement import validate_doc_retirement_plan_record
from .source_write_backup_preimage import validate_source_write_backup_preimage_receipt_record
from .source_write_executor_lease import validate_source_write_executor_lease_record
from .source_write_preflight import validate_source_write_executor_preflight_record
from .generated_status import validate_generated_status_snapshot_record
from .intervention_delivery import validate_manager_intervention_delivery_record
from .intervention_settlement import validate_manager_intervention_settlement_record
from .manager_intervention import validate_manager_intervention_record
from .markdown_authority import (
    validate_markdown_authority_entry_record,
    validate_markdown_authority_index_record,
)
from .markdown_governance import validate_markdown_audit_record
from .memory_supersession import (
    validate_memory_claim_record,
    validate_memory_conflict_record,
    validate_memory_promotion_review_record,
    validate_memory_supersession_record,
)
from .models import canonical_json, sha256_text
from .predicate import end_state_hash
from .provider_auth import validate_provider_auth_preflight_record
from .rag_embedding_receipt import validate_rag_embedding_receipt_record
from .rag_local_vector_trial import validate_rag_local_vector_trial_record
from .rag_retrieval_query import validate_rag_retrieval_query_record
from .readiness_review import validate_readiness_review_record
from .real_agent_system_trial import validate_real_agent_system_trial_record
from .real_agent_trial import validate_real_agent_trial_record
from .rag_embedding_job import validate_rag_embedding_job_record
from .rag_index_plan import validate_rag_index_plan_record
from .resource_enforcement import validate_resource_enforcement_trial_record
from .resource_telemetry import validate_resource_telemetry_record
from .runner_parity import validate_runner_dry_run_parity_record
from .run_trace import _next_state
from .session_start_brief import validate_session_start_brief_record
from .semantic_hook_approval import validate_semantic_hook_approval_binding_record
from .semantic_hook_install_transaction import validate_semantic_hook_install_transaction_record
from .semantic_hook_operator_approval import validate_semantic_hook_operator_approval_packet_record
from .semantic_hook_operator_readback import validate_semantic_hook_operator_readback_receipt_record
from .semantic_hook_install_plan import validate_semantic_hook_install_plan_record
from .semantic_hook_run import validate_semantic_hook_record_record, validate_semantic_hook_run_record
from .semantic_hook_target_snapshot import validate_semantic_hook_target_snapshot_record
from .semantic_oracle_review import validate_semantic_oracle_review_record
from .shadow_approval import validate_shadow_approval_packet_record
from .shadow_launch import validate_shadow_launch_plan_record
from .shadow_runner import validate_shadow_runner_transaction_record
from .shareability_bundle import validate_shareability_bundle_record
from .shareability_receiver import validate_shareability_receiver_trial_record
from .surface_bindings import validate_runtime_surface_record, validate_surface_binding_record
from .surface_promise import validate_surface_promise_record
from .surface_receipt import provider_message_id as _provider_message_id
from .store import JsonStore
from .terminal_source import validate_terminal_source_packet_record
from .work_mode_decision import validate_work_mode_decision_record
from .simulation_sweep import validate_simulation_sweep_record


def replay_check(state: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    sessions = state.get("sessions") or {}
    indexes = state.get("indexes") or {}
    contexts = state.get("contexts") or {}
    checkpoints = state.get("checkpoints") or {}
    task_runs = state.get("task_runs") or {}
    run_events = state.get("run_events") or {}
    ams_events = state.get("ams_events") or {}
    admission_reviews = state.get("admission_reviews") or {}
    resource_policies = state.get("resource_policies") or {}
    resource_claims = state.get("resource_claims") or {}
    resource_telemetry_samples = state.get("resource_telemetry_samples") or {}
    resource_enforcement_trials = state.get("resource_enforcement_trials") or {}
    shareability_bundles = state.get("shareability_bundles") or {}
    shareability_receiver_trials = state.get("shareability_receiver_trials") or {}
    tool_definitions = state.get("tool_definitions") or {}
    surface_definitions = state.get("surface_definitions") or {}
    runtime_surfaces = state.get("runtime_surfaces") or {}
    surface_bindings = state.get("surface_bindings") or {}
    surface_promises = state.get("surface_promises") or {}
    shadow_launch_plans = state.get("shadow_launch_plans") or {}
    shadow_runner_transactions = state.get("shadow_runner_transactions") or {}
    attention_signals = state.get("attention_signals") or {}
    manager_interventions = state.get("manager_interventions") or {}
    manager_intervention_deliveries = state.get("manager_intervention_deliveries") or {}
    manager_intervention_settlements = state.get("manager_intervention_settlements") or {}
    architecture_audits = state.get("architecture_audits") or {}
    architecture_gate_reviews = state.get("architecture_gate_reviews") or {}
    rag_index_plans = state.get("rag_index_plans") or {}
    downloaded_artifact_quarantines = state.get("downloaded_artifact_quarantines") or {}
    rag_embedding_jobs = state.get("rag_embedding_jobs") or {}
    provider_auth_preflights = state.get("provider_auth_preflights") or {}
    rag_embedding_receipts = state.get("rag_embedding_receipts") or {}
    rag_retrieval_queries = state.get("rag_retrieval_queries") or {}
    rag_local_vector_trials = state.get("rag_local_vector_trials") or {}
    agent_memory_trials = state.get("agent_memory_trials") or {}
    memory_claims = state.get("memory_claims") or {}
    memory_promotion_reviews = state.get("memory_promotion_reviews") or {}
    memory_supersession_records = state.get("memory_supersession_records") or {}
    memory_conflict_records = state.get("memory_conflict_records") or {}
    real_agent_trials = state.get("real_agent_trials") or {}
    real_agent_system_trials = state.get("real_agent_system_trials") or {}
    provider_results = state.get("provider_results") or {}
    incident_packets = state.get("incident_packets") or {}
    outbox_items = state.get("outbox_items") or {}
    outbox_receipts = state.get("outbox_receipts") or {}
    store_backup_drills = state.get("store_backup_drills") or {}
    runner_dry_run_parities = state.get("runner_dry_run_parities") or {}
    shadow_approval_packets = state.get("shadow_approval_packets") or {}
    discord_source_packets = state.get("discord_source_packets") or {}
    discord_canary_send_plans = state.get("discord_canary_send_plans") or {}
    discord_canary_receipts = state.get("discord_canary_receipts") or {}
    terminal_source_packets = state.get("terminal_source_packets") or {}
    conformance_packs = state.get("conformance_packs") or {}
    markdown_audits = state.get("markdown_audits") or {}
    readiness_reviews = state.get("readiness_reviews") or {}
    doc_retirement_plans = state.get("doc_retirement_plans") or {}
    doc_action_execution_plans = state.get("doc_action_execution_plans") or {}
    doc_action_operator_approval_packets = state.get("doc_action_operator_approval_packets") or {}
    doc_action_patch_previews = state.get("doc_action_patch_previews") or {}
    doc_action_patch_readback_receipts = state.get("doc_action_patch_readback_receipts") or {}
    doc_action_patch_artifact_receipts = state.get("doc_action_patch_artifact_receipts") or {}
    doc_action_patch_artifact_approval_packets = state.get("doc_action_patch_artifact_approval_packets") or {}
    doc_action_patch_dry_run_plans = state.get("doc_action_patch_dry_run_plans") or {}
    doc_action_patch_dry_run_readback_receipts = state.get("doc_action_patch_dry_run_readback_receipts") or {}
    doc_action_patch_live_execution_approval_packets = (
        state.get("doc_action_patch_live_execution_approval_packets") or {}
    )
    doc_action_patch_executor_preflights = state.get("doc_action_patch_executor_preflights") or {}
    doc_action_patch_apply_boundary_packets = state.get("doc_action_patch_apply_boundary_packets") or {}
    doc_action_patch_apply_acceptance_packets = state.get("doc_action_patch_apply_acceptance_packets") or {}
    source_write_executor_preflights = state.get("source_write_executor_preflights") or {}
    source_write_backup_preimage_receipts = state.get("source_write_backup_preimage_receipts") or {}
    source_write_executor_leases = state.get("source_write_executor_leases") or {}
    generated_status_snapshots = state.get("generated_status_snapshots") or {}
    session_start_briefs = state.get("session_start_briefs") or {}
    markdown_authority_indexes = state.get("markdown_authority_indexes") or {}
    markdown_authority_entries = state.get("markdown_authority_entries") or {}
    codebase_spider_graph_snapshots = state.get("codebase_spider_graph_snapshots") or {}
    codebase_graph_nodes = state.get("codebase_graph_nodes") or {}
    codebase_graph_edges = state.get("codebase_graph_edges") or {}
    codebase_graph_query_receipts = state.get("codebase_graph_query_receipts") or {}
    blast_radius_reviews = state.get("blast_radius_reviews") or {}
    work_mode_decisions = state.get("work_mode_decisions") or {}
    simulation_sweeps = state.get("simulation_sweeps") or {}
    ams_emulation_trials = state.get("ams_emulation_trials") or {}
    semantic_oracle_reviews = state.get("semantic_oracle_reviews") or {}
    semantic_hook_records = state.get("semantic_hook_records") or {}
    semantic_hook_runs = state.get("semantic_hook_runs") or {}
    semantic_hook_install_plans = state.get("semantic_hook_install_plans") or {}
    semantic_hook_approval_bindings = state.get("semantic_hook_approval_bindings") or {}
    semantic_hook_target_snapshots = state.get("semantic_hook_target_snapshots") or {}
    semantic_hook_install_transactions = state.get("semantic_hook_install_transactions") or {}
    semantic_hook_operator_approval_packets = state.get("semantic_hook_operator_approval_packets") or {}
    semantic_hook_operator_readback_receipts = state.get("semantic_hook_operator_readback_receipts") or {}

    for event_id, event in (state.get("events") or {}).items():
        if not isinstance(event, dict):
            errors.append(f"event {event_id} is not an object")
            continue
        if event.get("event_id") != event_id:
            errors.append(f"event key mismatch: {event_id}")
        for required in ("event_id", "channel_id", "message_id", "received_at"):
            if not event.get(required):
                errors.append(f"event {event_id} missing {required}")

    for sid, session in sessions.items():
        for required in ("session_id", "attention_id", "discord_root_message_id", "state"):
            if not session.get(required):
                errors.append(f"session {sid} missing {required}")
        if session.get("session_id") != sid:
            errors.append(f"session key mismatch: {sid}")
        for event_id in session.get("event_ids") or []:
            if event_id not in state.get("events", {}):
                errors.append(f"session {sid} references missing event {event_id}")
        for msg_id in session.get("message_ids") or []:
            mapped = (indexes.get("message_to_session") or {}).get(msg_id)
            if mapped != sid:
                errors.append(f"message index mismatch {msg_id}: {mapped} != {sid}")
        attn = session.get("attention_id")
        if attn:
            mapped = (indexes.get("attention_to_session") or {}).get(attn)
            if mapped != sid:
                errors.append(f"attention index mismatch {attn}: {mapped} != {sid}")
        checkpoint_id = session.get("last_summary_checkpoint_id")
        if checkpoint_id and checkpoint_id not in checkpoints:
            errors.append(f"session {sid} references missing checkpoint {checkpoint_id}")
        seen_provider_keys: set[tuple[str, str]] = set()
        for binding in session.get("provider_sessions") or []:
            key = (str(binding.get("provider")), str(binding.get("surface")))
            if key in seen_provider_keys:
                errors.append(f"session {sid} duplicate provider binding {key}")
            seen_provider_keys.add(key)
            if not binding.get("provider_session_id"):
                errors.append(f"session {sid} provider binding {key} missing provider_session_id")
            if binding.get("last_checkpoint_id") and binding["last_checkpoint_id"] not in checkpoints:
                errors.append(f"session {sid} provider binding {key} references missing checkpoint")
        codex_bindings = [
            b for b in session.get("provider_sessions") or []
            if b.get("provider") == "openai_codex" and b.get("surface") == session.get("codex_surface")
        ]
        if session.get("codex_thread_id") and not codex_bindings:
            errors.append(f"session {sid} has codex_thread_id but no provider binding")
        claude_bindings = [
            b for b in session.get("provider_sessions") or []
            if b.get("provider") == "anthropic_claude" and b.get("surface") == session.get("claude_surface")
        ]
        if session.get("claude_session_id") and not claude_bindings:
            errors.append(f"session {sid} has claude_session_id but no provider binding")

    for cid, context in contexts.items():
        sid = context.get("session_id")
        if sid not in sessions:
            errors.append(f"context {cid} references missing session {sid}")

    for checkpoint_id, checkpoint in checkpoints.items():
        sid = checkpoint.get("session_id")
        if sid not in sessions:
            errors.append(f"checkpoint {checkpoint_id} references missing session {sid}")
        if not str(checkpoint.get("checkpoint_sha256") or "").startswith("sha256:"):
            errors.append(f"checkpoint {checkpoint_id} missing sha256")
        else:
            without_hash = dict(checkpoint)
            expected = without_hash.pop("checkpoint_sha256")
            actual = sha256_text(canonical_json(without_hash))
            if expected != actual:
                errors.append(f"checkpoint {checkpoint_id} sha256 mismatch")

    for task_run_id, task_run in task_runs.items():
        for required in ("task_run_id", "session_id", "context_id", "attention_id", "provider", "state", "created_at"):
            if not task_run.get(required):
                errors.append(f"task_run {task_run_id} missing {required}")
        if task_run.get("task_run_id") != task_run_id:
            errors.append(f"task_run key mismatch: {task_run_id}")
        sid = task_run.get("session_id")
        cid = task_run.get("context_id")
        if sid not in sessions:
            errors.append(f"task_run {task_run_id} references missing session {sid}")
        if cid not in contexts:
            errors.append(f"task_run {task_run_id} references missing context {cid}")
        elif contexts[cid].get("session_id") != sid:
            errors.append(f"task_run {task_run_id} context/session mismatch")
        elif task_run.get("input_context_sha256") != sha256_text(canonical_json(contexts[cid])):
            errors.append(f"task_run {task_run_id} input context sha256 mismatch")
        parent_run_id = task_run.get("parent_run_id")
        if parent_run_id and parent_run_id not in task_runs:
            errors.append(f"task_run {task_run_id} references missing parent_run_id {parent_run_id}")
        checkpoint_id = task_run.get("summary_checkpoint_id")
        if checkpoint_id and checkpoint_id not in checkpoints:
            errors.append(f"task_run {task_run_id} references missing checkpoint {checkpoint_id}")
        provider_session_id = task_run.get("provider_session_id")
        if provider_session_id and sid in sessions:
            bindings = sessions[sid].get("provider_sessions") or []
            matched = [
                binding for binding in bindings
                if binding.get("provider") == task_run.get("provider")
                and binding.get("provider_session_id") == provider_session_id
                and (
                    task_run.get("provider_surface") is None
                    or binding.get("surface") == task_run.get("provider_surface")
                )
            ]
            if not matched:
                errors.append(f"task_run {task_run_id} provider_session_id not bound to session")
        definition_result = validate_task_run_definition_pins(state, task_run)
        if not definition_result["ok"]:
            for reason_code in definition_result["reason_codes"]:
                errors.append(f"task_run {task_run_id} {reason_code}")

    seen_tool_names: set[tuple[str, str]] = set()
    for definition_id, definition in tool_definitions.items():
        if definition.get("definition_id") != definition_id:
            errors.append(f"tool_definition key mismatch: {definition_id}")
        key = (str(definition.get("name")), str(definition.get("version")))
        if key in seen_tool_names:
            errors.append(f"duplicate tool_definition {key}")
        seen_tool_names.add(key)
        if definition.get("definition_sha256") != _record_hash(definition):
            errors.append(f"tool_definition {definition_id} sha256 mismatch")

    seen_surfaces: set[tuple[str, str, str]] = set()
    for definition_id, definition in surface_definitions.items():
        if definition.get("definition_id") != definition_id:
            errors.append(f"surface_definition key mismatch: {definition_id}")
        key = (
            str(definition.get("provider")),
            str(definition.get("surface")),
            str(definition.get("version")),
        )
        if key in seen_surfaces:
            errors.append(f"duplicate surface_definition {key}")
        seen_surfaces.add(key)
        if definition.get("definition_sha256") != _record_hash(definition):
            errors.append(f"surface_definition {definition_id} sha256 mismatch")

    seen_runtime_surfaces: set[tuple[str, str, str]] = set()
    for runtime_surface_id, surface in runtime_surfaces.items():
        if surface.get("runtime_surface_id") != runtime_surface_id:
            errors.append(f"runtime_surface key mismatch: {runtime_surface_id}")
        key = (
            str(surface.get("runtime_name")),
            str(surface.get("provider")),
            str(surface.get("surface")),
        )
        if key in seen_runtime_surfaces:
            errors.append(f"duplicate runtime_surface {key}")
        seen_runtime_surfaces.add(key)
        validation = validate_runtime_surface_record(surface, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"runtime_surface {runtime_surface_id} {reason_code}")

    seen_surface_bindings: set[tuple[str, str, str | None]] = set()
    for surface_binding_id, binding in surface_bindings.items():
        if binding.get("surface_binding_id") != surface_binding_id:
            errors.append(f"surface_binding key mismatch: {surface_binding_id}")
        key = (
            str(binding.get("runtime_surface_id")),
            str(binding.get("session_id")),
            binding.get("provider_session_id"),
        )
        if key in seen_surface_bindings:
            errors.append(f"duplicate surface_binding {key}")
        seen_surface_bindings.add(key)
        validation = validate_surface_binding_record(binding, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"surface_binding {surface_binding_id} {reason_code}")

    for surface_promise_id, promise in surface_promises.items():
        if promise.get("surface_promise_id") != surface_promise_id:
            errors.append(f"surface_promise key mismatch: {surface_promise_id}")
        validation = validate_surface_promise_record(promise, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"surface_promise {surface_promise_id} {reason_code}")

    for indexed_plan_id, plan_id in (indexes.get("shadow_launch_plan_ids") or {}).items():
        if indexed_plan_id != plan_id:
            errors.append(f"shadow_launch_plan index mismatch: {indexed_plan_id} != {plan_id}")
        if plan_id not in shadow_launch_plans:
            errors.append(f"shadow_launch_plan index references missing plan {plan_id}")

    for shadow_launch_plan_id, plan in shadow_launch_plans.items():
        if plan.get("shadow_launch_plan_id") != shadow_launch_plan_id:
            errors.append(f"shadow_launch_plan key mismatch: {shadow_launch_plan_id}")
        indexed = (indexes.get("shadow_launch_plan_ids") or {}).get(shadow_launch_plan_id)
        if indexed != shadow_launch_plan_id:
            errors.append(f"shadow_launch_plan index missing: {shadow_launch_plan_id}")
        validation = validate_shadow_launch_plan_record(plan, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"shadow_launch_plan {shadow_launch_plan_id} {reason_code}")

    for indexed_transaction_id, transaction_id in (indexes.get("shadow_runner_transaction_ids") or {}).items():
        if indexed_transaction_id != transaction_id:
            errors.append(f"shadow_runner_transaction index mismatch: {indexed_transaction_id} != {transaction_id}")
        if transaction_id not in shadow_runner_transactions:
            errors.append(f"shadow_runner_transaction index references missing transaction {transaction_id}")

    for transaction_id, transaction in shadow_runner_transactions.items():
        if transaction.get("shadow_runner_transaction_id") != transaction_id:
            errors.append(f"shadow_runner_transaction key mismatch: {transaction_id}")
        indexed = (indexes.get("shadow_runner_transaction_ids") or {}).get(transaction_id)
        if indexed != transaction_id:
            errors.append(f"shadow_runner_transaction index missing: {transaction_id}")
        validation = validate_shadow_runner_transaction_record(transaction, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"shadow_runner_transaction {transaction_id} {reason_code}")

    for indexed_signal_id, signal_id in (indexes.get("attention_signal_ids") or {}).items():
        if indexed_signal_id != signal_id:
            errors.append(f"attention_signal index mismatch: {indexed_signal_id} != {signal_id}")
        if signal_id not in attention_signals:
            errors.append(f"attention_signal index references missing signal {signal_id}")

    for signal_id, signal in attention_signals.items():
        if signal.get("attention_signal_id") != signal_id:
            errors.append(f"attention_signal key mismatch: {signal_id}")
        indexed = (indexes.get("attention_signal_ids") or {}).get(signal_id)
        if indexed != signal_id:
            errors.append(f"attention_signal index missing: {signal_id}")
        source_ref = signal.get("source_ref")
        if source_ref:
            mapped = (indexes.get("source_ref_to_attention_signal") or {}).get(source_ref)
            if mapped != signal_id:
                errors.append(f"attention_signal source index mismatch: {source_ref}")
        content_sha256 = signal.get("content_sha256")
        if content_sha256:
            mapped = (indexes.get("content_to_attention_signal") or {}).get(content_sha256)
            if mapped != signal_id:
                errors.append(f"attention_signal content index mismatch: {content_sha256}")
        validation = validate_attention_signal_record(signal, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"attention_signal {signal_id} {reason_code}")

    for indexed_intervention_id, intervention_id in (indexes.get("manager_intervention_ids") or {}).items():
        if indexed_intervention_id != intervention_id:
            errors.append(f"manager_intervention index mismatch: {indexed_intervention_id} != {intervention_id}")
        if intervention_id not in manager_interventions:
            errors.append(f"manager_intervention index references missing intervention {intervention_id}")

    for intervention_id, intervention in manager_interventions.items():
        if intervention.get("manager_intervention_id") != intervention_id:
            errors.append(f"manager_intervention key mismatch: {intervention_id}")
        indexed = (indexes.get("manager_intervention_ids") or {}).get(intervention_id)
        if indexed != intervention_id:
            errors.append(f"manager_intervention index missing: {intervention_id}")
        validation = validate_manager_intervention_record(intervention, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"manager_intervention {intervention_id} {reason_code}")

    for indexed_delivery_id, delivery_id in (indexes.get("manager_intervention_delivery_ids") or {}).items():
        if indexed_delivery_id != delivery_id:
            errors.append(f"manager_intervention_delivery index mismatch: {indexed_delivery_id} != {delivery_id}")
        if delivery_id not in manager_intervention_deliveries:
            errors.append(f"manager_intervention_delivery index references missing delivery {delivery_id}")

    for delivery_id, delivery in manager_intervention_deliveries.items():
        if delivery.get("manager_intervention_delivery_id") != delivery_id:
            errors.append(f"manager_intervention_delivery key mismatch: {delivery_id}")
        indexed = (indexes.get("manager_intervention_delivery_ids") or {}).get(delivery_id)
        if indexed != delivery_id:
            errors.append(f"manager_intervention_delivery index missing: {delivery_id}")
        validation = validate_manager_intervention_delivery_record(delivery, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"manager_intervention_delivery {delivery_id} {reason_code}")

    for indexed_settlement_id, settlement_id in (indexes.get("manager_intervention_settlement_ids") or {}).items():
        if indexed_settlement_id != settlement_id:
            errors.append(
                f"manager_intervention_settlement index mismatch: {indexed_settlement_id} != {settlement_id}"
            )
        if settlement_id not in manager_intervention_settlements:
            errors.append(f"manager_intervention_settlement index references missing settlement {settlement_id}")

    for settlement_id, settlement in manager_intervention_settlements.items():
        if settlement.get("manager_intervention_settlement_id") != settlement_id:
            errors.append(f"manager_intervention_settlement key mismatch: {settlement_id}")
        indexed = (indexes.get("manager_intervention_settlement_ids") or {}).get(settlement_id)
        if indexed != settlement_id:
            errors.append(f"manager_intervention_settlement index missing: {settlement_id}")
        validation = validate_manager_intervention_settlement_record(settlement, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"manager_intervention_settlement {settlement_id} {reason_code}")

    for indexed_audit_id, audit_id in (indexes.get("architecture_audit_ids") or {}).items():
        if indexed_audit_id != audit_id:
            errors.append(f"architecture_audit index mismatch: {indexed_audit_id} != {audit_id}")
        if audit_id not in architecture_audits:
            errors.append(f"architecture_audit index references missing audit {audit_id}")

    for audit_id, audit in architecture_audits.items():
        if audit.get("architecture_audit_id") != audit_id:
            errors.append(f"architecture_audit key mismatch: {audit_id}")
        indexed = (indexes.get("architecture_audit_ids") or {}).get(audit_id)
        if indexed != audit_id:
            errors.append(f"architecture_audit index missing: {audit_id}")
        validation = validate_architecture_audit_record(audit)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"architecture_audit {audit_id} {reason_code}")

    for indexed_gate_id, gate_id in (indexes.get("architecture_gate_review_ids") or {}).items():
        if indexed_gate_id != gate_id:
            errors.append(f"architecture_gate_review index mismatch: {indexed_gate_id} != {gate_id}")
        if gate_id not in architecture_gate_reviews:
            errors.append(f"architecture_gate_review index references missing gate {gate_id}")

    for gate_id, gate in architecture_gate_reviews.items():
        if gate.get("architecture_gate_review_id") != gate_id:
            errors.append(f"architecture_gate_review key mismatch: {gate_id}")
        indexed = (indexes.get("architecture_gate_review_ids") or {}).get(gate_id)
        if indexed != gate_id:
            errors.append(f"architecture_gate_review index missing: {gate_id}")
        validation = validate_architecture_gate_review_record(gate, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"architecture_gate_review {gate_id} {reason_code}")

    for indexed_plan_id, plan_id in (indexes.get("rag_index_plan_ids") or {}).items():
        if indexed_plan_id != plan_id:
            errors.append(f"rag_index_plan index mismatch: {indexed_plan_id} != {plan_id}")
        if plan_id not in rag_index_plans:
            errors.append(f"rag_index_plan index references missing plan {plan_id}")

    for plan_id, plan in rag_index_plans.items():
        if plan.get("rag_index_plan_id") != plan_id:
            errors.append(f"rag_index_plan key mismatch: {plan_id}")
        indexed = (indexes.get("rag_index_plan_ids") or {}).get(plan_id)
        if indexed != plan_id:
            errors.append(f"rag_index_plan index missing: {plan_id}")
        validation = validate_rag_index_plan_record(plan)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"rag_index_plan {plan_id} {reason_code}")

    for indexed_quarantine_id, quarantine_id in (indexes.get("downloaded_artifact_quarantine_ids") or {}).items():
        if indexed_quarantine_id != quarantine_id:
            errors.append(
                f"downloaded_artifact_quarantine index mismatch: {indexed_quarantine_id} != {quarantine_id}"
            )
        if quarantine_id not in downloaded_artifact_quarantines:
            errors.append(f"downloaded_artifact_quarantine index references missing quarantine {quarantine_id}")

    for quarantine_id, quarantine in downloaded_artifact_quarantines.items():
        if quarantine.get("downloaded_artifact_quarantine_id") != quarantine_id:
            errors.append(f"downloaded_artifact_quarantine key mismatch: {quarantine_id}")
        indexed = (indexes.get("downloaded_artifact_quarantine_ids") or {}).get(quarantine_id)
        if indexed != quarantine_id:
            errors.append(f"downloaded_artifact_quarantine index missing: {quarantine_id}")
        validation = validate_downloaded_artifact_quarantine_record(quarantine)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"downloaded_artifact_quarantine {quarantine_id} {reason_code}")

    for indexed_job_id, job_id in (indexes.get("rag_embedding_job_ids") or {}).items():
        if indexed_job_id != job_id:
            errors.append(f"rag_embedding_job index mismatch: {indexed_job_id} != {job_id}")
        if job_id not in rag_embedding_jobs:
            errors.append(f"rag_embedding_job index references missing job {job_id}")

    for job_id, job in rag_embedding_jobs.items():
        if job.get("rag_embedding_job_id") != job_id:
            errors.append(f"rag_embedding_job key mismatch: {job_id}")
        indexed = (indexes.get("rag_embedding_job_ids") or {}).get(job_id)
        if indexed != job_id:
            errors.append(f"rag_embedding_job index missing: {job_id}")
        validation = validate_rag_embedding_job_record(job, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"rag_embedding_job {job_id} {reason_code}")

    for indexed_preflight_id, preflight_id in (indexes.get("provider_auth_preflight_ids") or {}).items():
        if indexed_preflight_id != preflight_id:
            errors.append(f"provider_auth_preflight index mismatch: {indexed_preflight_id} != {preflight_id}")
        if preflight_id not in provider_auth_preflights:
            errors.append(f"provider_auth_preflight index references missing preflight {preflight_id}")

    for preflight_id, preflight in provider_auth_preflights.items():
        if preflight.get("provider_auth_preflight_id") != preflight_id:
            errors.append(f"provider_auth_preflight key mismatch: {preflight_id}")
        indexed = (indexes.get("provider_auth_preflight_ids") or {}).get(preflight_id)
        if indexed != preflight_id:
            errors.append(f"provider_auth_preflight index missing: {preflight_id}")
        validation = validate_provider_auth_preflight_record(preflight)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"provider_auth_preflight {preflight_id} {reason_code}")

    for indexed_receipt_id, receipt_id in (indexes.get("rag_embedding_receipt_ids") or {}).items():
        if indexed_receipt_id != receipt_id:
            errors.append(f"rag_embedding_receipt index mismatch: {indexed_receipt_id} != {receipt_id}")
        if receipt_id not in rag_embedding_receipts:
            errors.append(f"rag_embedding_receipt index references missing receipt {receipt_id}")

    for receipt_id, receipt in rag_embedding_receipts.items():
        if receipt.get("rag_embedding_receipt_id") != receipt_id:
            errors.append(f"rag_embedding_receipt key mismatch: {receipt_id}")
        indexed = (indexes.get("rag_embedding_receipt_ids") or {}).get(receipt_id)
        if indexed != receipt_id:
            errors.append(f"rag_embedding_receipt index missing: {receipt_id}")
        validation = validate_rag_embedding_receipt_record(receipt, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"rag_embedding_receipt {receipt_id} {reason_code}")

    for indexed_query_id, query_id in (indexes.get("rag_retrieval_query_ids") or {}).items():
        if indexed_query_id != query_id:
            errors.append(f"rag_retrieval_query index mismatch: {indexed_query_id} != {query_id}")
        if query_id not in rag_retrieval_queries:
            errors.append(f"rag_retrieval_query index references missing query {query_id}")

    for query_id, query in rag_retrieval_queries.items():
        if query.get("rag_retrieval_query_id") != query_id:
            errors.append(f"rag_retrieval_query key mismatch: {query_id}")
        indexed = (indexes.get("rag_retrieval_query_ids") or {}).get(query_id)
        if indexed != query_id:
            errors.append(f"rag_retrieval_query index missing: {query_id}")
        validation = validate_rag_retrieval_query_record(query, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"rag_retrieval_query {query_id} {reason_code}")

    for indexed_trial_id, trial_id in (indexes.get("rag_local_vector_trial_ids") or {}).items():
        if indexed_trial_id != trial_id:
            errors.append(f"rag_local_vector_trial index mismatch: {indexed_trial_id} != {trial_id}")
        if trial_id not in rag_local_vector_trials:
            errors.append(f"rag_local_vector_trial index references missing trial {trial_id}")

    for trial_id, trial in rag_local_vector_trials.items():
        if trial.get("rag_local_vector_trial_id") != trial_id:
            errors.append(f"rag_local_vector_trial key mismatch: {trial_id}")
        indexed = (indexes.get("rag_local_vector_trial_ids") or {}).get(trial_id)
        if indexed != trial_id:
            errors.append(f"rag_local_vector_trial index missing: {trial_id}")
        validation = validate_rag_local_vector_trial_record(trial, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"rag_local_vector_trial {trial_id} {reason_code}")

    for indexed_trial_id, trial_id in (indexes.get("agent_memory_trial_ids") or {}).items():
        if indexed_trial_id != trial_id:
            errors.append(f"agent_memory_trial index mismatch: {indexed_trial_id} != {trial_id}")
        if trial_id not in agent_memory_trials:
            errors.append(f"agent_memory_trial index references missing trial {trial_id}")

    for trial_id, trial in agent_memory_trials.items():
        if trial.get("agent_memory_trial_id") != trial_id:
            errors.append(f"agent_memory_trial key mismatch: {trial_id}")
        indexed = (indexes.get("agent_memory_trial_ids") or {}).get(trial_id)
        if indexed != trial_id:
            errors.append(f"agent_memory_trial index missing: {trial_id}")
        validation = validate_agent_memory_trial_record(trial, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"agent_memory_trial {trial_id} {reason_code}")

    for indexed_claim_id, claim_id in (indexes.get("memory_claim_ids") or {}).items():
        if indexed_claim_id != claim_id:
            errors.append(f"memory_claim index mismatch: {indexed_claim_id} != {claim_id}")
        if claim_id not in memory_claims:
            errors.append(f"memory_claim index references missing claim {claim_id}")

    for claim_id, claim in memory_claims.items():
        if claim.get("memory_claim_id") != claim_id:
            errors.append(f"memory_claim key mismatch: {claim_id}")
        indexed = (indexes.get("memory_claim_ids") or {}).get(claim_id)
        if indexed != claim_id:
            errors.append(f"memory_claim index missing: {claim_id}")
        validation = validate_memory_claim_record(claim)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"memory_claim {claim_id} {reason_code}")

    for indexed_review_id, review_id in (indexes.get("memory_promotion_review_ids") or {}).items():
        if indexed_review_id != review_id:
            errors.append(f"memory_promotion_review index mismatch: {indexed_review_id} != {review_id}")
        if review_id not in memory_promotion_reviews:
            errors.append(f"memory_promotion_review index references missing review {review_id}")

    for review_id, review in memory_promotion_reviews.items():
        if review.get("memory_promotion_review_id") != review_id:
            errors.append(f"memory_promotion_review key mismatch: {review_id}")
        indexed = (indexes.get("memory_promotion_review_ids") or {}).get(review_id)
        if indexed != review_id:
            errors.append(f"memory_promotion_review index missing: {review_id}")
        validation = validate_memory_promotion_review_record(review, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"memory_promotion_review {review_id} {reason_code}")

    for indexed_record_id, record_id in (indexes.get("memory_supersession_record_ids") or {}).items():
        if indexed_record_id != record_id:
            errors.append(f"memory_supersession index mismatch: {indexed_record_id} != {record_id}")
        if record_id not in memory_supersession_records:
            errors.append(f"memory_supersession index references missing record {record_id}")

    for record_id, record in memory_supersession_records.items():
        if record.get("memory_supersession_record_id") != record_id:
            errors.append(f"memory_supersession key mismatch: {record_id}")
        indexed = (indexes.get("memory_supersession_record_ids") or {}).get(record_id)
        if indexed != record_id:
            errors.append(f"memory_supersession index missing: {record_id}")
        validation = validate_memory_supersession_record(record, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"memory_supersession {record_id} {reason_code}")

    for indexed_record_id, record_id in (indexes.get("memory_conflict_record_ids") or {}).items():
        if indexed_record_id != record_id:
            errors.append(f"memory_conflict index mismatch: {indexed_record_id} != {record_id}")
        if record_id not in memory_conflict_records:
            errors.append(f"memory_conflict index references missing record {record_id}")

    for record_id, record in memory_conflict_records.items():
        if record.get("memory_conflict_record_id") != record_id:
            errors.append(f"memory_conflict key mismatch: {record_id}")
        indexed = (indexes.get("memory_conflict_record_ids") or {}).get(record_id)
        if indexed != record_id:
            errors.append(f"memory_conflict index missing: {record_id}")
        validation = validate_memory_conflict_record(record, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"memory_conflict {record_id} {reason_code}")

    for indexed_trial_id, trial_id in (indexes.get("real_agent_trial_ids") or {}).items():
        if indexed_trial_id != trial_id:
            errors.append(f"real_agent_trial index mismatch: {indexed_trial_id} != {trial_id}")
        if trial_id not in real_agent_trials:
            errors.append(f"real_agent_trial index references missing trial {trial_id}")

    for trial_id, trial in real_agent_trials.items():
        if trial.get("real_agent_trial_id") != trial_id:
            errors.append(f"real_agent_trial key mismatch: {trial_id}")
        indexed = (indexes.get("real_agent_trial_ids") or {}).get(trial_id)
        if indexed != trial_id:
            errors.append(f"real_agent_trial index missing: {trial_id}")
        validation = validate_real_agent_trial_record(trial, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"real_agent_trial {trial_id} {reason_code}")

    for indexed_trial_id, trial_id in (indexes.get("real_agent_system_trial_ids") or {}).items():
        if indexed_trial_id != trial_id:
            errors.append(f"real_agent_system_trial index mismatch: {indexed_trial_id} != {trial_id}")
        if trial_id not in real_agent_system_trials:
            errors.append(f"real_agent_system_trial index references missing trial {trial_id}")

    for trial_id, trial in real_agent_system_trials.items():
        if trial.get("real_agent_system_trial_id") != trial_id:
            errors.append(f"real_agent_system_trial key mismatch: {trial_id}")
        indexed = (indexes.get("real_agent_system_trial_ids") or {}).get(trial_id)
        if indexed != trial_id:
            errors.append(f"real_agent_system_trial index missing: {trial_id}")
        validation = validate_real_agent_system_trial_record(trial, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"real_agent_system_trial {trial_id} {reason_code}")

    events_by_run: dict[str, list[dict[str, Any]]] = {}
    for run_event_id, event in run_events.items():
        for required in ("run_event_id", "task_run_id", "session_id", "sequence", "event_type", "created_at", "event_sha256"):
            if not event.get(required):
                errors.append(f"run_event {run_event_id} missing {required}")
        if event.get("run_event_id") != run_event_id:
            errors.append(f"run_event key mismatch: {run_event_id}")
        task_run_id = event.get("task_run_id")
        if task_run_id not in task_runs:
            errors.append(f"run_event {run_event_id} references missing task_run {task_run_id}")
        elif event.get("session_id") != task_runs[task_run_id].get("session_id"):
            errors.append(f"run_event {run_event_id} session/task_run mismatch")
        if event.get("event_type") == "result.ingested":
            provider_result_id = (event.get("payload") or {}).get("provider_result_id")
            if provider_result_id not in provider_results:
                errors.append(f"run_event {run_event_id} references missing provider_result")
        if event.get("event_type") == "incident.opened":
            incident_packet_id = (event.get("payload") or {}).get("incident_packet_id")
            if incident_packet_id not in incident_packets:
                errors.append(f"run_event {run_event_id} references missing incident_packet")
        expected_hash = event.get("event_sha256")
        without_hash = dict(event)
        without_hash.pop("event_sha256", None)
        actual_hash = sha256_text(canonical_json(without_hash))
        if expected_hash != actual_hash:
            errors.append(f"run_event {run_event_id} sha256 mismatch")
        events_by_run.setdefault(str(task_run_id), []).append(event)

    for task_run_id in task_runs:
        events = sorted(
            events_by_run.get(task_run_id, []),
            key=lambda event: int(event.get("sequence", 0) or 0),
        )
        if not events:
            errors.append(f"task_run {task_run_id} has no run_events")
            continue
        previous_hash = None
        previous_state = None
        previous_event_type = None
        for expected_sequence, event in enumerate(events, start=1):
            sequence = int(event.get("sequence", 0) or 0)
            if sequence != expected_sequence:
                errors.append(
                    f"task_run {task_run_id} sequence mismatch: {sequence} != {expected_sequence}"
                )
            if event.get("previous_event_sha256") != previous_hash:
                errors.append(f"task_run {task_run_id} previous hash mismatch at sequence {sequence}")
            if event.get("from_state") != previous_state:
                errors.append(f"task_run {task_run_id} state transition mismatch at sequence {sequence}")
            if expected_sequence == 1:
                if event.get("event_type") != "run.created":
                    errors.append(f"task_run {task_run_id} first event is not run.created")
                if event.get("from_state") is not None or event.get("to_state") != "planned":
                    errors.append(f"task_run {task_run_id} first event does not create planned state")
            elif event.get("event_type") == "trace.illegal_transition":
                if event.get("to_state") != "blocked":
                    errors.append(f"task_run {task_run_id} illegal transition event did not block run")
            else:
                expected_to_state, illegal = _next_state(
                    str(event.get("event_type") or ""),
                    str(previous_state or "planned"),
                    event.get("payload") or {},
                )
                if illegal:
                    errors.append(
                        f"task_run {task_run_id} illegal semantic transition at sequence {sequence}"
                    )
                elif event.get("to_state") != expected_to_state:
                    errors.append(
                        f"task_run {task_run_id} semantic state mismatch at sequence {sequence}: "
                        f"{event.get('to_state')} != {expected_to_state}"
                    )
            if event.get("event_type") == "run.dispatch_intent":
                _validate_dispatch_intent_event(errors, state, task_runs[task_run_id], event)
            if event.get("event_type") == "run.dispatched":
                if previous_event_type != "run.dispatch_intent":
                    errors.append(f"task_run {task_run_id} dispatched without prior dispatch intent")
            previous_hash = event.get("event_sha256")
            previous_state = event.get("to_state")
            previous_event_type = event.get("event_type")
        if task_runs[task_run_id].get("state") != previous_state:
            errors.append(f"task_run {task_run_id} final state mismatch")

    for ams_event_id, event in ams_events.items():
        for required in ("schema_version", "id", "source", "type", "subject", "time", "data_sha256", "event_sha256"):
            if not event.get(required):
                errors.append(f"ams_event {ams_event_id} missing {required}")
        if event.get("id") != ams_event_id:
            errors.append(f"ams_event key mismatch: {ams_event_id}")
        if event.get("session_id") and event["session_id"] not in sessions:
            errors.append(f"ams_event {ams_event_id} references missing session")
        if event.get("task_run_id") and event["task_run_id"] not in task_runs:
            errors.append(f"ams_event {ams_event_id} references missing task_run")
        if event.get("parent_event_id") and event["parent_event_id"] not in ams_events:
            errors.append(f"ams_event {ams_event_id} references missing parent_event")
        incident_packet_id = (event.get("data") or {}).get("incident_packet_id")
        if event.get("type") == "ams.ams.incident.opened":
            incident = incident_packets.get(incident_packet_id)
            if not incident:
                errors.append(f"ams_event {ams_event_id} references missing incident_packet")
            else:
                if event.get("session_id") != incident.get("session_id"):
                    errors.append(f"ams_event {ams_event_id} session/incident mismatch")
                if event.get("task_run_id") != incident.get("task_run_id"):
                    errors.append(f"ams_event {ams_event_id} task_run/incident mismatch")
        data_hash = sha256_text(canonical_json(event.get("data") or {}))
        if event.get("data_sha256") != data_hash:
            errors.append(f"ams_event {ams_event_id} data sha256 mismatch")
        without_hash = dict(event)
        expected_hash = without_hash.pop("event_sha256", None)
        if expected_hash != sha256_text(canonical_json(without_hash)):
            errors.append(f"ams_event {ams_event_id} sha256 mismatch")

    for review_id, review in admission_reviews.items():
        for required in (
            "admission_review_id",
            "request_uid",
            "subject_kind",
            "subject_id",
            "operation",
            "request_sha256",
            "response",
            "created_at",
            "review_sha256",
        ):
            if not review.get(required):
                errors.append(f"admission_review {review_id} missing {required}")
        if review.get("admission_review_id") != review_id:
            errors.append(f"admission_review key mismatch: {review_id}")
        if review.get("subject_kind") == "task_run" and review.get("subject_id") not in task_runs:
            errors.append(f"admission_review {review_id} references missing task_run")
        if review.get("request_sha256") != sha256_text(canonical_json(review.get("request") or {})):
            errors.append(f"admission_review {review_id} request sha256 mismatch")
        response = review.get("response") or {}
        status = response.get("status")
        allowed = bool(response.get("allowed"))
        if allowed != (status == "allow"):
            errors.append(f"admission_review {review_id} allowed/status mismatch")
        without_hash = dict(review)
        expected_hash = without_hash.pop("review_sha256", None)
        if expected_hash != sha256_text(canonical_json(without_hash)):
            errors.append(f"admission_review {review_id} sha256 mismatch")

    claims_by_run: dict[str, list[dict[str, Any]]] = {}
    active_claims_by_run: dict[str, list[dict[str, Any]]] = {}
    for claim_id, claim in resource_claims.items():
        for required in (
            "resource_claim_id",
            "task_run_id",
            "policy_id",
            "policy_sha256",
            "resource_verdict_id",
            "provider_profile_id",
            "state",
            "reserved",
            "created_at",
            "updated_at",
            "expires_at",
            "claim_sha256",
        ):
            if not claim.get(required):
                errors.append(f"resource_claim {claim_id} missing {required}")
        if claim.get("resource_claim_id") != claim_id:
            errors.append(f"resource_claim key mismatch: {claim_id}")
        task_run_id = claim.get("task_run_id")
        if task_run_id not in task_runs:
            errors.append(f"resource_claim {claim_id} references missing task_run")
        else:
            claims_by_run.setdefault(task_run_id, []).append(claim)
            if claim.get("state") == "active":
                active_claims_by_run.setdefault(task_run_id, []).append(claim)
        if claim.get("state") not in {"reserved", "active", "released", "expired"}:
            errors.append(f"resource_claim {claim_id} invalid state")
        without_hash = dict(claim)
        expected_hash = without_hash.pop("claim_sha256", None)
        if expected_hash != sha256_text(canonical_json(without_hash)):
            errors.append(f"resource_claim {claim_id} sha256 mismatch")

    for task_run_id, task_run in task_runs.items():
        if task_run.get("state") in {"dispatching", "in_flight", "dispatched", "landed", "verified", "completed"}:
            if not claims_by_run.get(task_run_id):
                errors.append(f"task_run {task_run_id} dispatched without resource_claim")
        if task_run.get("state") in {"dispatching", "in_flight", "landed", "verified"}:
            if not active_claims_by_run.get(task_run_id):
                errors.append(f"task_run {task_run_id} in-flight without active resource_claim")
        if task_run.get("state") in {"completed", "failed", "blocked"}:
            if active_claims_by_run.get(task_run_id):
                errors.append(f"task_run {task_run_id} terminal with active resource_claim")

    for indexed_telemetry_id, telemetry_id in (indexes.get("resource_telemetry_ids") or {}).items():
        if indexed_telemetry_id != telemetry_id:
            errors.append(f"resource_telemetry index mismatch: {indexed_telemetry_id} != {telemetry_id}")
        if telemetry_id not in resource_telemetry_samples:
            errors.append(f"resource_telemetry index references missing sample {telemetry_id}")

    for claim_id, telemetry_id in (indexes.get("resource_claim_to_telemetry") or {}).items():
        if claim_id not in resource_claims:
            errors.append(f"resource_telemetry claim index references missing claim {claim_id}")
        if telemetry_id not in resource_telemetry_samples:
            errors.append(f"resource_telemetry claim index references missing sample {telemetry_id}")
        elif resource_telemetry_samples[telemetry_id].get("resource_claim_id") != claim_id:
            errors.append(f"resource_telemetry claim index mismatch: {claim_id} -> {telemetry_id}")

    for telemetry_id, telemetry in resource_telemetry_samples.items():
        if telemetry.get("resource_telemetry_id") != telemetry_id:
            errors.append(f"resource_telemetry key mismatch: {telemetry_id}")
        indexed = (indexes.get("resource_telemetry_ids") or {}).get(telemetry_id)
        if indexed != telemetry_id:
            errors.append(f"resource_telemetry index missing: {telemetry_id}")
        validation = validate_resource_telemetry_record(telemetry)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"resource_telemetry {telemetry_id} {reason_code}")
        task_run_id = telemetry.get("task_run_id")
        claim_id = telemetry.get("resource_claim_id")
        task_run = task_runs.get(task_run_id)
        claim = resource_claims.get(claim_id)
        if not task_run:
            errors.append(f"resource_telemetry {telemetry_id} references missing task_run")
        if not claim:
            errors.append(f"resource_telemetry {telemetry_id} references missing resource_claim")
        if task_run and telemetry.get("session_id") != task_run.get("session_id"):
            errors.append(f"resource_telemetry {telemetry_id} session mismatch")
        if claim:
            if claim.get("task_run_id") != task_run_id:
                errors.append(f"resource_telemetry {telemetry_id} task_run/resource_claim mismatch")
            if telemetry.get("reserved_snapshot") != claim.get("reserved"):
                errors.append(f"resource_telemetry {telemetry_id} reserved snapshot mismatch")
            claim_indexed = (indexes.get("resource_claim_to_telemetry") or {}).get(claim_id)
            if claim_indexed != telemetry_id:
                errors.append(f"resource_telemetry claim index missing: {claim_id}")
        provider_result_id = telemetry.get("provider_result_id")
        if provider_result_id:
            provider_result = provider_results.get(provider_result_id)
            if not provider_result:
                errors.append(f"resource_telemetry {telemetry_id} references missing provider_result")
            elif provider_result.get("task_run_id") != task_run_id:
                errors.append(f"resource_telemetry {telemetry_id} provider_result task_run mismatch")

    for indexed_trial_id, trial_id in (indexes.get("resource_enforcement_trial_ids") or {}).items():
        if indexed_trial_id != trial_id:
            errors.append(f"resource_enforcement index mismatch: {indexed_trial_id} != {trial_id}")
        if trial_id not in resource_enforcement_trials:
            errors.append(f"resource_enforcement index references missing trial {trial_id}")

    for trial_id, trial in resource_enforcement_trials.items():
        if trial.get("resource_enforcement_trial_id") != trial_id:
            errors.append(f"resource_enforcement key mismatch: {trial_id}")
        indexed = (indexes.get("resource_enforcement_trial_ids") or {}).get(trial_id)
        if indexed != trial_id:
            errors.append(f"resource_enforcement index missing: {trial_id}")
        task_run = task_runs.get(trial.get("task_run_id"))
        claim = resource_claims.get(trial.get("resource_claim_id"))
        telemetry = resource_telemetry_samples.get(trial.get("resource_telemetry_id"))
        if not task_run:
            errors.append(f"resource_enforcement {trial_id} references missing task_run")
        elif trial.get("session_id") != task_run.get("session_id"):
            errors.append(f"resource_enforcement {trial_id} session mismatch")
        if not claim:
            errors.append(f"resource_enforcement {trial_id} references missing resource_claim")
        if not telemetry:
            errors.append(f"resource_enforcement {trial_id} references missing resource_telemetry")
        elif telemetry.get("resource_claim_id") != trial.get("resource_claim_id"):
            errors.append(f"resource_enforcement {trial_id} telemetry claim mismatch")
        validation = validate_resource_enforcement_trial_record(trial, claim=claim, telemetry=telemetry)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"resource_enforcement {trial_id} {reason_code}")

    for indexed_bundle_id, bundle_id in (indexes.get("shareability_bundle_ids") or {}).items():
        if indexed_bundle_id != bundle_id:
            errors.append(f"shareability_bundle index mismatch: {indexed_bundle_id} != {bundle_id}")
        if bundle_id not in shareability_bundles:
            errors.append(f"shareability_bundle index references missing bundle {bundle_id}")

    for bundle_id, bundle in shareability_bundles.items():
        if bundle.get("shareability_bundle_id") != bundle_id:
            errors.append(f"shareability_bundle key mismatch: {bundle_id}")
        indexed = (indexes.get("shareability_bundle_ids") or {}).get(bundle_id)
        if indexed != bundle_id:
            errors.append(f"shareability_bundle index missing: {bundle_id}")
        validation = validate_shareability_bundle_record(bundle)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"shareability_bundle {bundle_id} {reason_code}")

    for indexed_trial_id, trial_id in (indexes.get("shareability_receiver_trial_ids") or {}).items():
        if indexed_trial_id != trial_id:
            errors.append(f"shareability_receiver_trial index mismatch: {indexed_trial_id} != {trial_id}")
        if trial_id not in shareability_receiver_trials:
            errors.append(f"shareability_receiver_trial index references missing trial {trial_id}")

    for trial_id, trial in shareability_receiver_trials.items():
        if trial.get("shareability_receiver_trial_id") != trial_id:
            errors.append(f"shareability_receiver_trial key mismatch: {trial_id}")
        indexed = (indexes.get("shareability_receiver_trial_ids") or {}).get(trial_id)
        if indexed != trial_id:
            errors.append(f"shareability_receiver_trial index missing: {trial_id}")
        validation = validate_shareability_receiver_trial_record(trial)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"shareability_receiver_trial {trial_id} {reason_code}")

    for provider_result_id, result in provider_results.items():
        for required in (
            "provider_result_id",
            "task_run_id",
            "provider",
            "surface",
            "status",
            "output_refs",
            "token_usage",
            "provider_msg_refs",
            "started_at",
            "ended_at",
            "ingested_at",
            "source_class",
            "sha256",
        ):
            if not result.get(required) and required not in {"surface", "provider_msg_refs", "output_refs"}:
                errors.append(f"provider_result {provider_result_id} missing {required}")
        if result.get("provider_result_id") != provider_result_id:
            errors.append(f"provider_result key mismatch: {provider_result_id}")
        task_run_id = result.get("task_run_id")
        if task_run_id not in task_runs:
            errors.append(f"provider_result {provider_result_id} references missing task_run")
        else:
            task_run = task_runs[task_run_id]
            if result.get("provider") != task_run.get("provider"):
                errors.append(f"provider_result {provider_result_id} provider/task_run mismatch")
            if result.get("surface") != task_run.get("provider_surface"):
                errors.append(f"provider_result {provider_result_id} surface/task_run mismatch")
        without_hash = dict(result)
        expected_hash = without_hash.pop("sha256", None)
        if expected_hash != sha256_text(canonical_json(without_hash)):
            errors.append(f"provider_result {provider_result_id} sha256 mismatch")

    for incident_id, packet in incident_packets.items():
        for required in (
            "incident_packet_id",
            "trigger",
            "ids",
            "last_events",
            "policy_hashes",
            "store_revision",
            "predicate_results",
            "compaction_epoch",
            "created_at",
            "incident_sha256",
        ):
            if required not in packet:
                errors.append(f"incident_packet {incident_id} missing {required}")
        if packet.get("incident_packet_id") != incident_id:
            errors.append(f"incident_packet key mismatch: {incident_id}")
        if packet.get("task_run_id") and packet["task_run_id"] not in task_runs:
            errors.append(f"incident_packet {incident_id} references missing task_run")
        if packet.get("session_id") and packet["session_id"] not in sessions:
            errors.append(f"incident_packet {incident_id} references missing session")
        ams_event_id = (packet.get("ids") or {}).get("ams_event_id")
        if ams_event_id:
            ams_event = ams_events.get(ams_event_id)
            if not ams_event:
                errors.append(f"incident_packet {incident_id} references missing ams_event")
            elif (ams_event.get("data") or {}).get("incident_packet_id") != incident_id:
                errors.append(f"incident_packet {incident_id} ams_event back-reference mismatch")
        without_hash = dict(packet)
        expected_hash = without_hash.pop("incident_sha256", None)
        if expected_hash != sha256_text(canonical_json(without_hash)):
            errors.append(f"incident_packet {incident_id} sha256 mismatch")

    receipts_by_outbox: dict[str, list[dict[str, Any]]] = {}
    for outbox_id, item in outbox_items.items():
        for required in (
            "outbox_id",
            "task_run_id",
            "session_id",
            "target",
            "method",
            "payload_sha256",
            "idempotency_key",
            "state",
            "created_at",
            "updated_at",
            "outbox_sha256",
        ):
            if not item.get(required):
                errors.append(f"outbox_item {outbox_id} missing {required}")
        if item.get("outbox_id") != outbox_id:
            errors.append(f"outbox_item key mismatch: {outbox_id}")
        task_run_id = item.get("task_run_id")
        if task_run_id not in task_runs:
            errors.append(f"outbox_item {outbox_id} references missing task_run")
        elif item.get("session_id") != task_runs[task_run_id].get("session_id"):
            errors.append(f"outbox_item {outbox_id} session/task_run mismatch")
        if item.get("admission_review_id") and item["admission_review_id"] not in admission_reviews:
            errors.append(f"outbox_item {outbox_id} references missing admission_review")
        if item.get("payload_sha256") != sha256_text(canonical_json(item.get("payload") or {})):
            errors.append(f"outbox_item {outbox_id} payload sha256 mismatch")
        without_hash = dict(item)
        expected_hash = without_hash.pop("outbox_sha256", None)
        if expected_hash != sha256_text(canonical_json(without_hash)):
            errors.append(f"outbox_item {outbox_id} sha256 mismatch")

    for receipt_id, receipt in outbox_receipts.items():
        for required in (
            "outbox_receipt_id",
            "outbox_id",
            "task_run_id",
            "status",
            "attempt",
            "response_sha256",
            "created_at",
            "receipt_sha256",
        ):
            if not receipt.get(required):
                errors.append(f"outbox_receipt {receipt_id} missing {required}")
        if receipt.get("outbox_receipt_id") != receipt_id:
            errors.append(f"outbox_receipt key mismatch: {receipt_id}")
        outbox_id = receipt.get("outbox_id")
        if outbox_id not in outbox_items:
            errors.append(f"outbox_receipt {receipt_id} references missing outbox_item")
        else:
            receipts_by_outbox.setdefault(outbox_id, []).append(receipt)
            if receipt.get("task_run_id") != outbox_items[outbox_id].get("task_run_id"):
                errors.append(f"outbox_receipt {receipt_id} task_run/outbox mismatch")
        if receipt.get("response_sha256") != sha256_text(canonical_json(receipt.get("response_payload") or {})):
            errors.append(f"outbox_receipt {receipt_id} response sha256 mismatch")
        if receipt.get("status") in {"sent", "readback_verified"}:
            if not receipt.get("readback_ref") or not _provider_message_id(receipt.get("response_payload") or {}):
                errors.append(f"outbox_receipt {receipt_id} missing readback/provider message id")
        without_hash = dict(receipt)
        expected_hash = without_hash.pop("receipt_sha256", None)
        if expected_hash != sha256_text(canonical_json(without_hash)):
            errors.append(f"outbox_receipt {receipt_id} sha256 mismatch")

    for outbox_id, item in outbox_items.items():
        if item.get("state") != "queued" and not receipts_by_outbox.get(outbox_id):
            errors.append(f"outbox_item {outbox_id} terminal state without receipt")
        last_receipt_id = item.get("last_receipt_id")
        if last_receipt_id and last_receipt_id not in outbox_receipts:
            errors.append(f"outbox_item {outbox_id} references missing last_receipt")

    for indexed_drill_id, drill_id in (indexes.get("store_backup_drill_ids") or {}).items():
        if indexed_drill_id != drill_id:
            errors.append(f"store_backup_drill index mismatch: {indexed_drill_id} != {drill_id}")
        if drill_id not in store_backup_drills:
            errors.append(f"store_backup_drill index references missing drill {drill_id}")

    for drill_id, drill in store_backup_drills.items():
        if drill.get("store_backup_drill_id") != drill_id:
            errors.append(f"store_backup_drill key mismatch: {drill_id}")
        indexed = (indexes.get("store_backup_drill_ids") or {}).get(drill_id)
        if indexed != drill_id:
            errors.append(f"store_backup_drill index missing: {drill_id}")
        validation = validate_store_backup_drill_record(drill)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"store_backup_drill {drill_id} {reason_code}")

    for indexed_parity_id, parity_id in (indexes.get("runner_dry_run_parity_ids") or {}).items():
        if indexed_parity_id != parity_id:
            errors.append(f"runner_dry_run_parity index mismatch: {indexed_parity_id} != {parity_id}")
        if parity_id not in runner_dry_run_parities:
            errors.append(f"runner_dry_run_parity index references missing parity {parity_id}")

    for parity_id, parity in runner_dry_run_parities.items():
        if parity.get("runner_dry_run_parity_id") != parity_id:
            errors.append(f"runner_dry_run_parity key mismatch: {parity_id}")
        indexed = (indexes.get("runner_dry_run_parity_ids") or {}).get(parity_id)
        if indexed != parity_id:
            errors.append(f"runner_dry_run_parity index missing: {parity_id}")
        validation = validate_runner_dry_run_parity_record(parity, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"runner_dry_run_parity {parity_id} {reason_code}")

    for indexed_packet_id, packet_id in (indexes.get("shadow_approval_packet_ids") or {}).items():
        if indexed_packet_id != packet_id:
            errors.append(f"shadow_approval_packet index mismatch: {indexed_packet_id} != {packet_id}")
        if packet_id not in shadow_approval_packets:
            errors.append(f"shadow_approval_packet index references missing packet {packet_id}")

    for packet_id, packet in shadow_approval_packets.items():
        if packet.get("shadow_approval_packet_id") != packet_id:
            errors.append(f"shadow_approval_packet key mismatch: {packet_id}")
        indexed = (indexes.get("shadow_approval_packet_ids") or {}).get(packet_id)
        if indexed != packet_id:
            errors.append(f"shadow_approval_packet index missing: {packet_id}")
        validation = validate_shadow_approval_packet_record(packet, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"shadow_approval_packet {packet_id} {reason_code}")

    for indexed_packet_id, packet_id in (indexes.get("discord_source_packet_ids") or {}).items():
        if indexed_packet_id != packet_id:
            errors.append(f"discord_source_packet index mismatch: {indexed_packet_id} != {packet_id}")
        if packet_id not in discord_source_packets:
            errors.append(f"discord_source_packet index references missing packet {packet_id}")

    for source_ref, packet_id in (indexes.get("source_ref_to_discord_source_packet") or {}).items():
        packet = discord_source_packets.get(packet_id)
        if not packet:
            errors.append(f"discord_source_packet source_ref index references missing packet {packet_id}")
        elif packet.get("source_ref") != source_ref:
            errors.append(f"discord_source_packet source_ref index mismatch: {source_ref} != {packet.get('source_ref')}")

    for packet_id, packet in discord_source_packets.items():
        if packet.get("discord_source_packet_id") != packet_id:
            errors.append(f"discord_source_packet key mismatch: {packet_id}")
        indexed = (indexes.get("discord_source_packet_ids") or {}).get(packet_id)
        if indexed != packet_id:
            errors.append(f"discord_source_packet index missing: {packet_id}")
        mapped = (indexes.get("source_ref_to_discord_source_packet") or {}).get(packet.get("source_ref"))
        if mapped != packet_id:
            errors.append(f"discord_source_packet source_ref index missing: {packet_id}")
        validation = validate_discord_source_packet_record(packet, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"discord_source_packet {packet_id} {reason_code}")

    for indexed_plan_id, plan_id in (indexes.get("discord_canary_send_plan_ids") or {}).items():
        if indexed_plan_id != plan_id:
            errors.append(f"discord_canary_send_plan index mismatch: {indexed_plan_id} != {plan_id}")
        if plan_id not in discord_canary_send_plans:
            errors.append(f"discord_canary_send_plan index references missing plan {plan_id}")

    for plan_id, plan in discord_canary_send_plans.items():
        if plan.get("discord_canary_send_plan_id") != plan_id:
            errors.append(f"discord_canary_send_plan key mismatch: {plan_id}")
        indexed = (indexes.get("discord_canary_send_plan_ids") or {}).get(plan_id)
        if indexed != plan_id:
            errors.append(f"discord_canary_send_plan index missing: {plan_id}")
        validation = validate_discord_canary_send_plan_record(plan, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"discord_canary_send_plan {plan_id} {reason_code}")

    for indexed_receipt_id, receipt_id in (indexes.get("discord_canary_receipt_ids") or {}).items():
        if indexed_receipt_id != receipt_id:
            errors.append(f"discord_canary_receipt index mismatch: {indexed_receipt_id} != {receipt_id}")
        if receipt_id not in discord_canary_receipts:
            errors.append(f"discord_canary_receipt index references missing receipt {receipt_id}")

    for receipt_id, receipt in discord_canary_receipts.items():
        if receipt.get("discord_canary_receipt_id") != receipt_id:
            errors.append(f"discord_canary_receipt key mismatch: {receipt_id}")
        indexed = (indexes.get("discord_canary_receipt_ids") or {}).get(receipt_id)
        if indexed != receipt_id:
            errors.append(f"discord_canary_receipt index missing: {receipt_id}")
        validation = validate_discord_canary_receipt_record(receipt, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"discord_canary_receipt {receipt_id} {reason_code}")

    for indexed_packet_id, packet_id in (indexes.get("terminal_source_packet_ids") or {}).items():
        if indexed_packet_id != packet_id:
            errors.append(f"terminal_source_packet index mismatch: {indexed_packet_id} != {packet_id}")
        if packet_id not in terminal_source_packets:
            errors.append(f"terminal_source_packet index references missing packet {packet_id}")

    for packet_id, packet in terminal_source_packets.items():
        if packet.get("terminal_source_packet_id") != packet_id:
            errors.append(f"terminal_source_packet key mismatch: {packet_id}")
        indexed = (indexes.get("terminal_source_packet_ids") or {}).get(packet_id)
        if indexed != packet_id:
            errors.append(f"terminal_source_packet index missing: {packet_id}")
        mapped = (indexes.get("source_ref_to_terminal_source_packet") or {}).get(packet.get("source_ref"))
        if mapped != packet_id:
            errors.append(f"terminal_source_packet source_ref index missing: {packet_id}")
        validation = validate_terminal_source_packet_record(packet, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"terminal_source_packet {packet_id} {reason_code}")

    for indexed_pack_id, pack_id in (indexes.get("conformance_pack_ids") or {}).items():
        if indexed_pack_id != pack_id:
            errors.append(f"conformance_pack index mismatch: {indexed_pack_id} != {pack_id}")
        if pack_id not in conformance_packs:
            errors.append(f"conformance_pack index references missing pack {pack_id}")

    for pack_id, pack in conformance_packs.items():
        if pack.get("conformance_pack_id") != pack_id:
            errors.append(f"conformance_pack key mismatch: {pack_id}")
        indexed = (indexes.get("conformance_pack_ids") or {}).get(pack_id)
        if indexed != pack_id:
            errors.append(f"conformance_pack index missing: {pack_id}")
        validation = validate_conformance_pack_record(pack)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"conformance_pack {pack_id} {reason_code}")

    for indexed_audit_id, audit_id in (indexes.get("markdown_audit_ids") or {}).items():
        if indexed_audit_id != audit_id:
            errors.append(f"markdown_audit index mismatch: {indexed_audit_id} != {audit_id}")
        if audit_id not in markdown_audits:
            errors.append(f"markdown_audit index references missing audit {audit_id}")

    for audit_id, audit in markdown_audits.items():
        if audit.get("markdown_audit_id") != audit_id:
            errors.append(f"markdown_audit key mismatch: {audit_id}")
        indexed = (indexes.get("markdown_audit_ids") or {}).get(audit_id)
        if indexed != audit_id:
            errors.append(f"markdown_audit index missing: {audit_id}")
        validation = validate_markdown_audit_record(audit)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"markdown_audit {audit_id} {reason_code}")

    for indexed_review_id, review_id in (indexes.get("readiness_review_ids") or {}).items():
        if indexed_review_id != review_id:
            errors.append(f"readiness_review index mismatch: {indexed_review_id} != {review_id}")
        if review_id not in readiness_reviews:
            errors.append(f"readiness_review index references missing review {review_id}")

    for review_id, review in readiness_reviews.items():
        if review.get("readiness_review_id") != review_id:
            errors.append(f"readiness_review key mismatch: {review_id}")
        indexed = (indexes.get("readiness_review_ids") or {}).get(review_id)
        if indexed != review_id:
            errors.append(f"readiness_review index missing: {review_id}")
        validation = validate_readiness_review_record(review)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"readiness_review {review_id} {reason_code}")

    for indexed_plan_id, plan_id in (indexes.get("doc_retirement_plan_ids") or {}).items():
        if indexed_plan_id != plan_id:
            errors.append(f"doc_retirement_plan index mismatch: {indexed_plan_id} != {plan_id}")
        if plan_id not in doc_retirement_plans:
            errors.append(f"doc_retirement_plan index references missing plan {plan_id}")

    for plan_id, plan in doc_retirement_plans.items():
        if plan.get("doc_retirement_plan_id") != plan_id:
            errors.append(f"doc_retirement_plan key mismatch: {plan_id}")
        indexed = (indexes.get("doc_retirement_plan_ids") or {}).get(plan_id)
        if indexed != plan_id:
            errors.append(f"doc_retirement_plan index missing: {plan_id}")
        validation = validate_doc_retirement_plan_record(plan)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"doc_retirement_plan {plan_id} {reason_code}")

    for indexed_plan_id, plan_id in (indexes.get("doc_action_execution_plan_ids") or {}).items():
        if indexed_plan_id != plan_id:
            errors.append(f"doc_action_execution_plan index mismatch: {indexed_plan_id} != {plan_id}")
        if plan_id not in doc_action_execution_plans:
            errors.append(f"doc_action_execution_plan index references missing plan {plan_id}")

    for plan_id, plan in doc_action_execution_plans.items():
        if plan.get("doc_action_execution_plan_id") != plan_id:
            errors.append(f"doc_action_execution_plan key mismatch: {plan_id}")
        indexed = (indexes.get("doc_action_execution_plan_ids") or {}).get(plan_id)
        if indexed != plan_id:
            errors.append(f"doc_action_execution_plan index missing: {plan_id}")
        validation = validate_doc_action_execution_plan_record(plan)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"doc_action_execution_plan {plan_id} {reason_code}")
        source_ref = plan.get("source_plan_ref") or {}
        source_plan = doc_retirement_plans.get(source_ref.get("doc_retirement_plan_id"))
        source_validation = validate_doc_action_execution_plan_against_source(plan, source_plan)
        if not source_validation["ok"]:
            for reason_code in source_validation["reason_codes"]:
                errors.append(f"doc_action_execution_plan {plan_id} {reason_code}")

    for indexed_packet_id, packet_id in (indexes.get("doc_action_operator_approval_packet_ids") or {}).items():
        if indexed_packet_id != packet_id:
            errors.append(f"doc_action_operator_approval index mismatch: {indexed_packet_id} != {packet_id}")
        if packet_id not in doc_action_operator_approval_packets:
            errors.append(f"doc_action_operator_approval index references missing packet {packet_id}")

    for packet_id, packet in doc_action_operator_approval_packets.items():
        if packet.get("doc_action_operator_approval_packet_id") != packet_id:
            errors.append(f"doc_action_operator_approval key mismatch: {packet_id}")
        indexed = (indexes.get("doc_action_operator_approval_packet_ids") or {}).get(packet_id)
        if indexed != packet_id:
            errors.append(f"doc_action_operator_approval index missing: {packet_id}")
        execution_plan = doc_action_execution_plans.get(packet.get("doc_action_execution_plan_id"))
        validation = validate_doc_action_operator_approval_packet_record(packet, execution_plan=execution_plan)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"doc_action_operator_approval {packet_id} {reason_code}")

    for indexed_preview_id, preview_id in (indexes.get("doc_action_patch_preview_ids") or {}).items():
        if indexed_preview_id != preview_id:
            errors.append(f"doc_action_patch_preview index mismatch: {indexed_preview_id} != {preview_id}")
        if preview_id not in doc_action_patch_previews:
            errors.append(f"doc_action_patch_preview index references missing preview {preview_id}")

    for preview_id, preview in doc_action_patch_previews.items():
        if preview.get("doc_action_patch_preview_id") != preview_id:
            errors.append(f"doc_action_patch_preview key mismatch: {preview_id}")
        indexed = (indexes.get("doc_action_patch_preview_ids") or {}).get(preview_id)
        if indexed != preview_id:
            errors.append(f"doc_action_patch_preview index missing: {preview_id}")
        approval_packet = doc_action_operator_approval_packets.get(preview.get("doc_action_operator_approval_packet_id"))
        execution_plan = doc_action_execution_plans.get(preview.get("doc_action_execution_plan_id"))
        validation = validate_doc_action_patch_preview_record(
            preview,
            approval_packet=approval_packet,
            execution_plan=execution_plan,
        )
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"doc_action_patch_preview {preview_id} {reason_code}")

    for indexed_receipt_id, receipt_id in (indexes.get("doc_action_patch_readback_receipt_ids") or {}).items():
        if indexed_receipt_id != receipt_id:
            errors.append(f"doc_action_patch_readback index mismatch: {indexed_receipt_id} != {receipt_id}")
        if receipt_id not in doc_action_patch_readback_receipts:
            errors.append(f"doc_action_patch_readback index references missing receipt {receipt_id}")

    for receipt_id, receipt in doc_action_patch_readback_receipts.items():
        if receipt.get("doc_action_patch_readback_receipt_id") != receipt_id:
            errors.append(f"doc_action_patch_readback key mismatch: {receipt_id}")
        indexed = (indexes.get("doc_action_patch_readback_receipt_ids") or {}).get(receipt_id)
        if indexed != receipt_id:
            errors.append(f"doc_action_patch_readback index missing: {receipt_id}")
        patch_preview_id = receipt.get("doc_action_patch_preview_id")
        patch_preview = doc_action_patch_previews.get(patch_preview_id)
        approval_packet = None
        execution_plan = None
        if not patch_preview:
            errors.append(f"doc_action_patch_readback references missing doc_action_patch_preview {patch_preview_id}")
        else:
            expected_preview_hash = patch_preview.get("doc_action_patch_preview_sha256")
            if receipt.get("doc_action_patch_preview_sha256") != expected_preview_hash:
                errors.append(f"doc_action_patch_readback {receipt_id} patch preview hash mismatch")
            approval_packet = doc_action_operator_approval_packets.get(
                patch_preview.get("doc_action_operator_approval_packet_id")
            )
            execution_plan = doc_action_execution_plans.get(patch_preview.get("doc_action_execution_plan_id"))
        validation = validate_doc_action_patch_readback_receipt_record(
            receipt,
            patch_preview=patch_preview,
            approval_packet=approval_packet,
            execution_plan=execution_plan,
        )
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"doc_action_patch_readback {receipt_id} {reason_code}")

    for indexed_receipt_id, receipt_id in (indexes.get("doc_action_patch_artifact_receipt_ids") or {}).items():
        if indexed_receipt_id != receipt_id:
            errors.append(f"doc_action_patch_artifact index mismatch: {indexed_receipt_id} != {receipt_id}")
        if receipt_id not in doc_action_patch_artifact_receipts:
            errors.append(f"doc_action_patch_artifact index references missing receipt {receipt_id}")

    for receipt_id, receipt in doc_action_patch_artifact_receipts.items():
        if receipt.get("doc_action_patch_artifact_receipt_id") != receipt_id:
            errors.append(f"doc_action_patch_artifact key mismatch: {receipt_id}")
        indexed = (indexes.get("doc_action_patch_artifact_receipt_ids") or {}).get(receipt_id)
        if indexed != receipt_id:
            errors.append(f"doc_action_patch_artifact index missing: {receipt_id}")
        readback_id = receipt.get("doc_action_patch_readback_receipt_id")
        readback = doc_action_patch_readback_receipts.get(readback_id)
        patch_preview = None
        approval_packet = None
        execution_plan = None
        if not readback:
            errors.append(f"doc_action_patch_artifact references missing doc_action_patch_readback {readback_id}")
        else:
            expected_readback_hash = readback.get("doc_action_patch_readback_receipt_sha256")
            if receipt.get("doc_action_patch_readback_receipt_sha256") != expected_readback_hash:
                errors.append(f"doc_action_patch_artifact {receipt_id} readback receipt hash mismatch")
            patch_preview = doc_action_patch_previews.get(readback.get("doc_action_patch_preview_id"))
            if patch_preview:
                approval_packet = doc_action_operator_approval_packets.get(
                    patch_preview.get("doc_action_operator_approval_packet_id")
                )
                execution_plan = doc_action_execution_plans.get(patch_preview.get("doc_action_execution_plan_id"))
        validation = validate_doc_action_patch_artifact_receipt_record(
            receipt,
            readback_receipt=readback,
            patch_preview=patch_preview,
            approval_packet=approval_packet,
            execution_plan=execution_plan,
        )
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"doc_action_patch_artifact {receipt_id} {reason_code}")

    for indexed_packet_id, packet_id in (indexes.get("doc_action_patch_artifact_approval_packet_ids") or {}).items():
        if indexed_packet_id != packet_id:
            errors.append(f"doc_action_patch_artifact_approval index mismatch: {indexed_packet_id} != {packet_id}")
        if packet_id not in doc_action_patch_artifact_approval_packets:
            errors.append(f"doc_action_patch_artifact_approval index references missing packet {packet_id}")

    for packet_id, packet in doc_action_patch_artifact_approval_packets.items():
        if packet.get("doc_action_patch_artifact_approval_packet_id") != packet_id:
            errors.append(f"doc_action_patch_artifact_approval key mismatch: {packet_id}")
        indexed = (indexes.get("doc_action_patch_artifact_approval_packet_ids") or {}).get(packet_id)
        if indexed != packet_id:
            errors.append(f"doc_action_patch_artifact_approval index missing: {packet_id}")
        artifact_receipt_id = packet.get("doc_action_patch_artifact_receipt_id")
        artifact_receipt = doc_action_patch_artifact_receipts.get(artifact_receipt_id)
        if not artifact_receipt:
            errors.append(
                f"doc_action_patch_artifact_approval references missing doc_action_patch_artifact {artifact_receipt_id}"
            )
        else:
            expected_artifact_hash = artifact_receipt.get("doc_action_patch_artifact_receipt_sha256")
            if packet.get("doc_action_patch_artifact_receipt_sha256") != expected_artifact_hash:
                errors.append(f"doc_action_patch_artifact_approval {packet_id} artifact receipt hash mismatch")
        validation = validate_doc_action_patch_artifact_approval_packet_record(
            packet,
            artifact_receipt=artifact_receipt,
        )
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"doc_action_patch_artifact_approval {packet_id} {reason_code}")

    for indexed_plan_id, plan_id in (indexes.get("doc_action_patch_dry_run_plan_ids") or {}).items():
        if indexed_plan_id != plan_id:
            errors.append(f"doc_action_patch_dry_run index mismatch: {indexed_plan_id} != {plan_id}")
        if plan_id not in doc_action_patch_dry_run_plans:
            errors.append(f"doc_action_patch_dry_run index references missing plan {plan_id}")

    for plan_id, plan in doc_action_patch_dry_run_plans.items():
        if plan.get("doc_action_patch_dry_run_plan_id") != plan_id:
            errors.append(f"doc_action_patch_dry_run key mismatch: {plan_id}")
        indexed = (indexes.get("doc_action_patch_dry_run_plan_ids") or {}).get(plan_id)
        if indexed != plan_id:
            errors.append(f"doc_action_patch_dry_run index missing: {plan_id}")
        approval_packet_id = plan.get("doc_action_patch_artifact_approval_packet_id")
        approval_packet = doc_action_patch_artifact_approval_packets.get(approval_packet_id)
        if not approval_packet:
            errors.append(
                f"doc_action_patch_dry_run references missing doc_action_patch_artifact_approval {approval_packet_id}"
            )
        else:
            expected_approval_hash = approval_packet.get("doc_action_patch_artifact_approval_packet_sha256")
            if plan.get("doc_action_patch_artifact_approval_packet_sha256") != expected_approval_hash:
                errors.append(f"doc_action_patch_dry_run {plan_id} approval packet hash mismatch")
        validation = validate_doc_action_patch_dry_run_plan_record(plan, approval_packet=approval_packet)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"doc_action_patch_dry_run {plan_id} {reason_code}")

    for indexed_receipt_id, receipt_id in (
        indexes.get("doc_action_patch_dry_run_readback_receipt_ids") or {}
    ).items():
        if indexed_receipt_id != receipt_id:
            errors.append(f"doc_action_patch_dry_run_readback index mismatch: {indexed_receipt_id} != {receipt_id}")
        if receipt_id not in doc_action_patch_dry_run_readback_receipts:
            errors.append(f"doc_action_patch_dry_run_readback index references missing receipt {receipt_id}")

    for receipt_id, receipt in doc_action_patch_dry_run_readback_receipts.items():
        if receipt.get("doc_action_patch_dry_run_readback_receipt_id") != receipt_id:
            errors.append(f"doc_action_patch_dry_run_readback key mismatch: {receipt_id}")
        indexed = (indexes.get("doc_action_patch_dry_run_readback_receipt_ids") or {}).get(receipt_id)
        if indexed != receipt_id:
            errors.append(f"doc_action_patch_dry_run_readback index missing: {receipt_id}")
        dry_run_plan_id = receipt.get("doc_action_patch_dry_run_plan_id")
        dry_run_plan = doc_action_patch_dry_run_plans.get(dry_run_plan_id)
        if not dry_run_plan:
            errors.append(f"doc_action_patch_dry_run_readback references missing doc_action_patch_dry_run {dry_run_plan_id}")
        else:
            expected_dry_run_hash = dry_run_plan.get("doc_action_patch_dry_run_plan_sha256")
            if receipt.get("doc_action_patch_dry_run_plan_sha256") != expected_dry_run_hash:
                errors.append(f"doc_action_patch_dry_run_readback {receipt_id} dry-run plan hash mismatch")
        validation = validate_doc_action_patch_dry_run_readback_receipt_record(
            receipt,
            dry_run_plan=dry_run_plan,
        )
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"doc_action_patch_dry_run_readback {receipt_id} {reason_code}")

    for indexed_packet_id, packet_id in (
        indexes.get("doc_action_patch_live_execution_approval_packet_ids") or {}
    ).items():
        if indexed_packet_id != packet_id:
            errors.append(
                "doc_action_patch_live_execution_approval index mismatch: "
                f"{indexed_packet_id} != {packet_id}"
            )
        if packet_id not in doc_action_patch_live_execution_approval_packets:
            errors.append(
                f"doc_action_patch_live_execution_approval index references missing packet {packet_id}"
            )

    for packet_id, packet in doc_action_patch_live_execution_approval_packets.items():
        if packet.get("doc_action_patch_live_execution_approval_packet_id") != packet_id:
            errors.append(f"doc_action_patch_live_execution_approval key mismatch: {packet_id}")
        indexed = (indexes.get("doc_action_patch_live_execution_approval_packet_ids") or {}).get(packet_id)
        if indexed != packet_id:
            errors.append(f"doc_action_patch_live_execution_approval index missing: {packet_id}")
        dry_run_readback_id = packet.get("doc_action_patch_dry_run_readback_receipt_id")
        dry_run_readback = doc_action_patch_dry_run_readback_receipts.get(dry_run_readback_id)
        if not dry_run_readback:
            errors.append(
                "doc_action_patch_live_execution_approval references missing "
                f"doc_action_patch_dry_run_readback {dry_run_readback_id}"
            )
        else:
            expected_readback_hash = dry_run_readback.get("doc_action_patch_dry_run_readback_receipt_sha256")
            if packet.get("doc_action_patch_dry_run_readback_receipt_sha256") != expected_readback_hash:
                errors.append(
                    f"doc_action_patch_live_execution_approval {packet_id} dry-run readback hash mismatch"
                )
        dry_run_plan_id = packet.get("doc_action_patch_dry_run_plan_id")
        dry_run_plan = doc_action_patch_dry_run_plans.get(dry_run_plan_id)
        if not dry_run_plan:
            errors.append(
                f"doc_action_patch_live_execution_approval references missing doc_action_patch_dry_run {dry_run_plan_id}"
            )
        else:
            expected_dry_run_hash = dry_run_plan.get("doc_action_patch_dry_run_plan_sha256")
            if packet.get("doc_action_patch_dry_run_plan_sha256") != expected_dry_run_hash:
                errors.append(f"doc_action_patch_live_execution_approval {packet_id} dry-run plan hash mismatch")
        validation = validate_doc_action_patch_live_execution_approval_packet_record(
            packet,
            dry_run_readback_receipt=dry_run_readback,
            dry_run_plan=dry_run_plan,
        )
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"doc_action_patch_live_execution_approval {packet_id} {reason_code}")

    for indexed_preflight_id, preflight_id in (indexes.get("doc_action_patch_executor_preflight_ids") or {}).items():
        if indexed_preflight_id != preflight_id:
            errors.append(f"doc_action_patch_executor_preflight index mismatch: {indexed_preflight_id} != {preflight_id}")
        if preflight_id not in doc_action_patch_executor_preflights:
            errors.append(f"doc_action_patch_executor_preflight index references missing preflight {preflight_id}")

    for preflight_id, preflight in doc_action_patch_executor_preflights.items():
        if preflight.get("doc_action_patch_executor_preflight_id") != preflight_id:
            errors.append(f"doc_action_patch_executor_preflight key mismatch: {preflight_id}")
        indexed = (indexes.get("doc_action_patch_executor_preflight_ids") or {}).get(preflight_id)
        if indexed != preflight_id:
            errors.append(f"doc_action_patch_executor_preflight index missing: {preflight_id}")
        approval_packet_id = preflight.get("doc_action_patch_live_execution_approval_packet_id")
        approval_packet = doc_action_patch_live_execution_approval_packets.get(approval_packet_id)
        if not approval_packet:
            errors.append(
                "doc_action_patch_executor_preflight references missing "
                f"doc_action_patch_live_execution_approval {approval_packet_id}"
            )
        else:
            expected_approval_hash = approval_packet.get("doc_action_patch_live_execution_approval_packet_sha256")
            if preflight.get("doc_action_patch_live_execution_approval_packet_sha256") != expected_approval_hash:
                errors.append(f"doc_action_patch_executor_preflight {preflight_id} approval packet hash mismatch")
        validation = validate_doc_action_patch_executor_preflight_record(
            preflight,
            approval_packet=approval_packet,
        )
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"doc_action_patch_executor_preflight {preflight_id} {reason_code}")

    for indexed_packet_id, packet_id in (indexes.get("doc_action_patch_apply_boundary_packet_ids") or {}).items():
        if indexed_packet_id != packet_id:
            errors.append(f"doc_action_patch_apply_boundary index mismatch: {indexed_packet_id} != {packet_id}")
        if packet_id not in doc_action_patch_apply_boundary_packets:
            errors.append(f"doc_action_patch_apply_boundary index references missing packet {packet_id}")

    for packet_id, packet in doc_action_patch_apply_boundary_packets.items():
        if packet.get("doc_action_patch_apply_boundary_packet_id") != packet_id:
            errors.append(f"doc_action_patch_apply_boundary key mismatch: {packet_id}")
        indexed = (indexes.get("doc_action_patch_apply_boundary_packet_ids") or {}).get(packet_id)
        if indexed != packet_id:
            errors.append(f"doc_action_patch_apply_boundary index missing: {packet_id}")
        preflight_id = packet.get("doc_action_patch_executor_preflight_id")
        executor_preflight = doc_action_patch_executor_preflights.get(preflight_id)
        if not executor_preflight:
            errors.append(
                "doc_action_patch_apply_boundary references missing "
                f"doc_action_patch_executor_preflight {preflight_id}"
            )
        else:
            expected_preflight_hash = executor_preflight.get("doc_action_patch_executor_preflight_sha256")
            if packet.get("doc_action_patch_executor_preflight_sha256") != expected_preflight_hash:
                errors.append(f"doc_action_patch_apply_boundary {packet_id} executor preflight hash mismatch")
        validation = validate_doc_action_patch_apply_boundary_packet_record(
            packet,
            executor_preflight=executor_preflight,
        )
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"doc_action_patch_apply_boundary {packet_id} {reason_code}")

    for indexed_packet_id, packet_id in (indexes.get("doc_action_patch_apply_acceptance_packet_ids") or {}).items():
        if indexed_packet_id != packet_id:
            errors.append(f"doc_action_patch_apply_acceptance index mismatch: {indexed_packet_id} != {packet_id}")
        if packet_id not in doc_action_patch_apply_acceptance_packets:
            errors.append(f"doc_action_patch_apply_acceptance index references missing packet {packet_id}")

    for packet_id, packet in doc_action_patch_apply_acceptance_packets.items():
        if packet.get("doc_action_patch_apply_acceptance_packet_id") != packet_id:
            errors.append(f"doc_action_patch_apply_acceptance key mismatch: {packet_id}")
        indexed = (indexes.get("doc_action_patch_apply_acceptance_packet_ids") or {}).get(packet_id)
        if indexed != packet_id:
            errors.append(f"doc_action_patch_apply_acceptance index missing: {packet_id}")
        apply_boundary_packet_id = packet.get("doc_action_patch_apply_boundary_packet_id")
        apply_boundary_packet = doc_action_patch_apply_boundary_packets.get(apply_boundary_packet_id)
        if not apply_boundary_packet:
            errors.append(
                "doc_action_patch_apply_acceptance references missing "
                f"doc_action_patch_apply_boundary {apply_boundary_packet_id}"
            )
        else:
            expected_apply_boundary_hash = apply_boundary_packet.get("doc_action_patch_apply_boundary_packet_sha256")
            if packet.get("doc_action_patch_apply_boundary_packet_sha256") != expected_apply_boundary_hash:
                errors.append(f"doc_action_patch_apply_acceptance {packet_id} apply boundary packet hash mismatch")
        validation = validate_doc_action_patch_apply_acceptance_packet_record(
            packet,
            apply_boundary_packet=apply_boundary_packet,
        )
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"doc_action_patch_apply_acceptance {packet_id} {reason_code}")

    for indexed_preflight_id, preflight_id in (indexes.get("source_write_executor_preflight_ids") or {}).items():
        if indexed_preflight_id != preflight_id:
            errors.append(f"source_write_executor_preflight index mismatch: {indexed_preflight_id} != {preflight_id}")
        if preflight_id not in source_write_executor_preflights:
            errors.append(f"source_write_executor_preflight index references missing preflight {preflight_id}")

    for preflight_id, preflight in source_write_executor_preflights.items():
        if preflight.get("source_write_executor_preflight_id") != preflight_id:
            errors.append(f"source_write_executor_preflight key mismatch: {preflight_id}")
        indexed = (indexes.get("source_write_executor_preflight_ids") or {}).get(preflight_id)
        if indexed != preflight_id:
            errors.append(f"source_write_executor_preflight index missing: {preflight_id}")
        acceptance_id = preflight.get("doc_action_patch_apply_acceptance_packet_id")
        acceptance = doc_action_patch_apply_acceptance_packets.get(acceptance_id)
        if not acceptance:
            errors.append(
                "source_write_executor_preflight references missing "
                f"doc_action_patch_apply_acceptance {acceptance_id}"
            )
        else:
            expected_acceptance_hash = acceptance.get("doc_action_patch_apply_acceptance_packet_sha256")
            if preflight.get("doc_action_patch_apply_acceptance_packet_sha256") != expected_acceptance_hash:
                errors.append(
                    f"source_write_executor_preflight {preflight_id} apply acceptance packet hash mismatch"
                )
        validation = validate_source_write_executor_preflight_record(preflight, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"source_write_executor_preflight {preflight_id} {reason_code}")

    for indexed_receipt_id, receipt_id in (indexes.get("source_write_backup_preimage_receipt_ids") or {}).items():
        if indexed_receipt_id != receipt_id:
            errors.append(
                f"source_write_backup_preimage index mismatch: {indexed_receipt_id} != {receipt_id}"
            )
        if receipt_id not in source_write_backup_preimage_receipts:
            errors.append(f"source_write_backup_preimage index references missing receipt {receipt_id}")

    for receipt_id, receipt in source_write_backup_preimage_receipts.items():
        if receipt.get("source_write_backup_preimage_receipt_id") != receipt_id:
            errors.append(f"source_write_backup_preimage key mismatch: {receipt_id}")
        indexed = (indexes.get("source_write_backup_preimage_receipt_ids") or {}).get(receipt_id)
        if indexed != receipt_id:
            errors.append(f"source_write_backup_preimage index missing: {receipt_id}")
        preflight_id = receipt.get("source_write_executor_preflight_id")
        preflight = source_write_executor_preflights.get(preflight_id)
        if not preflight:
            errors.append(
                "source_write_backup_preimage references missing "
                f"source_write_executor_preflight {preflight_id}"
            )
        else:
            expected_preflight_hash = preflight.get("source_write_executor_preflight_sha256")
            if receipt.get("source_write_executor_preflight_sha256") != expected_preflight_hash:
                errors.append(f"source_write_backup_preimage {receipt_id} source preflight hash mismatch")
        validation = validate_source_write_backup_preimage_receipt_record(receipt, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"source_write_backup_preimage {receipt_id} {reason_code}")

    for indexed_lease_id, lease_id in (indexes.get("source_write_executor_lease_ids") or {}).items():
        if indexed_lease_id != lease_id:
            errors.append(f"source_write_executor_lease index mismatch: {indexed_lease_id} != {lease_id}")
        if lease_id not in source_write_executor_leases:
            errors.append(f"source_write_executor_lease index references missing lease {lease_id}")

    for lease_id, lease in source_write_executor_leases.items():
        if lease.get("source_write_executor_lease_id") != lease_id:
            errors.append(f"source_write_executor_lease key mismatch: {lease_id}")
        indexed = (indexes.get("source_write_executor_lease_ids") or {}).get(lease_id)
        if indexed != lease_id:
            errors.append(f"source_write_executor_lease index missing: {lease_id}")
        receipt_id = lease.get("source_write_backup_preimage_receipt_id")
        receipt = source_write_backup_preimage_receipts.get(receipt_id)
        if not receipt:
            errors.append(
                "source_write_executor_lease references missing "
                f"source_write_backup_preimage {receipt_id}"
            )
        else:
            expected_receipt_hash = receipt.get("source_write_backup_preimage_receipt_sha256")
            if lease.get("source_write_backup_preimage_receipt_sha256") != expected_receipt_hash:
                errors.append(f"source_write_executor_lease {lease_id} backup preimage receipt hash mismatch")
        validation = validate_source_write_executor_lease_record(lease, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"source_write_executor_lease {lease_id} {reason_code}")

    for indexed_snapshot_id, snapshot_id in (indexes.get("generated_status_snapshot_ids") or {}).items():
        if indexed_snapshot_id != snapshot_id:
            errors.append(f"generated_status_snapshot index mismatch: {indexed_snapshot_id} != {snapshot_id}")
        if snapshot_id not in generated_status_snapshots:
            errors.append(f"generated_status_snapshot index references missing snapshot {snapshot_id}")

    for snapshot_id, snapshot in generated_status_snapshots.items():
        if snapshot.get("generated_status_snapshot_id") != snapshot_id:
            errors.append(f"generated_status_snapshot key mismatch: {snapshot_id}")
        indexed = (indexes.get("generated_status_snapshot_ids") or {}).get(snapshot_id)
        if indexed != snapshot_id:
            errors.append(f"generated_status_snapshot index missing: {snapshot_id}")
        validation = validate_generated_status_snapshot_record(snapshot)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"generated_status_snapshot {snapshot_id} {reason_code}")

    for indexed_brief_id, brief_id in (indexes.get("session_start_brief_ids") or {}).items():
        if indexed_brief_id != brief_id:
            errors.append(f"session_start_brief index mismatch: {indexed_brief_id} != {brief_id}")
        if brief_id not in session_start_briefs:
            errors.append(f"session_start_brief index references missing brief {brief_id}")

    for brief_id, brief in session_start_briefs.items():
        if brief.get("session_start_brief_id") != brief_id:
            errors.append(f"session_start_brief key mismatch: {brief_id}")
        indexed = (indexes.get("session_start_brief_ids") or {}).get(brief_id)
        if indexed != brief_id:
            errors.append(f"session_start_brief index missing: {brief_id}")
        validation = validate_session_start_brief_record(brief)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"session_start_brief {brief_id} {reason_code}")

    for indexed_index_id, index_id in (indexes.get("markdown_authority_index_ids") or {}).items():
        if indexed_index_id != index_id:
            errors.append(f"markdown_authority_index index mismatch: {indexed_index_id} != {index_id}")
        if index_id not in markdown_authority_indexes:
            errors.append(f"markdown_authority_index index references missing index {index_id}")

    for indexed_entry_id, entry_id in (indexes.get("markdown_authority_entry_ids") or {}).items():
        if indexed_entry_id != entry_id:
            errors.append(f"markdown_authority_entry index mismatch: {indexed_entry_id} != {entry_id}")
        if entry_id not in markdown_authority_entries:
            errors.append(f"markdown_authority_entry index references missing entry {entry_id}")

    for entry_id, entry in markdown_authority_entries.items():
        if entry.get("markdown_authority_entry_id") != entry_id:
            errors.append(f"markdown_authority_entry key mismatch: {entry_id}")
        indexed = (indexes.get("markdown_authority_entry_ids") or {}).get(entry_id)
        if indexed != entry_id:
            errors.append(f"markdown_authority_entry index missing: {entry_id}")
        validation = validate_markdown_authority_entry_record(entry)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"markdown_authority_entry {entry_id} {reason_code}")

    for index_id, index in markdown_authority_indexes.items():
        if index.get("markdown_authority_index_id") != index_id:
            errors.append(f"markdown_authority_index key mismatch: {index_id}")
        indexed = (indexes.get("markdown_authority_index_ids") or {}).get(index_id)
        if indexed != index_id:
            errors.append(f"markdown_authority_index index missing: {index_id}")
        validation = validate_markdown_authority_index_record(index, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"markdown_authority_index {index_id} {reason_code}")

    for indexed_snapshot_id, snapshot_id in (indexes.get("codebase_spider_graph_snapshot_ids") or {}).items():
        if indexed_snapshot_id != snapshot_id:
            errors.append(f"codebase_spider_graph index mismatch: {indexed_snapshot_id} != {snapshot_id}")
        if snapshot_id not in codebase_spider_graph_snapshots:
            errors.append(f"codebase_spider_graph index references missing snapshot {snapshot_id}")

    for indexed_node_id, node_id in (indexes.get("codebase_graph_node_ids") or {}).items():
        if indexed_node_id != node_id:
            errors.append(f"codebase_graph_node index mismatch: {indexed_node_id} != {node_id}")
        if node_id not in codebase_graph_nodes:
            errors.append(f"codebase_graph_node index references missing node {node_id}")

    for indexed_edge_id, edge_id in (indexes.get("codebase_graph_edge_ids") or {}).items():
        if indexed_edge_id != edge_id:
            errors.append(f"codebase_graph_edge index mismatch: {indexed_edge_id} != {edge_id}")
        if edge_id not in codebase_graph_edges:
            errors.append(f"codebase_graph_edge index references missing edge {edge_id}")

    for indexed_query_id, query_id in (indexes.get("codebase_graph_query_receipt_ids") or {}).items():
        if indexed_query_id != query_id:
            errors.append(f"codebase_graph_query index mismatch: {indexed_query_id} != {query_id}")
        if query_id not in codebase_graph_query_receipts:
            errors.append(f"codebase_graph_query index references missing receipt {query_id}")

    for node_id, node in codebase_graph_nodes.items():
        if node.get("codebase_graph_node_id") != node_id:
            errors.append(f"codebase_graph_node key mismatch: {node_id}")
        indexed = (indexes.get("codebase_graph_node_ids") or {}).get(node_id)
        if indexed != node_id:
            errors.append(f"codebase_graph_node index missing: {node_id}")
        validation = validate_codebase_graph_node_record(node)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"codebase_graph_node {node_id} {reason_code}")

    for edge_id, edge in codebase_graph_edges.items():
        if edge.get("codebase_graph_edge_id") != edge_id:
            errors.append(f"codebase_graph_edge key mismatch: {edge_id}")
        indexed = (indexes.get("codebase_graph_edge_ids") or {}).get(edge_id)
        if indexed != edge_id:
            errors.append(f"codebase_graph_edge index missing: {edge_id}")
        validation = validate_codebase_graph_edge_record(edge, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"codebase_graph_edge {edge_id} {reason_code}")

    for snapshot_id, snapshot in codebase_spider_graph_snapshots.items():
        if snapshot.get("codebase_spider_graph_snapshot_id") != snapshot_id:
            errors.append(f"codebase_spider_graph key mismatch: {snapshot_id}")
        indexed = (indexes.get("codebase_spider_graph_snapshot_ids") or {}).get(snapshot_id)
        if indexed != snapshot_id:
            errors.append(f"codebase_spider_graph index missing: {snapshot_id}")
        validation = validate_codebase_spider_graph_snapshot_record(snapshot, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"codebase_spider_graph {snapshot_id} {reason_code}")

    for query_id, query in codebase_graph_query_receipts.items():
        if query.get("codebase_graph_query_receipt_id") != query_id:
            errors.append(f"codebase_graph_query key mismatch: {query_id}")
        indexed = (indexes.get("codebase_graph_query_receipt_ids") or {}).get(query_id)
        if indexed != query_id:
            errors.append(f"codebase_graph_query index missing: {query_id}")
        validation = validate_codebase_graph_query_receipt_record(query, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"codebase_graph_query {query_id} {reason_code}")

    for indexed_review_id, review_id in (indexes.get("blast_radius_review_ids") or {}).items():
        if indexed_review_id != review_id:
            errors.append(f"blast_radius_review index mismatch: {indexed_review_id} != {review_id}")
        if review_id not in blast_radius_reviews:
            errors.append(f"blast_radius_review index references missing review {review_id}")

    for review_id, review in blast_radius_reviews.items():
        if review.get("blast_radius_review_id") != review_id:
            errors.append(f"blast_radius_review key mismatch: {review_id}")
        indexed = (indexes.get("blast_radius_review_ids") or {}).get(review_id)
        if indexed != review_id:
            errors.append(f"blast_radius_review index missing: {review_id}")
        validation = validate_blast_radius_review_record(review, state=state)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"blast_radius_review {review_id} {reason_code}")

    for indexed_decision_id, decision_id in (indexes.get("work_mode_decision_ids") or {}).items():
        if indexed_decision_id != decision_id:
            errors.append(f"work_mode_decision index mismatch: {indexed_decision_id} != {decision_id}")
        if decision_id not in work_mode_decisions:
            errors.append(f"work_mode_decision index references missing decision {decision_id}")

    for decision_id, decision in work_mode_decisions.items():
        if decision.get("work_mode_decision_id") != decision_id:
            errors.append(f"work_mode_decision key mismatch: {decision_id}")
        indexed = (indexes.get("work_mode_decision_ids") or {}).get(decision_id)
        if indexed != decision_id:
            errors.append(f"work_mode_decision index missing: {decision_id}")
        validation = validate_work_mode_decision_record(decision)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"work_mode_decision {decision_id} {reason_code}")

    for indexed_sweep_id, sweep_id in (indexes.get("simulation_sweep_ids") or {}).items():
        if indexed_sweep_id != sweep_id:
            errors.append(f"simulation_sweep index mismatch: {indexed_sweep_id} != {sweep_id}")
        if sweep_id not in simulation_sweeps:
            errors.append(f"simulation_sweep index references missing sweep {sweep_id}")

    for sweep_id, sweep in simulation_sweeps.items():
        if sweep.get("simulation_sweep_id") != sweep_id:
            errors.append(f"simulation_sweep key mismatch: {sweep_id}")
        indexed = (indexes.get("simulation_sweep_ids") or {}).get(sweep_id)
        if indexed != sweep_id:
            errors.append(f"simulation_sweep index missing: {sweep_id}")
        validation = validate_simulation_sweep_record(sweep)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"simulation_sweep {sweep_id} {reason_code}")

    for indexed_trial_id, trial_id in (indexes.get("ams_emulation_trial_ids") or {}).items():
        if indexed_trial_id != trial_id:
            errors.append(f"ams_emulation_trial index mismatch: {indexed_trial_id} != {trial_id}")
        if trial_id not in ams_emulation_trials:
            errors.append(f"ams_emulation_trial index references missing trial {trial_id}")

    for trial_id, trial in ams_emulation_trials.items():
        if trial.get("ams_emulation_trial_id") != trial_id:
            errors.append(f"ams_emulation_trial key mismatch: {trial_id}")
        indexed = (indexes.get("ams_emulation_trial_ids") or {}).get(trial_id)
        if indexed != trial_id:
            errors.append(f"ams_emulation_trial index missing: {trial_id}")
        validation = validate_ams_emulation_trial_record(trial)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"ams_emulation_trial {trial_id} {reason_code}")

    for indexed_review_id, review_id in (indexes.get("semantic_oracle_review_ids") or {}).items():
        if indexed_review_id != review_id:
            errors.append(f"semantic_oracle_review index mismatch: {indexed_review_id} != {review_id}")
        if review_id not in semantic_oracle_reviews:
            errors.append(f"semantic_oracle_review index references missing review {review_id}")

    for review_id, review in semantic_oracle_reviews.items():
        if review.get("semantic_oracle_review_id") != review_id:
            errors.append(f"semantic_oracle_review key mismatch: {review_id}")
        indexed = (indexes.get("semantic_oracle_review_ids") or {}).get(review_id)
        if indexed != review_id:
            errors.append(f"semantic_oracle_review index missing: {review_id}")
        sweep_id = review.get("simulation_sweep_id")
        if sweep_id and sweep_id not in simulation_sweeps:
            errors.append(f"semantic_oracle_review references missing simulation_sweep {sweep_id}")
        elif sweep_id:
            expected_sweep_hash = simulation_sweeps[sweep_id].get("simulation_sweep_sha256")
            if review.get("simulation_sweep_sha256") != expected_sweep_hash:
                errors.append(f"semantic_oracle_review {review_id} simulation_sweep hash mismatch")
        validation = validate_semantic_oracle_review_record(review)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"semantic_oracle_review {review_id} {reason_code}")

    for indexed_record_id, record_id in (indexes.get("semantic_hook_record_ids") or {}).items():
        if indexed_record_id != record_id:
            errors.append(f"semantic_hook_record index mismatch: {indexed_record_id} != {record_id}")
        if record_id not in semantic_hook_records:
            errors.append(f"semantic_hook_record index references missing record {record_id}")

    for record_id, hook_record in semantic_hook_records.items():
        if hook_record.get("semantic_hook_record_id") != record_id:
            errors.append(f"semantic_hook_record key mismatch: {record_id}")
        indexed = (indexes.get("semantic_hook_record_ids") or {}).get(record_id)
        if indexed != record_id:
            errors.append(f"semantic_hook_record index missing: {record_id}")
        review_id = hook_record.get("semantic_oracle_review_id")
        if review_id and review_id not in semantic_oracle_reviews:
            errors.append(f"semantic_hook_record references missing semantic_oracle_review {review_id}")
        elif review_id:
            expected_review_hash = semantic_oracle_reviews[review_id].get("semantic_oracle_review_sha256")
            if hook_record.get("semantic_oracle_review_sha256") != expected_review_hash:
                errors.append(f"semantic_hook_record {record_id} semantic_oracle_review hash mismatch")
        validation = validate_semantic_hook_record_record(hook_record)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"semantic_hook_record {record_id} {reason_code}")

    for indexed_run_id, run_id in (indexes.get("semantic_hook_run_ids") or {}).items():
        if indexed_run_id != run_id:
            errors.append(f"semantic_hook_run index mismatch: {indexed_run_id} != {run_id}")
        if run_id not in semantic_hook_runs:
            errors.append(f"semantic_hook_run index references missing run {run_id}")

    for run_id, hook_run in semantic_hook_runs.items():
        if hook_run.get("semantic_hook_run_id") != run_id:
            errors.append(f"semantic_hook_run key mismatch: {run_id}")
        indexed = (indexes.get("semantic_hook_run_ids") or {}).get(run_id)
        if indexed != run_id:
            errors.append(f"semantic_hook_run index missing: {run_id}")
        review_id = hook_run.get("semantic_oracle_review_id")
        if review_id and review_id not in semantic_oracle_reviews:
            errors.append(f"semantic_hook_run references missing semantic_oracle_review {review_id}")
        elif review_id:
            expected_review_hash = semantic_oracle_reviews[review_id].get("semantic_oracle_review_sha256")
            if hook_run.get("semantic_oracle_review_sha256") != expected_review_hash:
                errors.append(f"semantic_hook_run {run_id} semantic_oracle_review hash mismatch")
        for receipt in hook_run.get("record_family_receipts") or []:
            record_id = receipt.get("semantic_hook_record_id")
            hook_record = semantic_hook_records.get(record_id)
            if not hook_record:
                errors.append(f"semantic_hook_run {run_id} references missing semantic_hook_record {record_id}")
                continue
            if hook_record.get("semantic_hook_run_id") != run_id:
                errors.append(f"semantic_hook_run {run_id} record {record_id} points at another run")
            if hook_record.get("record_family") != receipt.get("record_family"):
                errors.append(f"semantic_hook_run {run_id} record {record_id} family mismatch")
            if hook_record.get("semantic_hook_record_sha256") != receipt.get("semantic_hook_record_sha256"):
                errors.append(f"semantic_hook_run {run_id} record {record_id} hash mismatch")
        validation = validate_semantic_hook_run_record(hook_run)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"semantic_hook_run {run_id} {reason_code}")

    for indexed_plan_id, plan_id in (indexes.get("semantic_hook_install_plan_ids") or {}).items():
        if indexed_plan_id != plan_id:
            errors.append(f"semantic_hook_install_plan index mismatch: {indexed_plan_id} != {plan_id}")
        if plan_id not in semantic_hook_install_plans:
            errors.append(f"semantic_hook_install_plan index references missing plan {plan_id}")

    for plan_id, install_plan in semantic_hook_install_plans.items():
        if install_plan.get("semantic_hook_install_plan_id") != plan_id:
            errors.append(f"semantic_hook_install_plan key mismatch: {plan_id}")
        indexed = (indexes.get("semantic_hook_install_plan_ids") or {}).get(plan_id)
        if indexed != plan_id:
            errors.append(f"semantic_hook_install_plan index missing: {plan_id}")
        run_id = install_plan.get("semantic_hook_run_id")
        if run_id and run_id not in semantic_hook_runs:
            errors.append(f"semantic_hook_install_plan references missing semantic_hook_run {run_id}")
        elif run_id:
            expected_run_hash = semantic_hook_runs[run_id].get("semantic_hook_run_sha256")
            if install_plan.get("semantic_hook_run_sha256") != expected_run_hash:
                errors.append(f"semantic_hook_install_plan {plan_id} semantic_hook_run hash mismatch")
            expected_record_count = len(
                [
                    record
                    for record in semantic_hook_records.values()
                    if record.get("semantic_hook_run_id") == run_id
                ]
            )
            if install_plan.get("semantic_hook_record_count") != expected_record_count:
                errors.append(f"semantic_hook_install_plan {plan_id} hook record count mismatch")
        validation = validate_semantic_hook_install_plan_record(install_plan)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"semantic_hook_install_plan {plan_id} {reason_code}")

    for indexed_binding_id, binding_id in (indexes.get("semantic_hook_approval_binding_ids") or {}).items():
        if indexed_binding_id != binding_id:
            errors.append(f"semantic_hook_approval_binding index mismatch: {indexed_binding_id} != {binding_id}")
        if binding_id not in semantic_hook_approval_bindings:
            errors.append(f"semantic_hook_approval_binding index references missing binding {binding_id}")

    for binding_id, binding in semantic_hook_approval_bindings.items():
        if binding.get("semantic_hook_approval_binding_id") != binding_id:
            errors.append(f"semantic_hook_approval_binding key mismatch: {binding_id}")
        indexed = (indexes.get("semantic_hook_approval_binding_ids") or {}).get(binding_id)
        if indexed != binding_id:
            errors.append(f"semantic_hook_approval_binding index missing: {binding_id}")
        plan_id = binding.get("semantic_hook_install_plan_id")
        install_plan = semantic_hook_install_plans.get(plan_id)
        if not install_plan:
            errors.append(f"semantic_hook_approval_binding references missing semantic_hook_install_plan {plan_id}")
        else:
            expected_plan_hash = install_plan.get("semantic_hook_install_plan_sha256")
            if binding.get("semantic_hook_install_plan_sha256") != expected_plan_hash:
                errors.append(f"semantic_hook_approval_binding {binding_id} install plan hash mismatch")
        validation = validate_semantic_hook_approval_binding_record(binding, install_plan=install_plan)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"semantic_hook_approval_binding {binding_id} {reason_code}")

    for indexed_snapshot_id, snapshot_id in (indexes.get("semantic_hook_target_snapshot_ids") or {}).items():
        if indexed_snapshot_id != snapshot_id:
            errors.append(f"semantic_hook_target_snapshot index mismatch: {indexed_snapshot_id} != {snapshot_id}")
        if snapshot_id not in semantic_hook_target_snapshots:
            errors.append(f"semantic_hook_target_snapshot index references missing snapshot {snapshot_id}")

    for snapshot_id, snapshot in semantic_hook_target_snapshots.items():
        if snapshot.get("semantic_hook_target_snapshot_id") != snapshot_id:
            errors.append(f"semantic_hook_target_snapshot key mismatch: {snapshot_id}")
        indexed = (indexes.get("semantic_hook_target_snapshot_ids") or {}).get(snapshot_id)
        if indexed != snapshot_id:
            errors.append(f"semantic_hook_target_snapshot index missing: {snapshot_id}")
        binding_id = snapshot.get("semantic_hook_approval_binding_id")
        binding = semantic_hook_approval_bindings.get(binding_id)
        install_plan = None
        if not binding:
            errors.append(f"semantic_hook_target_snapshot references missing semantic_hook_approval_binding {binding_id}")
        else:
            expected_binding_hash = binding.get("semantic_hook_approval_binding_sha256")
            if snapshot.get("semantic_hook_approval_binding_sha256") != expected_binding_hash:
                errors.append(f"semantic_hook_target_snapshot {snapshot_id} approval binding hash mismatch")
            install_plan = semantic_hook_install_plans.get(binding.get("semantic_hook_install_plan_id"))
        if not install_plan:
            errors.append(f"semantic_hook_target_snapshot references missing semantic_hook_install_plan {snapshot.get('semantic_hook_install_plan_id')}")
        else:
            expected_plan_hash = install_plan.get("semantic_hook_install_plan_sha256")
            if snapshot.get("semantic_hook_install_plan_sha256") != expected_plan_hash:
                errors.append(f"semantic_hook_target_snapshot {snapshot_id} install plan hash mismatch")
        validation = validate_semantic_hook_target_snapshot_record(
            snapshot,
            binding=binding,
            install_plan=install_plan,
        )
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"semantic_hook_target_snapshot {snapshot_id} {reason_code}")

    for indexed_transaction_id, transaction_id in (indexes.get("semantic_hook_install_transaction_ids") or {}).items():
        if indexed_transaction_id != transaction_id:
            errors.append(f"semantic_hook_install_transaction index mismatch: {indexed_transaction_id} != {transaction_id}")
        if transaction_id not in semantic_hook_install_transactions:
            errors.append(f"semantic_hook_install_transaction index references missing transaction {transaction_id}")

    for transaction_id, transaction in semantic_hook_install_transactions.items():
        if transaction.get("semantic_hook_install_transaction_id") != transaction_id:
            errors.append(f"semantic_hook_install_transaction key mismatch: {transaction_id}")
        indexed = (indexes.get("semantic_hook_install_transaction_ids") or {}).get(transaction_id)
        if indexed != transaction_id:
            errors.append(f"semantic_hook_install_transaction index missing: {transaction_id}")
        snapshot_id = transaction.get("semantic_hook_target_snapshot_id")
        snapshot = semantic_hook_target_snapshots.get(snapshot_id)
        binding = None
        install_plan = None
        hook_run = None
        if not snapshot:
            errors.append(f"semantic_hook_install_transaction references missing semantic_hook_target_snapshot {snapshot_id}")
        else:
            expected_snapshot_hash = snapshot.get("semantic_hook_target_snapshot_sha256")
            if transaction.get("semantic_hook_target_snapshot_sha256") != expected_snapshot_hash:
                errors.append(f"semantic_hook_install_transaction {transaction_id} target snapshot hash mismatch")
            binding = semantic_hook_approval_bindings.get(snapshot.get("semantic_hook_approval_binding_id"))
            install_plan = semantic_hook_install_plans.get(snapshot.get("semantic_hook_install_plan_id"))
        if not binding:
            errors.append(
                f"semantic_hook_install_transaction references missing semantic_hook_approval_binding {transaction.get('semantic_hook_approval_binding_id')}"
            )
        else:
            expected_binding_hash = binding.get("semantic_hook_approval_binding_sha256")
            if transaction.get("semantic_hook_approval_binding_sha256") != expected_binding_hash:
                errors.append(f"semantic_hook_install_transaction {transaction_id} approval binding hash mismatch")
        if not install_plan:
            errors.append(
                f"semantic_hook_install_transaction references missing semantic_hook_install_plan {transaction.get('semantic_hook_install_plan_id')}"
            )
        else:
            expected_plan_hash = install_plan.get("semantic_hook_install_plan_sha256")
            if transaction.get("semantic_hook_install_plan_sha256") != expected_plan_hash:
                errors.append(f"semantic_hook_install_transaction {transaction_id} install plan hash mismatch")
            hook_run = semantic_hook_runs.get(install_plan.get("semantic_hook_run_id"))
        if not hook_run:
            errors.append(f"semantic_hook_install_transaction references missing semantic_hook_run {transaction.get('semantic_hook_run_id')}")
        else:
            expected_run_hash = hook_run.get("semantic_hook_run_sha256")
            if transaction.get("semantic_hook_run_sha256") != expected_run_hash:
                errors.append(f"semantic_hook_install_transaction {transaction_id} hook run hash mismatch")
        validation = validate_semantic_hook_install_transaction_record(
            transaction,
            target_snapshot=snapshot,
            binding=binding,
            install_plan=install_plan,
            hook_run=hook_run,
        )
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"semantic_hook_install_transaction {transaction_id} {reason_code}")

    for indexed_packet_id, packet_id in (indexes.get("semantic_hook_operator_approval_packet_ids") or {}).items():
        if indexed_packet_id != packet_id:
            errors.append(f"semantic_hook_operator_approval index mismatch: {indexed_packet_id} != {packet_id}")
        if packet_id not in semantic_hook_operator_approval_packets:
            errors.append(f"semantic_hook_operator_approval index references missing packet {packet_id}")

    for packet_id, packet in semantic_hook_operator_approval_packets.items():
        if packet.get("semantic_hook_operator_approval_packet_id") != packet_id:
            errors.append(f"semantic_hook_operator_approval key mismatch: {packet_id}")
        indexed = (indexes.get("semantic_hook_operator_approval_packet_ids") or {}).get(packet_id)
        if indexed != packet_id:
            errors.append(f"semantic_hook_operator_approval index missing: {packet_id}")
        transaction_id = packet.get("semantic_hook_install_transaction_id")
        transaction = semantic_hook_install_transactions.get(transaction_id)
        snapshot = None
        binding = None
        install_plan = None
        hook_run = None
        if not transaction:
            errors.append(f"semantic_hook_operator_approval references missing semantic_hook_install_transaction {transaction_id}")
        else:
            expected_transaction_hash = transaction.get("semantic_hook_install_transaction_sha256")
            if packet.get("semantic_hook_install_transaction_sha256") != expected_transaction_hash:
                errors.append(f"semantic_hook_operator_approval {packet_id} install transaction hash mismatch")
            snapshot = semantic_hook_target_snapshots.get(transaction.get("semantic_hook_target_snapshot_id"))
            binding = semantic_hook_approval_bindings.get(transaction.get("semantic_hook_approval_binding_id"))
            install_plan = semantic_hook_install_plans.get(transaction.get("semantic_hook_install_plan_id"))
            hook_run = semantic_hook_runs.get(transaction.get("semantic_hook_run_id"))
        if not snapshot:
            errors.append(
                f"semantic_hook_operator_approval references missing semantic_hook_target_snapshot {packet.get('semantic_hook_target_snapshot_id')}"
            )
        else:
            expected_snapshot_hash = snapshot.get("semantic_hook_target_snapshot_sha256")
            if packet.get("semantic_hook_target_snapshot_sha256") != expected_snapshot_hash:
                errors.append(f"semantic_hook_operator_approval {packet_id} target snapshot hash mismatch")
        if not binding:
            errors.append(
                f"semantic_hook_operator_approval references missing semantic_hook_approval_binding {packet.get('semantic_hook_approval_binding_id')}"
            )
        else:
            expected_binding_hash = binding.get("semantic_hook_approval_binding_sha256")
            if packet.get("semantic_hook_approval_binding_sha256") != expected_binding_hash:
                errors.append(f"semantic_hook_operator_approval {packet_id} approval binding hash mismatch")
        if not install_plan:
            errors.append(
                f"semantic_hook_operator_approval references missing semantic_hook_install_plan {packet.get('semantic_hook_install_plan_id')}"
            )
        else:
            expected_plan_hash = install_plan.get("semantic_hook_install_plan_sha256")
            if packet.get("semantic_hook_install_plan_sha256") != expected_plan_hash:
                errors.append(f"semantic_hook_operator_approval {packet_id} install plan hash mismatch")
        if not hook_run:
            errors.append(f"semantic_hook_operator_approval references missing semantic_hook_run {packet.get('semantic_hook_run_id')}")
        else:
            expected_run_hash = hook_run.get("semantic_hook_run_sha256")
            if packet.get("semantic_hook_run_sha256") != expected_run_hash:
                errors.append(f"semantic_hook_operator_approval {packet_id} hook run hash mismatch")
        validation = validate_semantic_hook_operator_approval_packet_record(
            packet,
            transaction=transaction,
            target_snapshot=snapshot,
            binding=binding,
            install_plan=install_plan,
            hook_run=hook_run,
        )
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"semantic_hook_operator_approval {packet_id} {reason_code}")

    for indexed_receipt_id, receipt_id in (indexes.get("semantic_hook_operator_readback_receipt_ids") or {}).items():
        if indexed_receipt_id != receipt_id:
            errors.append(f"semantic_hook_operator_readback index mismatch: {indexed_receipt_id} != {receipt_id}")
        if receipt_id not in semantic_hook_operator_readback_receipts:
            errors.append(f"semantic_hook_operator_readback index references missing receipt {receipt_id}")

    for receipt_id, receipt in semantic_hook_operator_readback_receipts.items():
        if receipt.get("semantic_hook_operator_readback_receipt_id") != receipt_id:
            errors.append(f"semantic_hook_operator_readback key mismatch: {receipt_id}")
        indexed = (indexes.get("semantic_hook_operator_readback_receipt_ids") or {}).get(receipt_id)
        if indexed != receipt_id:
            errors.append(f"semantic_hook_operator_readback index missing: {receipt_id}")
        packet_id = receipt.get("semantic_hook_operator_approval_packet_id")
        packet = semantic_hook_operator_approval_packets.get(packet_id)
        if not packet:
            errors.append(f"semantic_hook_operator_readback references missing semantic_hook_operator_approval_packet {packet_id}")
        else:
            expected_packet_hash = packet.get("semantic_hook_operator_approval_packet_sha256")
            if receipt.get("semantic_hook_operator_approval_packet_sha256") != expected_packet_hash:
                errors.append(f"semantic_hook_operator_readback {receipt_id} operator packet hash mismatch")
        validation = validate_semantic_hook_operator_readback_receipt_record(receipt, packet=packet)
        if not validation["ok"]:
            for reason_code in validation["reason_codes"]:
                errors.append(f"semantic_hook_operator_readback {receipt_id} {reason_code}")

    return {
        "ok": not errors,
        "errors": errors,
        "counts": {
            "sessions": len(sessions),
            "events": len(state.get("events") or {}),
            "contexts": len(contexts),
            "checkpoints": len(checkpoints),
            "task_runs": len(task_runs),
            "run_events": len(run_events),
            "ams_events": len(ams_events),
            "admission_reviews": len(admission_reviews),
            "resource_policies": len(resource_policies),
            "resource_claims": len(resource_claims),
            "resource_telemetry_samples": len(resource_telemetry_samples),
            "resource_enforcement_trials": len(resource_enforcement_trials),
            "shareability_bundles": len(shareability_bundles),
            "shareability_receiver_trials": len(shareability_receiver_trials),
            "tool_definitions": len(tool_definitions),
            "surface_definitions": len(surface_definitions),
            "runtime_surfaces": len(runtime_surfaces),
            "surface_bindings": len(surface_bindings),
            "surface_promises": len(surface_promises),
            "shadow_launch_plans": len(shadow_launch_plans),
            "shadow_runner_transactions": len(shadow_runner_transactions),
            "attention_signals": len(attention_signals),
            "manager_interventions": len(manager_interventions),
            "manager_intervention_deliveries": len(manager_intervention_deliveries),
            "manager_intervention_settlements": len(manager_intervention_settlements),
            "architecture_audits": len(architecture_audits),
            "architecture_gate_reviews": len(architecture_gate_reviews),
            "rag_index_plans": len(rag_index_plans),
            "downloaded_artifact_quarantines": len(downloaded_artifact_quarantines),
            "rag_embedding_jobs": len(rag_embedding_jobs),
            "provider_auth_preflights": len(provider_auth_preflights),
            "rag_embedding_receipts": len(rag_embedding_receipts),
            "rag_retrieval_queries": len(rag_retrieval_queries),
            "rag_local_vector_trials": len(rag_local_vector_trials),
            "agent_memory_trials": len(agent_memory_trials),
            "memory_claims": len(memory_claims),
            "memory_promotion_reviews": len(memory_promotion_reviews),
            "memory_supersession_records": len(memory_supersession_records),
            "memory_conflict_records": len(memory_conflict_records),
            "real_agent_trials": len(real_agent_trials),
            "real_agent_system_trials": len(real_agent_system_trials),
            "provider_results": len(provider_results),
            "incident_packets": len(incident_packets),
            "outbox_items": len(outbox_items),
            "outbox_receipts": len(outbox_receipts),
            "store_backup_drills": len(store_backup_drills),
            "runner_dry_run_parities": len(runner_dry_run_parities),
            "shadow_approval_packets": len(shadow_approval_packets),
            "discord_source_packets": len(discord_source_packets),
            "discord_canary_send_plans": len(discord_canary_send_plans),
            "discord_canary_receipts": len(discord_canary_receipts),
            "terminal_source_packets": len(terminal_source_packets),
            "conformance_packs": len(conformance_packs),
            "markdown_audits": len(markdown_audits),
            "readiness_reviews": len(readiness_reviews),
            "doc_retirement_plans": len(doc_retirement_plans),
            "doc_action_execution_plans": len(doc_action_execution_plans),
            "doc_action_operator_approval_packets": len(doc_action_operator_approval_packets),
            "doc_action_patch_previews": len(doc_action_patch_previews),
            "doc_action_patch_readback_receipts": len(doc_action_patch_readback_receipts),
            "doc_action_patch_artifact_receipts": len(doc_action_patch_artifact_receipts),
            "doc_action_patch_artifact_approval_packets": len(doc_action_patch_artifact_approval_packets),
            "doc_action_patch_dry_run_plans": len(doc_action_patch_dry_run_plans),
            "doc_action_patch_dry_run_readback_receipts": len(doc_action_patch_dry_run_readback_receipts),
            "doc_action_patch_live_execution_approval_packets": len(
                doc_action_patch_live_execution_approval_packets
            ),
            "doc_action_patch_executor_preflights": len(doc_action_patch_executor_preflights),
            "doc_action_patch_apply_boundary_packets": len(doc_action_patch_apply_boundary_packets),
            "doc_action_patch_apply_acceptance_packets": len(doc_action_patch_apply_acceptance_packets),
            "source_write_executor_preflights": len(source_write_executor_preflights),
            "source_write_backup_preimage_receipts": len(source_write_backup_preimage_receipts),
            "source_write_executor_leases": len(source_write_executor_leases),
            "generated_status_snapshots": len(generated_status_snapshots),
            "session_start_briefs": len(session_start_briefs),
            "markdown_authority_indexes": len(markdown_authority_indexes),
            "markdown_authority_entries": len(markdown_authority_entries),
            "codebase_spider_graph_snapshots": len(codebase_spider_graph_snapshots),
            "codebase_graph_nodes": len(codebase_graph_nodes),
            "codebase_graph_edges": len(codebase_graph_edges),
            "codebase_graph_query_receipts": len(codebase_graph_query_receipts),
            "blast_radius_reviews": len(blast_radius_reviews),
            "work_mode_decisions": len(work_mode_decisions),
            "simulation_sweeps": len(simulation_sweeps),
            "ams_emulation_trials": len(ams_emulation_trials),
            "semantic_oracle_reviews": len(semantic_oracle_reviews),
            "semantic_hook_records": len(semantic_hook_records),
            "semantic_hook_runs": len(semantic_hook_runs),
            "semantic_hook_install_plans": len(semantic_hook_install_plans),
            "semantic_hook_approval_bindings": len(semantic_hook_approval_bindings),
            "semantic_hook_target_snapshots": len(semantic_hook_target_snapshots),
            "semantic_hook_install_transactions": len(semantic_hook_install_transactions),
            "semantic_hook_operator_approval_packets": len(semantic_hook_operator_approval_packets),
            "semantic_hook_operator_readback_receipts": len(semantic_hook_operator_readback_receipts),
        },
    }


def _validate_dispatch_intent_event(
    errors: list[str],
    state: dict[str, Any],
    task_run: dict[str, Any],
    event: dict[str, Any],
) -> None:
    task_run_id = str(task_run.get("task_run_id") or "")
    context = (state.get("contexts") or {}).get(task_run.get("context_id"))
    if not isinstance(context, dict):
        errors.append(f"task_run {task_run_id} dispatch intent references missing context")
        return
    intent = context.get("intent") or {}
    end_state = intent.get("end_state") or {}
    payload = event.get("payload") or {}
    if not intent or not end_state:
        errors.append(f"task_run {task_run_id} dispatch intent without context intent")
    if payload.get("intent_sha256") != sha256_text(canonical_json(intent)):
        errors.append(f"task_run {task_run_id} dispatch intent sha256 mismatch")
    if payload.get("end_state_sha256") != end_state_hash(end_state):
        errors.append(f"task_run {task_run_id} dispatch end_state sha256 mismatch")
    if (context.get("lease") or {}).get("end_state_sha256") != end_state_hash(end_state):
        errors.append(f"task_run {task_run_id} lease/end_state sha256 mismatch")
    claim_id = payload.get("resource_claim_id")
    claim = (state.get("resource_claims") or {}).get(claim_id)
    if not claim or claim.get("task_run_id") != task_run_id:
        errors.append(f"task_run {task_run_id} dispatch intent references missing resource_claim")
    if not _capability_allowed_for_run(state, task_run):
        errors.append(f"task_run {task_run_id} dispatch intent without capability allow")
    session = (state.get("sessions") or {}).get(task_run.get("session_id")) or {}
    provider_session_id = task_run.get("provider_session_id")
    if provider_session_id:
        matched = [
            binding for binding in session.get("provider_sessions") or []
            if binding.get("provider") == task_run.get("provider")
            and binding.get("surface") == task_run.get("provider_surface")
            and binding.get("provider_session_id") == provider_session_id
        ]
        if not matched:
            errors.append(f"task_run {task_run_id} dispatch intent without provider binding")


def _capability_allowed_for_run(state: dict[str, Any], task_run: dict[str, Any]) -> bool:
    run_tools = set(task_run.get("tool_scope") or [])
    for review in (state.get("admission_reviews") or {}).values():
        if review.get("subject_kind") != "task_run":
            continue
        if review.get("subject_id") != task_run.get("task_run_id"):
            continue
        if not str(review.get("operation") or "").startswith("capability"):
            continue
        response = review.get("response") or {}
        request = review.get("request") or {}
        request_tools = set(request.get("tools") or [])
        if run_tools and not run_tools.issubset(request_tools):
            continue
        if response.get("status") == "allow" and response.get("allowed") is True:
            return True
    return False


class ReplayChecker:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def check(self) -> dict[str, Any]:
        return replay_check(self.store.load())
