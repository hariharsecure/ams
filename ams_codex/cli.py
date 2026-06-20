from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .admission import AdmissionReviewStore
from .agent_memory_sim import default_runtime_root, init_agent_sim_runtime, run_default_agent_memory_trial
from .ams_emulation import AmsEmulationTrialStore
from .ams_event import AMSEventStore
from .architecture_audit import ArchitectureAuditStore
from .architecture_gate import ArchitectureGateStore
from .artifact_quarantine import DownloadedArtifactQuarantineStore
from .attention_router import AttentionRouterStore
from .backup_restore import StoreBackupDrillStore
from .blast_radius import BlastRadiusReviewStore
from .capability_policy import (
    build_capability_request,
    build_default_capability_policy,
    evaluate_capability_request,
)
from .checkpoint import CheckpointStore
from .claude_adapter import ClaudeDryRunAdapter
from .codebase_spider_graph import CodebaseGraphQueryStore, CodebaseSpiderGraphStore
from .codex_adapter import CodexDryRunAdapter
from .conformance_pack import ConformancePackStore
from .console import build_console_report, render_html, render_text, write_console
from .context import ContextStore
from .definition_registry import DefinitionRegistryStore
from .discord_canary import DiscordCanarySendPlanStore
from .discord_canary_receipt import DiscordCanaryReceiptStore
from .discord_source import DiscordSourcePacketStore
from .doc_action_execution import DocActionExecutionPlanStore
from .doc_action_operator_approval import DocActionOperatorApprovalPacketStore
from .doc_action_patch_artifact import DocActionPatchArtifactReceiptStore
from .doc_action_patch_artifact_approval import DocActionPatchArtifactApprovalPacketStore
from .doc_action_patch_apply_acceptance import DocActionPatchApplyAcceptancePacketStore
from .doc_action_patch_apply_boundary import DocActionPatchApplyBoundaryPacketStore
from .doc_action_patch_dry_run import DocActionPatchDryRunPlanStore
from .doc_action_patch_dry_run_readback import DocActionPatchDryRunReadbackReceiptStore
from .doc_action_patch_executor_preflight import DocActionPatchExecutorPreflightStore
from .doc_action_patch_live_execution_approval import DocActionPatchLiveExecutionApprovalPacketStore
from .doc_action_patch_preview import DocActionPatchPreviewStore
from .doc_action_patch_readback import DocActionPatchReadbackReceiptStore
from .doc_retirement import DocRetirementPlanStore
from .dispatch import dispatch
from .epoch import EpochCloser
from .gate_adapter import GateShadowAdapter, build_action
from .generated_status import GeneratedStatusSnapshotStore
from .install_preflight import run_install_preflight
from .intervention_delivery import ManagerInterventionDeliveryStore
from .intervention_settlement import ManagerInterventionSettlementStore
from .manager_intervention import ManagerInterventionStore, parse_target_agent
from .markdown_authority import MarkdownAuthorityStore, parse_supersession_edge
from .markdown_governance import MarkdownAuditStore
from .memory_supersession import MemorySupersessionStore
from .predicate import PredicateStore
from .provider_auth import ProviderAuthPreflightStore
from .provider_result import ProviderResultStore
from .rag_embedding_receipt import RAGEmbeddingReceiptStore
from .rag_embedding_job import RAGEmbeddingJobStore
from .rag_index_plan import RAGIndexPlanStore
from .rag_local_vector_trial import RAGLocalVectorTrialStore
from .rag_retrieval_query import RAGRetrievalQueryStore
from .readiness_review import ReadinessReviewStore
from .real_agent_system_trial import RealAgentSystemTrialStore
from .real_agent_trial import run_real_agent_smoke_trial
from .replay import ReplayChecker
from .replay_oracle import ReplayOracle
from .outbox import OutboxStore
from .package_manifest import verify_package_manifest, write_package_manifest
from .resource_claim import ResourceClaimStore
from .resource_enforcement import ResourceEnforcementTrialStore
from .resource_policy import build_default_resource_policy, evaluate_task_run
from .resource_telemetry import ResourceTelemetryStore
from .runner_parity import RunnerDryRunParityStore
from .session_start_brief import SessionStartBriefStore
from .semantic_hook_approval import SemanticHookApprovalBindingStore
from .semantic_hook_install_transaction import SemanticHookInstallTransactionStore
from .semantic_hook_operator_approval import SemanticHookOperatorApprovalPacketStore
from .semantic_hook_target_snapshot import SemanticHookTargetSnapshotStore
from .surface_bindings import SurfaceBindingStore
from .surface_promise import SurfacePromiseStore
from .run_trace import RunTraceStore
from .shadow_approval import ShadowApprovalPacketStore
from .runner_boundary import runner_preflight
from .session_registry import SessionRegistry
from .self_eval import run_self_eval
from .semantic_hook_install_plan import SemanticHookInstallPlanStore
from .semantic_hook_run import SemanticHookRunStore
from .semantic_oracle_review import SemanticOracleReviewStore
from .semantic_hook_operator_readback import SemanticHookOperatorReadbackReceiptStore
from .shadow_launch import ShadowLaunchStore
from .shadow_readiness import evaluate_shadow_readiness
from .shadow_runner import ShadowRunnerStore
from .shareability_bundle import ShareabilityBundleStore
from .shareability_receiver import ShareabilityReceiverTrialStore
from .signed_policy import SignedPolicyConfig, verify_signed_policy
from .simulation import run_dual_agent_simulation, run_full_simulation, run_incident_simulation
from .simulation_sweep import SimulationSweepStore
from .source_write_backup_preimage import SourceWriteBackupPreimageReceiptStore
from .source_write_executor_lease import SourceWriteExecutorLeaseStore
from .source_write_preflight import SourceWriteExecutorPreflightStore
from .store import JsonStore, empty_state
from .storage_probe import run_storage_probe
from .terminal_source import TerminalSourcePacketStore
from .trace_export import TraceExporter
from .work_mode_decision import WorkModeDecisionStore
from .workspace import path_is_under as _path_is_under, repo_root, workspace_root


def default_runtime_store() -> Path:
    return Path.home() / ".ams" / "stores" / "ams_codex_store.json"


def load_json(path: str) -> dict:
    with Path(path).open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"expected JSON object: {path}")
    return data


def print_json(data: object) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def cmd_init(args: argparse.Namespace) -> int:
    store = JsonStore(args.store)
    if Path(args.store).exists() and not args.force:
        print(f"store already exists: {args.store}", file=sys.stderr)
        return 2
    store.save(empty_state(), check_revision=False)
    print(f"initialized {args.store}")
    return 0


def cmd_ingest_event(args: argparse.Namespace) -> int:
    raw = load_json(args.event_file)
    store = JsonStore(args.store)
    registry = SessionRegistry(store)
    session, created = registry.ingest_event(raw)
    result = {"created": created, "session": session}
    if args.context:
        context = ContextStore(store).create_for_event(session, raw)
        result["context"] = context
    print_json(result)
    return 0


def cmd_checkpoint(args: argparse.Namespace) -> int:
    checkpoint = CheckpointStore(JsonStore(args.store)).create(
        args.session_id,
        trigger=args.trigger,
        state_summary=args.summary,
        next_action=args.next_action,
        decisions=args.decision or [],
        open_questions=args.open_question or [],
        constraints=args.constraint or [],
    )
    print_json(checkpoint)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    state = JsonStore(args.store).load()
    sessions = list(state["sessions"].values())
    payload = {
        "store": str(args.store),
        "sessions": len(sessions),
        "contexts": len(state["contexts"]),
        "checkpoints": len(state["checkpoints"]),
        "events": len(state["events"]),
        "task_runs": len(state.get("task_runs", {})),
        "run_events": len(state.get("run_events", {})),
        "ams_events": len(state.get("ams_events", {})),
        "admission_reviews": len(state.get("admission_reviews", {})),
        "resource_policies": len(state.get("resource_policies", {})),
        "resource_claims": len(state.get("resource_claims", {})),
        "resource_telemetry_samples": len(state.get("resource_telemetry_samples", {})),
        "resource_enforcement_trials": len(state.get("resource_enforcement_trials", {})),
        "shareability_bundles": len(state.get("shareability_bundles", {})),
        "shareability_receiver_trials": len(state.get("shareability_receiver_trials", {})),
        "tool_definitions": len(state.get("tool_definitions", {})),
        "surface_definitions": len(state.get("surface_definitions", {})),
        "runtime_surfaces": len(state.get("runtime_surfaces", {})),
        "surface_bindings": len(state.get("surface_bindings", {})),
        "surface_promises": len(state.get("surface_promises", {})),
        "shadow_launch_plans": len(state.get("shadow_launch_plans", {})),
        "shadow_runner_transactions": len(state.get("shadow_runner_transactions", {})),
        "attention_signals": len(state.get("attention_signals", {})),
        "manager_interventions": len(state.get("manager_interventions", {})),
        "manager_intervention_deliveries": len(state.get("manager_intervention_deliveries", {})),
        "manager_intervention_settlements": len(state.get("manager_intervention_settlements", {})),
        "architecture_audits": len(state.get("architecture_audits", {})),
        "architecture_gate_reviews": len(state.get("architecture_gate_reviews", {})),
        "rag_index_plans": len(state.get("rag_index_plans", {})),
        "downloaded_artifact_quarantines": len(state.get("downloaded_artifact_quarantines", {})),
        "rag_embedding_jobs": len(state.get("rag_embedding_jobs", {})),
        "provider_auth_preflights": len(state.get("provider_auth_preflights", {})),
        "rag_embedding_receipts": len(state.get("rag_embedding_receipts", {})),
        "rag_retrieval_queries": len(state.get("rag_retrieval_queries", {})),
        "rag_local_vector_trials": len(state.get("rag_local_vector_trials", {})),
        "agent_memory_trials": len(state.get("agent_memory_trials", {})),
        "memory_claims": len(state.get("memory_claims", {})),
        "memory_promotion_reviews": len(state.get("memory_promotion_reviews", {})),
        "memory_supersession_records": len(state.get("memory_supersession_records", {})),
        "memory_conflict_records": len(state.get("memory_conflict_records", {})),
        "real_agent_trials": len(state.get("real_agent_trials", {})),
        "real_agent_system_trials": len(state.get("real_agent_system_trials", {})),
        "provider_results": len(state.get("provider_results", {})),
        "incident_packets": len(state.get("incident_packets", {})),
        "outbox_items": len(state.get("outbox_items", {})),
        "outbox_receipts": len(state.get("outbox_receipts", {})),
        "store_backup_drills": len(state.get("store_backup_drills", {})),
        "runner_dry_run_parities": len(state.get("runner_dry_run_parities", {})),
        "shadow_approval_packets": len(state.get("shadow_approval_packets", {})),
        "discord_source_packets": len(state.get("discord_source_packets", {})),
        "discord_canary_send_plans": len(state.get("discord_canary_send_plans", {})),
        "discord_canary_receipts": len(state.get("discord_canary_receipts", {})),
        "terminal_source_packets": len(state.get("terminal_source_packets", {})),
        "conformance_packs": len(state.get("conformance_packs", {})),
        "markdown_audits": len(state.get("markdown_audits", {})),
        "readiness_reviews": len(state.get("readiness_reviews", {})),
        "doc_retirement_plans": len(state.get("doc_retirement_plans", {})),
        "doc_action_execution_plans": len(state.get("doc_action_execution_plans", {})),
        "doc_action_operator_approval_packets": len(state.get("doc_action_operator_approval_packets", {})),
        "doc_action_patch_previews": len(state.get("doc_action_patch_previews", {})),
        "doc_action_patch_readback_receipts": len(state.get("doc_action_patch_readback_receipts", {})),
        "doc_action_patch_artifact_receipts": len(state.get("doc_action_patch_artifact_receipts", {})),
        "doc_action_patch_artifact_approval_packets": len(
            state.get("doc_action_patch_artifact_approval_packets", {})
        ),
        "doc_action_patch_dry_run_plans": len(state.get("doc_action_patch_dry_run_plans", {})),
        "doc_action_patch_dry_run_readback_receipts": len(
            state.get("doc_action_patch_dry_run_readback_receipts", {})
        ),
        "doc_action_patch_live_execution_approval_packets": len(
            state.get("doc_action_patch_live_execution_approval_packets", {})
        ),
        "doc_action_patch_executor_preflights": len(
            state.get("doc_action_patch_executor_preflights", {})
        ),
        "doc_action_patch_apply_boundary_packets": len(
            state.get("doc_action_patch_apply_boundary_packets", {})
        ),
        "doc_action_patch_apply_acceptance_packets": len(
            state.get("doc_action_patch_apply_acceptance_packets", {})
        ),
        "source_write_executor_preflights": len(state.get("source_write_executor_preflights", {})),
        "source_write_backup_preimage_receipts": len(state.get("source_write_backup_preimage_receipts", {})),
        "source_write_executor_leases": len(state.get("source_write_executor_leases", {})),
        "generated_status_snapshots": len(state.get("generated_status_snapshots", {})),
        "session_start_briefs": len(state.get("session_start_briefs", {})),
        "markdown_authority_indexes": len(state.get("markdown_authority_indexes", {})),
        "markdown_authority_entries": len(state.get("markdown_authority_entries", {})),
        "codebase_spider_graph_snapshots": len(state.get("codebase_spider_graph_snapshots", {})),
        "codebase_graph_nodes": len(state.get("codebase_graph_nodes", {})),
        "codebase_graph_edges": len(state.get("codebase_graph_edges", {})),
        "codebase_graph_query_receipts": len(state.get("codebase_graph_query_receipts", {})),
        "blast_radius_reviews": len(state.get("blast_radius_reviews", {})),
        "work_mode_decisions": len(state.get("work_mode_decisions", {})),
        "simulation_sweeps": len(state.get("simulation_sweeps", {})),
        "ams_emulation_trials": len(state.get("ams_emulation_trials", {})),
        "semantic_oracle_reviews": len(state.get("semantic_oracle_reviews", {})),
        "semantic_hook_records": len(state.get("semantic_hook_records", {})),
        "semantic_hook_runs": len(state.get("semantic_hook_runs", {})),
        "semantic_hook_install_plans": len(state.get("semantic_hook_install_plans", {})),
        "semantic_hook_approval_bindings": len(state.get("semantic_hook_approval_bindings", {})),
        "semantic_hook_target_snapshots": len(state.get("semantic_hook_target_snapshots", {})),
        "semantic_hook_install_transactions": len(state.get("semantic_hook_install_transactions", {})),
        "semantic_hook_operator_approval_packets": len(state.get("semantic_hook_operator_approval_packets", {})),
        "semantic_hook_operator_readback_receipts": len(state.get("semantic_hook_operator_readback_receipts", {})),
        "active_sessions": [
            {
                "session_id": s["session_id"],
                "state": s.get("state"),
                "codex_thread_id": s.get("codex_thread_id"),
                "claude_session_id": s.get("claude_session_id"),
                "provider_bindings": len(s.get("provider_sessions") or []),
                "last_summary_checkpoint_id": s.get("last_summary_checkpoint_id"),
                "updated_at": s.get("updated_at"),
            }
            for s in sorted(sessions, key=lambda row: row.get("updated_at", ""), reverse=True)
            if s.get("state") in {"pending", "active", "blocked"}
        ],
    }
    print_json(payload)
    return 0


def cmd_prepare_codex(args: argparse.Namespace) -> int:
    adapter = CodexDryRunAdapter(JsonStore(args.store))
    if args.bind_thread_id:
        session = adapter.bind_thread(args.session_id, args.bind_thread_id)
        print_json({"bound": True, "session": session})
        return 0
    if args.resume_thread:
        request = adapter.prepare_resume_request(
            args.session_id,
            model=args.model,
            cwd=args.cwd,
            sandbox=args.sandbox,
        )
        print_json({"dry_run": True, "request": request})
        return 0
    request = adapter.prepare_request(
        args.session_id,
        args.context_id,
        model=args.model,
        cwd=args.cwd,
        sandbox=args.sandbox,
        active_turn_id=args.active_turn_id,
    )
    print_json({"dry_run": True, "request": request})
    return 0


def cmd_prepare_claude(args: argparse.Namespace) -> int:
    adapter = ClaudeDryRunAdapter(JsonStore(args.store))
    if args.bind_session_id:
        session = adapter.bind_session(
            args.session_id,
            args.bind_session_id,
            claude_agent_id=args.bind_agent_id,
        )
        print_json({"bound": True, "session": session})
        return 0
    request = adapter.prepare_request(args.session_id, args.context_id, role=args.role)
    print_json({"dry_run": True, "request": request})
    return 0


def cmd_gate_check(args: argparse.Namespace) -> int:
    payload = load_json(args.payload_file) if args.payload_file else {"dry_run": True}
    flags = args.risk_flag or []
    action = build_action(
        tool=args.tool,
        endpoint=args.endpoint,
        method=args.method,
        payload=payload,
        channel_id=args.channel_id,
        requester=args.requester,
        host=args.host,
        risk_flags=flags,
    )
    verdict = GateShadowAdapter(JsonStore(args.store)).check(action)
    print_json({"action": action, "verdict": verdict})
    return 0


def cmd_replay_check(args: argparse.Namespace) -> int:
    result = ReplayChecker(JsonStore(args.store)).check()
    print_json(result)
    return 0 if result["ok"] else 1


def cmd_replay_oracle(args: argparse.Namespace) -> int:
    result = ReplayOracle(
        JsonStore(args.store),
        exhaustive=getattr(args, "exhaustive", False),
        max_records_per_collection=getattr(args, "max_records_per_collection", 5),
    ).check()
    if args.full_output:
        print_json(result)
    else:
        print_json(
            {
                "baseline": result["baseline"],
                "summary": result["summary"],
                "misses": result["misses"],
                "skipped_count": len(result.get("skipped") or []),
                "unhashed_collections": result.get("unhashed_collections") or [],
                "ok": result["ok"],
            }
        )
    return 0 if result["ok"] else 1


def cmd_create_run(args: argparse.Namespace) -> int:
    task_run = RunTraceStore(JsonStore(args.store)).create_run(
        args.session_id,
        args.context_id,
        actor=args.actor,
        provider=args.provider,
        provider_surface=args.provider_surface,
        action=args.action,
        cwd=args.cwd,
        model=args.model,
        tool_scope=args.tool_scope or [],
        parent_run_id=args.parent_run_id,
        requested_by=args.requested_by,
        attempt=args.attempt,
        retry_of=args.retry_of,
        method=args.method,
        sandbox=args.sandbox,
        gate_mode=args.gate_mode,
        capability_snapshot_sha256=args.capability_snapshot_sha256,
    )
    print_json(task_run)
    return 0


def cmd_append_run_event(args: argparse.Namespace) -> int:
    payload = load_json(args.payload_file) if args.payload_file else {}
    token_usage = load_json(args.token_usage_file) if args.token_usage_file else {}
    event = RunTraceStore(JsonStore(args.store)).append_event(
        args.task_run_id,
        args.event_type,
        payload=payload,
        artifact_refs=args.artifact_ref or [],
        token_usage=token_usage,
        reason_codes=args.reason_code or [],
        risk_flags=args.risk_flag or [],
    )
    print_json(event)
    return 0


def cmd_resource_check(args: argparse.Namespace) -> int:
    store = JsonStore(args.store)
    state = store.load()
    task_run = state.get("task_runs", {}).get(args.task_run_id)
    if not task_run:
        raise KeyError(f"unknown task_run_id: {args.task_run_id}")
    policy = load_json(args.policy_file) if args.policy_file else build_default_resource_policy()
    current_usage = load_json(args.usage_file) if args.usage_file else {}
    verdict = evaluate_task_run(task_run, policy, current_usage=current_usage)
    print_json(verdict)
    return 0 if verdict["status"] == "allow" else 1


def cmd_capability_check(args: argparse.Namespace) -> int:
    policy = load_json(args.policy_file) if args.policy_file else build_default_capability_policy()
    request = build_capability_request(
        actor=args.actor,
        tier=args.tier,
        action=args.action,
        paths=args.path or [],
        tools=args.tool or [],
        egress_mode=args.egress_mode,
        change_request_id=args.change_request_id,
        admission_review_id=args.admission_review_id,
        signed_policy_sha256=args.signed_policy_sha256,
        architecture_gate_review_id=args.architecture_gate_review_id,
        architecture_audit_id=args.architecture_audit_id,
        architecture_audit_sha256=args.architecture_audit_sha256,
        blast_radius_review_id=args.blast_radius_review_id,
        blast_radius_review_sha256=args.blast_radius_review_sha256,
    )
    verdict = evaluate_capability_request(request, policy)
    print_json({"request": request, "verdict": verdict})
    return 0 if verdict["status"] == "allow" else 1


def cmd_append_ams_event(args: argparse.Namespace) -> int:
    data = load_json(args.data_file) if args.data_file else {}
    event = AMSEventStore(JsonStore(args.store)).append(
        event_type=args.event_type,
        source=args.source,
        subject=args.subject,
        data=data,
        session_id=args.session_id,
        task_run_id=args.task_run_id,
        trace_id=args.trace_id,
        span_id=args.span_id,
        dataschema=args.dataschema,
        parent_event_id=args.parent_event_id,
    )
    print_json(event)
    return 0


def cmd_admission_review(args: argparse.Namespace) -> int:
    request = load_json(args.request_file) if args.request_file else {}
    verdict = load_json(args.verdict_file) if args.verdict_file else None
    review = AdmissionReviewStore(JsonStore(args.store)).create(
        subject_kind=args.subject_kind,
        subject_id=args.subject_id,
        operation=args.operation,
        request=request,
        verdict=verdict,
        status=args.status,
        reason_codes=args.reason_code or None,
        policy_refs=args.policy_ref or None,
        reviewer=args.reviewer,
        ttl_seconds=args.ttl_seconds,
    )
    print_json(review)
    return 0 if review["response"]["allowed"] else 1


def cmd_claim_resource(args: argparse.Namespace) -> int:
    policy = load_json(args.policy_file) if args.policy_file else build_default_resource_policy()
    current_usage = load_json(args.usage_file) if args.usage_file else {}
    result = ResourceClaimStore(JsonStore(args.store)).reserve(
        args.task_run_id,
        policy=policy,
        current_usage=current_usage,
        ttl_seconds=args.ttl_seconds,
    )
    print_json(result)
    return 0 if result["reserved"] else 1


def cmd_update_resource_claim(args: argparse.Namespace) -> int:
    claim = ResourceClaimStore(JsonStore(args.store)).transition(args.resource_claim_id, args.state)
    print_json(claim)
    return 0


def cmd_record_resource_telemetry(args: argparse.Namespace) -> int:
    observed = {
        "input_tokens": args.input_tokens,
        "output_tokens": args.output_tokens,
        "runtime_ms": args.runtime_ms,
        "cost_microusd": args.cost_microusd,
        "cpu_core_ms": args.cpu_core_ms,
        "peak_memory_mb": args.peak_memory_mb,
        "peak_gpu_memory_mb": args.peak_gpu_memory_mb,
        "network_bytes": args.network_bytes,
        "disk_read_bytes": args.disk_read_bytes,
        "disk_write_bytes": args.disk_write_bytes,
    }
    source_ref = {
        "kind": args.source_ref_kind,
        "ref": args.source_ref,
    }
    if args.artifact_sha256:
        source_ref["artifact_sha256"] = args.artifact_sha256
    telemetry = ResourceTelemetryStore(JsonStore(args.store)).record(
        args.resource_claim_id,
        observed=observed,
        source_type=args.source_type,
        source_ref=source_ref,
        provider_result_id=args.provider_result_id,
    )
    print_json(telemetry)
    return 0 if telemetry["settlement_status"] == "within_limits" else 1


def cmd_resource_enforcement_trial(args: argparse.Namespace) -> int:
    trial = ResourceEnforcementTrialStore(JsonStore(args.store)).create(
        resource_claim_id=args.resource_claim_id,
        mode=args.mode,
        timeout_seconds=args.timeout_seconds,
        source_root=args.source_root,
        label=args.label,
    )
    print_json(trial)
    return 0 if trial["status"] in {"within_budget", "killed_over_budget"} else 1


def cmd_shareability_bundle(args: argparse.Namespace) -> int:
    bundle = ShareabilityBundleStore(JsonStore(args.store)).create(
        source_root=args.source_root,
        output_dir=args.output_dir,
        label=args.label,
        include_all_refs=args.all_refs,
        overwrite=args.overwrite,
    )
    print_json(bundle)
    return 0 if bundle["status"] == "allow" else 1


def cmd_shareability_receiver_trial(args: argparse.Namespace) -> int:
    source_state = JsonStore(args.source_store).load()
    source_bundle = (source_state.get("shareability_bundles") or {}).get(args.shareability_bundle_id)
    if not source_bundle:
        raise SystemExit(f"missing shareability bundle: {args.shareability_bundle_id}")
    trial = ShareabilityReceiverTrialStore(JsonStore(args.store)).create(
        source_bundle=source_bundle,
        receiver_root=args.receiver_root,
        label=args.label,
        run_python_compile=args.run_python_compile,
        focused_tests=args.focused_test or [],
    )
    print_json(trial)
    return 0 if trial["status"] == "allow" else 1


def cmd_dispatch_run(args: argparse.Namespace) -> int:
    result = dispatch(JsonStore(args.store), args.task_run_id)
    print_json(result)
    return 0 if result["dispatched"] else 1


def cmd_provider_result(args: argparse.Namespace) -> int:
    token_usage = load_json(args.token_usage_file) if args.token_usage_file else {}
    result = ProviderResultStore(JsonStore(args.store)).ingest(
        args.task_run_id,
        status=args.status,
        output_refs=args.output_ref or [],
        token_usage=token_usage,
        provider_msg_refs=args.provider_msg_ref or [],
        source_class=args.source_class,
    )
    print_json(result)
    return 0 if args.status == "ok" else 1


def cmd_evaluate_run(args: argparse.Namespace) -> int:
    result = PredicateStore(JsonStore(args.store)).evaluate_run(args.task_run_id)
    print_json(result)
    return 0 if result["passed"] else 1


def cmd_outbox_create(args: argparse.Namespace) -> int:
    payload = load_json(args.payload_file) if args.payload_file else {}
    item = OutboxStore(JsonStore(args.store)).create_item(
        args.task_run_id,
        target=args.target,
        channel_id=args.channel_id,
        endpoint=args.endpoint,
        method=args.method,
        payload=payload,
        admission_review_id=args.admission_review_id,
        idempotency_key=args.idempotency_key,
    )
    print_json(item)
    return 0


def cmd_outbox_receipt(args: argparse.Namespace) -> int:
    response_payload = load_json(args.response_file) if args.response_file else {}
    receipt = OutboxStore(JsonStore(args.store)).record_receipt(
        args.outbox_id,
        status=args.status,
        response_payload=response_payload,
        readback_ref=args.readback_ref,
        reason_codes=args.reason_code or [],
    )
    print_json(receipt)
    return 0


def cmd_surface_promise_create(args: argparse.Namespace) -> int:
    promised_surfaces = load_json(args.promise_file) if args.promise_file else [
        {
            "surface": args.surface,
            "target": args.target,
            "channel_id": args.channel_id,
            "outbox_id": args.outbox_id,
            "required": args.required,
            "required_readback": args.required_readback,
        }
    ]
    if not isinstance(promised_surfaces, list):
        raise SystemExit("promise file must contain a JSON array")
    promise = SurfacePromiseStore(JsonStore(args.store)).create(
        args.task_run_id,
        promised_surfaces=promised_surfaces,
        source_packet_ref=args.source_packet_ref,
        promise_reason=args.promise_reason,
    )
    print_json(promise)
    return 0 if promise["surface_delivery_status"] in {
        "delivered_and_readback_verified",
        "not_required_by_packet",
        "blocked_with_reason_and_deferred",
    } else 1


def cmd_surface_promise_check(args: argparse.Namespace) -> int:
    promise = SurfacePromiseStore(JsonStore(args.store)).check(args.surface_promise_id)
    print_json(promise)
    return 0 if promise["surface_delivery_status"] in {
        "delivered_and_readback_verified",
        "not_required_by_packet",
        "blocked_with_reason_and_deferred",
    } else 1


def cmd_simulate_dual(args: argparse.Namespace) -> int:
    raw = load_json(args.event_file)
    result = run_dual_agent_simulation(raw, JsonStore(args.store))
    print_json(result)
    return 0 if result["replay"]["ok"] else 1


def cmd_simulate_full(args: argparse.Namespace) -> int:
    raw = load_json(args.event_file)
    result = run_full_simulation(
        raw,
        JsonStore(args.store),
        blast_radius_ensure_graph=args.full_blast_radius_graph,
    )
    print_json(result)
    return 0 if result["replay"]["ok"] and result["final_state"] == "completed" else 1


def cmd_simulate_incident(args: argparse.Namespace) -> int:
    raw = load_json(args.event_file)
    result = run_incident_simulation(
        raw,
        JsonStore(args.store),
        blast_radius_ensure_graph=args.full_blast_radius_graph,
    )
    print_json(result)
    return 0 if result["replay"]["ok"] and result["final_state"] == "blocked" else 1


def cmd_storage_probe(args: argparse.Namespace) -> int:
    result = run_storage_probe(
        iterations=args.iterations,
        payload_bytes=args.payload_bytes,
        directory=args.output_dir,
    )
    print_json(result)
    return 0


def cmd_close_epoch(args: argparse.Namespace) -> int:
    result = EpochCloser(JsonStore(args.store)).close(label=args.label)
    print_json(result)
    return 0 if result["closed"] else 1


def cmd_console(args: argparse.Namespace) -> int:
    report = build_console_report(JsonStore(args.store))
    if args.output:
        path = write_console(report, args.output, fmt=args.format)
        print_json({"output": str(path), "replay_ok": bool((report.get("replay") or {}).get("ok"))})
    else:
        rendered = render_html(report) if args.format == "html" else render_text(report)
        print(rendered, end="")
    return 0 if (report.get("replay") or {}).get("ok") else 1


def cmd_self_eval(args: argparse.Namespace) -> int:
    result = run_self_eval(cases=args.cases)
    print_json(result)
    metrics = result["metrics"]
    return 0 if result["predicate_audit"]["audited"] and metrics["ams_silent_failures"] == 0 else 1


def cmd_verify_policy(args: argparse.Namespace) -> int:
    config = SignedPolicyConfig(
        allowed_signers_path=Path(args.allowed_signers_file),
        signer_identity=args.signer_identity,
        pinned_fingerprints=tuple(args.pinned_fingerprint or []),
        namespace=args.namespace,
    )
    result = verify_signed_policy(args.policy_file, args.signature_file, config)
    print_json(result)
    return 0 if result["allowed"] else 1


def cmd_install_definitions(args: argparse.Namespace) -> int:
    result = DefinitionRegistryStore(JsonStore(args.store)).install_defaults()
    print_json(result)
    return 0


def cmd_registry_status(args: argparse.Namespace) -> int:
    result = DefinitionRegistryStore(JsonStore(args.store)).status()
    print_json(result)
    return 0


def cmd_surface_declare(args: argparse.Namespace) -> int:
    surface = SurfaceBindingStore(JsonStore(args.store)).declare_surface(
        provider=args.provider,
        surface=args.surface,
        runtime_name=args.runtime_name,
        transport=args.transport,
        endpoint=args.endpoint,
        binding_kind=args.binding_kind,
        rollout_mode=args.rollout_mode,
        status=args.status,
        process_owner=args.process_owner,
        capability_tier=args.capability_tier,
        resource_profile_id=args.resource_profile_id,
        workspace_roots=args.workspace_root,
        egress_modes=args.egress_mode,
        session_semantics=args.session_semantics,
        inject_allowed=args.inject_allowed,
        approval_id=args.approval_id,
        package_manifest_sha256=args.package_manifest_sha256,
    )
    print_json(surface)
    return 0


def cmd_surface_bind(args: argparse.Namespace) -> int:
    binding = SurfaceBindingStore(JsonStore(args.store)).bind_surface(
        runtime_surface_id=args.runtime_surface_id,
        session_id=args.session_id,
        provider_session_id=args.provider_session_id,
        task_run_id=args.task_run_id,
        binding_role=args.binding_role,
        status=args.status,
    )
    print_json(binding)
    return 0


def cmd_surface_status(args: argparse.Namespace) -> int:
    result = SurfaceBindingStore(JsonStore(args.store)).status()
    print_json(result)
    return 0


def cmd_build_package_manifest(args: argparse.Namespace) -> int:
    result = write_package_manifest(JsonStore(args.store), args.output)
    print_json(result)
    return 0


def cmd_verify_package(args: argparse.Namespace) -> int:
    config = SignedPolicyConfig(
        allowed_signers_path=Path(args.allowed_signers_file),
        signer_identity=args.signer_identity,
        pinned_fingerprints=tuple(args.pinned_fingerprint or []),
        namespace=args.namespace,
    )
    result = verify_package_manifest(
        args.manifest_file,
        args.signature_file,
        config,
        store=JsonStore(args.store),
    )
    print_json(result)
    return 0 if result["allowed"] else 1


def cmd_runner_preflight(args: argparse.Namespace) -> int:
    envelope = load_json(args.envelope_file)
    result = runner_preflight(
        envelope,
        JsonStore(args.store),
        live=args.live,
        shadow_launch_plan_id=args.shadow_launch_plan_id,
        shadow_launch_plan_sha256=args.shadow_launch_plan_sha256,
    )
    print_json(result)
    return 0 if result["allowed"] else 1


def cmd_runner_dry_run_parity(args: argparse.Namespace) -> int:
    runner_preflight_result = load_json(args.runner_preflight_file) if args.runner_preflight_file else None
    result = RunnerDryRunParityStore(JsonStore(args.store)).create(
        envelope=load_json(args.envelope_file),
        package_verification=load_json(args.package_verification_file),
        package_manifest=load_json(args.package_manifest_file),
        runner_preflight_result=runner_preflight_result,
        live=not args.dry_run,
        shadow_launch_plan_id=args.shadow_launch_plan_id,
        shadow_launch_plan_sha256=args.shadow_launch_plan_sha256,
    )
    print_json(result)
    return 0 if result["status"] == "ready_for_operator_review" else 1


def cmd_install_preflight(args: argparse.Namespace) -> int:
    result = run_install_preflight(
        store_path=args.store,
        package_manifest_path=args.package_manifest,
        expected_agent_user=args.expected_agent_user,
    )
    print_json(result)
    return 0 if result["ready_for_live"] else 1


def cmd_shadow_readiness(args: argparse.Namespace) -> int:
    install_preflight = load_json(args.install_preflight_file)
    package_verification = load_json(args.package_verification_file)
    result = evaluate_shadow_readiness(
        install_preflight=install_preflight,
        package_verification=package_verification,
        approval_id=args.approval_id,
        egress_mode=args.egress_mode,
    )
    print_json(result)
    return 0 if result["allowed"] else 1


def cmd_shadow_launch_plan(args: argparse.Namespace) -> int:
    install_preflight = load_json(args.install_preflight_file)
    package_verification = load_json(args.package_verification_file)
    result = ShadowLaunchStore(JsonStore(args.store)).create_plan(
        install_preflight=install_preflight,
        package_verification=package_verification,
        approval_id=args.approval_id,
        egress_mode=args.egress_mode,
        runtime_surface_ids=args.runtime_surface_id or [],
        surface_binding_ids=args.surface_binding_id or [],
        surface_promise_ids=args.surface_promise_id or [],
        source_refs={
            "install_preflight_file": str(Path(args.install_preflight_file).expanduser().resolve(strict=False)),
            "package_verification_file": str(Path(args.package_verification_file).expanduser().resolve(strict=False)),
        },
    )
    print_json(result)
    return 0 if result["ready_to_launch"] else 1


def cmd_shadow_runner_transaction(args: argparse.Namespace) -> int:
    runner_preflight = load_json(args.runner_preflight_file)
    result = ShadowRunnerStore(JsonStore(args.store)).create_transaction(
        runner_preflight=runner_preflight,
        argv=args.argv or [],
        cwd=args.cwd,
        requested_by=args.requested_by,
        approval_id=args.approval_id,
        purpose=args.purpose,
        env_names=args.env_name or [],
        redacted_env_names=args.redacted_env_name or [],
        abort_conditions=args.abort_condition or [],
        rollback_steps=args.rollback_step or [],
    )
    print_json(result)
    return 0 if result["ready_for_operator_review"] else 1


def cmd_shadow_approval_packet(args: argparse.Namespace) -> int:
    result = ShadowApprovalPacketStore(JsonStore(args.store)).create(
        shadow_launch_plan_id=args.shadow_launch_plan_id,
        shadow_runner_transaction_id=args.shadow_runner_transaction_id,
        runner_dry_run_parity_id=args.runner_dry_run_parity_id,
        store_backup_drill_id=args.store_backup_drill_id,
        requested_by=args.requested_by,
        readback_ref=args.readback_ref,
        readback_text=args.readback_text,
    )
    print_json(result)
    return 0 if result["status"] == "ready_for_operator_approval" else 1


def cmd_attention_signal_ingest(args: argparse.Namespace) -> int:
    raw = load_json(args.signal_file)
    result = AttentionRouterStore(JsonStore(args.store)).ingest(raw)
    print_json(result)
    return 0 if result["route_status"] != "ignored" else 1


def cmd_discord_source_packet(args: argparse.Namespace) -> int:
    raw = load_json(args.packet_file)
    result = DiscordSourcePacketStore(JsonStore(args.store)).create(
        raw,
        create_attention_signal=args.create_attention_signal,
    )
    print_json(result)
    return 0 if result["status"] == "ready_for_attention" else 1


def cmd_discord_canary_send_plan(args: argparse.Namespace) -> int:
    result = DiscordCanarySendPlanStore(JsonStore(args.store)).create(
        outbox_id=args.outbox_id,
        admission_review_id=args.admission_review_id,
        surface_promise_id=args.surface_promise_id,
        discord_source_packet_id=args.discord_source_packet_id,
        operator_review_ref=args.operator_review_ref,
    )
    print_json(result)
    return 0 if result["status"] == "ready_for_operator_approval" else 1


def cmd_discord_canary_receipt(args: argparse.Namespace) -> int:
    response_payload = load_json(args.response_file)
    result = DiscordCanaryReceiptStore(JsonStore(args.store)).create(
        discord_canary_send_plan_id=args.discord_canary_send_plan_id,
        response_payload=response_payload,
        readback_ref=args.readback_ref,
        observed_nonce=args.observed_nonce,
        observation_mode=args.observation_mode,
    )
    print_json(result)
    return 0 if result["status"] == "recorded" else 1


def cmd_terminal_source_packet(args: argparse.Namespace) -> int:
    raw_packet = load_json(args.packet_file)
    result = TerminalSourcePacketStore(JsonStore(args.store)).create(
        raw_packet,
        create_attention_signal=args.create_attention_signal,
    )
    print_json(result)
    return 0 if result["status"] == "ready_for_attention" else 1


def cmd_conformance_pack(args: argparse.Namespace) -> int:
    result = ConformancePackStore(JsonStore(args.store)).create(
        repo_root=args.repo_root,
        evidence_root=args.evidence_root,
        target_milestone=args.target_milestone,
        label=args.label,
        check_store_paths=args.check_store or [],
        command_specs=args.command or [],
        command_timeout_seconds=args.command_timeout_seconds,
        include_python_compile=not args.skip_python_compile,
    )
    print_json(result)
    return 0 if result["status"] == "passed" else 1


def cmd_markdown_audit(args: argparse.Namespace) -> int:
    if args.session_window_days < 1:
        print("--session-window-days must be >= 1", file=sys.stderr)
        return 2
    result = MarkdownAuditStore(JsonStore(args.store)).create(
        source_root=args.source_root,
        label=args.label,
        include_local_session_metadata=args.include_local_session_metadata,
        session_window_days=args.session_window_days,
    )
    print_json(result)
    return 0 if result["status"] == "allow" else 1


def cmd_readiness_review(args: argparse.Namespace) -> int:
    if args.session_window_days < 1:
        print("--session-window-days must be >= 1", file=sys.stderr)
        return 2
    result = ReadinessReviewStore(JsonStore(args.store)).create(
        source_root=args.source_root,
        label=args.label,
        include_local_session_metadata=args.include_local_session_metadata,
        session_window_days=args.session_window_days,
    )
    print_json(result)
    return 0 if result["status"] == "allow" else 1


def cmd_doc_retirement_plan(args: argparse.Namespace) -> int:
    if args.session_window_days < 1:
        print("--session-window-days must be >= 1", file=sys.stderr)
        return 2
    result = DocRetirementPlanStore(JsonStore(args.store)).create(
        source_root=args.source_root,
        label=args.label,
        include_local_session_metadata=args.include_local_session_metadata,
        session_window_days=args.session_window_days,
    )
    print_json(result)
    return 0 if result["status"] == "allow" else 1


def cmd_doc_action_execution_plan(args: argparse.Namespace) -> int:
    if args.session_window_days < 1:
        print("--session-window-days must be >= 1", file=sys.stderr)
        return 2
    if args.max_actions < 1:
        print("--max-actions must be >= 1", file=sys.stderr)
        return 2
    result = DocActionExecutionPlanStore(JsonStore(args.store)).create(
        source_root=args.source_root,
        label=args.label,
        include_local_session_metadata=args.include_local_session_metadata,
        session_window_days=args.session_window_days,
        max_actions=args.max_actions,
        action_kinds=args.action_kind or [],
    )
    print_json(result)
    return 0 if result["status"] in {"allow", "defer"} else 1


def cmd_doc_action_operator_approval(args: argparse.Namespace) -> int:
    result = DocActionOperatorApprovalPacketStore(JsonStore(args.store)).create(
        doc_action_execution_plan_id=args.doc_action_execution_plan_id,
        source_root=args.source_root,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "ready_for_operator_review" else 1


def cmd_doc_action_patch_preview(args: argparse.Namespace) -> int:
    result = DocActionPatchPreviewStore(JsonStore(args.store)).create(
        doc_action_operator_approval_packet_id=args.doc_action_operator_approval_packet_id,
        source_root=args.source_root,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "ready_for_review" else 1


def cmd_doc_action_patch_readback(args: argparse.Namespace) -> int:
    readback_text = (
        Path(args.readback_file).read_text(encoding="utf-8")
        if args.readback_file else args.readback_text
    )
    result = DocActionPatchReadbackReceiptStore(JsonStore(args.store)).create(
        doc_action_patch_preview_id=args.doc_action_patch_preview_id,
        readback_ref=args.readback_ref,
        readback_text=readback_text or "",
        requested_by=args.requested_by,
        source_root=args.source_root,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "readback_verified" else 1


def cmd_doc_action_patch_artifact(args: argparse.Namespace) -> int:
    result = DocActionPatchArtifactReceiptStore(JsonStore(args.store)).create(
        doc_action_patch_readback_receipt_id=args.doc_action_patch_readback_receipt_id,
        source_root=args.source_root,
        artifact_root=args.artifact_root,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "artifact_ready" else 1


def cmd_doc_action_patch_artifact_approval(args: argparse.Namespace) -> int:
    result = DocActionPatchArtifactApprovalPacketStore(JsonStore(args.store)).create(
        doc_action_patch_artifact_receipt_id=args.doc_action_patch_artifact_receipt_id,
        artifact_action_id=args.artifact_action_id,
        source_root=args.source_root,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "ready_for_operator_review" else 1


def cmd_doc_action_patch_dry_run_plan(args: argparse.Namespace) -> int:
    result = DocActionPatchDryRunPlanStore(JsonStore(args.store)).create(
        doc_action_patch_artifact_approval_packet_id=args.doc_action_patch_artifact_approval_packet_id,
        source_root=args.source_root,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "dry_run_ready" else 1


def cmd_doc_action_patch_dry_run_readback(args: argparse.Namespace) -> int:
    readback_text = (
        Path(args.readback_file).read_text(encoding="utf-8")
        if args.readback_file else args.readback_text
    )
    result = DocActionPatchDryRunReadbackReceiptStore(JsonStore(args.store)).create(
        doc_action_patch_dry_run_plan_id=args.doc_action_patch_dry_run_plan_id,
        readback_ref=args.readback_ref,
        readback_text=readback_text or "",
        requested_by=args.requested_by,
        source_root=args.source_root,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "readback_verified" else 1


def cmd_doc_action_patch_live_execution_approval(args: argparse.Namespace) -> int:
    approval_text = (
        Path(args.approval_file).read_text(encoding="utf-8")
        if args.approval_file else args.approval_text
    )
    result = DocActionPatchLiveExecutionApprovalPacketStore(JsonStore(args.store)).create(
        doc_action_patch_dry_run_readback_receipt_id=args.doc_action_patch_dry_run_readback_receipt_id,
        approval_ref=args.approval_ref,
        approval_text=approval_text or "",
        requested_by=args.requested_by,
        source_root=args.source_root,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "approved_for_executor_review" else 1


def cmd_doc_action_patch_executor_preflight(args: argparse.Namespace) -> int:
    result = DocActionPatchExecutorPreflightStore(JsonStore(args.store)).create(
        doc_action_patch_live_execution_approval_packet_id=args.doc_action_patch_live_execution_approval_packet_id,
        source_root=args.source_root,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "preflight_ready" else 1


def cmd_doc_action_patch_apply_boundary(args: argparse.Namespace) -> int:
    result = DocActionPatchApplyBoundaryPacketStore(JsonStore(args.store)).create(
        doc_action_patch_executor_preflight_id=args.doc_action_patch_executor_preflight_id,
        source_root=args.source_root,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "ready_for_operator_apply_acceptance" else 1


def cmd_doc_action_patch_apply_acceptance(args: argparse.Namespace) -> int:
    acceptance_text = (
        Path(args.acceptance_file).read_text(encoding="utf-8")
        if args.acceptance_file else args.acceptance_text
    )
    result = DocActionPatchApplyAcceptancePacketStore(JsonStore(args.store)).create(
        doc_action_patch_apply_boundary_packet_id=args.doc_action_patch_apply_boundary_packet_id,
        acceptance_ref=args.acceptance_ref,
        acceptance_text=acceptance_text or "",
        requested_by=args.requested_by,
        source_root=args.source_root,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "accepted_for_backup_preimage_review" else 1


def cmd_source_write_executor_preflight(args: argparse.Namespace) -> int:
    result = SourceWriteExecutorPreflightStore(JsonStore(args.store)).create(
        doc_action_patch_apply_acceptance_packet_id=args.doc_action_patch_apply_acceptance_packet_id,
        architecture_gate_review_id=args.architecture_gate_review_id,
        blast_radius_review_id=args.blast_radius_review_id,
        source_root=args.source_root,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "ready_for_backup_preimage_capture" else 1


def cmd_source_write_backup_preimage_receipt(args: argparse.Namespace) -> int:
    result = SourceWriteBackupPreimageReceiptStore(JsonStore(args.store)).create(
        source_write_executor_preflight_id=args.source_write_executor_preflight_id,
        source_root=args.source_root,
        backup_root=args.backup_root,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "backup_preimage_captured" else 1


def cmd_source_write_executor_lease(args: argparse.Namespace) -> int:
    result = SourceWriteExecutorLeaseStore(JsonStore(args.store)).create(
        source_write_backup_preimage_receipt_id=args.source_write_backup_preimage_receipt_id,
        source_root=args.source_root,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "ready_for_source_write_receipt" else 1


def cmd_generated_status_snapshot(args: argparse.Namespace) -> int:
    if args.session_window_days < 1:
        print("--session-window-days must be >= 1", file=sys.stderr)
        return 2
    result = GeneratedStatusSnapshotStore(JsonStore(args.store)).create(
        source_root=args.source_root,
        output_path=args.output_path,
        label=args.label,
        include_local_session_metadata=args.include_local_session_metadata,
        session_window_days=args.session_window_days,
        write_file=not args.no_write_file,
        allow_overwrite=args.allow_overwrite,
    )
    print_json(result)
    return 0 if result["status"] == "allow" else 1


def cmd_session_start_brief(args: argparse.Namespace) -> int:
    result = SessionStartBriefStore(JsonStore(args.store)).create(
        source_root=args.source_root,
        output_path=args.output_path,
        label=args.label,
        write_file=not args.no_write_file,
        allow_overwrite=args.allow_overwrite,
    )
    print_json(result)
    return 0 if result["status"] == "allow" else 1


def cmd_markdown_authority_index(args: argparse.Namespace) -> int:
    try:
        supersession_edges = [parse_supersession_edge(value) for value in args.supersedes]
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    result = MarkdownAuthorityStore(JsonStore(args.store)).create(
        source_root=args.source_root,
        label=args.label,
        supersession_edges=supersession_edges,
    )
    print_json(result)
    return 0 if result["index"]["status"] == "allow" else 1


def cmd_work_mode_decision(args: argparse.Namespace) -> int:
    request_text = None
    if args.request_file:
        request_text = Path(args.request_file).read_text(encoding="utf-8")
    result = WorkModeDecisionStore(JsonStore(args.store)).create(
        request_text=request_text,
        request_ref=args.request_ref,
        changed_paths=args.changed_path,
        source_root=args.source_root,
        label=args.label,
        source_surface=args.source_surface,
        session_id=args.session_id,
    )
    print_json(result)
    return 0 if result["status"] == "allow" else 1


def cmd_simulation_sweep(args: argparse.Namespace) -> int:
    result = SimulationSweepStore(JsonStore(args.store)).create(
        source_root=args.source_root,
        simulation_area=args.simulation_area,
        scenario_count=args.scenarios,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "allow" else 1


def cmd_ams_emulation_trial(args: argparse.Namespace) -> int:
    result = AmsEmulationTrialStore(JsonStore(args.store)).create(
        source_root=args.source_root,
        emulation_area=args.emulation_area,
        scenario_count=args.scenarios,
        label=args.label,
        timeout_seconds=args.timeout_seconds,
        allow_external_agents=args.allow_external_agents,
        agent_command_file=args.agent_command_file,
    )
    print_json(result)
    return 0 if result["metrics"]["failed_invocations"] == 0 and result["metrics"]["live_boundary_leak_count"] == 0 else 1


def cmd_semantic_oracle_review(args: argparse.Namespace) -> int:
    result = SemanticOracleReviewStore(JsonStore(args.store)).create(
        simulation_sweep_id=args.simulation_sweep_id,
        source_root=args.source_root,
        output_path=args.output_path,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "allow" else 1


def cmd_semantic_hook_run(args: argparse.Namespace) -> int:
    result = SemanticHookRunStore(JsonStore(args.store)).create(
        semantic_oracle_review_id=args.semantic_oracle_review_id,
        source_root=args.source_root,
        label=args.label,
        runner_mode=args.runner_mode,
    )
    print_json(result)
    return 0 if result["status"] == "allow" else 1


def cmd_semantic_hook_install_plan(args: argparse.Namespace) -> int:
    result = SemanticHookInstallPlanStore(JsonStore(args.store)).create(
        semantic_hook_run_id=args.semantic_hook_run_id,
        source_root=args.source_root,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "ready_for_operator_review" else 1


def cmd_semantic_hook_approval_binding(args: argparse.Namespace) -> int:
    package_verification = load_json(args.package_verification_file) if args.package_verification_file else None
    package_manifest = load_json(args.package_manifest_file) if args.package_manifest_file else None
    readback_text = (
        Path(args.operator_readback_file).read_text(encoding="utf-8")
        if args.operator_readback_file else args.operator_readback_text
    )
    result = SemanticHookApprovalBindingStore(JsonStore(args.store)).create(
        semantic_hook_install_plan_id=args.semantic_hook_install_plan_id,
        source_root=args.source_root,
        package_verification=package_verification,
        package_manifest=package_manifest,
        rollback_proof_ref=args.rollback_proof_ref,
        rollback_proof_sha256=args.rollback_proof_sha256,
        rollback_preflight_passed=args.rollback_preflight_passed,
        operator_readback_ref=args.operator_readback_ref,
        operator_readback_text=readback_text or "",
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "ready_for_operator_approval" else 1


def cmd_semantic_hook_target_snapshot(args: argparse.Namespace) -> int:
    result = SemanticHookTargetSnapshotStore(JsonStore(args.store)).create(
        semantic_hook_approval_binding_id=args.semantic_hook_approval_binding_id,
        source_root=args.source_root,
        home_root=args.home_root,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "ready_for_operator_review" else 1


def cmd_semantic_hook_install_transaction(args: argparse.Namespace) -> int:
    result = SemanticHookInstallTransactionStore(JsonStore(args.store)).create(
        semantic_hook_target_snapshot_id=args.semantic_hook_target_snapshot_id,
        source_root=args.source_root,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "ready_for_operator_review" else 1


def cmd_semantic_hook_operator_approval(args: argparse.Namespace) -> int:
    result = SemanticHookOperatorApprovalPacketStore(JsonStore(args.store)).create(
        semantic_hook_install_transaction_id=args.semantic_hook_install_transaction_id,
        source_root=args.source_root,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "ready_for_operator_review" else 1


def cmd_semantic_hook_operator_readback(args: argparse.Namespace) -> int:
    readback_text = (
        Path(args.readback_file).read_text(encoding="utf-8")
        if args.readback_file else args.readback_text
    )
    result = SemanticHookOperatorReadbackReceiptStore(JsonStore(args.store)).create(
        semantic_hook_operator_approval_packet_id=args.semantic_hook_operator_approval_packet_id,
        readback_ref=args.readback_ref,
        readback_text=readback_text or "",
        requested_by=args.requested_by,
        source_root=args.source_root,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "readback_verified" else 1


def cmd_manager_intervention_evaluate(args: argparse.Namespace) -> int:
    targets = [parse_target_agent(value) for value in args.target_agent or []] or None
    result = ManagerInterventionStore(JsonStore(args.store)).evaluate(
        target_agents=targets,
        session_id=args.session_id,
        task_run_id=args.task_run_id,
        include_resolved=args.include_resolved,
        max_signals=args.max_signals,
    )
    print_json(result)
    return 0


def cmd_manager_intervention_attach_delivery(args: argparse.Namespace) -> int:
    targets = [parse_target_agent(value) for value in args.target_agent or []] or None
    record = ManagerInterventionDeliveryStore(JsonStore(args.store)).attach(
        args.manager_intervention_id,
        target_agents=targets,
        surface=args.surface,
        target=args.target,
        channel_id=args.channel_id,
        endpoint=args.endpoint,
        admission_review_id=args.admission_review_id,
        promise_reason=args.promise_reason,
        idempotency_key=args.idempotency_key,
    )
    print_json(record)
    return 0


def cmd_manager_intervention_settle(args: argparse.Namespace) -> int:
    record = ManagerInterventionSettlementStore(JsonStore(args.store)).settle(
        args.manager_intervention_id,
        target_agent=parse_target_agent(args.target_agent),
        ack_status=args.ack_status,
        readback_ref=args.readback_ref,
        readback_summary=args.readback_summary,
        source_refs_used=args.source_ref_used or [],
        priority_decision=args.priority_decision,
        deferred_signal_ids=args.deferred_signal_id or [],
        priority_reason=args.priority_reason,
        next_domain=args.next_domain,
        crosses_domains=args.crosses_domains,
        domain_reason=args.domain_reason,
        idempotency_key=args.idempotency_key,
    )
    print_json(record)
    return 0 if record["settlement_status"] == "accepted" else 1


def cmd_architecture_audit(args: argparse.Namespace) -> int:
    result = ArchitectureAuditStore(JsonStore(args.store)).create(
        source_root=args.source_root,
        package_name=args.package_name,
    )
    print_json(result)
    return 0 if result["status"] != "deny" else 1


def cmd_architecture_gate_review(args: argparse.Namespace) -> int:
    result = ArchitectureGateStore(JsonStore(args.store)).create(
        subject_kind=args.subject_kind,
        subject_id=args.subject_id,
        paths=args.path or [],
        architecture_audit_id=args.architecture_audit_id,
    )
    print_json(result)
    return 0 if result["decision"] != "deny" else 1


def cmd_codebase_spider_graph(args: argparse.Namespace) -> int:
    result = CodebaseSpiderGraphStore(JsonStore(args.store)).create(
        source_root=args.source_root,
        package_name=args.package_name,
        label=args.label,
        architecture_audit_id=args.architecture_audit_id,
    )
    if args.full_output:
        print_json(result)
    else:
        snapshot = dict(result["snapshot"])
        snapshot.pop("node_refs", None)
        snapshot.pop("edge_refs", None)
        print_json(
            {
                "snapshot": snapshot,
                "created": {
                    "codebase_graph_nodes": len(result["nodes"]),
                    "codebase_graph_edges": len(result["edges"]),
                    "architecture_audit_id": result["architecture_audit"]["architecture_audit_id"],
                    "architecture_audit_sha256": result["architecture_audit"]["architecture_audit_sha256"],
                },
            }
        )
    return 0 if result["snapshot"]["status"] == "allow" else 1


def cmd_codebase_graph_query(args: argparse.Namespace) -> int:
    result = CodebaseGraphQueryStore(JsonStore(args.store)).create(
        source_root=args.source_root,
        query_kind=args.query_kind,
        paths=args.path or [],
        depth=args.depth,
        snapshot_id=args.snapshot_id,
        label=args.label,
    )
    print_json(result)
    return 0 if result["status"] == "allow" else 1


def cmd_blast_radius_review(args: argparse.Namespace) -> int:
    result = BlastRadiusReviewStore(JsonStore(args.store)).create(
        source_root=args.source_root,
        subject_kind=args.subject_kind,
        subject_id=args.subject_id,
        paths=args.path or [],
        change_intent=args.change_intent,
        package_name=args.package_name,
        graph_snapshot_id=args.graph_snapshot_id,
        ensure_graph=args.ensure_graph,
        depth=args.depth,
        max_impact_paths=args.max_impact_paths,
        label=args.label,
    )
    print_json(result)
    return 0 if result["decision"] == "allow" else 1


def cmd_rag_index_plan(args: argparse.Namespace) -> int:
    result = RAGIndexPlanStore(JsonStore(args.store)).create(
        source_root=args.source_root,
        collection=args.collection,
        allowed_globs=args.include_glob,
        denied_globs=args.exclude_glob,
        max_file_bytes=args.max_file_bytes,
        max_total_bytes=args.max_total_bytes,
        chunk_chars=args.chunk_chars,
        embedding_provider=args.embedding_provider,
        embedding_model=args.embedding_model,
        embedding_dimensions=args.embedding_dimensions,
        vector_store_provider=args.vector_store_provider,
    )
    print_json(result)
    return 0


def cmd_downloaded_artifact_quarantine(args: argparse.Namespace) -> int:
    result = DownloadedArtifactQuarantineStore(JsonStore(args.store)).create(
        source_uri=args.source_uri,
        source_type=args.source_type,
        declared_media_type=args.declared_media_type,
        declared_sha256=args.declared_sha256,
        size_bytes=args.size_bytes,
        download_status=args.download_status,
        quarantine_status=args.quarantine_status,
        local_path=args.local_path,
        reviewed_by=args.reviewed_by,
        reviewed_at=args.reviewed_at,
        reason_codes=args.reason_code or None,
    )
    print_json(result)
    return 0 if result["quarantine_status"] != "rejected" else 1


def cmd_rag_embedding_job(args: argparse.Namespace) -> int:
    result = RAGEmbeddingJobStore(JsonStore(args.store)).create(
        rag_index_plan_id=args.rag_index_plan_id,
        capability_admission_review_id=args.capability_admission_review_id,
        resource_admission_review_id=args.resource_admission_review_id,
        downloaded_artifact_quarantine_ids=args.downloaded_artifact_quarantine_id or [],
        batch_size=args.batch_size,
        idempotency_key=args.idempotency_key,
    )
    print_json(result)
    return 0 if result["status"] == "ready_for_operator_review" else 1


def cmd_provider_auth_preflight(args: argparse.Namespace) -> int:
    result = ProviderAuthPreflightStore(JsonStore(args.store)).create(
        subject_kind=args.subject_kind,
        subject_id=args.subject_id,
        provider=args.provider,
        operation=args.operation,
        surface=args.surface,
        model=args.model,
        auth_mode=args.auth_mode,
        required_env_names=args.required_env_name,
        present_env_names=args.present_env_name,
    )
    print_json(result)
    return 0 if result["status"] == "ready" else 1


def cmd_rag_embedding_receipt(args: argparse.Namespace) -> int:
    result = RAGEmbeddingReceiptStore(JsonStore(args.store)).create(
        rag_embedding_job_id=args.rag_embedding_job_id,
        provider_auth_preflight_id=args.provider_auth_preflight_id,
        receipt_mode=args.receipt_mode,
        external_vector_store_ref=args.external_vector_store_ref,
    )
    print_json(result)
    return 0 if result["status"] == "recorded" else 1


def cmd_rag_retrieval_query(args: argparse.Namespace) -> int:
    result = RAGRetrievalQueryStore(JsonStore(args.store)).create(
        rag_embedding_receipt_id=args.rag_embedding_receipt_id,
        query_sha256=args.query_sha256,
        query_length=args.query_length,
        query_ref=args.query_ref,
        retrieval_mode=args.retrieval_mode,
        top_k=args.top_k,
        taint_labels=args.taint_label,
    )
    print_json(result)
    return 0 if result["status"] == "ready_for_operator_review" else 1


def cmd_rag_local_vector_trial(args: argparse.Namespace) -> int:
    result = RAGLocalVectorTrialStore(JsonStore(args.store)).create(
        rag_index_plan_id=args.rag_index_plan_id,
        query_text=args.query_text,
        label=args.label,
        top_k=args.top_k,
        taint_labels=args.taint_label,
    )
    print_json(result)
    return 0 if result["status"] == "allow" else 1


def cmd_memory_promotion_review(args: argparse.Namespace) -> int:
    result = MemorySupersessionStore(JsonStore(args.store)).create_review(
        domain=args.domain,
        subject=args.subject,
        predicate=args.predicate,
        value_sha256=args.value_sha256,
        source_ref=args.source_ref,
        source_kind=args.source_kind,
        scope=args.scope,
        value_ref=args.value_ref,
        value_summary=args.value_summary,
        trust_class=args.trust_class,
        valid_from=args.valid_from,
        valid_until=args.valid_until,
        supersedes_claim_id=args.supersedes_claim_id,
        supersession_mode=args.supersession_mode,
        operator_confirmed=args.operator_confirmed,
        operator_confirmation_ref=args.operator_confirmation_ref,
        operator_confirmation_sha256=args.operator_confirmation_sha256,
        label=args.label,
    )
    print_json(result)
    return 0 if result["review"]["status"] in {"promoted", "duplicate", "needs_operator"} else 1


def cmd_backup_restore_drill(args: argparse.Namespace) -> int:
    result = StoreBackupDrillStore(JsonStore(args.store)).create(
        backup_path=args.backup_path,
        restore_path=args.restore_path,
        label=args.label,
        overwrite=args.force,
    )
    print_json(result)
    return 0 if result["status"] == "passed" else 1


def cmd_agent_sim_init(args: argparse.Namespace) -> int:
    result = init_agent_sim_runtime(args.runtime_root, create_venvs=args.create_venvs)
    print_json(result)
    return 0


def cmd_agent_sim_run(args: argparse.Namespace) -> int:
    result = run_default_agent_memory_trial(
        JsonStore(args.store),
        runtime_root=args.runtime_root,
        create_venvs=args.create_venvs,
        trial_label=args.trial_label,
    )
    print_json(result)
    return 0 if result["metrics"]["total_ams_forget_count"] == 0 else 1


def cmd_real_agent_smoke(args: argparse.Namespace) -> int:
    result = run_real_agent_smoke_trial(
        JsonStore(args.store),
        runtime_root=args.runtime_root,
        approval_id=args.approval_id,
        timeout_seconds=args.timeout_seconds,
    )
    print_json(result)
    return 0 if result["metrics"]["nonzero_invocations"] == 0 and result["metrics"]["timed_out_invocations"] == 0 else 1


def cmd_real_agent_system_trial(args: argparse.Namespace) -> int:
    result = RealAgentSystemTrialStore(JsonStore(args.store)).create(
        source_root=args.source_root,
        runtime_root=args.runtime_root,
        label=args.label,
        timeout_seconds=args.timeout_seconds,
        allow_real_agents=args.allow_real_agents,
    )
    print_json(result)
    metrics = result.get("metrics") or {}
    if result["status"] == "allow":
        return 0
    if (
        result.get("execution_mode") == "stubbed_runner"
        and metrics.get("nonzero_invocations") == 0
        and metrics.get("timed_out_invocations") == 0
        and metrics.get("parse_failure_count") == 0
        and metrics.get("ams_backed_pass_rate_delta", -1) >= 0
    ):
        return 0
    return 1


def cmd_export_trace(args: argparse.Namespace) -> int:
    for row in TraceExporter(JsonStore(args.store)).rows():
        print(json.dumps(row, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AMS/Codex local dry-run tools")
    parser.add_argument("--store", default=str(default_runtime_store()), help="path to local JSON store")
    parser.add_argument(
        "--fixture",
        action="store_true",
        help="allow --store inside the repo for tracked fixtures; runtime stores must live outside",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="initialize local store")
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func=cmd_init)

    p_ingest = sub.add_parser("ingest-event", help="ingest a Discord event envelope")
    p_ingest.add_argument("--event-file", required=True)
    p_ingest.add_argument("--context", action="store_true", help="also create an ATP context slice")
    p_ingest.set_defaults(func=cmd_ingest_event)

    p_checkpoint = sub.add_parser("checkpoint", help="write a summary checkpoint")
    p_checkpoint.add_argument("--session-id", required=True)
    p_checkpoint.add_argument("--trigger", default="manual")
    p_checkpoint.add_argument("--summary", required=True)
    p_checkpoint.add_argument("--next-action", required=True)
    p_checkpoint.add_argument("--decision", action="append")
    p_checkpoint.add_argument("--open-question", action="append")
    p_checkpoint.add_argument("--constraint", action="append")
    p_checkpoint.set_defaults(func=cmd_checkpoint)

    p_status = sub.add_parser("status", help="show local store status")
    p_status.set_defaults(func=cmd_status)

    p_codex = sub.add_parser("prepare-codex", help="build dry-run Codex app-server request")
    p_codex.add_argument("--session-id", required=True)
    p_codex.add_argument("--context-id")
    p_codex.add_argument("--model", default="gpt-5.5")
    p_codex.add_argument("--cwd", default=workspace_root())
    p_codex.add_argument("--sandbox", default="read-only")
    p_codex.add_argument("--active-turn-id")
    p_codex.add_argument("--bind-thread-id", help="bind a known/fake Codex thread id to the session")
    p_codex.add_argument("--resume-thread", action="store_true", help="build thread/resume envelope")
    p_codex.set_defaults(func=cmd_prepare_codex)

    p_claude = sub.add_parser("prepare-claude", help="build dry-run Claude Agent SDK request")
    p_claude.add_argument("--session-id", required=True)
    p_claude.add_argument("--context-id")
    p_claude.add_argument("--role", default="verifier")
    p_claude.add_argument("--bind-session-id", help="bind a known/fake Claude session id")
    p_claude.add_argument("--bind-agent-id", help="bind a known/fake Claude subagent id")
    p_claude.set_defaults(func=cmd_prepare_claude)

    p_gate = sub.add_parser("gate-check", help="run local shadow gate check")
    p_gate.add_argument("--tool", required=True)
    p_gate.add_argument("--endpoint")
    p_gate.add_argument("--method", default="READ")
    p_gate.add_argument("--payload-file")
    p_gate.add_argument("--channel-id")
    p_gate.add_argument("--requester", default="agent:agent_b")
    p_gate.add_argument("--host", default="example-host.local")
    p_gate.add_argument("--risk-flag", action="append")
    p_gate.set_defaults(func=cmd_gate_check)

    p_replay = sub.add_parser("replay-check", help="validate local store references and indexes")
    p_replay.set_defaults(func=cmd_replay_check)

    p_replay_oracle = sub.add_parser("replay-oracle", help="run in-memory delete/mutate replay fault oracle")
    p_replay_oracle.add_argument("--full-output", action="store_true")
    p_replay_oracle.add_argument("--exhaustive", action="store_true")
    p_replay_oracle.add_argument("--max-records-per-collection", type=int, default=5)
    p_replay_oracle.set_defaults(func=cmd_replay_oracle)

    p_run = sub.add_parser("create-run", help="create a local TaskRun record from a fresh context")
    p_run.add_argument("--session-id", required=True)
    p_run.add_argument("--context-id", required=True)
    p_run.add_argument("--actor", default="agent_b")
    p_run.add_argument("--requested-by", default="agent:agent_b")
    p_run.add_argument("--provider", default="openai_codex")
    p_run.add_argument("--provider-surface", default="app-server")
    p_run.add_argument("--action", default="dispatch")
    p_run.add_argument("--cwd", default=workspace_root())
    p_run.add_argument("--model")
    p_run.add_argument("--tool-scope", action="append")
    p_run.add_argument("--parent-run-id")
    p_run.add_argument("--attempt", type=int, default=1)
    p_run.add_argument("--retry-of")
    p_run.add_argument("--method", default="turn/start")
    p_run.add_argument("--sandbox", default="read-only")
    p_run.add_argument("--gate-mode", default="shadow_only")
    p_run.add_argument("--capability-snapshot-sha256")
    p_run.set_defaults(func=cmd_create_run)

    p_run_event = sub.add_parser("append-run-event", help="append a hash-chained RunTrace event")
    p_run_event.add_argument("--task-run-id", required=True)
    p_run_event.add_argument("--event-type", required=True)
    p_run_event.add_argument("--payload-file")
    p_run_event.add_argument("--token-usage-file")
    p_run_event.add_argument("--artifact-ref", action="append")
    p_run_event.add_argument("--reason-code", action="append")
    p_run_event.add_argument("--risk-flag", action="append")
    p_run_event.set_defaults(func=cmd_append_run_event)

    p_resource = sub.add_parser("resource-check", help="admission-check a TaskRun against resource policy")
    p_resource.add_argument("--task-run-id", required=True)
    p_resource.add_argument("--policy-file")
    p_resource.add_argument("--usage-file")
    p_resource.set_defaults(func=cmd_resource_check)

    p_cap = sub.add_parser("capability-check", help="check path/tool/egress capability policy")
    p_cap.add_argument("--actor", default="agent:agent_b")
    p_cap.add_argument("--tier", default="builder")
    p_cap.add_argument("--action", default="write")
    p_cap.add_argument("--path", action="append")
    p_cap.add_argument("--tool", action="append")
    p_cap.add_argument("--egress-mode", default="none")
    p_cap.add_argument("--change-request-id")
    p_cap.add_argument("--admission-review-id")
    p_cap.add_argument("--signed-policy-sha256")
    p_cap.add_argument("--architecture-gate-review-id")
    p_cap.add_argument("--architecture-audit-id")
    p_cap.add_argument("--architecture-audit-sha256")
    p_cap.add_argument("--blast-radius-review-id")
    p_cap.add_argument("--blast-radius-review-sha256")
    p_cap.add_argument("--policy-file")
    p_cap.set_defaults(func=cmd_capability_check)

    p_event = sub.add_parser("append-ams-event", help="append a local AMS event envelope")
    p_event.add_argument("--event-type", required=True)
    p_event.add_argument("--source", required=True)
    p_event.add_argument("--subject", required=True)
    p_event.add_argument("--data-file")
    p_event.add_argument("--session-id")
    p_event.add_argument("--task-run-id")
    p_event.add_argument("--trace-id")
    p_event.add_argument("--span-id")
    p_event.add_argument("--dataschema")
    p_event.add_argument("--parent-event-id")
    p_event.set_defaults(func=cmd_append_ams_event)

    p_adm = sub.add_parser("admission-review", help="create a generic local AdmissionReview")
    p_adm.add_argument("--subject-kind", required=True)
    p_adm.add_argument("--subject-id", required=True)
    p_adm.add_argument("--operation", required=True)
    p_adm.add_argument("--request-file")
    p_adm.add_argument("--verdict-file")
    p_adm.add_argument("--status", choices=["allow", "defer", "deny"])
    p_adm.add_argument("--reason-code", action="append")
    p_adm.add_argument("--policy-ref", action="append")
    p_adm.add_argument("--reviewer", default="ams.local")
    p_adm.add_argument("--ttl-seconds", type=int, default=900)
    p_adm.set_defaults(func=cmd_admission_review)

    p_claim = sub.add_parser("claim-resource", help="reserve resources for an allowed TaskRun")
    p_claim.add_argument("--task-run-id", required=True)
    p_claim.add_argument("--policy-file")
    p_claim.add_argument("--usage-file")
    p_claim.add_argument("--ttl-seconds", type=int, default=3600)
    p_claim.set_defaults(func=cmd_claim_resource)

    p_claim_update = sub.add_parser("update-resource-claim", help="transition a local resource claim")
    p_claim_update.add_argument("--resource-claim-id", required=True)
    p_claim_update.add_argument("--state", required=True, choices=["reserved", "active", "released", "expired"])
    p_claim_update.set_defaults(func=cmd_update_resource_claim)

    p_telemetry = sub.add_parser(
        "record-resource-telemetry",
        help="record local token/runtime/cost telemetry for a resource claim; no listener or provider polling",
    )
    p_telemetry.add_argument("--resource-claim-id", required=True)
    p_telemetry.add_argument("--provider-result-id")
    p_telemetry.add_argument(
        "--source-type",
        default="manual_local",
        choices=["manual_local", "provider_result_summary", "runner_summary", "synthetic"],
    )
    p_telemetry.add_argument("--source-ref-kind", default="manual")
    p_telemetry.add_argument("--source-ref", default="local://manual/resource-telemetry")
    p_telemetry.add_argument("--artifact-sha256")
    p_telemetry.add_argument("--input-tokens", type=int, default=0)
    p_telemetry.add_argument("--output-tokens", type=int, default=0)
    p_telemetry.add_argument("--runtime-ms", type=int, default=0)
    p_telemetry.add_argument("--cost-microusd", type=int, default=0)
    p_telemetry.add_argument("--cpu-core-ms", type=int, default=0)
    p_telemetry.add_argument("--peak-memory-mb", type=int, default=0)
    p_telemetry.add_argument("--peak-gpu-memory-mb", type=int, default=0)
    p_telemetry.add_argument("--network-bytes", type=int, default=0)
    p_telemetry.add_argument("--disk-read-bytes", type=int, default=0)
    p_telemetry.add_argument("--disk-write-bytes", type=int, default=0)
    p_telemetry.set_defaults(func=cmd_record_resource_telemetry)

    p_resource_enforcement = sub.add_parser(
        "resource-enforcement-trial",
        help="run an owned local subprocess under a timeout, write telemetry, and release its claim",
    )
    p_resource_enforcement.add_argument("--resource-claim-id", required=True)
    p_resource_enforcement.add_argument("--mode", choices=["within_budget", "timeout_kill"], default="within_budget")
    p_resource_enforcement.add_argument("--timeout-seconds", type=float, default=1.0)
    p_resource_enforcement.add_argument("--source-root", default=str(repo_root()))
    p_resource_enforcement.add_argument("--label", default="manual-resource-enforcement-trial")
    p_resource_enforcement.set_defaults(func=cmd_resource_enforcement_trial)

    p_shareability_bundle = sub.add_parser(
        "shareability-bundle",
        help="create and verify a local git bundle for offline/SSH handoff; no push, pull, SSH, or network",
    )
    p_shareability_bundle.add_argument("--source-root", default=str(repo_root()))
    p_shareability_bundle.add_argument("--output-dir", required=True)
    p_shareability_bundle.add_argument("--label", default="manual-shareability-bundle")
    ref_scope = p_shareability_bundle.add_mutually_exclusive_group()
    ref_scope.add_argument(
        "--all-refs",
        action="store_true",
        help="include every ref; creates a defer record because this can over-share private refs",
    )
    ref_scope.add_argument(
        "--head-only",
        action="store_true",
        help="default compatibility flag; include HEAD and tags at HEAD only",
    )
    p_shareability_bundle.add_argument("--overwrite", action="store_true")
    p_shareability_bundle.set_defaults(func=cmd_shareability_bundle)

    p_shareability_receiver = sub.add_parser(
        "shareability-receiver-trial",
        help="reconstruct a local clone from a verified bundle and record receiver-side provenance",
    )
    p_shareability_receiver.add_argument("--source-store", required=True)
    p_shareability_receiver.add_argument("--shareability-bundle-id", required=True)
    p_shareability_receiver.add_argument("--receiver-root", required=True)
    p_shareability_receiver.add_argument("--label", default="manual-shareability-receiver-trial")
    p_shareability_receiver.add_argument("--run-python-compile", action="store_true")
    p_shareability_receiver.add_argument("--focused-test", action="append", default=[])
    p_shareability_receiver.set_defaults(func=cmd_shareability_receiver_trial)

    p_dispatch = sub.add_parser("dispatch-run", help="dispatch a planned TaskRun through M8G checks")
    p_dispatch.add_argument("--task-run-id", required=True)
    p_dispatch.set_defaults(func=cmd_dispatch_run)

    p_provider_result = sub.add_parser("provider-result", help="ingest a provider result for a TaskRun")
    p_provider_result.add_argument("--task-run-id", required=True)
    p_provider_result.add_argument("--status", required=True, choices=["ok", "error", "timeout", "refused"])
    p_provider_result.add_argument("--output-ref", action="append")
    p_provider_result.add_argument("--token-usage-file")
    p_provider_result.add_argument("--provider-msg-ref", action="append")
    p_provider_result.add_argument("--source-class", default="trusted", choices=["trusted", "untrusted"])
    p_provider_result.set_defaults(func=cmd_provider_result)

    p_eval_run = sub.add_parser("evaluate-run", help="evaluate a TaskRun end-state predicate")
    p_eval_run.add_argument("--task-run-id", required=True)
    p_eval_run.set_defaults(func=cmd_evaluate_run)

    p_outbox = sub.add_parser("outbox-create", help="queue a local outbox item; does not send")
    p_outbox.add_argument("--task-run-id", required=True)
    p_outbox.add_argument("--target", default="discord")
    p_outbox.add_argument("--channel-id")
    p_outbox.add_argument("--endpoint")
    p_outbox.add_argument("--method", default="POST")
    p_outbox.add_argument("--payload-file")
    p_outbox.add_argument("--admission-review-id")
    p_outbox.add_argument("--idempotency-key")
    p_outbox.set_defaults(func=cmd_outbox_create)

    p_receipt = sub.add_parser("outbox-receipt", help="record a local outbox delivery/readback receipt")
    p_receipt.add_argument("--outbox-id", required=True)
    p_receipt.add_argument("--status", required=True, choices=["sent", "readback_verified", "deferred", "failed", "ambiguous"])
    p_receipt.add_argument("--response-file")
    p_receipt.add_argument("--readback-ref")
    p_receipt.add_argument("--reason-code", action="append")
    p_receipt.set_defaults(func=cmd_outbox_receipt)

    p_surface_promise = sub.add_parser(
        "surface-promise-create",
        help="record promised user-visible surfaces and evaluate delivery/readback",
    )
    p_surface_promise.add_argument("--task-run-id", required=True)
    p_surface_promise.add_argument("--promise-file")
    p_surface_promise.add_argument("--surface", default="discord")
    p_surface_promise.add_argument("--target", default="discord")
    p_surface_promise.add_argument("--channel-id")
    p_surface_promise.add_argument("--outbox-id")
    p_surface_promise.add_argument("--required", action=argparse.BooleanOptionalAction, default=True)
    p_surface_promise.add_argument("--required-readback", action=argparse.BooleanOptionalAction, default=True)
    p_surface_promise.add_argument("--source-packet-ref")
    p_surface_promise.add_argument("--promise-reason")
    p_surface_promise.set_defaults(func=cmd_surface_promise_create)

    p_surface_promise_check = sub.add_parser(
        "surface-promise-check",
        help="re-evaluate a recorded surface promise against outbox receipts",
    )
    p_surface_promise_check.add_argument("--surface-promise-id", required=True)
    p_surface_promise_check.set_defaults(func=cmd_surface_promise_check)

    p_sim = sub.add_parser("simulate-dual", help="run local Codex+Claude AMS dry-run")
    p_sim.add_argument("--event-file", required=True)
    p_sim.set_defaults(func=cmd_simulate_dual)

    p_sim_full = sub.add_parser("simulate-full", help="run the M8G end-to-end local dry-run")
    p_sim_full.add_argument("--event-file", required=True)
    p_sim_full.add_argument("--full-blast-radius-graph", action="store_true")
    p_sim_full.set_defaults(func=cmd_simulate_full)

    p_sim_incident = sub.add_parser("simulate-incident", help="run a local provider-error incident dry-run")
    p_sim_incident.add_argument("--event-file", required=True)
    p_sim_incident.add_argument("--full-blast-radius-graph", action="store_true")
    p_sim_incident.set_defaults(func=cmd_simulate_incident)

    p_storage_probe = sub.add_parser("storage-probe", help="measure local JSON store vs SQLite WAL writes")
    p_storage_probe.add_argument("--iterations", type=int, default=100)
    p_storage_probe.add_argument("--payload-bytes", type=int, default=512)
    p_storage_probe.add_argument("--output-dir")
    p_storage_probe.set_defaults(func=cmd_storage_probe)

    p_close_epoch = sub.add_parser("close-epoch", help="write a local epoch-close attestation if invariants pass")
    p_close_epoch.add_argument("--label", default="manual")
    p_close_epoch.set_defaults(func=cmd_close_epoch)

    p_console = sub.add_parser("console", help="render a read-only console report from the local store")
    p_console.add_argument("--format", choices=["text", "html"], default="text")
    p_console.add_argument("--output")
    p_console.set_defaults(func=cmd_console)

    p_self_eval = sub.add_parser("self-eval", help="run local raw-vs-AMS deterministic self-eval")
    p_self_eval.add_argument("--cases", type=int, default=20)
    p_self_eval.set_defaults(func=cmd_self_eval)

    p_verify_policy = sub.add_parser("verify-policy", help="verify a signed canonical JSON policy")
    p_verify_policy.add_argument("--policy-file", required=True)
    p_verify_policy.add_argument("--signature-file", required=True)
    p_verify_policy.add_argument("--allowed-signers-file", required=True)
    p_verify_policy.add_argument("--signer-identity", required=True)
    p_verify_policy.add_argument("--pinned-fingerprint", action="append", required=True)
    p_verify_policy.add_argument("--namespace", default="ams-policy")
    p_verify_policy.set_defaults(func=cmd_verify_policy)

    p_install_defs = sub.add_parser("install-definitions", help="install default local tool/surface definitions")
    p_install_defs.set_defaults(func=cmd_install_definitions)

    p_registry_status = sub.add_parser("registry-status", help="show local tool/surface registry status")
    p_registry_status.set_defaults(func=cmd_registry_status)

    p_surface_declare = sub.add_parser("surface-declare", help="declare a local runtime surface; does not launch or probe it")
    p_surface_declare.add_argument("--provider", required=True)
    p_surface_declare.add_argument("--surface", required=True)
    p_surface_declare.add_argument("--runtime-name", required=True)
    p_surface_declare.add_argument("--transport", required=True)
    p_surface_declare.add_argument("--endpoint")
    p_surface_declare.add_argument(
        "--binding-kind",
        default="provider_runtime",
        choices=["provider_runtime", "surface_adapter", "local_model_endpoint", "human_surface"],
    )
    p_surface_declare.add_argument("--rollout-mode", default="dry_run", choices=["dry_run", "shadow", "canary", "enforce"])
    p_surface_declare.add_argument("--status", default="declared", choices=["declared", "observed", "disabled"])
    p_surface_declare.add_argument("--process-owner", default="external", choices=["external", "ams_supervised", "none"])
    p_surface_declare.add_argument(
        "--capability-tier",
        default="observer",
        choices=["observer", "verifier", "builder", "maintainer", "signed_maintainer"],
    )
    p_surface_declare.add_argument("--resource-profile-id")
    p_surface_declare.add_argument("--workspace-root", action="append")
    p_surface_declare.add_argument("--egress-mode", action="append")
    p_surface_declare.add_argument(
        "--session-semantics",
        default="stateless",
        choices=["persistent_thread", "resumable_session", "stateless", "human_visible_stream", "outbox_queue"],
    )
    p_surface_declare.add_argument("--inject-allowed", action="store_true")
    p_surface_declare.add_argument("--approval-id")
    p_surface_declare.add_argument("--package-manifest-sha256")
    p_surface_declare.set_defaults(func=cmd_surface_declare)

    p_surface_bind = sub.add_parser("surface-bind", help="bind a declared runtime surface to an AMS session; does not dispatch")
    p_surface_bind.add_argument("--runtime-surface-id", required=True)
    p_surface_bind.add_argument("--session-id", required=True)
    p_surface_bind.add_argument("--provider-session-id")
    p_surface_bind.add_argument("--task-run-id")
    p_surface_bind.add_argument("--binding-role", default="worker", choices=["worker", "verifier", "observer", "egress_queue"])
    p_surface_bind.add_argument("--status", default="bound", choices=["bound", "paused", "released"])
    p_surface_bind.set_defaults(func=cmd_surface_bind)

    p_surface_status = sub.add_parser("surface-status", help="show local runtime surface and binding status")
    p_surface_status.set_defaults(func=cmd_surface_status)

    p_build_package = sub.add_parser("build-package-manifest", help="write a canonical local registry/gate package manifest")
    p_build_package.add_argument("--output", required=True)
    p_build_package.set_defaults(func=cmd_build_package_manifest)

    p_verify_package = sub.add_parser("verify-package", help="verify a signed package manifest and compare it to the local registry")
    p_verify_package.add_argument("--manifest-file", required=True)
    p_verify_package.add_argument("--signature-file", required=True)
    p_verify_package.add_argument("--allowed-signers-file", required=True)
    p_verify_package.add_argument("--signer-identity", required=True)
    p_verify_package.add_argument("--pinned-fingerprint", action="append", required=True)
    p_verify_package.add_argument("--namespace", default="ams-package")
    p_verify_package.set_defaults(func=cmd_verify_package)

    p_runner = sub.add_parser("runner-preflight", help="validate a dispatch envelope before any provider runner")
    p_runner.add_argument("--envelope-file", required=True)
    p_runner.add_argument("--live", action="store_true", help="must stay false unless live approval exists")
    p_runner.add_argument("--shadow-launch-plan-id")
    p_runner.add_argument("--shadow-launch-plan-sha256")
    p_runner.set_defaults(func=cmd_runner_preflight)

    p_runner_parity = sub.add_parser(
        "runner-dry-run-parity",
        help="record signed-manifest parity for an inert live-shadow runner preflight",
    )
    p_runner_parity.add_argument("--envelope-file", required=True)
    p_runner_parity.add_argument("--package-verification-file", required=True)
    p_runner_parity.add_argument("--package-manifest-file", required=True)
    p_runner_parity.add_argument("--runner-preflight-file")
    p_runner_parity.add_argument("--dry-run", action="store_true")
    p_runner_parity.add_argument("--shadow-launch-plan-id")
    p_runner_parity.add_argument("--shadow-launch-plan-sha256")
    p_runner_parity.set_defaults(func=cmd_runner_dry_run_parity)

    p_install_preflight = sub.add_parser("install-preflight", help="read-only live install/runtime readiness report")
    p_install_preflight.add_argument("--package-manifest")
    p_install_preflight.add_argument("--expected-agent-user", default="ams-agent")
    p_install_preflight.set_defaults(func=cmd_install_preflight)

    p_shadow = sub.add_parser("shadow-readiness", help="evaluate approval gates before live shadow start")
    p_shadow.add_argument("--install-preflight-file", required=True)
    p_shadow.add_argument("--package-verification-file", required=True)
    p_shadow.add_argument("--approval-id")
    p_shadow.add_argument("--egress-mode", default="none")
    p_shadow.set_defaults(func=cmd_shadow_readiness)

    p_shadow_launch = sub.add_parser(
        "shadow-launch-plan",
        help="store a no-egress shadow launch packet; does not launch anything",
    )
    p_shadow_launch.add_argument("--install-preflight-file", required=True)
    p_shadow_launch.add_argument("--package-verification-file", required=True)
    p_shadow_launch.add_argument("--approval-id")
    p_shadow_launch.add_argument("--egress-mode", default="none")
    p_shadow_launch.add_argument("--runtime-surface-id", action="append")
    p_shadow_launch.add_argument("--surface-binding-id", action="append")
    p_shadow_launch.add_argument("--surface-promise-id", action="append")
    p_shadow_launch.set_defaults(func=cmd_shadow_launch_plan)

    p_shadow_runner = sub.add_parser(
        "shadow-runner-transaction",
        help="store a dry-run launch transaction; does not start a process",
    )
    p_shadow_runner.add_argument("--runner-preflight-file", required=True)
    p_shadow_runner.add_argument("--argv", action="append", help="one argv element; repeat for each argument")
    p_shadow_runner.add_argument("--cwd", default=workspace_root())
    p_shadow_runner.add_argument("--requested-by", default="operator")
    p_shadow_runner.add_argument("--approval-id")
    p_shadow_runner.add_argument("--purpose", default="no-egress live shadow")
    p_shadow_runner.add_argument("--env-name", action="append", help="non-secret environment variable name to allow")
    p_shadow_runner.add_argument("--redacted-env-name", action="append", help="environment variable name recorded without value")
    p_shadow_runner.add_argument("--abort-condition", action="append")
    p_shadow_runner.add_argument("--rollback-step", action="append")
    p_shadow_runner.set_defaults(func=cmd_shadow_runner_transaction)

    p_shadow_approval = sub.add_parser(
        "shadow-approval-packet",
        help="record local no-egress live-shadow approval packet and readback; does not approve or start",
    )
    p_shadow_approval.add_argument("--shadow-launch-plan-id", required=True)
    p_shadow_approval.add_argument("--shadow-runner-transaction-id", required=True)
    p_shadow_approval.add_argument("--runner-dry-run-parity-id", required=True)
    p_shadow_approval.add_argument("--store-backup-drill-id", required=True)
    p_shadow_approval.add_argument("--requested-by", default="operator")
    p_shadow_approval.add_argument("--readback-ref")
    p_shadow_approval.add_argument("--readback-text", required=True)
    p_shadow_approval.set_defaults(func=cmd_shadow_approval_packet)

    p_attention = sub.add_parser(
        "attention-signal-ingest",
        help="normalize and route a local attention signal; does not start monitors or send egress",
    )
    p_attention.add_argument("--signal-file", required=True)
    p_attention.set_defaults(func=cmd_attention_signal_ingest)

    p_discord_source = sub.add_parser(
        "discord-source-packet",
        help="record a bounded read-only Discord source packet; no send, gateway, token, or raw-content storage",
    )
    p_discord_source.add_argument("--packet-file", required=True)
    p_discord_source.add_argument("--create-attention-signal", action="store_true")
    p_discord_source.set_defaults(func=cmd_discord_source_packet)

    p_discord_canary = sub.add_parser(
        "discord-canary-send-plan",
        help="record an inert Discord canary send/readback contract; does not send",
    )
    p_discord_canary.add_argument("--outbox-id", required=True)
    p_discord_canary.add_argument("--admission-review-id", required=True)
    p_discord_canary.add_argument("--surface-promise-id")
    p_discord_canary.add_argument("--discord-source-packet-id")
    p_discord_canary.add_argument("--operator-review-ref")
    p_discord_canary.set_defaults(func=cmd_discord_canary_send_plan)

    p_discord_receipt = sub.add_parser(
        "discord-canary-receipt",
        help="record supplied Discord canary receipt/readback evidence; does not call Discord",
    )
    p_discord_receipt.add_argument("--discord-canary-send-plan-id", required=True)
    p_discord_receipt.add_argument("--response-file", required=True)
    p_discord_receipt.add_argument("--readback-ref", required=True)
    p_discord_receipt.add_argument("--observed-nonce", required=True)
    p_discord_receipt.add_argument(
        "--observation-mode",
        default="external_observed",
        choices=["external_observed", "operator_supplied", "simulated_success"],
    )
    p_discord_receipt.set_defaults(func=cmd_discord_canary_receipt)

    p_terminal_source = sub.add_parser(
        "terminal-source-packet",
        help="record read-only terminal/tmux source evidence; does not attach, capture, inject, or signal",
    )
    p_terminal_source.add_argument("--packet-file", required=True)
    p_terminal_source.add_argument("--create-attention-signal", action="store_true")
    p_terminal_source.set_defaults(func=cmd_terminal_source_packet)

    p_conformance = sub.add_parser(
        "conformance-pack",
        help="generate a local conformance evidence pack; no live calls, no daemons",
    )
    p_conformance.add_argument("--repo-root", default=str(repo_root()))
    p_conformance.add_argument("--evidence-root", required=True)
    p_conformance.add_argument("--target-milestone", required=True)
    p_conformance.add_argument("--label", default="manual-conformance-pack")
    p_conformance.add_argument("--check-store", action="append", default=[])
    p_conformance.add_argument("--command", action="append", default=[])
    p_conformance.add_argument("--command-timeout-seconds", type=int, default=180)
    p_conformance.add_argument("--skip-python-compile", action="store_true")
    p_conformance.set_defaults(func=cmd_conformance_pack)

    p_markdown_audit = sub.add_parser(
        "markdown-audit",
        help="record markdown governance evidence; hashes metadata only, no raw transcript storage",
    )
    p_markdown_audit.add_argument("--source-root", default=str(repo_root()))
    p_markdown_audit.add_argument("--label", default="manual-markdown-audit")
    p_markdown_audit.add_argument("--include-local-session-metadata", action="store_true")
    p_markdown_audit.add_argument("--session-window-days", type=int, default=92)
    p_markdown_audit.set_defaults(func=cmd_markdown_audit)

    p_readiness_review = sub.add_parser(
        "readiness-review",
        help="record an overall AMS production-readiness critique; no live boundaries",
    )
    p_readiness_review.add_argument("--source-root", default=str(repo_root()))
    p_readiness_review.add_argument("--label", default="manual-readiness-review")
    p_readiness_review.add_argument("--include-local-session-metadata", action="store_true")
    p_readiness_review.add_argument("--session-window-days", type=int, default=92)
    p_readiness_review.set_defaults(func=cmd_readiness_review)

    p_doc_retirement = sub.add_parser(
        "doc-retirement-plan",
        help="record markdown retirement/generated-status decisions; no file rewrite or delete",
    )
    p_doc_retirement.add_argument("--source-root", default=str(repo_root()))
    p_doc_retirement.add_argument("--label", default="manual-doc-retirement-plan")
    p_doc_retirement.add_argument("--include-local-session-metadata", action="store_true")
    p_doc_retirement.add_argument("--session-window-days", type=int, default=92)
    p_doc_retirement.set_defaults(func=cmd_doc_retirement_plan)

    p_doc_action_execution = sub.add_parser(
        "doc-action-execution-plan",
        help="record a preview-only small-batch doc action execution plan; no file rewrite or delete",
    )
    p_doc_action_execution.add_argument("--source-root", default=str(repo_root()))
    p_doc_action_execution.add_argument("--label", default="manual-doc-action-execution-plan")
    p_doc_action_execution.add_argument("--include-local-session-metadata", action="store_true")
    p_doc_action_execution.add_argument("--session-window-days", type=int, default=92)
    p_doc_action_execution.add_argument("--max-actions", type=int, default=3)
    p_doc_action_execution.add_argument("--action-kind", action="append", default=[])
    p_doc_action_execution.set_defaults(func=cmd_doc_action_execution_plan)

    p_doc_action_operator_approval = sub.add_parser(
        "doc-action-operator-approval",
        help="record an inert operator review packet for a doc action execution plan; grants no live doc authority",
    )
    p_doc_action_operator_approval.add_argument("--source-root", default=str(repo_root()))
    p_doc_action_operator_approval.add_argument("--label", default="manual-doc-action-operator-approval")
    p_doc_action_operator_approval.add_argument("--doc-action-execution-plan-id", required=True)
    p_doc_action_operator_approval.set_defaults(func=cmd_doc_action_operator_approval)

    p_doc_action_patch_preview = sub.add_parser(
        "doc-action-patch-preview",
        help="record an inert semantic patch preview for a doc action approval packet; writes no source files",
    )
    p_doc_action_patch_preview.add_argument("--source-root", default=str(repo_root()))
    p_doc_action_patch_preview.add_argument("--label", default="manual-doc-action-patch-preview")
    p_doc_action_patch_preview.add_argument("--doc-action-operator-approval-packet-id", required=True)
    p_doc_action_patch_preview.set_defaults(func=cmd_doc_action_patch_preview)

    p_doc_action_patch_readback = sub.add_parser(
        "doc-action-patch-readback",
        help="verify an operator readback for a doc action patch preview; grants no live doc authority",
    )
    p_doc_action_patch_readback.add_argument("--source-root", default=str(repo_root()))
    p_doc_action_patch_readback.add_argument("--label", default="manual-doc-action-patch-readback")
    p_doc_action_patch_readback.add_argument("--doc-action-patch-preview-id", required=True)
    p_doc_action_patch_readback.add_argument("--readback-ref", required=True)
    p_doc_action_patch_readback.add_argument("--readback-text", default="")
    p_doc_action_patch_readback.add_argument("--readback-file")
    p_doc_action_patch_readback.add_argument("--requested-by", default="operator")
    p_doc_action_patch_readback.set_defaults(func=cmd_doc_action_patch_readback)

    p_doc_action_patch_artifact = sub.add_parser(
        "doc-action-patch-artifact",
        help="render external literal patch artifacts for a readback-verified doc action patch preview; writes no source files",
    )
    p_doc_action_patch_artifact.add_argument("--source-root", default=str(repo_root()))
    p_doc_action_patch_artifact.add_argument("--artifact-root")
    p_doc_action_patch_artifact.add_argument("--label", default="manual-doc-action-patch-artifact")
    p_doc_action_patch_artifact.add_argument("--doc-action-patch-readback-receipt-id", required=True)
    p_doc_action_patch_artifact.set_defaults(func=cmd_doc_action_patch_artifact)

    p_doc_action_patch_artifact_approval = sub.add_parser(
        "doc-action-patch-artifact-approval",
        help="record an inert operator review packet for one external doc action patch artifact; grants no source authority",
    )
    p_doc_action_patch_artifact_approval.add_argument("--source-root", default=str(repo_root()))
    p_doc_action_patch_artifact_approval.add_argument(
        "--label",
        default="manual-doc-action-patch-artifact-approval",
    )
    p_doc_action_patch_artifact_approval.add_argument("--doc-action-patch-artifact-receipt-id", required=True)
    p_doc_action_patch_artifact_approval.add_argument("--artifact-action-id")
    p_doc_action_patch_artifact_approval.set_defaults(func=cmd_doc_action_patch_artifact_approval)

    p_doc_action_patch_dry_run = sub.add_parser(
        "doc-action-patch-dry-run-plan",
        help="record an inert dry-run plan for one approved external doc patch artifact; writes no source files",
    )
    p_doc_action_patch_dry_run.add_argument("--source-root")
    p_doc_action_patch_dry_run.add_argument("--label", default="manual-doc-action-patch-dry-run")
    p_doc_action_patch_dry_run.add_argument("--doc-action-patch-artifact-approval-packet-id", required=True)
    p_doc_action_patch_dry_run.set_defaults(func=cmd_doc_action_patch_dry_run_plan)

    p_doc_action_patch_dry_run_readback = sub.add_parser(
        "doc-action-patch-dry-run-readback",
        help="verify an operator readback for a doc patch dry-run plan; grants no live doc authority",
    )
    p_doc_action_patch_dry_run_readback.add_argument("--source-root")
    p_doc_action_patch_dry_run_readback.add_argument("--label", default="manual-doc-action-patch-dry-run-readback")
    p_doc_action_patch_dry_run_readback.add_argument("--doc-action-patch-dry-run-plan-id", required=True)
    p_doc_action_patch_dry_run_readback.add_argument("--readback-ref", required=True)
    p_doc_action_patch_dry_run_readback.add_argument("--readback-text", default="")
    p_doc_action_patch_dry_run_readback.add_argument("--readback-file")
    p_doc_action_patch_dry_run_readback.add_argument("--requested-by", default="operator")
    p_doc_action_patch_dry_run_readback.set_defaults(func=cmd_doc_action_patch_dry_run_readback)

    p_doc_action_patch_live_execution_approval = sub.add_parser(
        "doc-action-patch-live-execution-approval",
        help="record operator approval for a future doc patch executor; performs no source writes",
    )
    p_doc_action_patch_live_execution_approval.add_argument("--source-root")
    p_doc_action_patch_live_execution_approval.add_argument(
        "--label",
        default="manual-doc-action-patch-live-execution-approval",
    )
    p_doc_action_patch_live_execution_approval.add_argument(
        "--doc-action-patch-dry-run-readback-receipt-id",
        required=True,
    )
    p_doc_action_patch_live_execution_approval.add_argument("--approval-ref", required=True)
    p_doc_action_patch_live_execution_approval.add_argument("--approval-text", default="")
    p_doc_action_patch_live_execution_approval.add_argument("--approval-file")
    p_doc_action_patch_live_execution_approval.add_argument("--requested-by", default="operator")
    p_doc_action_patch_live_execution_approval.set_defaults(func=cmd_doc_action_patch_live_execution_approval)

    p_doc_action_patch_executor_preflight = sub.add_parser(
        "doc-action-patch-executor-preflight",
        help="preflight a future doc patch executor; rechecks hashes and performs no source writes",
    )
    p_doc_action_patch_executor_preflight.add_argument("--source-root")
    p_doc_action_patch_executor_preflight.add_argument(
        "--label",
        default="manual-doc-action-patch-executor-preflight",
    )
    p_doc_action_patch_executor_preflight.add_argument(
        "--doc-action-patch-live-execution-approval-packet-id",
        required=True,
    )
    p_doc_action_patch_executor_preflight.set_defaults(func=cmd_doc_action_patch_executor_preflight)

    p_doc_action_patch_apply_boundary = sub.add_parser(
        "doc-action-patch-apply-boundary",
        help="record a source patch apply boundary; requires operator acceptance later and performs no source writes",
    )
    p_doc_action_patch_apply_boundary.add_argument("--source-root")
    p_doc_action_patch_apply_boundary.add_argument(
        "--label",
        default="manual-doc-action-patch-apply-boundary",
    )
    p_doc_action_patch_apply_boundary.add_argument(
        "--doc-action-patch-executor-preflight-id",
        required=True,
    )
    p_doc_action_patch_apply_boundary.set_defaults(func=cmd_doc_action_patch_apply_boundary)

    p_doc_action_patch_apply_acceptance = sub.add_parser(
        "doc-action-patch-apply-acceptance",
        help=(
            "record operator acceptance for backup/preimage review after an apply boundary; "
            "performs no source writes"
        ),
    )
    p_doc_action_patch_apply_acceptance.add_argument("--source-root")
    p_doc_action_patch_apply_acceptance.add_argument(
        "--label",
        default="manual-doc-action-patch-apply-acceptance",
    )
    p_doc_action_patch_apply_acceptance.add_argument(
        "--doc-action-patch-apply-boundary-packet-id",
        required=True,
    )
    p_doc_action_patch_apply_acceptance.add_argument("--acceptance-ref", required=True)
    p_doc_action_patch_apply_acceptance.add_argument("--acceptance-text", default="")
    p_doc_action_patch_apply_acceptance.add_argument("--acceptance-file")
    p_doc_action_patch_apply_acceptance.add_argument("--requested-by", default="operator")
    p_doc_action_patch_apply_acceptance.set_defaults(func=cmd_doc_action_patch_apply_acceptance)

    p_source_write_executor_preflight = sub.add_parser(
        "source-write-executor-preflight",
        help="preflight a future exclusive source-write executor; performs no source writes",
    )
    p_source_write_executor_preflight.add_argument("--source-root")
    p_source_write_executor_preflight.add_argument(
        "--label",
        default="manual-source-write-executor-preflight",
    )
    p_source_write_executor_preflight.add_argument(
        "--doc-action-patch-apply-acceptance-packet-id",
        required=True,
    )
    p_source_write_executor_preflight.add_argument("--architecture-gate-review-id")
    p_source_write_executor_preflight.add_argument("--blast-radius-review-id")
    p_source_write_executor_preflight.set_defaults(func=cmd_source_write_executor_preflight)

    p_source_write_backup_preimage = sub.add_parser(
        "source-write-backup-preimage-receipt",
        help="capture external backup/preimage evidence for a source-write preflight; performs no source writes",
    )
    p_source_write_backup_preimage.add_argument("--source-root")
    p_source_write_backup_preimage.add_argument("--backup-root")
    p_source_write_backup_preimage.add_argument(
        "--label",
        default="manual-source-write-backup-preimage",
    )
    p_source_write_backup_preimage.add_argument(
        "--source-write-executor-preflight-id",
        required=True,
    )
    p_source_write_backup_preimage.set_defaults(func=cmd_source_write_backup_preimage_receipt)

    p_source_write_executor_lease = sub.add_parser(
        "source-write-executor-lease",
        help="open an exclusive source-write executor lease after backup/preimage capture; performs no source writes",
    )
    p_source_write_executor_lease.add_argument("--source-root")
    p_source_write_executor_lease.add_argument(
        "--label",
        default="manual-source-write-executor-lease",
    )
    p_source_write_executor_lease.add_argument(
        "--source-write-backup-preimage-receipt-id",
        required=True,
    )
    p_source_write_executor_lease.set_defaults(func=cmd_source_write_executor_lease)

    p_generated_status = sub.add_parser(
        "generated-status-snapshot",
        help="write a compact generated status surface from AMS records; no source-doc rewrite",
    )
    p_generated_status.add_argument("--source-root", default=str(repo_root()))
    p_generated_status.add_argument("--output-path", default="GENERATED_STATUS.md")
    p_generated_status.add_argument("--label", default="manual-generated-status")
    p_generated_status.add_argument("--include-local-session-metadata", action="store_true")
    p_generated_status.add_argument("--session-window-days", type=int, default=92)
    p_generated_status.add_argument("--no-write-file", action="store_true")
    p_generated_status.add_argument("--allow-overwrite", action="store_true")
    p_generated_status.set_defaults(func=cmd_generated_status_snapshot)

    p_session_start = sub.add_parser(
        "session-start-brief",
        help="write compact new-session instructions from hashed AMS source refs; no live boundary",
    )
    p_session_start.add_argument("--source-root", default=str(repo_root()))
    p_session_start.add_argument("--output-path", default="NEW_CODEX_SESSION.md")
    p_session_start.add_argument("--label", default="manual-session-start-brief")
    p_session_start.add_argument("--no-write-file", action="store_true")
    p_session_start.add_argument("--allow-overwrite", action="store_true")
    p_session_start.set_defaults(func=cmd_session_start_brief)

    p_markdown_authority = sub.add_parser(
        "markdown-authority-index",
        help="record markdown authority tiers and startup surface; hashes metadata only",
    )
    p_markdown_authority.add_argument("--source-root", default=str(repo_root()))
    p_markdown_authority.add_argument("--label", default="manual-markdown-authority-index")
    p_markdown_authority.add_argument(
        "--supersedes",
        action="append",
        default=[],
        metavar="OLD=NEW",
        help="mark OLD markdown path superseded by NEW markdown path",
    )
    p_markdown_authority.set_defaults(func=cmd_markdown_authority_index)

    p_work_mode = sub.add_parser(
        "work-mode-decision",
        help="record whether a request needs session-isolation tests, cleanup audit, both, or standard verification",
    )
    p_work_mode.add_argument("--request-file", help="text prompt/request file to hash and classify; raw text is not stored")
    p_work_mode.add_argument("--request-ref")
    p_work_mode.add_argument("--changed-path", action="append")
    p_work_mode.add_argument("--source-root", default=str(repo_root()))
    p_work_mode.add_argument("--label", default="manual-work-mode-decision")
    p_work_mode.add_argument("--source-surface", default="codex")
    p_work_mode.add_argument("--session-id")
    p_work_mode.set_defaults(func=cmd_work_mode_decision)

    p_sweep = sub.add_parser(
        "simulation-sweep",
        help="run local no-Discord AMS scenario sweep and record feature reactions",
    )
    p_sweep.add_argument("--source-root", default=str(repo_root()))
    p_sweep.add_argument("--simulation-area")
    p_sweep.add_argument("--scenarios", type=int, default=1370)
    p_sweep.add_argument("--label", default="manual-simulation-sweep")
    p_sweep.set_defaults(func=cmd_simulation_sweep)

    p_emu = sub.add_parser(
        "ams-emulation-trial",
        help="run subprocess sandbox emulation of AMS with deterministic local agents; no live Discord/provider/RAG calls",
    )
    p_emu.add_argument("--source-root", default=str(repo_root()))
    p_emu.add_argument("--emulation-area")
    p_emu.add_argument("--scenarios", type=int)
    p_emu.add_argument("--label", default="manual-ams-emulation-trial")
    p_emu.add_argument("--timeout-seconds", type=int, default=2)
    p_emu.add_argument("--allow-external-agents", action="store_true")
    p_emu.add_argument("--agent-command-file")
    p_emu.set_defaults(func=cmd_ams_emulation_trial)

    p_semantic = sub.add_parser(
        "semantic-oracle-review",
        help="review a simulation sweep with semantic oracle and hook-shim rules; no live hooks installed",
    )
    p_semantic.add_argument("--simulation-sweep-id", required=True)
    p_semantic.add_argument("--source-root", default=str(repo_root()))
    p_semantic.add_argument("--output-path")
    p_semantic.add_argument("--label", default="manual-semantic-oracle-review")
    p_semantic.set_defaults(func=cmd_semantic_oracle_review)

    p_hook_run = sub.add_parser(
        "semantic-hook-run",
        help="record sandboxed semantic hook receipts for a semantic oracle review; no live hooks installed",
    )
    p_hook_run.add_argument("--semantic-oracle-review-id", required=True)
    p_hook_run.add_argument("--source-root", default=str(repo_root()))
    p_hook_run.add_argument("--label", default="manual-semantic-hook-run")
    p_hook_run.add_argument("--runner-mode", default="sandbox_simulated")
    p_hook_run.set_defaults(func=cmd_semantic_hook_run)

    p_hook_install = sub.add_parser(
        "semantic-hook-install-plan",
        help="plan trusted no-egress hook installation from sandbox hook records; installs nothing",
    )
    p_hook_install.add_argument("--semantic-hook-run-id", required=True)
    p_hook_install.add_argument("--source-root", default=str(repo_root()))
    p_hook_install.add_argument("--label", default="manual-semantic-hook-install-plan")
    p_hook_install.set_defaults(func=cmd_semantic_hook_install_plan)

    p_hook_approval = sub.add_parser(
        "semantic-hook-approval-binding",
        help="bind a semantic hook install plan to signed package, rollback, and operator readback evidence; installs nothing",
    )
    p_hook_approval.add_argument("--semantic-hook-install-plan-id", required=True)
    p_hook_approval.add_argument("--source-root", default=str(repo_root()))
    p_hook_approval.add_argument("--package-verification-file")
    p_hook_approval.add_argument("--package-manifest-file")
    p_hook_approval.add_argument("--rollback-proof-ref")
    p_hook_approval.add_argument("--rollback-proof-sha256")
    p_hook_approval.add_argument("--rollback-preflight-passed", action="store_true")
    p_hook_approval.add_argument("--operator-readback-ref")
    p_hook_approval.add_argument("--operator-readback-text", default="")
    p_hook_approval.add_argument("--operator-readback-file")
    p_hook_approval.add_argument("--label", default="manual-semantic-hook-approval-binding")
    p_hook_approval.set_defaults(func=cmd_semantic_hook_approval_binding)

    p_hook_targets = sub.add_parser(
        "semantic-hook-target-snapshot",
        help="hash hook target paths for a semantic hook approval binding; writes no hook or backup files",
    )
    p_hook_targets.add_argument("--semantic-hook-approval-binding-id", required=True)
    p_hook_targets.add_argument("--source-root", default=str(repo_root()))
    p_hook_targets.add_argument("--home-root")
    p_hook_targets.add_argument("--label", default="manual-semantic-hook-target-snapshot")
    p_hook_targets.set_defaults(func=cmd_semantic_hook_target_snapshot)

    p_hook_transaction = sub.add_parser(
        "semantic-hook-install-transaction",
        help="render no-write semantic hook install transaction steps from a target snapshot",
    )
    p_hook_transaction.add_argument("--semantic-hook-target-snapshot-id", required=True)
    p_hook_transaction.add_argument("--source-root", default=str(repo_root()))
    p_hook_transaction.add_argument("--label", default="manual-semantic-hook-install-transaction")
    p_hook_transaction.set_defaults(func=cmd_semantic_hook_install_transaction)

    p_hook_operator_approval = sub.add_parser(
        "semantic-hook-operator-approval",
        help="render an inert operator approval packet for a semantic hook install transaction",
    )
    p_hook_operator_approval.add_argument("--semantic-hook-install-transaction-id", required=True)
    p_hook_operator_approval.add_argument("--source-root", default=str(repo_root()))
    p_hook_operator_approval.add_argument("--label", default="manual-semantic-hook-operator-approval")
    p_hook_operator_approval.set_defaults(func=cmd_semantic_hook_operator_approval)

    p_hook_operator_readback = sub.add_parser(
        "semantic-hook-operator-readback",
        help="verify an operator readback for a semantic hook approval packet; grants no live authority",
    )
    p_hook_operator_readback.add_argument("--semantic-hook-operator-approval-packet-id", required=True)
    p_hook_operator_readback.add_argument("--readback-ref", required=True)
    p_hook_operator_readback.add_argument("--readback-text", default="")
    p_hook_operator_readback.add_argument("--readback-file")
    p_hook_operator_readback.add_argument("--requested-by", default="operator")
    p_hook_operator_readback.add_argument("--source-root", default=str(repo_root()))
    p_hook_operator_readback.add_argument("--label", default="manual-semantic-hook-operator-readback")
    p_hook_operator_readback.set_defaults(func=cmd_semantic_hook_operator_readback)

    p_manager = sub.add_parser(
        "manager-intervention-evaluate",
        help="build local manager intervention packets from routed attention signals; no egress",
    )
    p_manager.add_argument("--session-id")
    p_manager.add_argument("--task-run-id")
    p_manager.add_argument("--include-resolved", action="store_true")
    p_manager.add_argument("--max-signals", type=int, default=20)
    p_manager.add_argument(
        "--target-agent",
        action="append",
        help="agent_name:provider:surface, e.g. codex:openai_codex:codex-cli",
    )
    p_manager.set_defaults(func=cmd_manager_intervention_evaluate)

    p_manager_attach = sub.add_parser(
        "manager-intervention-attach-delivery",
        help="attach manager intervention to local outbox and surface promise records; no egress",
    )
    p_manager_attach.add_argument("--manager-intervention-id", required=True)
    p_manager_attach.add_argument(
        "--target-agent",
        action="append",
        help="agent_name:provider:surface subset; defaults to all intervention targets",
    )
    p_manager_attach.add_argument("--surface", help="override promised surface, e.g. discord or codex-cli")
    p_manager_attach.add_argument("--target", help="override outbox target, e.g. discord or openai_codex")
    p_manager_attach.add_argument("--channel-id")
    p_manager_attach.add_argument("--endpoint")
    p_manager_attach.add_argument("--admission-review-id")
    p_manager_attach.add_argument("--promise-reason")
    p_manager_attach.add_argument("--idempotency-key")
    p_manager_attach.set_defaults(func=cmd_manager_intervention_attach_delivery)

    p_manager_settle = sub.add_parser(
        "manager-intervention-settle",
        help="record an agent readback that settles a manager intervention; no egress",
    )
    p_manager_settle.add_argument("--manager-intervention-id", required=True)
    p_manager_settle.add_argument(
        "--target-agent",
        required=True,
        help="agent_name:provider:surface, e.g. codex:openai_codex:codex-cli",
    )
    p_manager_settle.add_argument(
        "--ack-status",
        required=True,
        choices=["acknowledged", "deferred", "resolved"],
    )
    p_manager_settle.add_argument("--readback-ref")
    p_manager_settle.add_argument("--readback-summary")
    p_manager_settle.add_argument("--source-ref-used", action="append")
    p_manager_settle.add_argument(
        "--priority-decision",
        default="none_deferred",
        choices=["none_deferred", "deferred"],
    )
    p_manager_settle.add_argument("--deferred-signal-id", action="append")
    p_manager_settle.add_argument("--priority-reason")
    p_manager_settle.add_argument("--next-domain")
    p_manager_settle.add_argument("--crosses-domains", action=argparse.BooleanOptionalAction, default=False)
    p_manager_settle.add_argument("--domain-reason")
    p_manager_settle.add_argument("--idempotency-key")
    p_manager_settle.set_defaults(func=cmd_manager_intervention_settle)

    p_architecture = sub.add_parser(
        "architecture-audit",
        help="write a local architecture quality audit; no network or downloads",
    )
    p_architecture.add_argument("--source-root", default=str(repo_root()))
    p_architecture.add_argument("--package-name", default="ams_codex")
    p_architecture.set_defaults(func=cmd_architecture_audit)

    p_architecture_gate = sub.add_parser(
        "architecture-gate-review",
        help="record architecture-audit evidence for AMS-authority paths; no code changes",
    )
    p_architecture_gate.add_argument("--subject-kind", required=True)
    p_architecture_gate.add_argument("--subject-id", required=True)
    p_architecture_gate.add_argument("--path", action="append", required=True)
    p_architecture_gate.add_argument("--architecture-audit-id")
    p_architecture_gate.set_defaults(func=cmd_architecture_gate_review)

    p_codebase_graph = sub.add_parser(
        "codebase-spider-graph",
        help="write a local static codebase graph snapshot; no network and no raw source storage",
    )
    p_codebase_graph.add_argument("--source-root", default=str(repo_root()))
    p_codebase_graph.add_argument("--package-name", default="ams_codex")
    p_codebase_graph.add_argument("--label", default="manual-codebase-spider-graph")
    p_codebase_graph.add_argument("--architecture-audit-id")
    p_codebase_graph.add_argument("--full-output", action="store_true")
    p_codebase_graph.set_defaults(func=cmd_codebase_spider_graph)

    p_codebase_query = sub.add_parser(
        "codebase-graph-query",
        help="record a hash-only codebase graph query receipt for impact, tests, or stale graph checks",
    )
    p_codebase_query.add_argument("--source-root", default=str(repo_root()))
    p_codebase_query.add_argument(
        "--query-kind",
        required=True,
        choices=["impact_slice", "related_tests", "stale_graph_check"],
    )
    p_codebase_query.add_argument("--path", action="append")
    p_codebase_query.add_argument("--depth", type=int, default=1)
    p_codebase_query.add_argument("--snapshot-id")
    p_codebase_query.add_argument("--label", default="manual-codebase-graph-query")
    p_codebase_query.set_defaults(func=cmd_codebase_graph_query)

    p_blast_radius = sub.add_parser(
        "blast-radius-review",
        help="record graph-backed source-change preflight evidence; no source writes",
    )
    p_blast_radius.add_argument("--source-root", default=str(repo_root()))
    p_blast_radius.add_argument("--package-name", default="ams_codex")
    p_blast_radius.add_argument("--subject-kind", required=True)
    p_blast_radius.add_argument("--subject-id", required=True)
    p_blast_radius.add_argument("--path", action="append", required=True)
    p_blast_radius.add_argument("--change-intent", default="source_change")
    p_blast_radius.add_argument("--graph-snapshot-id")
    p_blast_radius.add_argument("--ensure-graph", action=argparse.BooleanOptionalAction, default=True)
    p_blast_radius.add_argument("--depth", type=int, default=2)
    p_blast_radius.add_argument("--max-impact-paths", type=int, default=80)
    p_blast_radius.add_argument("--label", default="manual-blast-radius-review")
    p_blast_radius.set_defaults(func=cmd_blast_radius_review)

    p_rag = sub.add_parser(
        "rag-index-plan",
        help="write a local hash-only RAG index plan; no downloads, embeddings, or vector upload",
    )
    p_rag.add_argument("--source-root", default=str(repo_root()))
    p_rag.add_argument("--collection", default="ams_codebase_docs")
    p_rag.add_argument("--include-glob", action="append")
    p_rag.add_argument("--exclude-glob", action="append")
    p_rag.add_argument("--max-file-bytes", type=int, default=1_000_000)
    p_rag.add_argument("--max-total-bytes", type=int, default=5_000_000)
    p_rag.add_argument("--chunk-chars", type=int, default=2400)
    p_rag.add_argument("--embedding-provider", default="none", choices=["none", "openai", "local"])
    p_rag.add_argument("--embedding-model")
    p_rag.add_argument("--embedding-dimensions", type=int)
    p_rag.add_argument("--vector-store-provider", default="none", choices=["none", "openai_file_search", "local"])
    p_rag.set_defaults(func=cmd_rag_index_plan)

    p_quarantine = sub.add_parser(
        "downloaded-artifact-quarantine",
        help="record a downloaded/external artifact quarantine packet; does not download or index",
    )
    p_quarantine.add_argument("--source-uri", required=True)
    p_quarantine.add_argument("--source-type", default="unknown", choices=["url", "file", "dataset", "unknown"])
    p_quarantine.add_argument("--declared-media-type")
    p_quarantine.add_argument("--declared-sha256")
    p_quarantine.add_argument("--size-bytes", type=int)
    p_quarantine.add_argument(
        "--download-status",
        default="not_downloaded",
        choices=["not_downloaded", "downloaded_external"],
    )
    p_quarantine.add_argument(
        "--quarantine-status",
        default="quarantined",
        choices=["quarantined", "approved_for_index", "rejected"],
    )
    p_quarantine.add_argument("--local-path")
    p_quarantine.add_argument("--reviewed-by")
    p_quarantine.add_argument("--reviewed-at")
    p_quarantine.add_argument("--reason-code", action="append")
    p_quarantine.set_defaults(func=cmd_downloaded_artifact_quarantine)

    p_rag_embedding = sub.add_parser(
        "rag-embedding-job",
        help="write a provider-gated embedding/vector job plan; no provider calls or vector writes",
    )
    p_rag_embedding.add_argument("--rag-index-plan-id", required=True)
    p_rag_embedding.add_argument("--capability-admission-review-id")
    p_rag_embedding.add_argument("--resource-admission-review-id")
    p_rag_embedding.add_argument("--downloaded-artifact-quarantine-id", action="append")
    p_rag_embedding.add_argument("--batch-size", type=int, default=64)
    p_rag_embedding.add_argument("--idempotency-key")
    p_rag_embedding.set_defaults(func=cmd_rag_embedding_job)

    p_provider_auth = sub.add_parser(
        "provider-auth-preflight",
        help="record provider auth readiness by env-name presence only; no secret or network probe",
    )
    p_provider_auth.add_argument("--subject-kind", required=True)
    p_provider_auth.add_argument("--subject-id", required=True)
    p_provider_auth.add_argument("--provider", required=True)
    p_provider_auth.add_argument("--operation", required=True)
    p_provider_auth.add_argument("--surface")
    p_provider_auth.add_argument("--model")
    p_provider_auth.add_argument("--auth-mode", choices=["env_api_key", "none"])
    p_provider_auth.add_argument("--required-env-name", action="append")
    p_provider_auth.add_argument("--present-env-name", action="append")
    p_provider_auth.set_defaults(func=cmd_provider_auth_preflight)

    p_rag_receipt = sub.add_parser(
        "rag-embedding-receipt",
        help="record hash-only embedding/vector receipt evidence; does not call providers or write vectors",
    )
    p_rag_receipt.add_argument("--rag-embedding-job-id", required=True)
    p_rag_receipt.add_argument("--provider-auth-preflight-id")
    p_rag_receipt.add_argument(
        "--receipt-mode",
        default="planned_only",
        choices=["planned_only", "simulated_success", "external_observed", "failed"],
    )
    p_rag_receipt.add_argument("--external-vector-store-ref")
    p_rag_receipt.set_defaults(func=cmd_rag_embedding_receipt)

    p_rag_query = sub.add_parser(
        "rag-retrieval-query",
        help="record hash-only retrieval query/source refs; does not run retrieval or store query text",
    )
    p_rag_query.add_argument("--rag-embedding-receipt-id", required=True)
    p_rag_query.add_argument("--query-sha256", required=True)
    p_rag_query.add_argument("--query-length", required=True, type=int)
    p_rag_query.add_argument("--query-ref")
    p_rag_query.add_argument(
        "--retrieval-mode",
        default="simulated_refs",
        choices=["planned_only", "simulated_refs", "external_observed"],
    )
    p_rag_query.add_argument("--top-k", type=int, default=5)
    p_rag_query.add_argument("--taint-label", action="append")
    p_rag_query.set_defaults(func=cmd_rag_retrieval_query)

    p_rag_local_vector = sub.add_parser(
        "rag-local-vector-trial",
        help="run a local hash-feature retrieval trial; no network, providers, or vector writes",
    )
    p_rag_local_vector.add_argument("--rag-index-plan-id", required=True)
    p_rag_local_vector.add_argument("--query-text", required=True)
    p_rag_local_vector.add_argument("--label", default="manual-rag-local-vector-trial")
    p_rag_local_vector.add_argument("--top-k", type=int, default=5)
    p_rag_local_vector.add_argument("--taint-label", action="append")
    p_rag_local_vector.set_defaults(func=cmd_rag_local_vector_trial)

    p_memory_review = sub.add_parser(
        "memory-promotion-review",
        help="review a candidate memory claim before promotion; records duplicate/conflict/supersession evidence",
    )
    p_memory_review.add_argument("--domain", required=True)
    p_memory_review.add_argument("--subject", required=True)
    p_memory_review.add_argument("--predicate", required=True)
    p_memory_review.add_argument("--value-sha256", required=True)
    p_memory_review.add_argument("--source-ref", required=True)
    p_memory_review.add_argument("--source-kind", default="prompt")
    p_memory_review.add_argument("--scope", default="global")
    p_memory_review.add_argument("--value-ref")
    p_memory_review.add_argument("--value-summary", default="")
    p_memory_review.add_argument(
        "--trust-class",
        default="user_asserted",
        choices=[
            "user_asserted",
            "operator_asserted",
            "system_record",
            "generated_surface",
            "provider_evidence",
            "retrieved_evidence",
        ],
    )
    p_memory_review.add_argument("--valid-from")
    p_memory_review.add_argument("--valid-until")
    p_memory_review.add_argument("--supersedes-claim-id")
    p_memory_review.add_argument(
        "--supersession-mode",
        default="correction",
        choices=["correction", "temporal_update", "scope_refinement", "revocation", "duplicate"],
    )
    p_memory_review.add_argument("--operator-confirmed", action="store_true")
    p_memory_review.add_argument("--operator-confirmation-ref")
    p_memory_review.add_argument("--operator-confirmation-sha256")
    p_memory_review.add_argument("--label", default="manual-memory-promotion-review")
    p_memory_review.set_defaults(func=cmd_memory_promotion_review)

    p_backup = sub.add_parser(
        "backup-restore-drill",
        help="copy a runtime store to backup and restore paths, replay-checking all snapshots",
    )
    p_backup.add_argument("--backup-path", required=True)
    p_backup.add_argument("--restore-path", required=True)
    p_backup.add_argument("--label", default="manual-backup-restore-drill")
    p_backup.add_argument("--force", action="store_true")
    p_backup.set_defaults(func=cmd_backup_restore_drill)

    p_agent_sim_init = sub.add_parser(
        "agent-sim-init",
        help="create isolated local Claude/Codex simulation capsules; does not start agents",
    )
    p_agent_sim_init.add_argument("--runtime-root", default=default_runtime_root())
    p_agent_sim_init.add_argument("--create-venvs", action="store_true")
    p_agent_sim_init.set_defaults(func=cmd_agent_sim_init)

    p_agent_sim_run = sub.add_parser(
        "agent-sim-run",
        help="run fake Discord/Claude/Codex memory trial; does not start real agents",
    )
    p_agent_sim_run.add_argument("--runtime-root", default=default_runtime_root())
    p_agent_sim_run.add_argument("--create-venvs", action="store_true")
    p_agent_sim_run.add_argument("--trial-label", default="milestone-12-fake-discord-agent-memory")
    p_agent_sim_run.set_defaults(func=cmd_agent_sim_run)

    p_real_agent_smoke = sub.add_parser(
        "real-agent-smoke",
        help="run bounded real Claude/Codex non-interactive memory probes; no Discord egress",
    )
    p_real_agent_smoke.add_argument("--runtime-root", default=default_runtime_root())
    p_real_agent_smoke.add_argument("--approval-id", required=True)
    p_real_agent_smoke.add_argument("--timeout-seconds", type=int, default=180)
    p_real_agent_smoke.set_defaults(func=cmd_real_agent_smoke)

    p_real_agent_system = sub.add_parser(
        "real-agent-system-trial",
        help="run no-Discord Codex/Claude system behavior trial; real CLIs only with --allow-real-agents",
    )
    p_real_agent_system.add_argument("--runtime-root", default=default_runtime_root())
    p_real_agent_system.add_argument("--source-root", default=str(repo_root()))
    p_real_agent_system.add_argument("--label", default="manual-real-agent-system-trial")
    p_real_agent_system.add_argument("--timeout-seconds", type=int, default=120)
    p_real_agent_system.add_argument("--allow-real-agents", action="store_true")
    p_real_agent_system.set_defaults(func=cmd_real_agent_system_trial)

    p_trace = sub.add_parser("export-trace", help="emit local trace rows as JSONL")
    p_trace.set_defaults(func=cmd_export_trace)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    store_path = Path(args.store).expanduser().resolve(strict=False)
    if _path_is_under(store_path, repo_root().resolve()) and not args.fixture:
        parser.error("--store resolves inside the repo; pass --fixture for tracked fixtures or use a runtime path outside the repo")
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
