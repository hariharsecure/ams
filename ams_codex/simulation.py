from __future__ import annotations

from typing import Any

from .admission import AdmissionReviewStore
from .architecture_audit import ArchitectureAuditStore
from .architecture_gate import ArchitectureGateStore
from .blast_radius import BlastRadiusReviewStore
from .capability_policy import build_capability_request, evaluate_capability_request
from .checkpoint import CheckpointStore
from .claude_adapter import ClaudeDryRunAdapter
from .codex_adapter import CodexDryRunAdapter
from .context import ContextStore
from .dispatch import dispatch
from .gate_adapter import GateShadowAdapter, build_action
from .outbox import OutboxStore
from .predicate import PredicateStore
from .provider_result import ProviderResultStore
from .replay import ReplayChecker
from .resource_claim import ResourceClaimStore
from .session_registry import SessionRegistry
from .store import JsonStore
from .run_trace import RunTraceStore
from .workspace import repo_root


def run_dual_agent_simulation(raw_event: dict[str, Any], store: JsonStore | None = None) -> dict[str, Any]:
    store = store or JsonStore()
    registry = SessionRegistry(store)
    context_store = ContextStore(store)
    checkpoint_store = CheckpointStore(store)
    codex = CodexDryRunAdapter(store)
    claude = ClaudeDryRunAdapter(store)
    gate = GateShadowAdapter(store)

    session, created = registry.ingest_event(raw_event)
    context = context_store.create_for_event(session, raw_event)

    checkpoint = checkpoint_store.create(
        session["session_id"],
        trigger="pre_compact",
        state_summary="Simulation checkpoint before Codex/Claude handoff.",
        next_action="Run Codex builder dry-run, then Claude verifier dry-run.",
        decisions=["AMS owns continuity; Codex builds; Claude verifies"],
        constraints=["No live egress", "No persistent monitors"],
    )

    # Refresh context so it points at the checkpoint.
    session = registry.get(session["session_id"]) or session
    context = context_store.create_for_event(session, raw_event)

    codex_start = codex.prepare_request(session["session_id"], context["context_id"])
    session = codex.bind_thread(session["session_id"], "sim-codex-thread-001")
    context = context_store.create_for_event(session, raw_event)
    codex_turn = codex.prepare_request(session["session_id"], context["context_id"])

    claude_start = claude.prepare_request(session["session_id"], context["context_id"], role="verifier")
    session = claude.bind_session(
        session["session_id"],
        "sim-claude-session-001",
        claude_agent_id="sim-claude-agent-verifier-001",
    )
    context = context_store.create_for_event(session, raw_event)
    claude_resume = claude.prepare_request(session["session_id"], context["context_id"], role="verifier")

    build_gate_action = build_action(
        tool="ams_codex.prepare_codex",
        endpoint=None,
        method="READ",
        payload={"session_id": session["session_id"], "context_id": context["context_id"]},
        risk_flags=["non_trivial"],
    )
    build_gate = gate.check(build_gate_action)

    egress_gate_action = build_action(
        tool="discord_client.send",
        endpoint=f"/channels/{raw_event.get('channel_id')}/messages",
        method="POST",
        payload={"session_id": session["session_id"], "simulation": True},
        channel_id=str(raw_event.get("channel_id") or ""),
        risk_flags=["egress"],
    )
    egress_gate = gate.check(egress_gate_action)
    replay = ReplayChecker(store).check()

    return {
        "created_session": created,
        "session_id": session["session_id"],
        "context_id": context["context_id"],
        "checkpoint_id": checkpoint["summary_checkpoint_id"],
        "codex": {
            "start_method": codex_start["method"],
            "turn_method": codex_turn["method"],
            "thread_id": session.get("codex_thread_id"),
        },
        "claude": {
            "start_has_resume": "resume" in claude_start["options"],
            "resume_has_resume": claude_resume["options"].get("resume"),
            "session_id": session.get("claude_session_id"),
            "agent_id": session.get("claude_agent_id"),
        },
        "gates": {
            "build": build_gate,
            "egress": egress_gate,
        },
        "replay": replay,
    }


def run_full_simulation(
    raw_event: dict[str, Any],
    store: JsonStore | None = None,
    *,
    blast_radius_ensure_graph: bool = False,
) -> dict[str, Any]:
    store = store or JsonStore()
    registry = SessionRegistry(store)
    context_store = ContextStore(store)
    codex = CodexDryRunAdapter(store)
    trace = RunTraceStore(store)
    admission = AdmissionReviewStore(store)
    claims = ResourceClaimStore(store)
    provider_results = ProviderResultStore(store)
    predicates = PredicateStore(store)
    outbox = OutboxStore(store)

    session, created = registry.ingest_event(raw_event)
    session = codex.bind_thread(session["session_id"], "sim-codex-thread-m8g")
    context = context_store.create_for_event(session, raw_event)
    task_run = trace.create_run(
        session["session_id"],
        context["context_id"],
        actor="agent_b",
        provider="openai_codex",
        provider_surface="app-server",
        action="implement_and_verify",
        model="gpt-5.5",
        tool_scope=["Read", "ApplyPatch", "Tests"],
        sandbox="workspace-write",
    )
    capability_paths = ["ams_codex/simulation.py", "tests/test_m8g_full.py"]
    architecture_gate = _architecture_gate_for_task(store, task_run, capability_paths)
    blast_radius = _blast_radius_for_task(
        store,
        task_run,
        capability_paths,
        ensure_graph=blast_radius_ensure_graph,
    )
    capability_request = build_capability_request(
        actor="agent:agent_b",
        tier="builder",
        action="write",
        paths=capability_paths,
        tools=["Read", "ApplyPatch", "Tests"],
        egress_mode="ams_outbox",
        architecture_gate_review_id=architecture_gate["gate"]["architecture_gate_review_id"],
        architecture_audit_id=architecture_gate["audit"]["architecture_audit_id"],
        architecture_audit_sha256=architecture_gate["audit"]["architecture_audit_sha256"],
        blast_radius_review_id=blast_radius["blast_radius_review_id"],
        blast_radius_review_sha256=blast_radius["blast_radius_review_sha256"],
    )
    capability_verdict = evaluate_capability_request(capability_request)
    capability_review = admission.create(
        subject_kind="task_run",
        subject_id=task_run["task_run_id"],
        operation="capability.dispatch",
        request=capability_request,
        verdict=capability_verdict,
    )
    claim_result = claims.reserve(task_run["task_run_id"])
    claim = claim_result["claim"]
    if claim:
        claim = claims.transition(claim["resource_claim_id"], "active")
    dispatch_result = dispatch(store, task_run["task_run_id"])
    provider_result = provider_results.ingest(
        task_run["task_run_id"],
        status="ok",
        output_refs=["artifact://simulation/m8g-provider-output"],
        token_usage={"input": 128, "output": 64, "cached": 0},
        provider_msg_refs=["codex://sim-codex-thread-m8g/msg-001"],
    )
    predicate_result = predicates.evaluate_run(task_run["task_run_id"])
    outbox_item = outbox.create_item(
        task_run["task_run_id"],
        target="discord",
        channel_id=str(raw_event.get("channel_id") or "chan"),
        endpoint=f"/channels/{raw_event.get('channel_id') or 'chan'}/messages",
        payload={
            "content": "AMS M8G dry-run completed.",
            "task_run_id": task_run["task_run_id"],
        },
        admission_review_id=capability_review["admission_review_id"],
    )
    receipt = outbox.record_receipt(
        outbox_item["outbox_id"],
        status="readback_verified",
        response_payload={"message_id": "sim-discord-msg-m8g"},
        readback_ref=f"discord://{raw_event.get('channel_id') or 'chan'}/sim-discord-msg-m8g",
    )
    replay = ReplayChecker(store).check()
    final_run = trace.get_run(task_run["task_run_id"])
    return {
        "created_session": created,
        "session_id": session["session_id"],
        "context_id": context["context_id"],
        "task_run_id": task_run["task_run_id"],
        "capability_review_id": capability_review["admission_review_id"],
        "resource_claim_id": (claim or {}).get("resource_claim_id"),
        "dispatch": dispatch_result,
        "provider_result_id": provider_result["provider_result"]["provider_result_id"],
        "predicate": predicate_result,
        "outbox_id": outbox_item["outbox_id"],
        "outbox_nonce": outbox_item["nonce"],
        "receipt_id": receipt["outbox_receipt_id"],
        "final_state": (final_run or {}).get("state"),
        "replay": replay,
    }


def run_incident_simulation(
    raw_event: dict[str, Any],
    store: JsonStore | None = None,
    *,
    blast_radius_ensure_graph: bool = False,
) -> dict[str, Any]:
    store = store or JsonStore()
    registry = SessionRegistry(store)
    context_store = ContextStore(store)
    codex = CodexDryRunAdapter(store)
    trace = RunTraceStore(store)
    admission = AdmissionReviewStore(store)
    claims = ResourceClaimStore(store)
    provider_results = ProviderResultStore(store)

    session, created = registry.ingest_event(raw_event)
    session = codex.bind_thread(session["session_id"], "sim-codex-thread-incident")
    context = context_store.create_for_event(session, raw_event)
    task_run = trace.create_run(
        session["session_id"],
        context["context_id"],
        actor="agent_b",
        provider="openai_codex",
        provider_surface="app-server",
        action="simulate_provider_error",
        model="gpt-5.5",
        tool_scope=["Read", "ApplyPatch", "Tests"],
        sandbox="workspace-write",
    )
    capability_paths = ["ams_codex/simulation.py", "tests/test_m8h_incident_fixture.py"]
    architecture_gate = _architecture_gate_for_task(store, task_run, capability_paths)
    blast_radius = _blast_radius_for_task(
        store,
        task_run,
        capability_paths,
        ensure_graph=blast_radius_ensure_graph,
    )
    capability_request = build_capability_request(
        actor="agent:agent_b",
        tier="builder",
        action="write",
        paths=capability_paths,
        tools=["Read", "ApplyPatch", "Tests"],
        egress_mode="ams_outbox",
        architecture_gate_review_id=architecture_gate["gate"]["architecture_gate_review_id"],
        architecture_audit_id=architecture_gate["audit"]["architecture_audit_id"],
        architecture_audit_sha256=architecture_gate["audit"]["architecture_audit_sha256"],
        blast_radius_review_id=blast_radius["blast_radius_review_id"],
        blast_radius_review_sha256=blast_radius["blast_radius_review_sha256"],
    )
    capability_verdict = evaluate_capability_request(capability_request)
    capability_review = admission.create(
        subject_kind="task_run",
        subject_id=task_run["task_run_id"],
        operation="capability.dispatch",
        request=capability_request,
        verdict=capability_verdict,
    )
    claim_result = claims.reserve(task_run["task_run_id"])
    claim = claim_result["claim"]
    if claim:
        claim = claims.transition(claim["resource_claim_id"], "active")
    dispatch_result = dispatch(store, task_run["task_run_id"])
    provider_result = provider_results.ingest(
        task_run["task_run_id"],
        status="error",
        output_refs=["artifact://simulation/provider-error"],
        token_usage={"input": 64, "output": 0, "cached": 0},
        provider_msg_refs=["codex://sim-codex-thread-incident/msg-error"],
        source_class="trusted",
    )
    replay = ReplayChecker(store).check()
    final_run = trace.get_run(task_run["task_run_id"])
    incident = provider_result.get("incident") or {}
    return {
        "created_session": created,
        "session_id": session["session_id"],
        "context_id": context["context_id"],
        "task_run_id": task_run["task_run_id"],
        "capability_review_id": capability_review["admission_review_id"],
        "resource_claim_id": (claim or {}).get("resource_claim_id"),
        "dispatch": dispatch_result,
        "provider_result_id": provider_result["provider_result"]["provider_result_id"],
        "incident_packet_id": incident.get("incident_packet_id"),
        "ams_event_id": (incident.get("ids") or {}).get("ams_event_id"),
        "final_state": (final_run or {}).get("state"),
        "replay": replay,
    }


def _architecture_gate_for_task(
    store: JsonStore,
    task_run: dict[str, Any],
    paths: list[str],
) -> dict[str, Any]:
    audit = ArchitectureAuditStore(store).create(source_root=repo_root(), package_name="ams_codex")
    gate = ArchitectureGateStore(store).create(
        subject_kind="task_run",
        subject_id=task_run["task_run_id"],
        paths=paths,
        architecture_audit_id=audit["architecture_audit_id"],
    )
    return {"audit": audit, "gate": gate}


def _blast_radius_for_task(
    store: JsonStore,
    task_run: dict[str, Any],
    paths: list[str],
    *,
    ensure_graph: bool,
) -> dict[str, Any]:
    return BlastRadiusReviewStore(store).create(
        source_root=repo_root(),
        package_name="ams_codex",
        subject_kind="task_run",
        subject_id=task_run["task_run_id"],
        paths=paths,
        ensure_graph=ensure_graph,
        label="simulation-blast-radius",
    )
