from __future__ import annotations

from copy import deepcopy
from typing import Any

from .context_validation import validate_fresh_context
from .definition_registry import ensure_default_definitions_in_state, pin_definitions_to_task_run
from .models import AGENT_B, canonical_json, sha256_text, stable_id, utc_now
from .provider_bindings import find_provider_session
from .store import JsonStore
from .workspace import workspace_root


COMPLETED_STATES = {"completed"}
LEGACY_EVENT_STATE_TRANSITIONS = {
    "run_dispatched": "dispatched",
    "provider_started": "dispatched",
    "provider.started": "dispatched",
    "provider_landed": "landed",
    "provider.landed": "landed",
    "run_landed": "landed",
    "run.landed": "landed",
    "verified": "verified",
    "run.verified": "verified",
    "run_verified": "verified",
    "run.completed": "completed",
    "blocked": "blocked",
    "run.blocked": "blocked",
    "run_blocked": "blocked",
    "failed": "failed",
    "run.failed": "failed",
    "run_failed": "failed",
    "egress_deferred": "blocked",
    "egress.deferred": "blocked",
}
M8G_EVENT_STATE_TRANSITIONS = {
    "run.dispatch_intent": {"planned": "dispatching"},
    "run.dispatched": {"dispatching": "in_flight"},
    "run.timeout": {"in_flight": "failed"},
    "verify.passed": {"landed": "verified"},
    "verify.failed": {"landed": "failed"},
    "run.completed": {"verified": "completed"},
    "incident.opened": {
        "planned": "blocked",
        "dispatching": "blocked",
        "in_flight": "blocked",
        "dispatched": "blocked",
        "landed": "blocked",
        "failed": "blocked",
        "verified": "blocked",
    },
    "run.requeued": {"blocked": "planned"},
}


def _unique(values: list[Any]) -> list[Any]:
    result: list[Any] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def build_task_run(
    session: dict[str, Any],
    context: dict[str, Any],
    *,
    actor: str = AGENT_B,
    provider: str = "openai_codex",
    provider_surface: str | None = "app-server",
    action: str = "dispatch",
    cwd: str | None = None,
    model: str | None = None,
    tool_scope: list[str] | None = None,
    parent_run_id: str | None = None,
    requested_by: str = "agent:agent_b",
    attempt: int = 1,
    retry_of: str | None = None,
    method: str = "turn/start",
    sandbox: str = "read-only",
    gate_mode: str = "shadow_only",
    capability_snapshot_sha256: str | None = None,
) -> dict[str, Any]:
    validate_fresh_context(session, context)
    cwd = cwd or workspace_root()
    binding = find_provider_session(session, provider, provider_surface)
    if binding is None and provider_surface is None:
        binding = find_provider_session(session, provider)
    surface = provider_surface or (binding or {}).get("surface")
    now = utc_now()
    event_ids = list(session.get("event_ids") or [])
    lease = context.get("lease") or {}
    idempotency_key = stable_id(
        "idem",
        session["session_id"],
        context["context_id"],
        provider,
        surface,
        action,
        attempt,
    )
    task_run = {
        "schema_version": "ams.ams_codex.task_run.v0",
        "task_run_id": stable_id(
            "run",
            session["session_id"],
            context["context_id"],
            provider,
            surface,
            action,
            actor,
            now,
        ),
        "session_id": session["session_id"],
        "ams_task_id": session.get("ams_task_id"),
        "context_id": context["context_id"],
        "attention_id": session["attention_id"],
        "event_id": event_ids[-1] if event_ids else None,
        "parent_run_id": parent_run_id,
        "attempt": attempt,
        "retry_of": retry_of,
        "idempotency_key": idempotency_key,
        "actor": actor,
        "requested_by": requested_by,
        "lease_id": lease.get("lease_id") or session.get("lease_id"),
        "lease_holder": lease.get("holder") or session.get("lease_holder"),
        "lease_expires_at": lease.get("expires_at"),
        "lease_revision": None,
        "provider": provider,
        "provider_surface": surface,
        "provider_session_id": (binding or {}).get("provider_session_id"),
        "provider_agent_id": (binding or {}).get("provider_agent_id"),
        "provider_request_id": None,
        "provider_turn_id": (binding or {}).get("active_turn_id"),
        "method": method,
        "action": action,
        "state": "planned",
        "cwd": cwd,
        "sandbox": sandbox,
        "model": model,
        "tool_scope": tool_scope or [],
        "allowed_tools": tool_scope or [],
        "tool_definition_refs": [],
        "surface_definition_ref": None,
        "definition_snapshot_sha256": None,
        "pre_dispatch_gate_id": None,
        "tool_gate_ids": [],
        "pre_egress_gate_id": None,
        "gate_mode": gate_mode,
        "shadow_only": gate_mode == "shadow_only",
        "no_repeat_keys_checked": list(session.get("no_repeat_keys") or []),
        "no_repeat_verdict": "not_checked",
        "capability_snapshot_sha256": capability_snapshot_sha256,
        "input_context_sha256": sha256_text(canonical_json(context)),
        "summary_checkpoint_id": context.get("summary_checkpoint_id"),
        "compaction_epoch": int(context.get("compaction_epoch", 0) or 0),
        "source_refs": _unique(list(session.get("source_refs") or []) + list(context.get("source_refs") or [])),
        "artifact_refs": _unique(list(session.get("artifact_refs") or []) + list(context.get("artifact_refs") or [])),
        "receipts": [],
        "outcome": None,
        "error_class": None,
        "exit_status": None,
        "stdout_sha256": None,
        "stderr_sha256": None,
        "final_checkpoint_id": None,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "remaining_context_estimate": None,
        "duration_ms": None,
        "gate_wait_ms": None,
        "outbox_id": None,
        "delivery_status": "not_requested",
        "readback_ref": None,
        "readback_sha256": None,
        "started_at": None,
        "completed_at": None,
        "created_at": now,
        "updated_at": now,
    }
    return task_run


def build_run_event(
    task_run: dict[str, Any],
    *,
    sequence: int,
    event_type: str,
    payload: dict[str, Any] | None = None,
    previous_event_sha256: str | None = None,
    artifact_refs: list[str] | None = None,
    token_usage: dict[str, Any] | None = None,
    from_state: str | None = None,
    to_state: str | None = None,
    reason_codes: list[str] | None = None,
    risk_flags: list[str] | None = None,
) -> dict[str, Any]:
    payload = payload or {}
    event = {
        "schema_version": "ams.ams_codex.run_event.v0",
        "run_event_id": stable_id(
            "runevt",
            task_run["task_run_id"],
            sequence,
            event_type,
            payload,
            previous_event_sha256,
        ),
        "task_run_id": task_run["task_run_id"],
        "session_id": task_run["session_id"],
        "sequence": sequence,
        "event_type": event_type,
        "from_state": from_state,
        "to_state": to_state,
        "actor": task_run.get("actor"),
        "surface": task_run.get("provider_surface"),
        "payload": payload,
        "payload_sha256": sha256_text(canonical_json(payload)),
        "payload_summary": payload.get("summary") or payload.get("reason") or payload.get("state"),
        "artifact_refs": artifact_refs or [],
        "token_usage": token_usage or {},
        "reason_codes": reason_codes or [],
        "risk_flags": risk_flags or [],
        "previous_event_sha256": previous_event_sha256,
        "created_at": utc_now(),
    }
    event["event_sha256"] = sha256_text(canonical_json(event))
    return event


def _events_for_run_in_state(state: dict[str, Any], task_run_id: str) -> list[dict[str, Any]]:
    events = [
        event for event in (state.get("run_events") or {}).values()
        if event.get("task_run_id") == task_run_id
    ]
    return sorted((deepcopy(event) for event in events), key=lambda event: int(event.get("sequence", 0) or 0))


def _next_state(event_type: str, from_state: str, payload: dict[str, Any]) -> tuple[str, bool]:
    if from_state in COMPLETED_STATES:
        return from_state, event_type != "run.completed"
    if event_type == "result.ingested":
        if from_state != "in_flight":
            return "blocked", True
        status = str(payload.get("status") or "")
        return ("landed" if status == "ok" else "failed"), False
    allowed = M8G_EVENT_STATE_TRANSITIONS.get(event_type)
    if allowed is not None:
        if from_state in allowed:
            return allowed[from_state], False
        return "blocked", True
    return LEGACY_EVENT_STATE_TRANSITIONS.get(event_type, from_state), False


def append_run_event_to_state(
    state: dict[str, Any],
    task_run_id: str,
    event_type: str,
    *,
    payload: dict[str, Any] | None = None,
    artifact_refs: list[str] | None = None,
    token_usage: dict[str, Any] | None = None,
    reason_codes: list[str] | None = None,
    risk_flags: list[str] | None = None,
) -> dict[str, Any]:
    task_run = state.get("task_runs", {}).get(task_run_id)
    if not task_run:
        raise KeyError(f"unknown task_run_id: {task_run_id}")
    payload = payload or {}
    existing = _events_for_run_in_state(state, task_run_id)
    previous = existing[-1] if existing else None
    from_state = str(task_run.get("state") or "planned")
    to_state, illegal = _next_state(event_type, from_state, payload)
    actual_event_type = event_type
    actual_payload = payload
    actual_reason_codes = list(reason_codes or [])
    if illegal:
        actual_event_type = "trace.illegal_transition"
        actual_payload = {
            "attempted_event_type": event_type,
            "from_state": from_state,
            "reason": "illegal TaskRun state transition",
            "payload": payload,
        }
        actual_reason_codes.append("trace.illegal_transition")
        to_state = "blocked"
    event = build_run_event(
        task_run,
        sequence=len(existing) + 1,
        event_type=actual_event_type,
        payload=actual_payload,
        artifact_refs=artifact_refs,
        token_usage=token_usage,
        previous_event_sha256=previous.get("event_sha256") if previous else None,
        from_state=from_state,
        to_state=to_state,
        reason_codes=actual_reason_codes,
        risk_flags=risk_flags,
    )
    updated = deepcopy(task_run)
    updated["state"] = to_state
    if from_state == "planned" and to_state in {"dispatching", "dispatched", "in_flight"}:
        updated["started_at"] = event["created_at"]
    if to_state in {"completed", "failed", "blocked"}:
        updated["completed_at"] = event["created_at"]
    updated["artifact_refs"] = _unique(list(updated.get("artifact_refs") or []) + list(artifact_refs or []))
    if token_usage:
        input_tokens = token_usage.get("input_tokens", token_usage.get("input"))
        output_tokens = token_usage.get("output_tokens", token_usage.get("output"))
        cached_tokens = token_usage.get("cached_tokens", token_usage.get("cached"))
        if input_tokens is not None:
            updated["input_tokens"] = int(input_tokens)
        if output_tokens is not None:
            updated["output_tokens"] = int(output_tokens)
        total = token_usage.get("total_tokens")
        if total is None:
            total = int(input_tokens or 0) + int(output_tokens or 0) + int(cached_tokens or 0)
        updated["total_tokens"] = int(total)
    receipt = actual_payload.get("receipt") or actual_payload.get("receipt_ref")
    if receipt:
        updated["receipts"] = _unique(list(updated.get("receipts") or []) + [receipt])
    for field in (
        "provider_request_id",
        "provider_turn_id",
        "final_checkpoint_id",
        "outbox_id",
        "delivery_status",
        "readback_ref",
        "readback_sha256",
    ):
        if actual_payload.get(field) is not None:
            updated[field] = actual_payload[field]
    if actual_payload.get("error_class"):
        updated["error_class"] = actual_payload["error_class"]
    updated["updated_at"] = event["created_at"]
    state.setdefault("task_runs", {})[task_run_id] = updated
    state.setdefault("run_events", {})[event["run_event_id"]] = event
    return deepcopy(event)


class RunTraceStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create_run(
        self,
        session_id: str,
        context_id: str,
        *,
        actor: str = AGENT_B,
        provider: str = "openai_codex",
        provider_surface: str | None = "app-server",
        action: str = "dispatch",
        cwd: str | None = None,
        model: str | None = None,
        tool_scope: list[str] | None = None,
        parent_run_id: str | None = None,
        requested_by: str = "agent:agent_b",
        attempt: int = 1,
        retry_of: str | None = None,
        method: str = "turn/start",
        sandbox: str = "read-only",
        gate_mode: str = "shadow_only",
        capability_snapshot_sha256: str | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            session = state["sessions"].get(session_id)
            if not session:
                raise KeyError(f"unknown session_id: {session_id}")
            context = state["contexts"].get(context_id)
            if not context:
                raise KeyError(f"unknown context_id: {context_id}")
            if parent_run_id and parent_run_id not in state.get("task_runs", {}):
                raise KeyError(f"unknown parent_run_id: {parent_run_id}")
            task_run = build_task_run(
                session,
                context,
                actor=actor,
                provider=provider,
                provider_surface=provider_surface,
                action=action,
                cwd=cwd,
                model=model,
                tool_scope=tool_scope,
                parent_run_id=parent_run_id,
                requested_by=requested_by,
                attempt=attempt,
                retry_of=retry_of,
                method=method,
                sandbox=sandbox,
                gate_mode=gate_mode,
                capability_snapshot_sha256=capability_snapshot_sha256,
            )
            ensure_default_definitions_in_state(state)
            task_run = pin_definitions_to_task_run(state, task_run)
            state.setdefault("task_runs", {})[task_run["task_run_id"]] = deepcopy(task_run)
            event = build_run_event(
                task_run,
                sequence=1,
                event_type="run.created",
                from_state=None,
                to_state=task_run["state"],
                payload={
                    "state": task_run["state"],
                    "provider": provider,
                    "provider_surface": task_run.get("provider_surface"),
                    "provider_session_id": task_run.get("provider_session_id"),
                    "definition_snapshot_sha256": task_run.get("definition_snapshot_sha256"),
                },
            )
            state.setdefault("run_events", {})[event["run_event_id"]] = event
        result = deepcopy(task_run)
        result["initial_event"] = deepcopy(event)
        return result

    def append_event(
        self,
        task_run_id: str,
        event_type: str,
        *,
        payload: dict[str, Any] | None = None,
        artifact_refs: list[str] | None = None,
        token_usage: dict[str, Any] | None = None,
        reason_codes: list[str] | None = None,
        risk_flags: list[str] | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            event = append_run_event_to_state(
                state,
                task_run_id,
                event_type=event_type,
                payload=payload,
                artifact_refs=artifact_refs,
                token_usage=token_usage,
                reason_codes=reason_codes,
                risk_flags=risk_flags,
            )
        return deepcopy(event)

    def get_run(self, task_run_id: str) -> dict[str, Any] | None:
        return deepcopy(self.store.load().get("task_runs", {}).get(task_run_id))

    def _events_for_run(self, state: dict[str, Any], task_run_id: str) -> list[dict[str, Any]]:
        return _events_for_run_in_state(state, task_run_id)
