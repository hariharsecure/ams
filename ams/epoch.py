from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
from typing import Any

from .ams_event import build_ams_event
from .models import canonical_json, sha256_text
from .replay import replay_check
from .store import JsonStore


TERMINAL_RUN_STATES = {"completed", "failed", "blocked"}
IN_FLIGHT_RUN_STATES = {"dispatching", "in_flight", "landed", "verified"}


class EpochCloseRefused(RuntimeError):
    def __init__(self, report: dict[str, Any]) -> None:
        super().__init__("epoch close refused")
        self.report = report


def build_epoch_report(state: dict[str, Any]) -> dict[str, Any]:
    replay = replay_check(state)
    errors = list(replay["errors"])
    sessions = state.get("sessions") or {}
    contexts = state.get("contexts") or {}
    task_runs = state.get("task_runs") or {}
    resource_claims = state.get("resource_claims") or {}
    incident_packets = state.get("incident_packets") or {}
    ams_events = state.get("ams_events") or {}
    outbox_items = state.get("outbox_items") or {}
    outbox_receipts = state.get("outbox_receipts") or {}

    claim_states = Counter(str(claim.get("state") or "unknown") for claim in resource_claims.values())
    claims_by_run: dict[str, list[dict[str, Any]]] = defaultdict(list)
    active_claims_by_run: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for claim in resource_claims.values():
        task_run_id = str(claim.get("task_run_id") or "")
        claims_by_run[task_run_id].append(claim)
        if claim.get("state") == "active":
            active_claims_by_run[task_run_id].append(claim)

    for task_run_id, task_run in task_runs.items():
        state_name = task_run.get("state")
        if state_name in TERMINAL_RUN_STATES and active_claims_by_run.get(task_run_id):
            errors.append(f"epoch terminal task_run {task_run_id} still has active resource_claim")
        if state_name in IN_FLIGHT_RUN_STATES and not active_claims_by_run.get(task_run_id):
            errors.append(f"epoch in-flight task_run {task_run_id} has no active resource_claim")
        session = sessions.get(task_run.get("session_id")) or {}
        if int(task_run.get("compaction_epoch", 0) or 0) > int(session.get("compaction_epoch", 0) or 0):
            errors.append(f"epoch task_run {task_run_id} has future compaction_epoch")

    for context_id, context in contexts.items():
        session = sessions.get(context.get("session_id")) or {}
        if int(context.get("session_revision", 0) or 0) > int(session.get("session_revision", 0) or 0):
            errors.append(f"epoch context {context_id} has future session_revision")
        if int(context.get("compaction_epoch", 0) or 0) > int(session.get("compaction_epoch", 0) or 0):
            errors.append(f"epoch context {context_id} has future compaction_epoch")

    receipts_by_outbox: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for receipt in outbox_receipts.values():
        receipts_by_outbox[str(receipt.get("outbox_id") or "")].append(receipt)
    open_outbox_items = []
    for outbox_id, item in outbox_items.items():
        if item.get("state") != "queued" and not receipts_by_outbox.get(outbox_id):
            errors.append(f"epoch outbox_item {outbox_id} terminal without receipt")
        if item.get("state") == "queued":
            open_outbox_items.append(outbox_id)

    for incident_id, incident in incident_packets.items():
        ams_event_id = (incident.get("ids") or {}).get("ams_event_id")
        if not ams_event_id or ams_event_id not in ams_events:
            errors.append(f"epoch incident_packet {incident_id} missing linked ams_event")

    summary = {
        "schema_version": "ams.ams.epoch_report.v0",
        "state_sha256": sha256_text(canonical_json(state)),
        "replay_ok": replay["ok"],
        "counts": replay["counts"],
        "claim_states": dict(sorted(claim_states.items())),
        "open_outbox_items": sorted(open_outbox_items),
        "sessions": len(sessions),
        "task_runs": len(task_runs),
        "incidents": len(incident_packets),
    }
    return {
        "ok": not errors,
        "errors": errors,
        "summary": summary,
        "summary_sha256": sha256_text(canonical_json(summary)),
    }


class EpochCloser:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def close(self, *, label: str = "manual") -> dict[str, Any]:
        try:
            with self.store.locked() as state:
                report = build_epoch_report(state)
                if not report["ok"]:
                    raise EpochCloseRefused(report)
                event = build_ams_event(
                    event_type="ams.ams.epoch.closed",
                    source="ams://kernel/epoch",
                    subject=label,
                    data={
                        "label": label,
                        "summary": report["summary"],
                        "summary_sha256": report["summary_sha256"],
                    },
                )
                state.setdefault("ams_events", {})[event["id"]] = event
        except EpochCloseRefused as exc:
            return {"closed": False, "report": exc.report}
        replay_after = replay_check(self.store.load())
        return {
            "closed": True,
            "epoch_event": deepcopy(event),
            "report": report,
            "replay_after": replay_after,
        }
