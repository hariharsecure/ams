from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import canonical_json, sha256_text, stable_id, utc_now
from .store import JsonStore


def build_ams_event(
    *,
    event_type: str,
    source: str,
    subject: str,
    data: dict[str, Any] | None = None,
    session_id: str | None = None,
    task_run_id: str | None = None,
    trace_id: str | None = None,
    span_id: str | None = None,
    dataschema: str | None = None,
    parent_event_id: str | None = None,
) -> dict[str, Any]:
    data = data or {}
    now = utc_now()
    event_id = stable_id("amsevt", source, event_type, subject, data, now)
    event = {
        "schema_version": "ams.ams.ams_event.v0",
        "specversion": "1.0",
        "id": event_id,
        "source": source,
        "type": event_type,
        "subject": subject,
        "time": now,
        "datacontenttype": "application/json",
        "dataschema": dataschema,
        "data": data,
        "data_sha256": sha256_text(canonical_json(data)),
        "trace_id": trace_id or stable_id("trace", session_id or source, subject),
        "span_id": span_id or stable_id("span", event_id),
        "session_id": session_id,
        "task_run_id": task_run_id,
        "parent_event_id": parent_event_id,
    }
    event["event_sha256"] = sha256_text(canonical_json(event))
    return event


class AMSEventStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def append(
        self,
        *,
        event_type: str,
        source: str,
        subject: str,
        data: dict[str, Any] | None = None,
        session_id: str | None = None,
        task_run_id: str | None = None,
        trace_id: str | None = None,
        span_id: str | None = None,
        dataschema: str | None = None,
        parent_event_id: str | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            if session_id and session_id not in state.get("sessions", {}):
                raise KeyError(f"unknown session_id: {session_id}")
            if task_run_id and task_run_id not in state.get("task_runs", {}):
                raise KeyError(f"unknown task_run_id: {task_run_id}")
            if session_id and task_run_id:
                task_run = state.get("task_runs", {}).get(task_run_id) or {}
                if task_run.get("session_id") != session_id:
                    raise ValueError("task_run does not belong to session_id")
            if parent_event_id and parent_event_id not in state.get("ams_events", {}):
                raise KeyError(f"unknown parent_event_id: {parent_event_id}")
            event = build_ams_event(
                event_type=event_type,
                source=source,
                subject=subject,
                data=data,
                session_id=session_id,
                task_run_id=task_run_id,
                trace_id=trace_id,
                span_id=span_id,
                dataschema=dataschema,
                parent_event_id=parent_event_id,
            )
            state.setdefault("ams_events", {})[event["id"]] = event
        return deepcopy(event)
