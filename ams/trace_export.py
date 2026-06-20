from __future__ import annotations

from typing import Any

from .models import stable_id
from .store import JsonStore


def export_trace_rows(state: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for task_run in sorted((state.get("task_runs") or {}).values(), key=lambda row: str(row.get("created_at"))):
        trace_id = stable_id("trace", task_run.get("session_id"), task_run.get("task_run_id"))
        rows.append(
            {
                "trace_id": trace_id,
                "span_id": task_run.get("task_run_id"),
                "parent_span_id": None,
                "name": "ams.task_run",
                "start_time": task_run.get("started_at") or task_run.get("created_at"),
                "end_time": task_run.get("completed_at"),
                "attributes": {
                    "ams.task_run.id": task_run.get("task_run_id"),
                    "ams.task_run.state": task_run.get("state"),
                    "gen_ai.provider.name": task_run.get("provider"),
                    "gen_ai.request.model": task_run.get("model"),
                    "ams.surface": task_run.get("provider_surface"),
                },
            }
        )
        events = sorted(
            [
                event for event in (state.get("run_events") or {}).values()
                if event.get("task_run_id") == task_run.get("task_run_id")
            ],
            key=lambda event: int(event.get("sequence", 0) or 0),
        )
        previous_span_id = task_run.get("task_run_id")
        for event in events:
            rows.append(
                {
                    "trace_id": trace_id,
                    "span_id": event.get("run_event_id"),
                    "parent_span_id": previous_span_id,
                    "name": f"ams.run_event.{event.get('event_type')}",
                    "start_time": event.get("created_at"),
                    "end_time": event.get("created_at"),
                    "attributes": {
                        "ams.run_event.sequence": event.get("sequence"),
                        "ams.run_event.from_state": event.get("from_state"),
                        "ams.run_event.to_state": event.get("to_state"),
                        "ams.reason_codes": event.get("reason_codes") or [],
                    },
                }
            )
            previous_span_id = event.get("run_event_id")
    for result in sorted((state.get("provider_results") or {}).values(), key=lambda row: str(row.get("ingested_at"))):
        task_run = (state.get("task_runs") or {}).get(result.get("task_run_id")) or {}
        trace_id = stable_id("trace", task_run.get("session_id"), result.get("task_run_id"))
        rows.append(
            {
                "trace_id": trace_id,
                "span_id": result.get("provider_result_id"),
                "parent_span_id": result.get("task_run_id"),
                "name": "gen_ai.provider.result",
                "start_time": result.get("started_at"),
                "end_time": result.get("ended_at"),
                "attributes": {
                    "gen_ai.provider.name": result.get("provider"),
                    "gen_ai.operation.name": task_run.get("method"),
                    "gen_ai.response.finish_reasons": [result.get("status")],
                    "gen_ai.usage.input_tokens": (result.get("token_usage") or {}).get("input"),
                    "gen_ai.usage.output_tokens": (result.get("token_usage") or {}).get("output"),
                    "gen_ai.usage.cached_tokens": (result.get("token_usage") or {}).get("cached"),
                    "ams.surface": result.get("surface"),
                    "ams.source_class": result.get("source_class"),
                },
            }
        )
    return rows


class TraceExporter:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def rows(self) -> list[dict[str, Any]]:
        return export_trace_rows(self.store.load())
