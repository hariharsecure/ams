from __future__ import annotations

from copy import deepcopy
from typing import Any

from .incident import open_incident_in_state
from .models import canonical_json, sha256_text, stable_id, utc_now
from .resource_claim import settle_claims_for_run_in_state
from .run_trace import append_run_event_to_state
from .store import JsonStore


PROVIDER_RESULT_STATUSES = {"ok", "error", "timeout", "refused"}


def _hash_provider_result(record: dict[str, Any]) -> str:
    material = dict(record)
    material.pop("sha256", None)
    return sha256_text(canonical_json(material))


def build_provider_result(
    task_run: dict[str, Any],
    *,
    status: str,
    output_refs: list[str] | None = None,
    token_usage: dict[str, Any] | None = None,
    est_cost_usd: float | None = None,
    provider_msg_refs: list[str] | None = None,
    started_at: str | None = None,
    ended_at: str | None = None,
    source_class: str = "trusted",
) -> dict[str, Any]:
    if status not in PROVIDER_RESULT_STATUSES:
        raise ValueError(f"invalid provider result status: {status}")
    now = utc_now()
    usage = token_usage or {}
    record = {
        "schema_version": "ams.ams.provider_result.v0",
        "provider_result_id": stable_id(
            "provres",
            task_run.get("task_run_id"),
            status,
            output_refs or [],
            provider_msg_refs or [],
            ended_at or now,
        ),
        "task_run_id": task_run.get("task_run_id"),
        "provider": task_run.get("provider"),
        "surface": task_run.get("provider_surface"),
        "status": status,
        "output_refs": output_refs or [],
        "token_usage": {
            "input": int(usage.get("input", usage.get("input_tokens", 0)) or 0),
            "output": int(usage.get("output", usage.get("output_tokens", 0)) or 0),
            "cached": int(usage.get("cached", usage.get("cached_tokens", 0)) or 0),
        },
        "est_cost_usd": est_cost_usd,
        "provider_session_id": task_run.get("provider_session_id"),
        "provider_msg_refs": provider_msg_refs or [],
        "started_at": started_at or task_run.get("started_at") or now,
        "ended_at": ended_at or now,
        "ingested_at": now,
        "source_class": source_class,
    }
    record["sha256"] = _hash_provider_result(record)
    return record


class ProviderResultStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def ingest(
        self,
        task_run_id: str,
        *,
        status: str,
        output_refs: list[str] | None = None,
        token_usage: dict[str, Any] | None = None,
        est_cost_usd: float | None = None,
        provider_msg_refs: list[str] | None = None,
        source_class: str = "trusted",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            task_run = state.get("task_runs", {}).get(task_run_id)
            if not task_run:
                raise KeyError(f"unknown task_run_id: {task_run_id}")
            record = build_provider_result(
                task_run,
                status=status,
                output_refs=output_refs,
                token_usage=token_usage,
                est_cost_usd=est_cost_usd,
                provider_msg_refs=provider_msg_refs,
                source_class=source_class,
            )
            state.setdefault("provider_results", {})[record["provider_result_id"]] = record
            event = append_run_event_to_state(
                state,
                task_run_id,
                "result.ingested",
                payload={
                    "provider_result_id": record["provider_result_id"],
                    "status": status,
                    "output_refs": record["output_refs"],
                },
                token_usage=record["token_usage"],
                reason_codes=[f"provider_result.{status}"],
            )
            incident = None
            if status in {"error", "timeout", "refused"}:
                incident = open_incident_in_state(
                    state,
                    trigger=f"provider_result.{status}",
                    task_run_id=task_run_id,
                    reason_codes=[f"provider_result.{status}"],
                )
                settle_claims_for_run_in_state(state, task_run_id)
            result = {"provider_result": deepcopy(record), "run_event": event}
            if incident:
                result["incident"] = incident
            return result
