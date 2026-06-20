from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import canonical_json, sha256_text
from .resource_claim import settle_claims_for_run_in_state
from .run_trace import append_run_event_to_state
from .incident import open_incident_in_state
from .store import JsonStore
from .workspace import workspace_root


CHECK_TYPES = {
    "file_exists",
    "hash_matches",
    "command_exit_0",
    "command_output_matches",
    "test_passes",
    "record_exists",
    "json_state_matches",
    "git_state",
    "http_ok",
}


def end_state_hash(end_state: dict[str, Any]) -> str:
    return sha256_text(canonical_json(end_state))


def default_intent(*, requested_action: str, constraints: list[str]) -> dict[str, Any]:
    end_state = {
        "type": "all",
        "checks": [
            {
                "id": "provider_result_ok",
                "type": "record_exists",
                "args": {
                    "collection": "provider_results",
                    "where": {
                        "task_run_id": "@task_run_id",
                        "status": "ok",
                    },
                },
            }
        ],
    }
    return {
        "purpose": requested_action or "complete AMS dry-run task",
        "constraints": list(constraints),
        "two_up_context": "AMS owns continuity; provider workers execute bounded turns from this context.",
        "end_state": end_state,
        "deadline_s": 3600,
        "on_fail": "halt_and_escalate",
    }


def evaluate_end_state(
    end_state: dict[str, Any],
    *,
    state: dict[str, Any],
    task_run: dict[str, Any],
    workspace: str | None = None,
) -> dict[str, Any]:
    evidence = _evaluate_node(end_state, state=state, task_run=task_run, workspace=workspace)
    return {
        "passed": evidence["status"] == "pass",
        "evidence": _flatten_evidence(evidence),
        "root": evidence,
    }


def _evaluate_node(
    node: dict[str, Any],
    *,
    state: dict[str, Any],
    task_run: dict[str, Any],
    workspace: str | None,
) -> dict[str, Any]:
    node_type = str(node.get("type") or "")
    if node_type in {"all", "any"}:
        children = [
            _evaluate_node(child, state=state, task_run=task_run, workspace=workspace)
            for child in node.get("checks") or []
        ]
        if not children:
            return _evidence(node, "fail", reason="no checks")
        statuses = [child["status"] for child in children]
        passed = all(status == "pass" for status in statuses) if node_type == "all" else any(
            status == "pass" for status in statuses
        )
        return _evidence(node, "pass" if passed else "fail", children=children)
    if node_type not in CHECK_TYPES:
        return _evidence(node, "fail", reason=f"unknown check type: {node_type}")
    try:
        return _evaluate_check(node, state=state, task_run=task_run, workspace=workspace)
    except Exception as exc:  # pragma: no cover - caller turns this into an IncidentPacket.
        return _evidence(node, "crash", reason=f"{type(exc).__name__}: {exc}")


def _evaluate_check(
    node: dict[str, Any],
    *,
    state: dict[str, Any],
    task_run: dict[str, Any],
    workspace: str | None,
) -> dict[str, Any]:
    check_type = str(node.get("type"))
    args = node.get("args") or {}
    if check_type == "record_exists":
        collection = str(args.get("collection") or "")
        records = state.get(collection) or {}
        where = {key: _resolve_placeholder(value, task_run) for key, value in (args.get("where") or {}).items()}
        matches = [
            record_id for record_id, record in records.items()
            if isinstance(record, dict) and all(record.get(key) == value for key, value in where.items())
        ]
        return _evidence(
            node,
            "pass" if matches else "fail",
            details={"collection": collection, "matched_ids": matches},
        )
    if check_type == "json_state_matches":
        record = _select_record(args, state, task_run)
        expected = _resolve_placeholder(args.get("equals"), task_run)
        actual = _dig(record, args.get("path") or [])
        return _evidence(
            node,
            "pass" if actual == expected else "fail",
            details={"actual": actual, "expected": expected},
        )
    if check_type == "file_exists":
        path = _safe_workspace_path(str(args.get("path") or ""), workspace)
        return _evidence(node, "pass" if path.exists() else "fail", details={"path": str(path)})
    if check_type == "hash_matches":
        path = _safe_workspace_path(str(args.get("path") or ""), workspace)
        expected = str(args.get("sha256") or "")
        if not path.is_file():
            return _evidence(node, "fail", details={"path": str(path), "reason": "missing file"})
        actual = sha256_text(path.read_text(encoding="utf-8"))
        return _evidence(node, "pass" if actual == expected else "fail", details={"path": str(path), "actual": actual})
    return _evidence(node, "fail", reason=f"{check_type} is defined but not enabled in local M8G dry-run")


def _select_record(args: dict[str, Any], state: dict[str, Any], task_run: dict[str, Any]) -> dict[str, Any]:
    collection = str(args.get("collection") or "")
    records = state.get(collection) or {}
    record_id = _resolve_placeholder(args.get("record_id"), task_run)
    if record_id:
        record = records.get(str(record_id))
        return record if isinstance(record, dict) else {}
    where = {key: _resolve_placeholder(value, task_run) for key, value in (args.get("where") or {}).items()}
    for record in records.values():
        if isinstance(record, dict) and all(record.get(key) == value for key, value in where.items()):
            return record
    return {}


def _resolve_placeholder(value: Any, task_run: dict[str, Any]) -> Any:
    if value == "@task_run_id":
        return task_run.get("task_run_id")
    if value == "@session_id":
        return task_run.get("session_id")
    if value == "@context_id":
        return task_run.get("context_id")
    return value


def _dig(record: dict[str, Any], path: list[Any] | str) -> Any:
    parts = path.split(".") if isinstance(path, str) else list(path)
    value: Any = record
    for part in parts:
        if isinstance(value, dict):
            value = value.get(str(part))
        else:
            return None
    return value


def _safe_workspace_path(path: str, workspace: str | None) -> Path:
    root = Path(workspace or workspace_root()).expanduser().resolve(strict=False)
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"predicate path outside workspace: {path}") from exc
    return candidate


def _evidence(
    node: dict[str, Any],
    status: str,
    *,
    reason: str | None = None,
    details: dict[str, Any] | None = None,
    children: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    evidence = {
        "predicate_id": node.get("id") or node.get("type"),
        "type": node.get("type"),
        "status": status,
    }
    if reason:
        evidence["reason"] = reason
    if details:
        evidence["details"] = details
    if children is not None:
        evidence["children"] = children
    return evidence


def _flatten_evidence(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    children = evidence.get("children") or []
    if not children:
        return [evidence]
    flattened = [dict(evidence, children=len(children))]
    for child in children:
        flattened.extend(_flatten_evidence(child))
    return flattened


class PredicateStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def evaluate_run(self, task_run_id: str) -> dict[str, Any]:
        with self.store.locked() as state:
            task_run = state.get("task_runs", {}).get(task_run_id)
            if not task_run:
                raise KeyError(f"unknown task_run_id: {task_run_id}")
            context = state.get("contexts", {}).get(task_run.get("context_id"))
            if not context:
                raise KeyError(f"missing context for task_run_id: {task_run_id}")
            intent = context.get("intent") or {}
            end_state = intent.get("end_state") or {}
            result = evaluate_end_state(end_state, state=state, task_run=task_run, workspace=task_run.get("cwd"))
            crashed = any(row.get("status") == "crash" for row in result["evidence"])
            if crashed:
                incident = open_incident_in_state(
                    state,
                    trigger="predicate.evaluation_crash",
                    task_run_id=task_run_id,
                    predicate_results=result["evidence"],
                    reason_codes=["predicate.evaluation_crash"],
                )
                settled = settle_claims_for_run_in_state(state, task_run_id)
                return {
                    "passed": False,
                    "crashed": True,
                    "predicate": result,
                    "incident": incident,
                    "settled_claims": settled,
                }
            if result["passed"]:
                passed_event = append_run_event_to_state(
                    state,
                    task_run_id,
                    "verify.passed",
                    payload={"predicate_results": result["evidence"]},
                    reason_codes=["predicate.passed"],
                )
                completed_event = append_run_event_to_state(
                    state,
                    task_run_id,
                    "run.completed",
                    payload={"summary": "end-state predicate passed"},
                    reason_codes=["run.completed"],
                )
                settled = settle_claims_for_run_in_state(state, task_run_id)
                return {
                    "passed": True,
                    "crashed": False,
                    "predicate": result,
                    "events": [passed_event, completed_event],
                    "settled_claims": settled,
                }
            failed_event = append_run_event_to_state(
                state,
                task_run_id,
                "verify.failed",
                payload={"predicate_results": result["evidence"]},
                reason_codes=["predicate.failed"],
            )
            settled = settle_claims_for_run_in_state(state, task_run_id)
            return {
                "passed": False,
                "crashed": False,
                "predicate": result,
                "events": [failed_event],
                "settled_claims": settled,
            }
