from __future__ import annotations

from copy import deepcopy
import tempfile
from pathlib import Path
from typing import Any

from .models import canonical_json, sha256_text
from .predicate import default_intent, evaluate_end_state
from .replay import replay_check
from .simulation import run_full_simulation
from .store import JsonStore, empty_state


FAULTS = ("none", "delete_provider_result", "delete_outbox_receipt", "activate_terminal_claim", "mutate_context")


def run_self_eval(*, cases: int = 20) -> dict[str, Any]:
    if cases < len(FAULTS):
        raise ValueError(f"cases must be >= {len(FAULTS)}")
    results = []
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        predicate_audit = _predicate_audit(root)
        for index in range(cases):
            fault = FAULTS[index % len(FAULTS)]
            store = JsonStore(root / f"case_{index:03d}.json")
            simulation = run_full_simulation(
                {"channel_id": "eval", "message_id": f"case-{index:03d}", "content": f"eval {index}"},
                store,
            )
            clean_state = store.load()
            evaluated_state = _apply_fault(clean_state, fault)
            replay = replay_check(evaluated_state)
            raw_reported_success = _raw_reported_success(evaluated_state)
            ams_verified_success = replay["ok"] and _raw_reported_success(evaluated_state)
            fault_injected = fault != "none"
            results.append(
                {
                    "case_id": f"eval_{index:03d}",
                    "fault": fault,
                    "fault_injected": fault_injected,
                    "raw": {
                        "reported_success": raw_reported_success,
                        "silent_failure": fault_injected and raw_reported_success,
                    },
                    "ams": {
                        "verified_success": ams_verified_success,
                        "detected_fault": fault_injected and not replay["ok"],
                        "silent_failure": fault_injected and replay["ok"],
                        "replay_ok": replay["ok"],
                        "first_error": replay["errors"][0] if replay["errors"] else None,
                    },
                    "task_run_id": simulation["task_run_id"],
                }
            )
    return {
        "schema_version": "ams.ams.self_eval.v0",
        "cases": cases,
        "faults": list(FAULTS),
        "predicate_audit": predicate_audit,
        "metrics": _metrics(results),
        "results": results,
    }


def _apply_fault(state: dict[str, Any], fault: str) -> dict[str, Any]:
    mutated = deepcopy(state)
    if fault == "none":
        return mutated
    if fault == "delete_provider_result":
        mutated["provider_results"] = {}
        return mutated
    if fault == "delete_outbox_receipt":
        mutated["outbox_receipts"] = {}
        return mutated
    if fault == "activate_terminal_claim":
        claim = next(iter(mutated.get("resource_claims", {}).values()))
        claim["state"] = "active"
        claim["released_at"] = None
        return mutated
    if fault == "mutate_context":
        context = next(iter(mutated.get("contexts", {}).values()))
        context["requested_action"] = "tampered_by_eval"
        return mutated
    raise ValueError(f"unknown fault: {fault}")


def _raw_reported_success(state: dict[str, Any]) -> bool:
    return any(run.get("state") == "completed" for run in (state.get("task_runs") or {}).values())


def _metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(results)
    faulted = [row for row in results if row["fault_injected"]]
    clean = [row for row in results if not row["fault_injected"]]
    raw_silent = [row for row in results if row["raw"]["silent_failure"]]
    ams_silent = [row for row in results if row["ams"]["silent_failure"]]
    ams_detected = [row for row in results if row["ams"]["detected_fault"]]
    ams_clean_success = [row for row in clean if row["ams"]["verified_success"]]
    verified_success_rate = len(ams_clean_success) / len(clean) if clean else 0.0
    return {
        "total_cases": total,
        "faulted_cases": len(faulted),
        "clean_cases": len(clean),
        "raw_silent_failures": len(raw_silent),
        "raw_silent_failure_rate": _rate(len(raw_silent), len(faulted)),
        "ams_silent_failures": len(ams_silent),
        "ams_silent_failure_rate": _rate(len(ams_silent), len(faulted)),
        "ams_detected_faults": len(ams_detected),
        "ams_fault_detection_rate": _rate(len(ams_detected), len(faulted)),
        "ams_clean_verified_successes": len(ams_clean_success),
        "ams_clean_verified_success_rate": round(verified_success_rate, 4),
        "ams_pass3_clean": round(verified_success_rate ** 3, 4),
    }


def _predicate_audit(root: Path) -> dict[str, Any]:
    end_state = default_intent(requested_action="self eval predicate audit", constraints=[])["end_state"]
    null_task_run = {"task_run_id": "run_null"}
    null_result = evaluate_end_state(end_state, state=empty_state(), task_run=null_task_run)
    reference_store = JsonStore(root / "predicate_reference.json")
    reference = run_full_simulation(
        {"channel_id": "eval", "message_id": "predicate-reference", "content": "predicate reference"},
        reference_store,
    )
    reference_state = reference_store.load()
    reference_task_run = reference_state["task_runs"][reference["task_run_id"]]
    reference_result = evaluate_end_state(end_state, state=reference_state, task_run=reference_task_run)
    return {
        "end_state_sha256": sha256_text(canonical_json(end_state)),
        "null_agent_passed": null_result["passed"],
        "reference_solution_passed": reference_result["passed"],
        "audited": (not null_result["passed"]) and reference_result["passed"],
    }


def _rate(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 4)
