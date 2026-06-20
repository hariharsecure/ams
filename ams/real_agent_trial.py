from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Any, Callable

from .agent_memory_sim import _default_input_events, _signal_packet, init_agent_sim_runtime
from .attention_router import AttentionRouterStore
from .models import hash_without as _hash_without, canonical_json, content_hash, sha256_text, stable_id, utc_now
from .store import JsonStore


PROBES = [
    {
        "probe_id": "training_failure",
        "required": ["track-a", "failed"],
    },
    {
        "probe_id": "surface_order_rca",
        "required_any_groups": [["rca"], ["channel-b", "channel_a"]],
    },
    {
        "probe_id": "direct_egress_rule",
        "required": ["outbox"],
        "required_any": ["readback", "direct"],
    },
]


def run_real_agent_smoke_trial(
    store: JsonStore | None = None,
    *,
    runtime_root: str | Path,
    approval_id: str,
    timeout_seconds: int = 180,
    runner: Callable[[list[str], Path, str, int], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    store = store or JsonStore()
    runtime = init_agent_sim_runtime(runtime_root, create_venvs=True)
    root = Path(runtime["runtime_root"])
    run_started_at = utc_now()
    real_root = root / "real_provider" / stable_id(
        "realrun",
        approval_id,
        run_started_at,
        str(time.time_ns()),
    )
    real_root.mkdir(parents=True, exist_ok=True)

    input_events = _default_input_events()
    signal_by_fact: dict[str, dict[str, Any]] = {}
    signal_ids: list[str] = []
    for event in input_events:
        signal = AttentionRouterStore(store).ingest(_signal_packet(event))
        signal_by_fact[event["fact_id"]] = signal
        signal_ids.append(signal["attention_signal_id"])

    run_command = runner or _run_command
    invocations: list[dict[str, Any]] = []
    for capsule in runtime["capsules"]:
        agent_name = capsule["agent_name"]
        cwd = Path(capsule["workspace"])
        for arm in ("raw_compacted", "ams_backed"):
            output_dir = real_root / agent_name / arm
            output_dir.mkdir(parents=True, exist_ok=True)
            prompt = _prompt_for_arm(arm, input_events, signal_by_fact)
            spec = _invocation_spec(agent_name, cwd, prompt, output_dir)
            started_at = utc_now()
            result = run_command(spec["argv"], cwd, prompt, timeout_seconds)
            ended_at = utc_now()
            stdout_path = output_dir / "stdout.txt"
            stderr_path = output_dir / "stderr.txt"
            prompt_path = output_dir / "prompt.txt"
            stdout_path.write_text(result.get("stdout", ""), encoding="utf-8")
            stderr_path.write_text(result.get("stderr", ""), encoding="utf-8")
            prompt_path.write_text(prompt, encoding="utf-8")
            extra_refs = _extra_invocation_refs(spec)
            parsed = _parse_agent_json(_parse_source_text(result.get("stdout", ""), spec))
            scores = _score_response(parsed)
            invocation = {
                "invocation_id": stable_id("realinv", agent_name, arm, started_at, spec["argv"]),
                "agent_name": agent_name,
                "provider": capsule["provider"],
                "provider_session_id": capsule["provider_session_id"],
                "arm": arm,
                "argv": spec["argv"],
                "cwd": str(cwd),
                "env_names": ["PATH", "HOME", "TERM"],
                "prompt_sha256": content_hash(prompt),
                "stdout_ref": str(stdout_path),
                "stdout_sha256": _file_sha(stdout_path),
                "stderr_ref": str(stderr_path),
                "stderr_sha256": _file_sha(stderr_path),
                "prompt_ref": str(prompt_path),
                "returncode": result.get("returncode"),
                "timed_out": bool(result.get("timed_out")),
                "elapsed_ms": int(result.get("elapsed_ms", 0)),
                "started_at": started_at,
                "ended_at": ended_at,
                "parsed_response": parsed,
                "scores": scores,
            }
            invocation.update(extra_refs)
            invocations.append(invocation)

    metrics = _metrics(invocations)
    now = utc_now()
    record = {
        "schema_version": "ams.ams.real_agent_trial.v0",
        "real_agent_trial_id": stable_id("realtrial", approval_id, signal_ids, metrics, str(real_root)),
        "approval_id": approval_id,
        "mode": "real_provider_smoke",
        "runtime_root": runtime["runtime_root"],
        "artifact_root": str(real_root),
        "attention_signal_ids": signal_ids,
        "invocations": invocations,
        "metrics": metrics,
        "process_start_allowed": True,
        "egress_actions": [],
        "created_at": now,
        "updated_at": now,
    }
    record["trial_sha256"] = _hash_without(record, "trial_sha256")
    (real_root / "real_agent_trial.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with store.locked() as state:
        state.setdefault("real_agent_trials", {})[record["real_agent_trial_id"]] = deepcopy(record)
        state.setdefault("indexes", {}).setdefault("real_agent_trial_ids", {})[
            record["real_agent_trial_id"]
        ] = record["real_agent_trial_id"]
    return deepcopy(record)


def validate_real_agent_trial_record(
    record: dict[str, Any],
    *,
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    expected_hash = record.get("trial_sha256")
    if expected_hash and expected_hash != _hash_without(record, "trial_sha256"):
        reason_codes.append("real_agent_trial.hash_mismatch")
    if record.get("process_start_allowed") is not True:
        reason_codes.append("real_agent_trial.process_start_not_recorded")
    if record.get("egress_actions") != []:
        reason_codes.append("real_agent_trial.egress_actions_not_empty")
    for invocation in record.get("invocations") or []:
        if not invocation.get("stdout_sha256") or not invocation.get("prompt_sha256"):
            reason_codes.append("real_agent_trial.invocation_missing_hashes")
    if state is not None:
        signals = state.get("attention_signals") or {}
        for signal_id in record.get("attention_signal_ids") or []:
            if signal_id not in signals:
                reason_codes.append(f"real_agent_trial.attention_signal_missing:{signal_id}")
    return {"ok": not reason_codes, "reason_codes": reason_codes}


def _prompt_for_arm(arm: str, events: list[dict[str, Any]], signals: dict[str, dict[str, Any]]) -> str:
    if arm == "raw_compacted":
        visible_events = events[-2:]
        context = [
            {
                "fact_id": event["fact_id"],
                "content": event["content"],
            }
            for event in visible_events
        ]
        note = "This is a compacted transcript packet; earlier facts are absent."
    else:
        context = [
            {
                "fact_id": fact_id,
                "route_domain": signal["route_domain"],
                "priority": signal["priority"],
                "source_ref": signal["source_ref"],
                "summary": _summary_for_fact(fact_id),
            }
            for fact_id, signal in signals.items()
        ]
        note = "This is AMS-backed attention memory; use these durable signals over transcript recall."
    return (
        "You are participating in an AMS memory smoke test. Do not use tools. "
        "Do not post to Discord. Return only compact JSON with this shape: "
        "{\"answers\":[{\"probe_id\":\"training_failure\",\"answer\":\"...\"},"
        "{\"probe_id\":\"surface_order_rca\",\"answer\":\"...\"},"
        "{\"probe_id\":\"direct_egress_rule\",\"answer\":\"...\"}],"
        "\"notes\":\"...\"}.\n\n"
        f"{note}\n\n"
        f"Context:\n{json.dumps(context, indent=2, sort_keys=True)}\n"
    )


def _invocation_spec(agent_name: str, cwd: Path, prompt: str, output_dir: Path) -> dict[str, Any]:
    if agent_name == "claude":
        return {
            "argv": [
                "claude",
                "--print",
                "--output-format",
                "json",
                "--tools",
                "",
                "--permission-mode",
                "dontAsk",
                "--safe-mode",
                "--max-budget-usd",
                "0.25",
                prompt,
            ]
        }
    output_file = output_dir / "last_message.json"
    return {
        "argv": [
            "codex",
            "exec",
            "--json",
            "--ephemeral",
            "--sandbox",
            "read-only",
            "--ignore-rules",
            "--skip-git-repo-check",
            "--cd",
            str(cwd),
            "--output-last-message",
            str(output_file),
            prompt,
        ],
        "last_message_path": str(output_file),
    }


def _run_command(argv: list[str], cwd: Path, _prompt: str, timeout_seconds: int) -> dict[str, Any]:
    env = {name: os.environ[name] for name in ("PATH", "HOME", "TERM") if name in os.environ}
    start = time.monotonic()
    try:
        completed = subprocess.run(
            argv,
            cwd=str(cwd),
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        return {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "timed_out": False,
            "elapsed_ms": int((time.monotonic() - start) * 1000),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "timed_out": True,
            "elapsed_ms": int((time.monotonic() - start) * 1000),
        }


def _parse_agent_json(text: str) -> dict[str, Any]:
    stripped = text.strip()
    candidates = [stripped]
    fallback: dict[str, Any] | None = None
    for line in reversed(stripped.splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            candidates.append(line)
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            nested_text = _nested_response_text(parsed)
            if nested_text:
                nested = _parse_agent_json(nested_text)
                if nested and not nested.get("parse_error"):
                    return nested
            if "answers" in parsed:
                return parsed
            fallback = fallback or parsed
    if fallback is not None:
        return fallback
    return {"parse_error": True, "raw_preview": stripped[:500]}


def _nested_response_text(parsed: dict[str, Any]) -> str | None:
    if isinstance(parsed.get("result"), str):
        return parsed["result"]
    item = parsed.get("item")
    if isinstance(item, dict) and isinstance(item.get("text"), str):
        return item["text"]
    return None


def _parse_source_text(stdout: str, spec: dict[str, Any]) -> str:
    last_message = spec.get("last_message_path")
    if last_message:
        path = Path(last_message)
        if path.exists():
            text = path.read_text(encoding="utf-8")
            if text.strip():
                return text
    return stdout


def _extra_invocation_refs(spec: dict[str, Any]) -> dict[str, str]:
    last_message = spec.get("last_message_path")
    if not last_message:
        return {}
    path = Path(last_message)
    return {
        "last_message_ref": str(path),
        "last_message_sha256": _file_sha(path),
    }


def _score_response(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    answers = parsed.get("answers") if isinstance(parsed, dict) else None
    by_probe: dict[str, str] = {}
    if isinstance(answers, list):
        for row in answers:
            if isinstance(row, dict):
                by_probe[str(row.get("probe_id"))] = str(row.get("answer") or "")
    scores: list[dict[str, Any]] = []
    for probe in PROBES:
        answer = by_probe.get(probe["probe_id"], "").lower()
        passed = all(term in answer for term in probe.get("required", []))
        if passed and probe.get("required_any"):
            passed = any(term in answer for term in probe["required_any"])
        if passed and probe.get("required_any_groups"):
            passed = all(any(term in answer for term in group) for group in probe["required_any_groups"])
        scores.append(
            {
                "probe_id": probe["probe_id"],
                "passed": bool(passed),
                "answer_sha256": content_hash(answer),
            }
        )
    return scores


def _metrics(invocations: list[dict[str, Any]]) -> dict[str, Any]:
    by_arm: dict[str, dict[str, int]] = {}
    for invocation in invocations:
        arm = invocation["arm"]
        scores = invocation.get("scores") or []
        passed = sum(1 for score in scores if score.get("passed"))
        by_arm.setdefault(arm, {"passed": 0, "total": 0, "invocations": 0})
        by_arm[arm]["passed"] += passed
        by_arm[arm]["total"] += len(scores)
        by_arm[arm]["invocations"] += 1
    for arm_metrics in by_arm.values():
        total = arm_metrics["total"]
        arm_metrics["pass_rate"] = arm_metrics["passed"] / total if total else 0.0
    return {
        "invocation_count": len(invocations),
        "by_arm": by_arm,
        "nonzero_invocations": sum(1 for row in invocations if row.get("returncode") not in {0, None}),
        "timed_out_invocations": sum(1 for row in invocations if row.get("timed_out")),
    }


def _summary_for_fact(fact_id: str) -> str:
    return {
        "track_a_failed": "Track-A failed around 13:24 UTC and did not auto-requeue after SIGUSR1 broken pipe.",
        "gateway_disconnect": "Discord gateway disconnected and resume/source sequencing must be tracked.",
        "channel_a_rca": "A #channel-a message arriving before #channel-b requires RCA for surface ordering.",
        "ams_status_scoped": "AMS status must stay scoped to signed engine and dry-run enforcement until approved.",
        "ams_outbox_only": "Agents must not post directly to Discord; use AMS outbox and readback receipt.",
    }.get(fact_id, fact_id)


def _file_sha(path: Path) -> str:
    if not path.exists():
        return content_hash("")
    return "sha256:" + __import__("hashlib").sha256(path.read_bytes()).hexdigest()
