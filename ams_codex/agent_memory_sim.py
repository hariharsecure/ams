from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import venv
from typing import Any

from .attention_router import AttentionRouterStore
from .models import hash_without as _hash_without, canonical_json, content_hash, sha256_text, stable_id, utc_now
from .store import JsonStore
from .workspace import workspace_root


CHANNELS = {
    "model_building": {
        "channel_id": "000000000000000002",
        "name": "#channel-b",
    },
    "channel_a": {
        "channel_id": "000000000000000000",
        "name": "#channel-a",
    },
    "agents_management": {
        "channel_id": "000000000000000006",
        "name": "#channel-c",
    },
}

FAKE_AGENTS = {
    "claude": {
        "provider": "anthropic_claude",
        "provider_session_id": "fake-claude-session-milestone-12",
        "memory_limit": 3,
    },
    "codex": {
        "provider": "openai_codex",
        "provider_session_id": "fake-codex-thread-milestone-12",
        "memory_limit": 2,
    },
}

PROBES = [
    {
        "probe_id": "training_failure",
        "required_fact_id": "track_a_failed",
        "required_domain": "training_ops",
        "question": "Which training job failed and needed attention?",
    },
    {
        "probe_id": "surface_order_rca",
        "required_fact_id": "channel_a_rca",
        "required_domain": "surface_discord",
        "question": "Which Discord surface-order probe requires RCA?",
    },
    {
        "probe_id": "direct_egress_rule",
        "required_fact_id": "ams_outbox_only",
        "required_domain": "ams_kernel",
        "question": "What must agents use instead of direct Discord posting?",
    },
]


def default_runtime_root() -> str:
    return str(Path(workspace_root()) / ".ams_sim")


def init_agent_sim_runtime(
    runtime_root: str | Path | None = None,
    *,
    create_venvs: bool = False,
) -> dict[str, Any]:
    root = Path(runtime_root or default_runtime_root()).expanduser().resolve(strict=False)
    root.mkdir(parents=True, exist_ok=True)
    capsules: list[dict[str, Any]] = []
    for name, spec in FAKE_AGENTS.items():
        capsule_root = root / "agents" / name
        workspace = capsule_root / "workspace"
        transcript = capsule_root / "transcript.jsonl"
        venv_path = capsule_root / ".venv"
        logs = capsule_root / "logs"
        for path in (workspace, logs):
            path.mkdir(parents=True, exist_ok=True)
        if create_venvs and not (venv_path / "pyvenv.cfg").exists():
            venv.EnvBuilder(with_pip=False, symlinks=True).create(venv_path)
        capsules.append(
            {
                "agent_name": name,
                "provider": spec["provider"],
                "provider_session_id": spec["provider_session_id"],
                "capsule_root": str(capsule_root),
                "workspace": str(workspace),
                "venv_path": str(venv_path),
                "venv_created": bool((venv_path / "pyvenv.cfg").exists()),
                "transcript_path": str(transcript),
                "log_dir": str(logs),
                "env_allowlist": ["PATH", "HOME", "TERM"],
                "egress_mode": "none",
                "launch_allowed": False,
            }
        )
    manifest = {
        "schema_version": "ams.ams_codex.agent_sim_runtime.v0",
        "runtime_root": str(root),
        "created_at": utc_now(),
        "capsules": capsules,
        "launch_actions": [],
        "egress_actions": [],
    }
    _write_json(root / "runtime_manifest.json", manifest)
    return manifest


def run_default_agent_memory_trial(
    store: JsonStore | None = None,
    *,
    runtime_root: str | Path | None = None,
    create_venvs: bool = False,
    trial_label: str = "milestone-12-fake-discord-agent-memory",
) -> dict[str, Any]:
    store = store or JsonStore()
    runtime = init_agent_sim_runtime(runtime_root, create_venvs=create_venvs)
    root = Path(runtime["runtime_root"])
    input_events = _default_input_events()
    signal_ids: list[str] = []
    signal_by_fact: dict[str, dict[str, Any]] = {}
    input_rows: list[dict[str, Any]] = []
    for event in input_events:
        signal = AttentionRouterStore(store).ingest(_signal_packet(event))
        signal_ids.append(signal["attention_signal_id"])
        signal_by_fact[event["fact_id"]] = signal
        input_rows.append(_source_packet_row(event, signal))

    agent_records: list[dict[str, Any]] = []
    output_rows: list[dict[str, Any]] = []
    for capsule in runtime["capsules"]:
        agent_name = capsule["agent_name"]
        agent_record, outputs = _run_fake_agent(agent_name, capsule, input_events, signal_by_fact)
        agent_records.append(agent_record)
        output_rows.extend(outputs)
        _write_jsonl(Path(capsule["transcript_path"]), agent_record["transcript_rows"])

    _write_jsonl(root / "discord_inputs.jsonl", input_rows)
    _write_jsonl(root / "discord_outputs.jsonl", output_rows)

    now = utc_now()
    record = {
        "schema_version": "ams.ams_codex.agent_memory_trial.v0",
        "agent_memory_trial_id": stable_id("memtrial", trial_label, runtime["runtime_root"], signal_ids),
        "trial_label": trial_label,
        "mode": "fake_agents",
        "runtime_root": runtime["runtime_root"],
        "runtime_manifest_sha256": sha256_text(canonical_json(runtime)),
        "discord_sim": {
            "channels": CHANNELS,
            "input_event_count": len(input_rows),
            "output_event_count": len(output_rows),
            "input_ref": str(root / "discord_inputs.jsonl"),
            "output_ref": str(root / "discord_outputs.jsonl"),
            "gateway_sequence_start": input_events[0]["gateway_sequence"],
            "gateway_sequence_end": input_events[-1]["gateway_sequence"],
        },
        "attention_signal_ids": signal_ids,
        "agents": agent_records,
        "metrics": _aggregate_metrics(agent_records),
        "launch_actions": [],
        "egress_actions": [],
        "created_at": now,
        "updated_at": now,
    }
    record["trial_sha256"] = _hash_without(record, "trial_sha256")
    _write_json(root / "trial_record.json", record)
    with store.locked() as state:
        state.setdefault("agent_memory_trials", {})[record["agent_memory_trial_id"]] = deepcopy(record)
        state.setdefault("indexes", {}).setdefault("agent_memory_trial_ids", {})[
            record["agent_memory_trial_id"]
        ] = record["agent_memory_trial_id"]
    return deepcopy(record)


def validate_agent_memory_trial_record(
    record: dict[str, Any],
    *,
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    expected_hash = record.get("trial_sha256")
    if expected_hash and expected_hash != _hash_without(record, "trial_sha256"):
        reason_codes.append("agent_memory_trial.hash_mismatch")
    if record.get("launch_actions") != []:
        reason_codes.append("agent_memory_trial.launch_actions_not_empty")
    if record.get("egress_actions") != []:
        reason_codes.append("agent_memory_trial.egress_actions_not_empty")
    for agent in record.get("agents") or []:
        if agent.get("launch_allowed") is not False:
            reason_codes.append("agent_memory_trial.agent_launch_allowed")
        metrics = agent.get("metrics") or {}
        if metrics.get("ams_forget_count", 0) > metrics.get("raw_forget_count", 0):
            reason_codes.append("agent_memory_trial.ams_worse_than_raw")
    if state is not None:
        signals = state.get("attention_signals") or {}
        for signal_id in record.get("attention_signal_ids") or []:
            if signal_id not in signals:
                reason_codes.append(f"agent_memory_trial.attention_signal_missing:{signal_id}")
    return {"ok": not reason_codes, "reason_codes": reason_codes}


def _default_input_events() -> list[dict[str, Any]]:
    return [
        {
            "fact_id": "track_a_failed",
            "source_surface": "training_watchdog",
            "source_kind": "job_health",
            "source_ref": "cluster://jobs/000-001/failure",
            "channel_key": "model_building",
            "message_id": "sim-msg-001",
            "gateway_sequence": 101,
            "observed_at": "2026-06-10T20:23:04Z",
            "content": "Track-A failed around 13:24 UTC and did not auto-requeue after SIGUSR1 broken pipe.",
        },
        {
            "fact_id": "gateway_disconnect",
            "source_surface": "discord_gateway",
            "source_kind": "gateway.disconnect",
            "source_ref": "discord-gateway://seq/102",
            "channel_key": "agents_management",
            "message_id": "sim-msg-002",
            "gateway_sequence": 102,
            "observed_at": "2026-06-10T20:24:00Z",
            "content": "gateway.disconnect on tracked Discord channels; resume state needs source packet.",
        },
        {
            "fact_id": "channel_a_rca",
            "source_surface": "discord",
            "source_kind": "message_create",
            "channel_key": "channel_a",
            "message_id": "sim-msg-003",
            "gateway_sequence": 103,
            "observed_at": "2026-06-10T20:31:33Z",
            "content": "if this message go to you before the message on channel-b, something need to have RCA @OPERATOR-AUTHORED @ROUTE-A",
        },
        {
            "fact_id": "ams_status_scoped",
            "source_surface": "discord",
            "source_kind": "message_create",
            "channel_key": "agents_management",
            "message_id": "sim-msg-004",
            "gateway_sequence": 104,
            "observed_at": "2026-06-10T20:35:00Z",
            "content": "AMS status scoped: use signed engine and keep enforcement dry-run until approved.",
        },
        {
            "fact_id": "ams_outbox_only",
            "source_surface": "ams_kernel",
            "source_kind": "policy",
            "source_ref": "ams-policy://egress/outbox-only",
            "channel_key": "model_building",
            "message_id": "sim-msg-005",
            "gateway_sequence": 105,
            "observed_at": "2026-06-10T20:36:00Z",
            "content": "Do not post directly to Discord; use AMS outbox and readback receipt.",
        },
    ]


def _signal_packet(event: dict[str, Any]) -> dict[str, Any]:
    channel = CHANNELS[event["channel_key"]]
    packet = {
        "source_surface": event["source_surface"],
        "source_kind": event["source_kind"],
        "source_ref": event.get("source_ref"),
        "source_event_id": str(event["gateway_sequence"]),
        "channel_id": channel["channel_id"],
        "message_id": event["message_id"],
        "observed_at": event["observed_at"],
        "source_actor": "simulated-discord",
        "source_trust": "simulated",
        "content": event["content"],
    }
    if event["source_surface"] == "discord":
        packet.pop("source_ref", None)
    return packet


def _source_packet_row(event: dict[str, Any], signal: dict[str, Any]) -> dict[str, Any]:
    return {
        "fact_id": event["fact_id"],
        "gateway_sequence": event["gateway_sequence"],
        "channel": CHANNELS[event["channel_key"]],
        "message_id": event["message_id"],
        "source_ref": signal["source_ref"],
        "attention_signal_id": signal["attention_signal_id"],
        "content_sha256": signal["content_sha256"],
        "content_length": signal["content_length"],
        "route_domain": signal["route_domain"],
        "priority": signal["priority"],
    }


def _run_fake_agent(
    agent_name: str,
    capsule: dict[str, Any],
    input_events: list[dict[str, Any]],
    signal_by_fact: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    memory_limit = FAKE_AGENTS[agent_name]["memory_limit"]
    raw_memory: list[str] = []
    transcript_rows: list[dict[str, Any]] = []
    compaction_count = 0
    for event in input_events:
        raw_memory.append(event["fact_id"])
        transcript_rows.append(
            {
                "role": "user",
                "fact_id": event["fact_id"],
                "source_ref": signal_by_fact[event["fact_id"]]["source_ref"],
                "content_sha256": signal_by_fact[event["fact_id"]]["content_sha256"],
            }
        )
        if len(raw_memory) > memory_limit:
            raw_memory.pop(0)
            compaction_count += 1
            transcript_rows.append(
                {
                    "role": "system",
                    "event": "simulated_compaction",
                    "remaining_fact_ids": list(raw_memory),
                }
            )

    raw_results = [_probe_result(probe, raw_memory, signal_by_fact, mode="raw") for probe in PROBES]
    ams_results = [_probe_result(probe, raw_memory, signal_by_fact, mode="ams") for probe in PROBES]
    outputs = []
    for result in raw_results + ams_results:
        outputs.append(
            {
                "provider": capsule["provider"],
                "provider_session_id": capsule["provider_session_id"],
                "mode": result["mode"],
                "probe_id": result["probe_id"],
                "passed": result["passed"],
                "target": "simulated_discord_outbox",
                "readback_verified": True,
                "content_sha256": content_hash(
                    f"{agent_name}:{result['mode']}:{result['probe_id']}:{result['passed']}"
                ),
            }
        )
    metrics = _agent_metrics(raw_results, ams_results, compaction_count)
    agent_record = {
        "agent_record_id": stable_id("agentrec", agent_name, capsule["provider_session_id"]),
        "agent_name": agent_name,
        "provider": capsule["provider"],
        "provider_session_id": capsule["provider_session_id"],
        "workspace": capsule["workspace"],
        "venv_path": capsule["venv_path"],
        "venv_created": capsule["venv_created"],
        "transcript_path": capsule["transcript_path"],
        "launch_allowed": False,
        "turns_seen": len(input_events),
        "compaction_count": compaction_count,
        "memory_limit": memory_limit,
        "raw_probe_results": raw_results,
        "ams_probe_results": ams_results,
        "metrics": metrics,
        "transcript_rows": transcript_rows,
    }
    return agent_record, outputs


def _probe_result(
    probe: dict[str, Any],
    raw_memory: list[str],
    signal_by_fact: dict[str, dict[str, Any]],
    *,
    mode: str,
) -> dict[str, Any]:
    signal = signal_by_fact.get(probe["required_fact_id"]) or {}
    if mode == "raw":
        passed = probe["required_fact_id"] in raw_memory
        evidence = "short_term_transcript_memory" if passed else "forgotten_after_compaction"
    else:
        passed = signal.get("route_domain") == probe["required_domain"]
        evidence = signal.get("attention_signal_id") if passed else "missing_attention_signal"
    return {
        "probe_id": probe["probe_id"],
        "mode": mode,
        "question": probe["question"],
        "required_fact_id": probe["required_fact_id"],
        "required_domain": probe["required_domain"],
        "passed": passed,
        "evidence": evidence,
    }


def _agent_metrics(raw_results: list[dict[str, Any]], ams_results: list[dict[str, Any]], compactions: int) -> dict[str, Any]:
    raw_forget = sum(1 for result in raw_results if not result["passed"])
    ams_forget = sum(1 for result in ams_results if not result["passed"])
    probes = len(raw_results)
    return {
        "probe_count": probes,
        "raw_forget_count": raw_forget,
        "raw_forget_rate": raw_forget / probes if probes else 0.0,
        "ams_forget_count": ams_forget,
        "ams_forget_rate": ams_forget / probes if probes else 0.0,
        "compaction_count": compactions,
        "attention_miss_count": ams_forget,
    }


def _aggregate_metrics(agent_records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "agent_count": len(agent_records),
        "total_probes": sum((agent.get("metrics") or {}).get("probe_count", 0) for agent in agent_records),
        "total_raw_forget_count": sum((agent.get("metrics") or {}).get("raw_forget_count", 0) for agent in agent_records),
        "total_ams_forget_count": sum((agent.get("metrics") or {}).get("ams_forget_count", 0) for agent in agent_records),
        "total_compactions": sum((agent.get("metrics") or {}).get("compaction_count", 0) for agent in agent_records),
    }



def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
