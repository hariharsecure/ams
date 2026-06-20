from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ams.real_agent_system_trial import RealAgentSystemTrialStore
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.store import JsonStore


class RealAgentSystemTrialTest(unittest.TestCase):
    def test_system_trial_records_no_discord_behavior_with_stub_runner(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            trial = RealAgentSystemTrialStore(store).create(
                source_root=Path(td),
                runtime_root=Path(td) / "runtime",
                label="test-real-agent-system",
                runner=_system_stub_runner,
            )

            self.assertEqual(trial["mode"], "no_discord_real_agent_system_trial")
            self.assertEqual(trial["execution_mode"], "stubbed_runner")
            self.assertEqual(trial["egress_actions"], [])
            self.assertFalse(trial["live_boundaries"]["discord_message_sent"])
            self.assertFalse(trial["live_boundaries"]["provider_cli_invoked"])
            self.assertFalse(trial["live_boundaries"]["raw_prompt_stored_in_ams_state"])
            self.assertEqual(trial["scenario_count"], 3)
            self.assertEqual(trial["invocation_count"], 12)
            self.assertEqual(len(trial["attention_signal_ids"]), 6)
            self.assertGreaterEqual(trial["metrics"]["ams_backed_pass_rate_delta"], 0.0)
            self.assertIn("real_agent_system_trial.stubbed_runner", trial["reason_codes"])
            for invocation in trial["invocations"]:
                self.assertFalse(invocation["raw_prompt_stored_in_ams_state"])
                self.assertFalse(invocation["raw_output_stored_in_ams_state"])
                kinds = {ref["kind"] for ref in invocation["artifact_refs"]}
                self.assertIn("action_map_json", kinds)
                self.assertIn("intermediate_map_json", kinds)
                self.assertIn("parsed_response_json", kinds)
            replay = ReplayChecker(store).check()
            self.assertTrue(replay["ok"], replay["errors"])

    def test_real_agent_command_specs_are_bounded_without_running_providers(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            seen_argv: list[list[str]] = []

            trial = RealAgentSystemTrialStore(store).create(
                source_root=Path(td),
                runtime_root=Path(td) / "runtime",
                label="test-real-agent-system-command-specs",
                allow_real_agents=True,
                runner=lambda argv, cwd, prompt, timeout: _recording_system_stub_runner(
                    seen_argv,
                    argv,
                    cwd,
                    prompt,
                    timeout,
                ),
            )

            self.assertEqual(trial["execution_mode"], "stubbed_runner")
            self.assertFalse(trial["live_boundaries"]["provider_cli_invoked"])
            self.assertEqual(len(seen_argv), 12)
            codex_argvs = [argv for argv in seen_argv if argv[:2] == ["codex", "exec"]]
            claude_argvs = [argv for argv in seen_argv if argv and argv[0] == "claude"]
            self.assertEqual(len(codex_argvs), 6)
            self.assertEqual(len(claude_argvs), 6)
            for argv in codex_argvs:
                self.assertIn("--json", argv)
                self.assertIn("--ephemeral", argv)
                self.assertIn("--sandbox", argv)
                self.assertIn("read-only", argv)
                self.assertIn("--ignore-rules", argv)
                self.assertIn("--skip-git-repo-check", argv)
                self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", argv)
            for argv in claude_argvs:
                self.assertIn("--print", argv)
                self.assertIn("--output-format", argv)
                self.assertIn("json", argv)
                self.assertNotIn("discord", " ".join(argv[:-1]).lower())
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_missing_system_trial_attention_signal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            trial = RealAgentSystemTrialStore(store).create(
                source_root=Path(td),
                runtime_root=Path(td) / "runtime",
                label="test-real-agent-system-missing-signal",
                runner=_system_stub_runner,
            )
            state = store.load()
            missing = trial["attention_signal_ids"][0]
            state["attention_signals"].pop(missing)
            state["indexes"]["attention_signal_ids"].pop(missing)
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("real_agent_system_trial.attention_signal_missing", "\n".join(replay["errors"]))

    def test_replay_catches_system_trial_hash_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            trial = RealAgentSystemTrialStore(store).create(
                source_root=Path(td),
                runtime_root=Path(td) / "runtime",
                label="test-real-agent-system-hash-tamper",
                runner=_system_stub_runner,
            )
            state = store.load()
            state["real_agent_system_trials"][trial["real_agent_system_trial_id"]]["status"] = "allow"
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("real_agent_system_trial.hash_mismatch", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_system_trials(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            RealAgentSystemTrialStore(store).create(
                source_root=Path(td),
                runtime_root=Path(td) / "runtime",
                label="test-real-agent-system-oracle",
                runner=_system_stub_runner,
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("real_agent_system_trials", collections)


def _system_stub_runner(argv: list[str], cwd: Path, prompt: str, timeout_seconds: int) -> dict:
    scenario = _scenario_from_prompt(prompt)
    ams_backed = '"arm": "ams_backed"' in prompt
    payload = _payload_for(scenario, ams_backed=ams_backed)
    return {
        "returncode": 0,
        "stdout": json.dumps(payload),
        "stderr": "",
        "timed_out": False,
        "elapsed_ms": 10,
    }


def _recording_system_stub_runner(
    seen_argv: list[list[str]],
    argv: list[str],
    cwd: Path,
    prompt: str,
    timeout_seconds: int,
) -> dict:
    seen_argv.append(list(argv))
    if argv and argv[:2] == ["codex", "exec"]:
        output_path = Path(argv[argv.index("--output-last-message") + 1])
        output_path.write_text(json.dumps(_payload_for(_scenario_from_prompt(prompt), ams_backed=True)), encoding="utf-8")
        return {
            "returncode": 0,
            "stdout": json.dumps({"type": "turn.completed"}),
            "stderr": "",
            "timed_out": False,
            "elapsed_ms": 10,
        }
    return _system_stub_runner(argv, cwd, prompt, timeout_seconds)


def _scenario_from_prompt(prompt: str) -> str:
    if "poultry farm controller" in prompt:
        return "attention_poultry_restart"
    if "A month ago I said build quietly" in prompt:
        return "memory_supersession_month_gap"
    if "apply a change to AMS source right now" in prompt:
        return "source_write_guard"
    return "unknown"


def _payload_for(scenario_id: str, *, ams_backed: bool) -> dict:
    if scenario_id == "attention_poultry_restart" and ams_backed:
        final = "ACK P0 water pump first; temperature is rising; lighting stays P4."
        blocked = "do not post to Discord or write source now"
    elif scenario_id == "memory_supersession_month_gap" and ams_backed:
        final = "Current memory supersedes stale quiet-build claim; present basis, validity, and ask operator before action."
        blocked = "do not build quietly now"
    elif scenario_id == "source_write_guard" and ams_backed:
        final = "Lease exists, but receipt and post-write replay are missing; do not perform source write."
        blocked = "do not bypass direct source-write guard"
    else:
        final = "Compacted view is incomplete; answer conservatively, avoid Discord, and ask for AMS context."
        blocked = "do not make external calls"
    return {
        "intent_summary": final,
        "signals_seen": [
            {
                "signal": scenario_id,
                "priority": "P1" if ams_backed else "unknown",
                "domain": "no_discord_emulation",
            }
        ],
        "importance_urgency": [
            {
                "item": scenario_id,
                "importance": "high" if ams_backed else "uncertain",
                "urgency": "now" if ams_backed else "unknown",
            }
        ],
        "memory_decisions": [
            {
                "claim": scenario_id,
                "decision": "supersede" if scenario_id == "memory_supersession_month_gap" and ams_backed else "ask_operator",
            }
        ],
        "proposed_actions": [
            {
                "action_id": "ack-or-defer",
                "kind": "analysis_only",
                "needs_approval": True,
                "authority": "AMS",
            }
        ],
        "blocked_actions": [{"action": blocked, "reason": "outside no-Discord trial boundary"}],
        "intermediate_map": [
            {
                "step": "read_signal_refs",
                "input_refs": ["no-discord://fixture"] if ams_backed else ["raw_compacted_context"],
                "decision": "rank attention before action",
                "output_ref": f"scenario:{scenario_id}",
            }
        ],
        "final_answer": final,
    }


if __name__ == "__main__":
    unittest.main()
