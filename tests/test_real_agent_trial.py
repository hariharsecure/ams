from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ams.real_agent_trial import run_real_agent_smoke_trial
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.store import JsonStore


class RealAgentTrialTest(unittest.TestCase):
    def test_real_agent_smoke_trial_records_invocations_with_stub_runner(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            seen_argv: list[list[str]] = []

            trial = run_real_agent_smoke_trial(
                store,
                runtime_root=Path(td) / "runtime",
                approval_id="approval-test-real-agent",
                runner=lambda argv, cwd, prompt, timeout: _recording_stub_runner(
                    seen_argv,
                    argv,
                    cwd,
                    prompt,
                    timeout,
                ),
            )

            self.assertEqual(trial["mode"], "real_provider_smoke")
            self.assertTrue(trial["process_start_allowed"])
            self.assertEqual(trial["egress_actions"], [])
            self.assertIn("real_provider/realrun_", trial["artifact_root"])
            self.assertEqual(len(trial["invocations"]), 4)
            self.assertEqual(trial["metrics"]["nonzero_invocations"], 0)
            self.assertEqual(trial["metrics"]["timed_out_invocations"], 0)
            self.assertGreaterEqual(trial["metrics"]["by_arm"]["ams_backed"]["passed"], 6)
            self.assertTrue(ReplayChecker(store).check()["ok"])
            codex_argvs = [argv for argv in seen_argv if argv[:2] == ["codex", "exec"]]
            self.assertEqual(len(codex_argvs), 2)
            for argv in codex_argvs:
                self.assertIn("--sandbox", argv)
                self.assertIn("read-only", argv)
                self.assertIn("--ignore-rules", argv)
                self.assertIn("--skip-git-repo-check", argv)
                self.assertNotIn("--ask-for-approval", argv)
                self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", argv)

    def test_replay_keeps_failed_real_provider_attempt_as_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            trial = run_real_agent_smoke_trial(
                store,
                runtime_root=Path(td) / "runtime",
                approval_id="approval-test-real-agent-failed",
                runner=_failed_runner,
            )

            self.assertEqual(trial["metrics"]["nonzero_invocations"], 2)
            self.assertEqual(trial["metrics"]["timed_out_invocations"], 2)
            replay = ReplayChecker(store).check()
            self.assertTrue(replay["ok"], replay["errors"])

    def test_repeated_real_smoke_attempts_do_not_overwrite_trials(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            first = run_real_agent_smoke_trial(
                store,
                runtime_root=Path(td) / "runtime",
                approval_id="approval-test-real-agent-repeat",
                runner=_stub_runner,
            )
            second = run_real_agent_smoke_trial(
                store,
                runtime_root=Path(td) / "runtime",
                approval_id="approval-test-real-agent-repeat",
                runner=_stub_runner,
            )

            state = store.load()
            self.assertNotEqual(first["real_agent_trial_id"], second["real_agent_trial_id"])
            self.assertNotEqual(first["artifact_root"], second["artifact_root"])
            self.assertEqual(len(state["real_agent_trials"]), 2)
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_codex_output_last_message_is_scored_before_transport_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            trial = run_real_agent_smoke_trial(
                store,
                runtime_root=Path(td) / "runtime",
                approval_id="approval-test-real-agent-codex-jsonl",
                runner=_codex_jsonl_runner,
            )

            codex_ams = [
                row for row in trial["invocations"]
                if row["agent_name"] == "codex" and row["arm"] == "ams_backed"
            ][0]
            codex_raw = [
                row for row in trial["invocations"]
                if row["agent_name"] == "codex" and row["arm"] == "raw_compacted"
            ][0]
            self.assertIn("last_message_ref", codex_ams)
            self.assertTrue(codex_ams["last_message_sha256"].startswith("sha256:"))
            self.assertTrue(all(score["passed"] for score in codex_ams["scores"]))
            self.assertFalse(codex_raw["scores"][0]["passed"])
            self.assertFalse(codex_raw["scores"][1]["passed"])
            self.assertTrue(codex_raw["scores"][2]["passed"])

    def test_replay_catches_missing_real_trial_signal_reference(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            trial = run_real_agent_smoke_trial(
                store,
                runtime_root=Path(td) / "runtime",
                approval_id="approval-test-real-agent",
                runner=_stub_runner,
            )
            state = store.load()
            missing = trial["attention_signal_ids"][0]
            state["attention_signals"].pop(missing)
            state["indexes"]["attention_signal_ids"].pop(missing)
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("real_agent_trial.attention_signal_missing", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_real_agent_trials(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            run_real_agent_smoke_trial(
                store,
                runtime_root=Path(td) / "runtime",
                approval_id="approval-test-real-agent",
                runner=_stub_runner,
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("real_agent_trials", collections)


def _stub_runner(argv: list[str], cwd: Path, prompt: str, timeout_seconds: int) -> dict:
    if "AMS-backed attention memory" in prompt:
        payload = {
            "answers": [
                {"probe_id": "training_failure", "answer": "Track-A failed and needs attention."},
                {"probe_id": "surface_order_rca", "answer": "#channel-a before #channel-b needs RCA."},
                {"probe_id": "direct_egress_rule", "answer": "Use AMS outbox and readback; do not direct post."},
            ],
            "notes": "stub ams backed",
        }
    else:
        payload = {
            "answers": [
                {"probe_id": "training_failure", "answer": "not present"},
                {"probe_id": "surface_order_rca", "answer": "not present"},
                {"probe_id": "direct_egress_rule", "answer": "Use AMS outbox."},
            ],
            "notes": "stub raw compacted",
        }
    return {
        "returncode": 0,
        "stdout": json.dumps(payload),
        "stderr": "",
        "timed_out": False,
        "elapsed_ms": 10,
    }


def _recording_stub_runner(
    seen_argv: list[list[str]],
    argv: list[str],
    cwd: Path,
    prompt: str,
    timeout_seconds: int,
) -> dict:
    seen_argv.append(list(argv))
    return _stub_runner(argv, cwd, prompt, timeout_seconds)


def _failed_runner(argv: list[str], cwd: Path, prompt: str, timeout_seconds: int) -> dict:
    if argv and argv[0] == "codex":
        return {
            "returncode": None,
            "stdout": "",
            "stderr": "network unavailable",
            "timed_out": True,
            "elapsed_ms": timeout_seconds * 1000,
        }
    return {
        "returncode": 1,
        "stdout": "Not logged in",
        "stderr": "",
        "timed_out": False,
        "elapsed_ms": 20,
    }


def _codex_jsonl_runner(argv: list[str], cwd: Path, prompt: str, timeout_seconds: int) -> dict:
    if argv and argv[0] == "codex":
        if "AMS-backed attention memory" in prompt:
            payload = {
                "answers": [
                    {"probe_id": "training_failure", "answer": "Track-A failed around 13:24 UTC."},
                    {"probe_id": "surface_order_rca", "answer": "#channel-a before #channel-b needs RCA."},
                    {"probe_id": "direct_egress_rule", "answer": "Use AMS outbox and readback receipt."},
                ],
                "notes": "from last message file",
            }
        else:
            payload = {
                "answers": [
                    {"probe_id": "training_failure", "answer": "unknown"},
                    {"probe_id": "surface_order_rca", "answer": "unknown"},
                    {"probe_id": "direct_egress_rule", "answer": "Use AMS outbox and readback receipt."},
                ],
                "notes": "from compacted packet",
            }
        output_path = Path(argv[argv.index("--output-last-message") + 1])
        output_path.write_text(json.dumps(payload), encoding="utf-8")
        transport_only = "\n".join(
            [
                json.dumps({"type": "thread.started", "thread_id": "stub-thread"}),
                json.dumps({"type": "turn.completed", "usage": {"input_tokens": 1}}),
            ]
        )
        return {
            "returncode": 0,
            "stdout": transport_only,
            "stderr": "",
            "timed_out": False,
            "elapsed_ms": 50,
        }
    return _stub_runner(argv, cwd, prompt, timeout_seconds)


if __name__ == "__main__":
    unittest.main()
