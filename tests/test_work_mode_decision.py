from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ams.cli import cmd_work_mode_decision
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.store import JsonStore
from ams.work_mode_decision import WorkModeDecisionStore, _hash_without


class WorkModeDecisionTest(unittest.TestCase):
    def test_session_request_routes_to_session_isolation_tests(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            decision = WorkModeDecisionStore(store).create(
                request_text="How should agents preserve context after compaction and restart a Claude session?",
                changed_paths=["ams/session_registry.py"],
                source_root=Path(td),
                label="test-session-isolation",
            )

            self.assertEqual(decision["decision"], "session_isolation")
            self.assertTrue(decision["mode_flags"]["session_isolation_tests_required"])
            self.assertFalse(decision["mode_flags"]["cleanup_audit_required"])
            self.assertFalse(decision["raw_request_stored"])
            self.assertNotIn("preserve context", str(decision).lower())
            command_modes = {command["mode"] for command in decision["recommended_commands"]}
            self.assertIn("session_isolation_tests", command_modes)
            self.assertIn("standard_verification", command_modes)
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_cleanup_request_routes_to_cleanup_audit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            decision = WorkModeDecisionStore(store).create(
                request_text="Analyze dead code, duplicate logic, unused APIs, legacy files, and technical debt.",
                changed_paths=["ams/cli.py", "README.md"],
                source_root=Path(td),
                label="test-cleanup",
            )

            self.assertEqual(decision["decision"], "cleanup_audit")
            self.assertFalse(decision["mode_flags"]["session_isolation_tests_required"])
            self.assertTrue(decision["mode_flags"]["cleanup_audit_required"])
            command_modes = {command["mode"] for command in decision["recommended_commands"]}
            self.assertIn("cleanup_audit", command_modes)
            self.assertIn("standard_verification", command_modes)
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_mixed_request_routes_to_both(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            decision = WorkModeDecisionStore(store).create(
                request_text="Research session isolation and also do aggressive cleanup of duplicate legacy code.",
                changed_paths=["ams/agent_memory_sim.py", "ams/replay.py"],
                source_root=Path(td),
                label="test-both",
            )

            self.assertEqual(decision["decision"], "both")
            self.assertTrue(decision["mode_flags"]["session_isolation_tests_required"])
            self.assertTrue(decision["mode_flags"]["cleanup_audit_required"])
            command_modes = {command["mode"] for command in decision["recommended_commands"]}
            self.assertIn("session_isolation_tests", command_modes)
            self.assertIn("cleanup_audit", command_modes)

    def test_terms_do_not_match_inside_unrelated_words(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            decision = WorkModeDecisionStore(store).create(
                request_text="Update capability policy boundaries.",
                changed_paths=["ams/capability_policy.py"],
                source_root=Path(td),
                label="test-substring",
            )

            self.assertEqual(decision["decision"], "standard_verification")
            self.assertEqual(decision["trigger_summary"]["cleanup_terms"], [])

    def test_replay_catches_rehashed_boundary_change(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            decision = WorkModeDecisionStore(store).create(
                request_text="run session isolation checks",
                source_root=Path(td),
                label="test-tamper",
            )
            state = store.load()
            record = state["work_mode_decisions"][decision["work_mode_decision_id"]]
            record["live_boundaries"]["process_started"] = True
            record["work_mode_decision_sha256"] = _hash_without(record, "work_mode_decision_sha256")
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("work_mode_decision.process_started_not_false", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_work_mode_decisions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            WorkModeDecisionStore(store).create(
                request_text="cleanup dead code",
                source_root=Path(td),
                label="test-oracle",
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("work_mode_decisions", collections)

    def test_cli_hashes_request_file_without_storing_raw_text(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            request_file = root / "request.txt"
            request_file.write_text("Session compaction isolation test with secret body.", encoding="utf-8")
            args = SimpleNamespace(
                store=str(root / "store.json"),
                request_file=str(request_file),
                request_ref="local://request/test",
                changed_path=None,
                source_root=str(root),
                label="test-cli",
                source_surface="codex",
                session_id=None,
            )

            self.assertEqual(cmd_work_mode_decision(args), 0)
            state = JsonStore(root / "store.json").load()
            [decision] = state["work_mode_decisions"].values()
            self.assertEqual(decision["request_ref"], "local://request/test")
            self.assertTrue(decision["request_sha256"].startswith("sha256:"))
            self.assertNotIn("secret body", str(decision))


if __name__ == "__main__":
    unittest.main()
