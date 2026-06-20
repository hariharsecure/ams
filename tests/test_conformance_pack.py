from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from ams_codex.conformance_pack import ConformancePackStore
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.store import JsonStore, empty_state


class ConformancePackTest(unittest.TestCase):
    def test_conformance_pack_generates_local_evidence_and_replays(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            store.save(empty_state(), check_revision=False)

            pack = ConformancePackStore(store).create(
                repo_root=Path.cwd(),
                evidence_root=root / "evidence",
                target_milestone="MILESTONE-29",
                label="test-conformance-pack",
                check_store_paths=[store.path],
                command_specs=[f"{sys.executable} -m py_compile ams_codex/__init__.py"],
            )

            self.assertEqual(pack["status"], "passed", pack["reason_codes"])
            self.assertEqual(pack["reason_codes"], ["conformance_pack.passed"])
            self.assertTrue(pack["checks"]["json_valid"])
            self.assertTrue(pack["checks"]["python_compile_ok"])
            self.assertTrue(pack["checks"]["commands_ok"])
            self.assertTrue(pack["checks"]["stores_replay_ok"])
            self.assertTrue(pack["checks"]["stores_oracle_ok"])
            self.assertTrue(pack["checks"]["docs_current_ok"])
            self.assertFalse(pack["live_boundaries"]["network_call_performed"])
            self.assertFalse(pack["live_boundaries"]["persistent_process_started"])
            self.assertTrue(pack["command_results"][0]["policy_allowed"])
            self.assertTrue((root / "evidence" / "conformance_pack_record.json").exists())
            self.assertTrue((root / "evidence" / "conformance_summary.json").exists())
            summary = json.loads((root / "evidence" / "conformance_summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["conformance_pack_sha256"], pack["conformance_pack_sha256"])
            self.assertEqual(summary["warnings"], pack["warnings"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_conformance_pack_records_failed_command_without_live_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            store.save(empty_state(), check_revision=False)

            pack = ConformancePackStore(store).create(
                repo_root=Path.cwd(),
                evidence_root=root / "evidence",
                target_milestone="MILESTONE-29",
                label="test-failing-command-pack",
                check_store_paths=[store.path],
                command_specs=[f"{sys.executable} -m py_compile definitely_missing_conformance_file.py"],
            )

            self.assertEqual(pack["status"], "failed")
            self.assertIn("conformance_pack.command_failed", pack["reason_codes"])
            self.assertFalse(pack["checks"]["commands_ok"])
            self.assertEqual(pack["command_results"][0]["exit_code"], 1)
            self.assertTrue(pack["command_results"][0]["policy_allowed"])
            self.assertNotIn("stdout", pack["command_results"][0])
            self.assertNotIn("stderr", pack["command_results"][0])
            self.assertFalse(pack["live_boundaries"]["network_call_performed"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_conformance_pack_denies_unbounded_custom_command(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            store.save(empty_state(), check_revision=False)

            pack = ConformancePackStore(store).create(
                repo_root=Path.cwd(),
                evidence_root=root / "evidence",
                target_milestone="MILESTONE-29",
                label="test-denied-command-pack",
                check_store_paths=[store.path],
                command_specs=["ssh example.com"],
            )

            self.assertEqual(pack["status"], "failed")
            self.assertIn("conformance_pack.command_failed", pack["reason_codes"])
            self.assertFalse(pack["command_results"][0]["policy_allowed"])
            self.assertEqual(pack["command_results"][0]["exit_code"], 126)
            self.assertIn("denied_command:ssh", pack["command_results"][0]["policy_reason"])
            self.assertFalse(pack["live_boundaries"]["network_call_performed"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_conformance_pack_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            store.save(empty_state(), check_revision=False)
            pack = ConformancePackStore(store).create(
                repo_root=Path.cwd(),
                evidence_root=root / "evidence",
                target_milestone="MILESTONE-29",
                label="test-tamper-pack",
                check_store_paths=[store.path],
            )
            state = store.load()
            state["conformance_packs"][pack["conformance_pack_id"]]["live_boundaries"]["persistent_process_started"] = True
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("conformance_pack.persistent_process_started_not_false", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_conformance_packs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            store.save(empty_state(), check_revision=False)
            ConformancePackStore(store).create(
                repo_root=Path.cwd(),
                evidence_root=root / "evidence",
                target_milestone="MILESTONE-29",
                label="test-oracle-pack",
                check_store_paths=[store.path],
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("conformance_packs", collections)


if __name__ == "__main__":
    unittest.main()
