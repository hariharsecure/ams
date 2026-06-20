from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.architecture_audit import ArchitectureAuditStore
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.store import JsonStore


class ArchitectureAuditTest(unittest.TestCase):
    def test_audit_records_modularity_metrics_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pkg = root / "pkg"
            pkg.mkdir()
            (pkg / "__init__.py").write_text("", encoding="utf-8")
            (pkg / "alpha_core.py").write_text(
                "from . import beta_core\n\n\ndef run():\n    return beta_core.value()\n",
                encoding="utf-8",
            )
            (pkg / "beta_core.py").write_text(
                "def value():\n    total = 1\n    total += 1\n    return total\n",
                encoding="utf-8",
            )
            store = JsonStore(root / "store.json")

            audit = ArchitectureAuditStore(store).create(source_root=root, package_name="pkg")

            self.assertEqual(audit["analyzer"]["engine"], "python_ast")
            self.assertFalse(audit["analyzer"]["network_required"])
            self.assertEqual(audit["metrics"]["acyclicity"]["cycle_count"], 0)
            self.assertGreaterEqual(audit["metrics"]["modularity"]["internal_edges"], 1)
            self.assertTrue(audit["architecture_audit_sha256"].startswith("sha256:"))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_audit_marks_import_cycle_as_deny_but_replay_valid(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pkg = root / "pkg"
            pkg.mkdir()
            (pkg / "__init__.py").write_text("", encoding="utf-8")
            (pkg / "a.py").write_text("from . import b\n\ndef fa():\n    return b.fb()\n", encoding="utf-8")
            (pkg / "b.py").write_text("from . import a\n\ndef fb():\n    return a.fa()\n", encoding="utf-8")
            store = JsonStore(root / "store.json")

            audit = ArchitectureAuditStore(store).create(source_root=root, package_name="pkg")

            self.assertEqual(audit["status"], "deny")
            self.assertIn("architecture.import_cycle", audit["reason_codes"])
            self.assertTrue(audit["cycles"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_architecture_audit_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pkg = root / "pkg"
            pkg.mkdir()
            (pkg / "__init__.py").write_text("", encoding="utf-8")
            (pkg / "only.py").write_text("def x():\n    return 1\n", encoding="utf-8")
            store = JsonStore(root / "store.json")
            audit = ArchitectureAuditStore(store).create(source_root=root, package_name="pkg")
            state = store.load()
            state["architecture_audits"][audit["architecture_audit_id"]]["status"] = "allow"
            state["architecture_audits"][audit["architecture_audit_id"]]["file_count"] = 999
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("architecture_audit.hash_mismatch", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_architecture_audits(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pkg = root / "pkg"
            pkg.mkdir()
            (pkg / "__init__.py").write_text("", encoding="utf-8")
            (pkg / "only.py").write_text("def x():\n    return 1\n", encoding="utf-8")
            store = JsonStore(root / "store.json")
            ArchitectureAuditStore(store).create(source_root=root, package_name="pkg")

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("architecture_audits", collections)


if __name__ == "__main__":
    unittest.main()
