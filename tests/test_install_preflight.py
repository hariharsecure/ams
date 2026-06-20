from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.install_preflight import run_install_preflight


class InstallPreflightTest(unittest.TestCase):
    def test_runtime_store_outside_repo_passes_but_agent_user_defers(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "AMS"
            root.mkdir()
            store = Path(td) / "runtime" / "store.json"

            result = run_install_preflight(
                store_path=store,
                current_user="channel_a",
                expected_agent_user="ams-agent",
                env={},
                root=root,
            )

            self.assertFalse(result["ready_for_live"])
            checks = {check["name"]: check for check in result["checks"]}
            self.assertEqual(checks["runtime_store_outside_repo"]["status"], "pass")
            self.assertEqual(checks["separate_agent_user"]["status"], "defer")

    def test_runtime_store_inside_repo_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "AMS"
            root.mkdir()
            store = root / "data" / "store.json"

            result = run_install_preflight(
                store_path=store,
                current_user="ams-agent",
                expected_agent_user="ams-agent",
                env={},
                root=root,
            )

            checks = {check["name"]: check for check in result["checks"]}
            self.assertEqual(checks["runtime_store_outside_repo"]["status"], "fail")
            self.assertEqual(checks["runtime_store_outside_repo"]["reason_code"], "install.runtime_store_inside_repo")

    def test_ambient_secret_env_reports_names_not_values(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "AMS"
            root.mkdir()
            store = Path(td) / "runtime" / "store.json"

            result = run_install_preflight(
                store_path=store,
                current_user="ams-agent",
                expected_agent_user="ams-agent",
                env={"DISCORD_TOKEN": "super-secret-token-value"},
                root=root,
            )

            checks = {check["name"]: check for check in result["checks"]}
            details = checks["no_ambient_secret_env"]["details"]
            self.assertEqual(checks["no_ambient_secret_env"]["status"], "fail")
            self.assertEqual(details["present_secret_names"], ["DISCORD_TOKEN"])
            self.assertNotIn("super-secret-token-value", str(result))

    def test_package_manifest_path_can_pass(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "AMS"
            root.mkdir()
            store = Path(td) / "runtime" / "store.json"
            manifest = Path(td) / "package.json"
            manifest.write_text("{}", encoding="utf-8")

            result = run_install_preflight(
                store_path=store,
                package_manifest_path=manifest,
                current_user="ams-agent",
                expected_agent_user="ams-agent",
                env={},
                root=root,
            )

            self.assertTrue(result["ready_for_live"])
            checks = {check["name"]: check for check in result["checks"]}
            self.assertEqual(checks["package_manifest_available"]["status"], "pass")


if __name__ == "__main__":
    unittest.main()
