from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams_codex.gate_adapter import GateShadowAdapter, build_action
from ams_codex.store import JsonStore


class GateAdapterTest(unittest.TestCase):
    def test_local_readonly_allows_shadow(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            action = build_action(
                tool="ams_codex.status",
                endpoint=None,
                method="READ",
                payload={"status": True},
                risk_flags=[],
            )
            verdict = GateShadowAdapter(JsonStore(Path(td) / "store.json")).check(action)
            self.assertEqual(verdict["verdict"], "allow")
            self.assertTrue(verdict["shadow_only"])

    def test_discord_egress_defers_shadow(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            action = build_action(
                tool="discord_client.send",
                endpoint="/channels/chan/messages",
                method="POST",
                payload={"content": "hello"},
                channel_id="chan",
                risk_flags=["egress"],
            )
            verdict = GateShadowAdapter(JsonStore(Path(td) / "store.json")).check(action)
            self.assertEqual(verdict["verdict"], "defer")
            self.assertIn("shadow-defer-egress-needs-signed-engine", verdict["reasons"])


if __name__ == "__main__":
    unittest.main()
