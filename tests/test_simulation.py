from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams_codex.simulation import run_dual_agent_simulation
from ams_codex.store import JsonStore


class SimulationTest(unittest.TestCase):
    def test_dual_agent_simulation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            result = run_dual_agent_simulation(
                {"channel_id": "chan", "message_id": "root", "content": "build then verify"},
                JsonStore(Path(td) / "store.json"),
            )
            self.assertEqual(result["codex"]["start_method"], "thread/start")
            self.assertEqual(result["codex"]["turn_method"], "turn/start")
            self.assertEqual(result["claude"]["resume_has_resume"], "sim-claude-session-001")
            self.assertEqual(result["gates"]["egress"]["verdict"], "defer")
            self.assertTrue(result["replay"]["ok"])


if __name__ == "__main__":
    unittest.main()
