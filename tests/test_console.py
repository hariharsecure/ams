from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams_codex.console import build_console_report, render_html, render_text, write_console
from ams_codex.epoch import EpochCloser
from ams_codex.models import canonical_json
from ams_codex.simulation import run_full_simulation, run_incident_simulation
from ams_codex.store import JsonStore


class ConsoleTest(unittest.TestCase):
    def test_console_renders_text_and_html_for_replay_clean_store(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            run_full_simulation({"channel_id": "chan", "message_id": "root", "content": "build"}, store)
            EpochCloser(store).close(label="console-test")

            report = build_console_report(store)
            text = render_text(report)
            html = render_html(report)

            self.assertIn("Replay: OK", text)
            self.assertIn("Task Runs", text)
            self.assertIn("Replay: OK", html)
            self.assertIn("ams.ams_codex.epoch.closed", html)

    def test_console_does_not_mutate_store(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            run_incident_simulation({"channel_id": "chan", "message_id": "root", "content": "fail"}, store)
            before = canonical_json(store.load())

            report = build_console_report(store)
            render_text(report)
            render_html(report)

            self.assertEqual(canonical_json(store.load()), before)

    def test_console_renders_replay_failure_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            run_full_simulation({"channel_id": "chan", "message_id": "root", "content": "build"}, store)
            state = store.load()
            state["provider_results"] = {}
            store.save(state)

            report = build_console_report(store)
            html = render_html(report)

            self.assertFalse(report["replay"]["ok"])
            self.assertIn("Replay: FAIL", html)
            self.assertIn("replay-bad", html)
            self.assertIn("missing provider_result", html)

    def test_console_writes_html_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            output = root / "console.html"
            run_full_simulation({"channel_id": "chan", "message_id": "root", "content": "build"}, store)
            report = build_console_report(store)

            written = write_console(report, output, fmt="html")

            self.assertEqual(written, output)
            self.assertIn("AMS Console", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
