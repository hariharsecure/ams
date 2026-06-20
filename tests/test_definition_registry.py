from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.codex_adapter import CodexDryRunAdapter
from ams.context import ContextStore
from ams.definition_registry import DefinitionRegistryStore
from ams.dispatch import dispatch
from ams.replay import ReplayChecker
from ams.run_trace import RunTraceStore
from ams.session_registry import SessionRegistry
from ams.store import JsonStore


class DefinitionRegistryTest(unittest.TestCase):
    def test_install_defaults_populates_active_registry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            result = DefinitionRegistryStore(store).install_defaults()

            self.assertGreaterEqual(result["summary"]["active_tools"], 5)
            self.assertIn("discord_client.send", result["summary"]["disabled_tools"])
            self.assertIn("openai_codex/app-server:dry_run", result["summary"]["surfaces"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_create_run_pins_tool_and_surface_definitions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            session, context = _session_context(store)

            task_run = RunTraceStore(store).create_run(
                session["session_id"],
                context["context_id"],
                tool_scope=["Read", "ApplyPatch", "Tests"],
            )

            self.assertEqual(
                [ref["name"] for ref in task_run["tool_definition_refs"]],
                ["Read", "ApplyPatch", "Tests"],
            )
            self.assertEqual(task_run["surface_definition_ref"]["provider"], "openai_codex")
            self.assertTrue(task_run["definition_snapshot_sha256"].startswith("sha256:"))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_unknown_tool_fails_closed_at_run_creation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            session, context = _session_context(store)

            with self.assertRaisesRegex(ValueError, "definition.tool_missing:UnknownTool"):
                RunTraceStore(store).create_run(
                    session["session_id"],
                    context["context_id"],
                    tool_scope=["UnknownTool"],
                )

    def test_unknown_surface_fails_closed_at_run_creation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            session, context = _session_context(store)

            with self.assertRaisesRegex(ValueError, "definition.surface_missing:openai_codex/tmux"):
                RunTraceStore(store).create_run(
                    session["session_id"],
                    context["context_id"],
                    provider_surface="tmux",
                    tool_scope=["Read"],
                )

    def test_replay_rejects_tool_definition_drift(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            session, context = _session_context(store)
            RunTraceStore(store).create_run(
                session["session_id"],
                context["context_id"],
                tool_scope=["Read"],
            )
            state = store.load()
            read_def = next(
                definition for definition in state["tool_definitions"].values()
                if definition["name"] == "Read"
            )
            read_def["definition"]["description"] = "tampered after pinning"
            store.save(state)

            result = ReplayChecker(store).check()

            self.assertFalse(result["ok"])
            self.assertIn("tool_hash_mismatch:Read", "\n".join(result["errors"]))

    def test_dispatch_refuses_when_task_run_pin_is_tampered(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            session, context = _session_context(store)
            task_run = RunTraceStore(store).create_run(
                session["session_id"],
                context["context_id"],
                tool_scope=["Read"],
            )
            state = store.load()
            stored = state["task_runs"][task_run["task_run_id"]]
            stored["tool_definition_refs"][0]["definition_sha256"] = "sha256:" + "0" * 64
            stored["definition_snapshot_sha256"] = "sha256:" + "1" * 64
            store.save(state)

            result = dispatch(store, task_run["task_run_id"])

            self.assertFalse(result["dispatched"])
            self.assertEqual(result["reason_code"], "dispatch.definition_pins_invalid")
            self.assertIn("definition.run_tool_pin_mismatch:Read", result["reason_codes"])


def _session_context(store: JsonStore) -> tuple[dict, dict]:
    event = {"channel_id": "chan", "message_id": "root", "content": "build"}
    session, _ = SessionRegistry(store).ingest_event(event)
    session = CodexDryRunAdapter(store).bind_thread(session["session_id"], "thread-1")
    context = ContextStore(store).create_for_event(session, event)
    return session, context


if __name__ == "__main__":
    unittest.main()
