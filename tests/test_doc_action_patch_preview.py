from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams_codex.doc_action_execution import DocActionExecutionPlanStore, _hash_without as _execution_hash_without
from ams_codex.doc_action_operator_approval import (
    DocActionOperatorApprovalPacketStore,
    _hash_without as _approval_hash_without,
)
from ams_codex.doc_action_patch_preview import DocActionPatchPreviewStore, _hash_without
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.store import JsonStore


class DocActionPatchPreviewTest(unittest.TestCase):
    def test_patch_preview_is_inert_and_hashes_selected_actions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            fixture = _approval_fixture(store, root)

            preview = DocActionPatchPreviewStore(store).create(
                doc_action_operator_approval_packet_id=fixture["approval_packet"][
                    "doc_action_operator_approval_packet_id"
                ],
                source_root=root,
                label="test-doc-action-patch-preview",
            )

            self.assertEqual(preview["status"], "ready_for_review")
            self.assertTrue(all(preview["required_gates"].values()))
            self.assertEqual(preview["patch_summary"]["patch_count"], 1)
            self.assertEqual(preview["patch_summary"]["source_hash_match_count"], 1)
            self.assertFalse(preview["patch_summary"]["raw_patch_stored"])
            self.assertFalse(preview["patch_summary"]["raw_source_markdown_stored"])
            self.assertFalse(preview["patch_summary"]["preview_artifact_written"])
            patch = preview["patch_previews"][0]
            self.assertEqual(patch["source_path"], "STATUS.md")
            self.assertTrue(patch["source_hash_matches_plan"])
            self.assertTrue(patch["future_executor_must_recheck_source_sha256"])
            self.assertFalse(patch["raw_patch_stored"])
            self.assertFalse(patch["raw_source_markdown_stored"])
            self.assertFalse(patch["preview_artifact_written"])
            self.assertNotIn("secret body", str(preview))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_patch_preview_boundary_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            fixture = _patch_fixture(store, root)
            state = store.load()
            record = state["doc_action_patch_previews"][fixture["patch_preview"]["doc_action_patch_preview_id"]]
            record["live_boundaries"]["source_file_rewritten"] = True
            record["doc_action_patch_preview_sha256"] = _hash_without(record, "doc_action_patch_preview_sha256")
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_preview.source_file_rewritten_not_false", "\n".join(replay["errors"]))

    def test_replay_catches_patch_hash_tamper_with_recomputed_record_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            fixture = _patch_fixture(store, root)
            state = store.load()
            record = state["doc_action_patch_previews"][fixture["patch_preview"]["doc_action_patch_preview_id"]]
            record["patch_previews"][0]["semantic_patch_sha256"] = "sha256:" + ("0" * 64)
            record["patch_summary"]["patch_set_sha256"] = "sha256:" + ("1" * 64)
            record["doc_action_patch_preview_sha256"] = _hash_without(record, "doc_action_patch_preview_sha256")
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            joined = "\n".join(replay["errors"])
            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_preview.patch_summary_mismatch", joined)
            self.assertIn("doc_action_patch_preview.preview_hash_mismatch", joined)
            self.assertIn("doc_action_patch_preview.semantic_patch_hash_mismatch", joined)

    def test_replay_catches_patch_kind_tamper_with_recomputed_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            fixture = _patch_fixture(store, root)
            state = store.load()
            record = state["doc_action_patch_previews"][fixture["patch_preview"]["doc_action_patch_preview_id"]]
            record["patch_previews"][0]["patch_kind"] = "delete_source_file_after_approval"
            _rehash_patch_preview_record(record)
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_preview.patch_kind_mismatch", "\n".join(replay["errors"]))

    def test_replay_catches_current_source_ref_tamper_with_recomputed_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            fixture = _patch_fixture(store, root)
            state = store.load()
            record = state["doc_action_patch_previews"][fixture["patch_preview"]["doc_action_patch_preview_id"]]
            current_ref = record["patch_previews"][0]["current_source_ref"]
            current_ref["path"] = "../outside.md"
            current_ref["exists"] = False
            current_ref["under_source_root"] = False
            current_ref["line_count"] = None
            current_ref["size_bytes"] = None
            _rehash_patch_preview_record(record)
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            joined = "\n".join(replay["errors"])
            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_preview.current_source_ref_path_mismatch", joined)
            self.assertIn("doc_action_patch_preview.current_source_ref_missing", joined)
            self.assertIn("doc_action_patch_preview.current_source_ref_outside_root", joined)
            self.assertIn("doc_action_patch_preview.current_source_ref_line_count_missing", joined)
            self.assertIn("doc_action_patch_preview.current_source_ref_size_bytes_missing", joined)

    def test_replay_catches_stale_approval_packet_after_preview(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            fixture = _patch_fixture(store, root)
            state = store.load()
            packet_id = fixture["approval_packet"]["doc_action_operator_approval_packet_id"]
            packet = state["doc_action_operator_approval_packets"][packet_id]
            packet["approval_granted"] = True
            packet["doc_action_operator_approval_packet_sha256"] = _approval_hash_without(
                packet,
                "doc_action_operator_approval_packet_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            joined = "\n".join(replay["errors"])
            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_preview.approval_packet_hash_mismatch", joined)
            self.assertIn("doc_action_patch_preview.approval_packet_invalid", joined)

    def test_replay_catches_stale_execution_plan_after_preview(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            fixture = _patch_fixture(store, root)
            state = store.load()
            plan_id = fixture["execution_plan"]["doc_action_execution_plan_id"]
            plan = state["doc_action_execution_plans"][plan_id]
            plan["policy"]["write_allowed"] = True
            plan["doc_action_execution_plan_sha256"] = _execution_hash_without(
                plan,
                "doc_action_execution_plan_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            joined = "\n".join(replay["errors"])
            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_preview.execution_plan_hash_mismatch", joined)
            self.assertIn("doc_action_patch_preview.execution_plan_invalid", joined)

    def test_replay_oracle_covers_doc_action_patch_previews(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            _patch_fixture(store, root)

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("doc_action_patch_previews", collections)


def _patch_fixture(store: JsonStore, root: Path) -> dict[str, dict]:
    fixture = _approval_fixture(store, root)
    patch_preview = DocActionPatchPreviewStore(store).create(
        doc_action_operator_approval_packet_id=fixture["approval_packet"]["doc_action_operator_approval_packet_id"],
        source_root=root,
        label="test-doc-action-patch-preview",
    )
    return {**fixture, "patch_preview": patch_preview}


def _rehash_patch_preview_record(record: dict) -> None:
    patch_hashes = []
    for preview in record["patch_previews"]:
        preview["patch_preview_sha256"] = _hash_without(preview, "patch_preview_sha256")
        patch_hashes.append(preview["patch_preview_sha256"])
    record["patch_summary"]["patch_set_sha256"] = _patch_set_hash(patch_hashes)
    record["doc_action_patch_preview_sha256"] = _hash_without(record, "doc_action_patch_preview_sha256")


def _patch_set_hash(patch_hashes: list[str]) -> str:
    import json
    import hashlib

    material = json.dumps(sorted(patch_hashes), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def _approval_fixture(store: JsonStore, root: Path) -> dict[str, dict]:
    execution_plan = DocActionExecutionPlanStore(store).create(
        source_root=root,
        label="test-doc-action-execution",
        max_actions=1,
    )
    approval_packet = DocActionOperatorApprovalPacketStore(store).create(
        doc_action_execution_plan_id=execution_plan["doc_action_execution_plan_id"],
        source_root=root,
        label="test-doc-action-operator-approval",
    )
    return {"execution_plan": execution_plan, "approval_packet": approval_packet}


def _minimal_repo(root: Path, *, oversized_status: bool) -> Path:
    root.mkdir(exist_ok=True)
    (root / "AGENTS.md").write_text("# Agent Instructions\n\nStatus: active\nUpdated: 2026-06-12\n", encoding="utf-8")
    (root / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
    (root / "README.md").write_text("# Demo\n\nStatus: active\nUpdated: 2026-06-12\n", encoding="utf-8")
    (root / "MAP.md").write_text("# Map\n\nStatus: active\nUpdated: 2026-06-12\n", encoding="utf-8")
    status_body = "# Status\n\nStatus: active\nUpdated: 2026-06-12\n\nsecret body\n"
    if oversized_status:
        status_body += "\n".join(f"- generated historical line {index}" for index in range(901)) + "\n"
    (root / "STATUS.md").write_text(status_body, encoding="utf-8")
    (root / "MILESTONE_58_DOC_ACTION_PATCH_PREVIEW.md").write_text(
        "# MILESTONE-58\n\nStatus: complete\nDate: 2026-06-13\n\n## Verification\n\nok\n\n## Next Risk\n\nNone.\n",
        encoding="utf-8",
    )
    return root


if __name__ == "__main__":
    unittest.main()
