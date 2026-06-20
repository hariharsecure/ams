from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from ams.models import hash_without as _hash_without
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.shareability_bundle import ShareabilityBundleStore
from ams.store import JsonStore


GIT = shutil.which("git")


@unittest.skipUnless(GIT, "git required for shareability bundle tests")
class ShareabilityBundleTest(unittest.TestCase):
    def test_shareability_bundle_creates_verified_offline_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = _git_repo(root / "repo")
            store = JsonStore(root / "store.json")

            bundle = ShareabilityBundleStore(store).create(
                source_root=repo,
                output_dir=root / "out",
                label="test-shareability",
            )

            self.assertEqual(bundle["status"], "allow")
            self.assertEqual(bundle["reason_codes"], ["shareability_bundle.allow"])
            self.assertTrue(Path(bundle["bundle_path"]).exists())
            self.assertGreater(bundle["bundle_size_bytes"], 0)
            self.assertEqual(bundle["source"]["dirty_file_count"], 0)
            self.assertEqual(bundle["source"]["remote_count"], 0)
            self.assertFalse(bundle["include_all_refs"])
            self.assertEqual(bundle["ref_scope"]["mode"], "head_and_tags_at_head")
            self.assertEqual(bundle["ref_scope"]["selected_refs"], ["HEAD", "refs/tags/v0"])
            self.assertTrue(bundle["required_gates"]["safe_ref_scope"])
            self.assertTrue(bundle["required_gates"]["git_config_hardened"])
            self.assertFalse(bundle["source"]["remote_urls_stored"])
            self.assertFalse(bundle["boundaries"]["network_call_performed"])
            self.assertFalse(bundle["boundaries"]["remote_push_performed"])
            self.assertFalse(bundle["boundaries"]["remote_pull_performed"])
            self.assertTrue(bundle["required_gates"]["bundle_verified"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_dirty_tree_defers_but_still_records_verified_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = _git_repo(root / "repo")
            (repo / "dirty.txt").write_text("not committed\n", encoding="utf-8")
            store = JsonStore(root / "store.json")

            bundle = ShareabilityBundleStore(store).create(
                source_root=repo,
                output_dir=root / "out",
                label="test-shareability-dirty",
            )

            self.assertEqual(bundle["status"], "defer")
            self.assertIn("shareability_bundle.working_tree_clean_missing", bundle["reason_codes"])
            self.assertTrue(bundle["required_gates"]["bundle_verified"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_all_refs_is_explicit_defer_scope(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = _git_repo(root / "repo")
            store = JsonStore(root / "store.json")

            bundle = ShareabilityBundleStore(store).create(
                source_root=repo,
                output_dir=root / "out",
                label="test-shareability-all-refs",
                include_all_refs=True,
            )

            self.assertEqual(bundle["status"], "defer")
            self.assertIn("shareability_bundle.safe_ref_scope_missing", bundle["reason_codes"])
            self.assertEqual(bundle["ref_scope"]["mode"], "all_refs")
            self.assertTrue(bundle["ref_scope"]["all_refs_included"])
            self.assertTrue(bundle["required_gates"]["bundle_verified"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_repo_fsmonitor_helper_is_not_executed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = _git_repo(root / "repo")
            marker = root / "fsmonitor-ran"
            hook = root / "fsmonitor.sh"
            hook.write_text(f"#!/bin/sh\n/bin/echo ran > {marker}\nexit 0\n", encoding="utf-8")
            hook.chmod(0o755)
            _git(repo, "config", "core.fsmonitor", str(hook))
            store = JsonStore(root / "store.json")

            bundle = ShareabilityBundleStore(store).create(
                source_root=repo,
                output_dir=root / "out",
                label="test-shareability-hardened-git",
            )

            self.assertEqual(bundle["status"], "allow")
            self.assertFalse(marker.exists())
            self.assertTrue(bundle["git_safety"]["repo_config_helpers_disabled"])

    def test_replay_catches_boundary_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = _git_repo(root / "repo")
            store = JsonStore(root / "store.json")
            bundle = ShareabilityBundleStore(store).create(
                source_root=repo,
                output_dir=root / "out",
                label="test-shareability-tamper",
            )
            state = store.load()
            record = state["shareability_bundles"][bundle["shareability_bundle_id"]]
            record["boundaries"]["network_call_performed"] = True
            record["shareability_bundle_sha256"] = _hash_without(
                record,
                "shareability_bundle_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("shareability_bundle.network_call_performed_not_false", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_shareability_bundles(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = _git_repo(root / "repo")
            store = JsonStore(root / "store.json")
            ShareabilityBundleStore(store).create(
                source_root=repo,
                output_dir=root / "out",
                label="test-shareability-oracle",
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("shareability_bundles", collections)


def _git_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    _git(path, "init")
    _git(path, "config", "user.email", "ams@example.test")
    _git(path, "config", "user.name", "AMS Test")
    (path / "README.md").write_text("# test\n", encoding="utf-8")
    _git(path, "add", "README.md")
    _git(path, "commit", "-m", "initial")
    _git(path, "tag", "v0")
    return path


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        [GIT or "git", *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
    )


if __name__ == "__main__":
    unittest.main()
