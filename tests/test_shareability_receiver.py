from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from ams_codex.models import hash_without as _hash_without
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.shareability_bundle import ShareabilityBundleStore
from ams_codex.shareability_receiver import ShareabilityReceiverTrialStore
from ams_codex.store import JsonStore


GIT = shutil.which("git")


@unittest.skipUnless(GIT, "git required for shareability receiver tests")
class ShareabilityReceiverTrialTest(unittest.TestCase):
    def test_receiver_reconstructs_bundle_without_live_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source_store = JsonStore(root / "source.json")
            repo = _git_repo(root / "repo")
            bundle = ShareabilityBundleStore(source_store).create(
                source_root=repo,
                output_dir=root / "bundle",
                label="receiver-source",
            )
            receiver_store = JsonStore(root / "receiver.json")

            trial = ShareabilityReceiverTrialStore(receiver_store).create(
                source_bundle=bundle,
                receiver_root=root / "receiver",
                label="receiver-trial",
            )

            self.assertEqual(trial["status"], "allow", trial["reason_codes"])
            self.assertEqual(trial["reason_codes"], ["shareability_receiver_trial.allow"])
            self.assertTrue(Path(trial["receiver"]["clone_path"]).exists())
            self.assertTrue(trial["receiver"]["head_matches_source"])
            self.assertEqual(trial["receiver"]["tags_at_head"], ["v0"])
            self.assertEqual(trial["receiver"]["remote_count"], 0)
            self.assertTrue(trial["required_gates"]["bundle_sha_matches"])
            self.assertFalse(trial["boundaries"]["network_call_performed"])
            self.assertFalse(trial["boundaries"]["remote_pull_performed"])
            self.assertTrue(ReplayChecker(receiver_store).check()["ok"])

    def test_receiver_denies_bundle_sha_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = _git_repo(root / "repo")
            bundle = ShareabilityBundleStore(JsonStore(root / "source.json")).create(
                source_root=repo,
                output_dir=root / "bundle",
                label="receiver-source-mismatch",
            )
            bundle["bundle_sha256"] = "sha256:" + "0" * 64
            bundle["shareability_bundle_sha256"] = _hash_without(bundle, "shareability_bundle_sha256")

            trial = ShareabilityReceiverTrialStore(JsonStore(root / "receiver.json")).create(
                source_bundle=bundle,
                receiver_root=root / "receiver",
                label="receiver-mismatch",
            )

            self.assertEqual(trial["status"], "deny")
            self.assertIn("shareability_receiver_trial.bundle_sha_matches_missing", trial["reason_codes"])
            self.assertFalse(trial["required_gates"]["bundle_sha_matches"])
            self.assertFalse(trial["receiver"]["clone_created"])

    def test_replay_catches_receiver_boundary_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = _git_repo(root / "repo")
            bundle = ShareabilityBundleStore(JsonStore(root / "source.json")).create(
                source_root=repo,
                output_dir=root / "bundle",
                label="receiver-source-tamper",
            )
            store = JsonStore(root / "receiver.json")
            trial = ShareabilityReceiverTrialStore(store).create(
                source_bundle=bundle,
                receiver_root=root / "receiver",
                label="receiver-tamper",
            )
            state = store.load()
            record = state["shareability_receiver_trials"][trial["shareability_receiver_trial_id"]]
            record["boundaries"]["network_call_performed"] = True
            record["shareability_receiver_trial_sha256"] = _hash_without(
                record,
                "shareability_receiver_trial_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("shareability_receiver_trial.network_call_performed_not_false", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_shareability_receiver_trials(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = _git_repo(root / "repo")
            bundle = ShareabilityBundleStore(JsonStore(root / "source.json")).create(
                source_root=repo,
                output_dir=root / "bundle",
                label="receiver-source-oracle",
            )
            store = JsonStore(root / "receiver.json")
            ShareabilityReceiverTrialStore(store).create(
                source_bundle=bundle,
                receiver_root=root / "receiver",
                label="receiver-oracle",
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("shareability_receiver_trials", collections)


def _git_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    _git(path, "init")
    _git(path, "config", "user.email", "ams@example.test")
    _git(path, "config", "user.name", "AMS Test")
    (path / "README.md").write_text("# test\n", encoding="utf-8")
    (path / "schemas").mkdir()
    (path / "schemas" / "test.json").write_text('{"ok": true}\n', encoding="utf-8")
    _git(path, "add", "README.md", "schemas/test.json")
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
