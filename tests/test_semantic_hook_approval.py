from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from ams.models import canonical_json, sha256_text
from ams.package_manifest import build_package_manifest, verify_package_manifest
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.semantic_hook_approval import SemanticHookApprovalBindingStore, _hash_without
from ams.semantic_hook_install_plan import SemanticHookInstallPlanStore
from ams.semantic_hook_run import SemanticHookRunStore
from ams.semantic_oracle_review import SemanticOracleReviewStore
from ams.signed_policy import SignedPolicyConfig
from ams.simulation_sweep import SimulationSweepStore
from ams.store import JsonStore


SSH_KEYGEN = shutil.which("ssh-keygen")
READY_READBACK = (
    "Hook files remain unwritten until approval. "
    "No provider hook will execute from this packet. "
    "Egress mode is none. "
    "Rollback is restore previous hook files."
)


@unittest.skipUnless(SSH_KEYGEN, "ssh-keygen required for semantic hook approval tests")
class SemanticHookApprovalBindingTest(unittest.TestCase):
    def test_ready_binding_uses_exact_signed_package_and_stays_inert(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _approval_fixture(root)

            binding = SemanticHookApprovalBindingStore(fixture["store"]).create(
                semantic_hook_install_plan_id=fixture["install_plan"]["semantic_hook_install_plan_id"],
                source_root=Path.cwd(),
                package_verification=fixture["package"]["verification"],
                package_manifest=fixture["package"]["manifest"],
                rollback_proof_ref="local://semantic-hook-approval/rollback",
                rollback_proof_sha256=sha256_text("rollback proof"),
                rollback_preflight_passed=True,
                operator_readback_ref="local://semantic-hook-approval/readback",
                operator_readback_text=READY_READBACK,
                label="test-semantic-hook-approval",
            )

            self.assertEqual(binding["status"], "ready_for_operator_approval")
            self.assertEqual(binding["reason_codes"], ["semantic_hook_approval.ready_for_operator_approval"])
            self.assertTrue(all(binding["required_gates"].values()))
            self.assertTrue(binding["package_provenance"]["manifest_declares_exact_install_plan"])
            self.assertTrue(binding["package_provenance"]["manifest_declares_exact_hook_run"])
            self.assertTrue(binding["package_provenance"]["manifest_declares_exact_codex_preview"])
            self.assertTrue(binding["package_provenance"]["manifest_declares_exact_claude_preview"])
            self.assertFalse(binding["approval_granted"])
            self.assertFalse(binding["live_install_allowed"])
            self.assertFalse(binding["hook_file_write_allowed"])
            self.assertFalse(binding["hook_trust_allowed"])
            self.assertFalse(binding["provider_hook_execution_allowed"])
            self.assertEqual(binding["start_actions"], [])
            self.assertTrue(ReplayChecker(fixture["store"]).check()["ok"])

    def test_valid_signed_package_without_exact_hook_artifacts_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _approval_fixture(root, include_exact_artifacts=False)

            binding = SemanticHookApprovalBindingStore(fixture["store"]).create(
                semantic_hook_install_plan_id=fixture["install_plan"]["semantic_hook_install_plan_id"],
                source_root=Path.cwd(),
                package_verification=fixture["package"]["verification"],
                package_manifest=fixture["package"]["manifest"],
                rollback_proof_ref="local://semantic-hook-approval/rollback",
                rollback_proof_sha256=sha256_text("rollback proof"),
                rollback_preflight_passed=True,
                operator_readback_ref="local://semantic-hook-approval/readback",
                operator_readback_text=READY_READBACK,
                label="test-semantic-hook-approval-missing-artifacts",
            )

            self.assertEqual(binding["status"], "blocked")
            self.assertTrue(binding["package_provenance"]["signed_package_verified"])
            self.assertIn("semantic_hook_approval.manifest_declares_exact_install_plan_missing", binding["reason_codes"])
            self.assertTrue(ReplayChecker(fixture["store"]).check()["ok"])

    def test_replay_catches_authority_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _approval_fixture(root)
            binding = _create_ready_binding(fixture)
            state = fixture["store"].load()
            record = state["semantic_hook_approval_bindings"][binding["semantic_hook_approval_binding_id"]]
            record["live_install_allowed"] = True
            record["semantic_hook_approval_binding_sha256"] = _hash_without(
                record,
                "semantic_hook_approval_binding_sha256",
            )
            fixture["store"].save(state, validate=False)

            replay = ReplayChecker(fixture["store"]).check()

            self.assertFalse(replay["ok"])
            self.assertIn("semantic_hook_approval.live_install_allowed_not_false", "\n".join(replay["errors"]))

    def test_replay_catches_stale_install_plan_after_binding(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _approval_fixture(root)
            _create_ready_binding(fixture)
            state = fixture["store"].load()
            plan_id = fixture["install_plan"]["semantic_hook_install_plan_id"]
            plan = state["semantic_hook_install_plans"][plan_id]
            plan["install_targets"][0]["installed"] = True
            plan["semantic_hook_install_plan_sha256"] = _hash_without(
                plan,
                "semantic_hook_install_plan_sha256",
            )
            fixture["store"].save(state, validate=False)

            replay = ReplayChecker(fixture["store"]).check()

            self.assertFalse(replay["ok"])
            self.assertIn("semantic_hook_approval.install_plan_hash_mismatch", "\n".join(replay["errors"]))
            self.assertIn("semantic_hook_approval.required_gates_mismatch", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_semantic_hook_approval_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _approval_fixture(root)
            _create_ready_binding(fixture)

            result = ReplayOracle(fixture["store"]).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("semantic_hook_approval_bindings", collections)


def _approval_fixture(root: Path, *, include_exact_artifacts: bool = True) -> dict[str, object]:
    store = JsonStore(root / "store.json")
    sweep = SimulationSweepStore(store).create(
        source_root=Path.cwd(),
        simulation_area=root / "sim",
        scenario_count=1370,
        label="semantic-approval-source",
    )
    review = SemanticOracleReviewStore(store).create(
        simulation_sweep_id=sweep["simulation_sweep_id"],
        source_root=Path.cwd(),
        label="semantic-approval-review",
    )
    hook_run = SemanticHookRunStore(store).create(
        semantic_oracle_review_id=review["semantic_oracle_review_id"],
        source_root=Path.cwd(),
        label="semantic-approval-hook-run",
    )
    install_plan = SemanticHookInstallPlanStore(store).create(
        semantic_hook_run_id=hook_run["semantic_hook_run_id"],
        source_root=Path.cwd(),
        label="semantic-approval-install-plan",
    )
    package = _signed_package_fixture(root, store, install_plan, include_exact_artifacts=include_exact_artifacts)
    return {
        "store": store,
        "hook_run": hook_run,
        "install_plan": install_plan,
        "package": package,
    }


def _create_ready_binding(fixture: dict[str, object]) -> dict[str, object]:
    return SemanticHookApprovalBindingStore(fixture["store"]).create(
        semantic_hook_install_plan_id=fixture["install_plan"]["semantic_hook_install_plan_id"],
        source_root=Path.cwd(),
        package_verification=fixture["package"]["verification"],
        package_manifest=fixture["package"]["manifest"],
        rollback_proof_ref="local://semantic-hook-approval/rollback",
        rollback_proof_sha256=sha256_text("rollback proof"),
        rollback_preflight_passed=True,
        operator_readback_ref="local://semantic-hook-approval/readback",
        operator_readback_text=READY_READBACK,
        label="test-semantic-hook-approval-ready",
    )


def _signed_package_fixture(
    root: Path,
    store: JsonStore,
    install_plan: dict[str, object],
    *,
    include_exact_artifacts: bool,
) -> dict[str, object]:
    gate_artifacts = [
        {
            "artifact_id": "authority_gate_engine",
            "artifact_type": "gate_engine",
            "mode": "shadow_only",
            "artifact_sha256": None,
            "status": "not_packaged",
        }
    ]
    if include_exact_artifacts:
        gate_artifacts.extend(_hook_gate_artifacts(install_plan))
    manifest = build_package_manifest(
        store.load(),
        name="semantic-hook-approval-package",
        package_mode="shadow_only",
        gate_artifacts=gate_artifacts,
    )
    key_path = root / "signer"
    manifest_path = root / "package.json"
    manifest_path.write_text(canonical_json(manifest), encoding="utf-8")
    subprocess.run(
        [SSH_KEYGEN or "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "signer@example.test", "-f", str(key_path)],
        check=True,
        capture_output=True,
    )
    fingerprint = subprocess.run(
        [SSH_KEYGEN or "ssh-keygen", "-lf", str(key_path.with_suffix(".pub")), "-E", "sha256"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()[1]
    allowed_signers = root / "allowed_signers"
    allowed_signers.write_text(
        f"signer@example.test {key_path.with_suffix('.pub').read_text(encoding='utf-8')}",
        encoding="utf-8",
    )
    subprocess.run(
        [SSH_KEYGEN or "ssh-keygen", "-Y", "sign", "-f", str(key_path), "-n", "ams-package", str(manifest_path)],
        check=True,
        capture_output=True,
    )
    verification = verify_package_manifest(
        manifest_path,
        manifest_path.with_suffix(manifest_path.suffix + ".sig"),
        SignedPolicyConfig(
            allowed_signers_path=allowed_signers,
            signer_identity="signer@example.test",
            pinned_fingerprints=(fingerprint,),
            namespace="ams-package",
            ssh_keygen=SSH_KEYGEN or "ssh-keygen",
        ),
        store=store,
    )
    assert verification["allowed"], verification
    return {"manifest": manifest, "verification": verification}


def _hook_gate_artifacts(install_plan: dict[str, object]) -> list[dict[str, object]]:
    return [
        {
            "artifact_id": "semantic_hook_install_plan",
            "artifact_type": "hook_install_plan",
            "mode": "shadow_only",
            "artifact_sha256": install_plan["semantic_hook_install_plan_sha256"],
            "status": "packaged",
        },
        {
            "artifact_id": "semantic_hook_run",
            "artifact_type": "semantic_hook_run",
            "mode": "shadow_only",
            "artifact_sha256": install_plan["semantic_hook_run_sha256"],
            "status": "packaged",
        },
        {
            "artifact_id": "codex_hook_config_preview",
            "artifact_type": "hook_config_preview",
            "mode": "shadow_only",
            "artifact_sha256": install_plan["codex_hook_config_preview_sha256"],
            "status": "packaged",
        },
        {
            "artifact_id": "claude_hook_contract_preview",
            "artifact_type": "hook_contract_preview",
            "mode": "shadow_only",
            "artifact_sha256": install_plan["claude_hook_contract_preview_sha256"],
            "status": "packaged",
        },
    ]


if __name__ == "__main__":
    unittest.main()
