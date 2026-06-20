from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ams_codex.capability_policy import (
    build_capability_request,
    build_default_capability_policy,
    evaluate_capability_request,
)
from ams_codex.policy_common import policy_hash


class CapabilityPolicyTest(unittest.TestCase):
    def test_builder_can_edit_docs_and_tests(self) -> None:
        request = build_capability_request(
            tier="builder",
            action="write",
            paths=["SECURITY_KERNEL.md", "tests/test_new_behavior.py"],
            tools=["Read", "ApplyPatch", "Tests"],
        )
        verdict = evaluate_capability_request(request, build_default_capability_policy())
        self.assertEqual(verdict["status"], "allow", verdict["reason_codes"])

    def test_builder_protected_ams_authority_change_is_deferred(self) -> None:
        request = build_capability_request(
            tier="builder",
            action="write",
            paths=["ams_codex/resource_policy.py"],
            tools=["ApplyPatch"],
        )
        verdict = evaluate_capability_request(request, build_default_capability_policy())
        self.assertEqual(verdict["status"], "defer")
        self.assertIn("capability.ams_authority_requires_review", verdict["reason_codes"])
        self.assertIn("ams_codex/resource_policy.py", verdict["deferred_paths"])

    def test_builder_shareability_authority_change_is_deferred(self) -> None:
        request = build_capability_request(
            tier="builder",
            action="write",
            paths=[
                "ams_codex/shareability_bundle.py",
                "ams_codex/shareability_receiver.py",
                "schemas/shareability_bundle.schema.json",
                "schemas/shareability_receiver_trial.schema.json",
            ],
            tools=["ApplyPatch"],
        )
        verdict = evaluate_capability_request(request, build_default_capability_policy())
        self.assertEqual(verdict["status"], "defer")
        self.assertIn("capability.ams_authority_requires_review", verdict["reason_codes"])
        self.assertIn("ams_codex/shareability_bundle.py", verdict["deferred_paths"])
        self.assertIn("ams_codex/shareability_receiver.py", verdict["deferred_paths"])
        self.assertIn("schemas/shareability_bundle.schema.json", verdict["deferred_paths"])
        self.assertIn("schemas/shareability_receiver_trial.schema.json", verdict["deferred_paths"])

    def test_builder_rag_authority_change_is_deferred(self) -> None:
        request = build_capability_request(
            tier="builder",
            action="write",
            paths=[
                "ams_codex/rag_local_vector_trial.py",
                "schemas/rag_local_vector_trial.schema.json",
            ],
            tools=["ApplyPatch"],
        )
        verdict = evaluate_capability_request(request, build_default_capability_policy())
        self.assertEqual(verdict["status"], "defer")
        self.assertIn("capability.ams_authority_requires_review", verdict["reason_codes"])
        self.assertIn("ams_codex/rag_local_vector_trial.py", verdict["deferred_paths"])
        self.assertIn("schemas/rag_local_vector_trial.schema.json", verdict["deferred_paths"])

    def test_builder_doc_action_authority_change_is_deferred_by_example_policy(self) -> None:
        request = build_capability_request(
            tier="builder",
            action="write",
            paths=[
                "ams_codex/doc_action_execution.py",
                "ams_codex/doc_action_operator_approval.py",
                "ams_codex/doc_action_patch_preview.py",
                "ams_codex/doc_action_patch_readback.py",
                "ams_codex/doc_action_patch_artifact.py",
                "ams_codex/doc_action_patch_artifact_approval.py",
                "ams_codex/doc_action_patch_dry_run.py",
                "ams_codex/doc_action_patch_dry_run_readback.py",
                "ams_codex/doc_action_patch_live_execution_approval.py",
                "ams_codex/doc_action_patch_executor_preflight.py",
                "ams_codex/doc_action_patch_apply_boundary.py",
                "ams_codex/doc_action_patch_apply_acceptance.py",
                "schemas/doc_action_execution_plan.schema.json",
                "schemas/doc_action_operator_approval_packet.schema.json",
                "schemas/doc_action_patch_preview.schema.json",
                "schemas/doc_action_patch_readback_receipt.schema.json",
                "schemas/doc_action_patch_artifact_receipt.schema.json",
                "schemas/doc_action_patch_artifact_approval_packet.schema.json",
                "schemas/doc_action_patch_dry_run_plan.schema.json",
                "schemas/doc_action_patch_dry_run_readback_receipt.schema.json",
                "schemas/doc_action_patch_live_execution_approval_packet.schema.json",
                "schemas/doc_action_patch_executor_preflight.schema.json",
                "schemas/doc_action_patch_apply_boundary_packet.schema.json",
                "schemas/doc_action_patch_apply_acceptance_packet.schema.json",
            ],
            tools=["ApplyPatch"],
        )
        verdict = evaluate_capability_request(request, build_default_capability_policy())
        self.assertEqual(verdict["status"], "defer")
        self.assertIn("capability.ams_authority_requires_review", verdict["reason_codes"])
        self.assertIn("ams_codex/doc_action_execution.py", verdict["deferred_paths"])
        self.assertIn("ams_codex/doc_action_operator_approval.py", verdict["deferred_paths"])
        self.assertIn("ams_codex/doc_action_patch_preview.py", verdict["deferred_paths"])
        self.assertIn("ams_codex/doc_action_patch_readback.py", verdict["deferred_paths"])
        self.assertIn("ams_codex/doc_action_patch_artifact.py", verdict["deferred_paths"])
        self.assertIn("ams_codex/doc_action_patch_artifact_approval.py", verdict["deferred_paths"])
        self.assertIn("ams_codex/doc_action_patch_dry_run.py", verdict["deferred_paths"])
        self.assertIn("ams_codex/doc_action_patch_dry_run_readback.py", verdict["deferred_paths"])
        self.assertIn("ams_codex/doc_action_patch_live_execution_approval.py", verdict["deferred_paths"])
        self.assertIn("ams_codex/doc_action_patch_executor_preflight.py", verdict["deferred_paths"])
        self.assertIn("ams_codex/doc_action_patch_apply_boundary.py", verdict["deferred_paths"])
        self.assertIn("ams_codex/doc_action_patch_apply_acceptance.py", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_execution_plan.schema.json", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_operator_approval_packet.schema.json", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_patch_preview.schema.json", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_patch_readback_receipt.schema.json", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_patch_artifact_receipt.schema.json", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_patch_artifact_approval_packet.schema.json", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_patch_dry_run_plan.schema.json", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_patch_dry_run_readback_receipt.schema.json", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_patch_live_execution_approval_packet.schema.json", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_patch_executor_preflight.schema.json", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_patch_apply_boundary_packet.schema.json", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_patch_apply_acceptance_packet.schema.json", verdict["deferred_paths"])

    def test_checked_in_default_policy_hash_is_current_and_protects_doc_patch_readback(self) -> None:
        path = Path("examples/capability_policy.default.json")
        policy = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(policy["policy_sha256"], policy_hash(policy))
        request = build_capability_request(
            tier="builder",
            action="write",
            paths=[
                "ams_codex/doc_action_patch_readback.py",
                "ams_codex/doc_action_patch_artifact.py",
                "ams_codex/doc_action_patch_artifact_approval.py",
                "ams_codex/doc_action_patch_dry_run.py",
                "ams_codex/doc_action_patch_dry_run_readback.py",
                "ams_codex/doc_action_patch_live_execution_approval.py",
                "ams_codex/doc_action_patch_executor_preflight.py",
                "ams_codex/doc_action_patch_apply_boundary.py",
                "ams_codex/doc_action_patch_apply_acceptance.py",
                "schemas/doc_action_patch_readback_receipt.schema.json",
                "schemas/doc_action_patch_artifact_receipt.schema.json",
                "schemas/doc_action_patch_artifact_approval_packet.schema.json",
                "schemas/doc_action_patch_dry_run_plan.schema.json",
                "schemas/doc_action_patch_dry_run_readback_receipt.schema.json",
                "schemas/doc_action_patch_live_execution_approval_packet.schema.json",
                "schemas/doc_action_patch_executor_preflight.schema.json",
                "schemas/doc_action_patch_apply_boundary_packet.schema.json",
                "schemas/doc_action_patch_apply_acceptance_packet.schema.json",
            ],
            tools=["ApplyPatch"],
        )
        verdict = evaluate_capability_request(request, policy)
        self.assertEqual(verdict["status"], "defer", verdict["reason_codes"])
        self.assertIn("capability.ams_authority_requires_review", verdict["reason_codes"])
        self.assertIn("ams_codex/doc_action_patch_readback.py", verdict["deferred_paths"])
        self.assertIn("ams_codex/doc_action_patch_artifact.py", verdict["deferred_paths"])
        self.assertIn("ams_codex/doc_action_patch_artifact_approval.py", verdict["deferred_paths"])
        self.assertIn("ams_codex/doc_action_patch_dry_run.py", verdict["deferred_paths"])
        self.assertIn("ams_codex/doc_action_patch_dry_run_readback.py", verdict["deferred_paths"])
        self.assertIn("ams_codex/doc_action_patch_live_execution_approval.py", verdict["deferred_paths"])
        self.assertIn("ams_codex/doc_action_patch_executor_preflight.py", verdict["deferred_paths"])
        self.assertIn("ams_codex/doc_action_patch_apply_boundary.py", verdict["deferred_paths"])
        self.assertIn("ams_codex/doc_action_patch_apply_acceptance.py", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_patch_readback_receipt.schema.json", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_patch_artifact_receipt.schema.json", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_patch_artifact_approval_packet.schema.json", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_patch_dry_run_plan.schema.json", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_patch_dry_run_readback_receipt.schema.json", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_patch_live_execution_approval_packet.schema.json", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_patch_executor_preflight.schema.json", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_patch_apply_boundary_packet.schema.json", verdict["deferred_paths"])
        self.assertIn("schemas/doc_action_patch_apply_acceptance_packet.schema.json", verdict["deferred_paths"])

    def test_builder_registry_authority_change_is_deferred(self) -> None:
        request = build_capability_request(
            tier="builder",
            action="write",
            paths=[
                "ams_codex/definition_registry.py",
                "ams_codex/package_manifest.py",
                "ams_codex/runner_boundary.py",
                "ams_codex/install_preflight.py",
                "ams_codex/shadow_readiness.py",
                "ams_codex/shadow_launch.py",
                "ams_codex/shadow_runner.py",
                "ams_codex/agent_memory_sim.py",
                "ams_codex/real_agent_trial.py",
                "ams_codex/attention_router.py",
                "ams_codex/manager_intervention.py",
                "ams_codex/surface_bindings.py",
                "ams_codex/surface_promise.py",
                "schemas/tool_definition.schema.json",
                "schemas/runtime_surface.schema.json",
                "schemas/surface_binding.schema.json",
                "schemas/surface_promise.schema.json",
                "schemas/agent_memory_trial.schema.json",
                "schemas/real_agent_trial.schema.json",
                "schemas/attention_signal.schema.json",
                "schemas/manager_intervention.schema.json",
                "schemas/shadow_launch_plan.schema.json",
                "schemas/shadow_runner_transaction.schema.json",
                "schemas/package_manifest.schema.json",
            ],
            tools=["ApplyPatch"],
        )
        verdict = evaluate_capability_request(request, build_default_capability_policy())
        self.assertEqual(verdict["status"], "defer")
        self.assertIn("capability.ams_authority_requires_review", verdict["reason_codes"])

    def test_secret_paths_are_denied_even_for_signed_maintainer(self) -> None:
        request = build_capability_request(
            tier="signed_maintainer",
            action="write",
            paths=[".env"],
            tools=["ApplyPatch"],
            change_request_id="chg_1",
            admission_review_id="adm_1",
            signed_policy_sha256="sha256:" + "a" * 64,
        )
        verdict = evaluate_capability_request(request, build_default_capability_policy())
        self.assertEqual(verdict["status"], "deny")
        self.assertIn("capability.secret_path_denied", verdict["reason_codes"])

    def test_git_internals_are_denied(self) -> None:
        request = build_capability_request(
            tier="builder",
            action="write",
            paths=[".git/config"],
            tools=["ApplyPatch"],
        )
        verdict = evaluate_capability_request(request, build_default_capability_policy())
        self.assertEqual(verdict["status"], "deny")
        self.assertIn("capability.vcs_internal_denied", verdict["reason_codes"])

    def test_supply_chain_files_require_review(self) -> None:
        request = build_capability_request(
            tier="builder",
            action="write",
            paths=["pyproject.toml", ".github/workflows/ci.yml"],
            tools=["ApplyPatch"],
        )
        verdict = evaluate_capability_request(request, build_default_capability_policy())
        self.assertEqual(verdict["status"], "defer")
        self.assertIn("capability.supply_chain_requires_review", verdict["reason_codes"])

    def test_direct_egress_is_denied(self) -> None:
        request = build_capability_request(
            tier="builder",
            action="write",
            paths=["notes/status.md"],
            tools=["discord_client.send"],
            egress_mode="direct",
        )
        verdict = evaluate_capability_request(request, build_default_capability_policy())
        self.assertEqual(verdict["status"], "deny")
        self.assertIn("capability.direct_egress_denied", verdict["reason_codes"])
        self.assertIn("capability.tool_denied:discord_client.send", verdict["reason_codes"])

    def test_signed_maintainer_can_apply_reviewed_authority_change(self) -> None:
        request = build_capability_request(
            tier="signed_maintainer",
            action="write",
            paths=["ams_codex/replay.py"],
            tools=["ApplyPatch", "Tests"],
            change_request_id="chg_ams_kernel_1",
            admission_review_id="adm_allow_1",
            signed_policy_sha256="sha256:" + "b" * 64,
        )
        verdict = evaluate_capability_request(request, build_default_capability_policy())
        self.assertEqual(verdict["status"], "allow", verdict["reason_codes"])
        self.assertIn("ams_codex/replay.py", verdict["allowed_paths"])

    def test_outside_workspace_is_denied(self) -> None:
        request = build_capability_request(
            tier="builder",
            action="write",
            paths=["/home/user/.ssh/config"],
            tools=["ApplyPatch"],
        )
        verdict = evaluate_capability_request(request, build_default_capability_policy())
        self.assertEqual(verdict["status"], "deny")
        self.assertIn("capability.path_outside_workspace", verdict["reason_codes"])

    def test_policy_hash_mismatch_is_denied(self) -> None:
        policy = build_default_capability_policy()
        policy["tiers"][0]["allowed_actions"].append("write")
        request = build_capability_request(
            tier="builder",
            action="write",
            paths=["tests/test_new_behavior.py"],
            tools=["ApplyPatch"],
        )
        verdict = evaluate_capability_request(request, policy)
        self.assertEqual(verdict["status"], "deny")
        self.assertIn("capability.policy_hash_mismatch", verdict["reason_codes"])

    def test_relative_traversal_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td) / "AMS_codex"
            workspace.mkdir()
            policy = build_default_capability_policy()
            policy.pop("policy_sha256", None)
            policy["scope"]["workspace_roots"] = [str(workspace)]
            request = build_capability_request(
                tier="builder",
                action="write",
                paths=["../outside.txt"],
                tools=["ApplyPatch"],
            )
            verdict = evaluate_capability_request(request, policy)
            self.assertEqual(verdict["status"], "deny")
            self.assertIn("capability.path_outside_workspace", verdict["reason_codes"])

    def test_symlink_escape_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td) / "AMS_codex"
            outside = Path(td) / "outside"
            workspace.mkdir()
            outside.mkdir()
            (outside / "target.txt").write_text("outside", encoding="utf-8")
            (workspace / "link").symlink_to(outside)
            policy = build_default_capability_policy()
            policy.pop("policy_sha256", None)
            policy["scope"]["workspace_roots"] = [str(workspace)]
            request = build_capability_request(
                tier="builder",
                action="write",
                paths=[str(workspace / "link" / "target.txt")],
                tools=["ApplyPatch"],
            )
            verdict = evaluate_capability_request(request, policy)
            self.assertEqual(verdict["status"], "deny")
            self.assertIn("capability.path_outside_workspace", verdict["reason_codes"])

    def test_sibling_prefix_escape_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td) / "AMS_codex"
            sibling = Path(td) / "AMS_codex_evil"
            workspace.mkdir()
            sibling.mkdir()
            policy = build_default_capability_policy()
            policy.pop("policy_sha256", None)
            policy["scope"]["workspace_roots"] = [str(workspace)]
            request = build_capability_request(
                tier="builder",
                action="write",
                paths=[str(sibling / "STATUS.md")],
                tools=["ApplyPatch"],
            )
            verdict = evaluate_capability_request(request, policy)
            self.assertEqual(verdict["status"], "deny")
            self.assertIn("capability.path_outside_workspace", verdict["reason_codes"])


if __name__ == "__main__":
    unittest.main()
