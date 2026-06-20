from __future__ import annotations

from copy import deepcopy
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from ams.admission import AdmissionReviewStore
from ams.capability_policy import build_capability_request, evaluate_capability_request
from ams.codex_adapter import CodexDryRunAdapter
from ams.context import ContextStore
from ams.definition_registry import DefinitionRegistryStore
from ams.dispatch import dispatch
from ams.models import canonical_json, sha256_text
from ams.outbox import OutboxStore
from ams.package_manifest import build_package_manifest, verify_package_manifest
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.resource_claim import ResourceClaimStore
from ams.runner_boundary import runner_preflight
from ams.runner_parity import RunnerDryRunParityStore
from ams.run_trace import RunTraceStore
from ams.schema_validation import validate_record
from ams.session_registry import SessionRegistry
from ams.shadow_launch import ShadowLaunchStore
from ams.signed_policy import SignedPolicyConfig
from ams.store import JsonStore
from ams.surface_bindings import SurfaceBindingStore
from ams.surface_promise import SurfacePromiseStore


SSH_KEYGEN = shutil.which("ssh-keygen")
READY_INSTALL = {
    "schema_version": "ams.ams.install_preflight.v0",
    "ready_for_live": True,
    "status": "pass",
    "checks": [],
    "summary": {"pass": 4, "defer": 0, "fail": 0},
}


@unittest.skipUnless(SSH_KEYGEN, "ssh-keygen required for runner parity tests")
class RunnerDryRunParityTest(unittest.TestCase):
    def test_live_shadow_runner_parity_uses_signed_manifest_and_stays_inert(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store, envelope, package = _signed_manifest_dispatch_and_launch(root)
            preflight = _live_preflight(store, envelope, package["launch_plan"])

            parity = RunnerDryRunParityStore(store).create(
                envelope=envelope,
                package_verification=package["verification"],
                package_manifest=package["manifest_json"],
                runner_preflight_result=preflight,
            )

            self.assertEqual(parity["status"], "ready_for_operator_review")
            self.assertEqual(parity["reason_codes"], ["runner_parity.ready"])
            self.assertEqual(parity["runner_mode"], "live_shadow_preflight")
            self.assertTrue(parity["parity_checks"]["package_verified"])
            self.assertTrue(parity["parity_checks"]["runner_preflight_live_shadow"])
            self.assertTrue(parity["parity_checks"]["runner_preflight_inert"])
            self.assertFalse(parity["process_start_allowed"])
            self.assertFalse(parity["network_egress_allowed"])
            self.assertEqual(parity["start_actions"], [])
            self.assertEqual(parity["package_manifest_sha256"], package["manifest_json"]["manifest_sha256"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_parity_blocks_when_verification_hash_does_not_match_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store, envelope, package = _signed_manifest_dispatch_and_launch(root)
            preflight = _live_preflight(store, envelope, package["launch_plan"])
            verification = dict(package["verification"])
            verification["manifest_sha256"] = "sha256:" + "0" * 64

            parity = RunnerDryRunParityStore(store).create(
                envelope=envelope,
                package_verification=verification,
                package_manifest=package["manifest_json"],
                runner_preflight_result=preflight,
            )

            self.assertEqual(parity["status"], "blocked")
            self.assertIn("runner_parity.package_manifest_hash_mismatch", parity["reason_codes"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_parity_blocks_when_envelope_definition_is_not_manifested(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store, envelope, package = _signed_manifest_dispatch_and_launch(root)
            preflight = _live_preflight(store, envelope, package["launch_plan"])
            manifest = deepcopy(package["manifest_json"])
            missing_tool = envelope["tool_definition_refs"][0]["definition_id"]
            manifest["registry"]["tool_definitions"] = [
                item for item in manifest["registry"]["tool_definitions"]
                if item["definition_id"] != missing_tool
            ]
            manifest["manifest_sha256"] = _manifest_hash(manifest)
            verification = dict(package["verification"])
            verification["manifest_sha256"] = manifest["manifest_sha256"]

            parity = RunnerDryRunParityStore(store).create(
                envelope=envelope,
                package_verification=verification,
                package_manifest=manifest,
                runner_preflight_result=preflight,
            )

            self.assertEqual(parity["status"], "blocked")
            self.assertIn("runner_parity.envelope_definitions_not_manifested", parity["reason_codes"])
            self.assertIn("runner_parity.registry_mismatch", parity["reason_codes"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_runner_parity_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store, envelope, package = _signed_manifest_dispatch_and_launch(root)
            preflight = _live_preflight(store, envelope, package["launch_plan"])
            parity = RunnerDryRunParityStore(store).create(
                envelope=envelope,
                package_verification=package["verification"],
                package_manifest=package["manifest_json"],
                runner_preflight_result=preflight,
            )
            state = store.load()
            state["runner_dry_run_parities"][parity["runner_dry_run_parity_id"]]["process_start_allowed"] = True
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("runner_parity.process_start_allowed_not_false", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_runner_parity(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store, envelope, package = _signed_manifest_dispatch_and_launch(root)
            preflight = _live_preflight(store, envelope, package["launch_plan"])
            RunnerDryRunParityStore(store).create(
                envelope=envelope,
                package_verification=package["verification"],
                package_manifest=package["manifest_json"],
                runner_preflight_result=preflight,
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("runner_dry_run_parities", collections)


def _signed_manifest_dispatch_and_launch(root: Path) -> tuple[JsonStore, dict, dict]:
    store = JsonStore(root / "store.json")
    DefinitionRegistryStore(store).install_defaults()
    package = _signed_package_fixture(root, store)
    envelope = _dispatched_envelope(root, store)
    launch_plan = _shadow_launch_plan_for_envelope(
        store,
        envelope,
        package_manifest_sha256=package["verification"]["manifest_sha256"],
        package_verification=package["verification"],
    )
    package["launch_plan"] = launch_plan
    return store, envelope, package


def _dispatched_envelope(root: Path, store: JsonStore) -> dict:
    event = {"channel_id": "chan", "message_id": "root", "content": "build"}
    session, _ = SessionRegistry(store).ingest_event(event)
    session = CodexDryRunAdapter(store).bind_thread(session["session_id"], "thread-1")
    context = ContextStore(store).create_for_event(session, event)
    task_run = RunTraceStore(store).create_run(
        session["session_id"],
        context["context_id"],
        model="gpt-5.5",
        sandbox="workspace-write",
        tool_scope=["Read", "ApplyPatch", "Tests"],
    )
    request = build_capability_request(
        action="write",
        paths=["tests/test_runner_parity.py"],
        tools=["Read", "ApplyPatch", "Tests"],
        egress_mode="ams_outbox",
    )
    AdmissionReviewStore(store).create(
        subject_kind="task_run",
        subject_id=task_run["task_run_id"],
        operation="capability.dispatch",
        request=request,
        verdict=evaluate_capability_request(request),
    )
    claim = ResourceClaimStore(store).reserve(task_run["task_run_id"])["claim"]
    assert claim is not None
    ResourceClaimStore(store).transition(claim["resource_claim_id"], "active")
    result = dispatch(store, task_run["task_run_id"])
    assert result["dispatched"], result
    return result["envelope"]


def _shadow_launch_plan_for_envelope(
    store: JsonStore,
    envelope: dict,
    *,
    package_manifest_sha256: str,
    package_verification: dict,
) -> dict:
    surface = SurfaceBindingStore(store).declare_surface(
        provider=envelope["provider"],
        surface=envelope["surface"],
        runtime_name="runner-parity-codex-app-server",
        transport="stdio",
        rollout_mode="shadow",
        session_semantics="persistent_thread",
        capability_tier="builder",
        egress_modes=["none"],
        package_manifest_sha256=package_manifest_sha256,
    )
    binding = SurfaceBindingStore(store).bind_surface(
        runtime_surface_id=surface["runtime_surface_id"],
        session_id=envelope["session_id"],
        provider_session_id=envelope.get("provider_session_id"),
        task_run_id=envelope["task_run_id"],
    )
    outbox = OutboxStore(store).create_item(
        envelope["task_run_id"],
        target="discord",
        channel_id="chan",
        endpoint="/channels/chan/messages",
        payload={"content": "runner parity test"},
    )
    OutboxStore(store).record_receipt(
        outbox["outbox_id"],
        status="readback_verified",
        response_payload={"message_id": "runner-parity-msg"},
        readback_ref="discord://chan/runner-parity-msg",
    )
    promise = SurfacePromiseStore(store).create(
        envelope["task_run_id"],
        promised_surfaces=[
            {
                "surface": "discord",
                "target": "discord",
                "channel_id": "chan",
                "outbox_id": outbox["outbox_id"],
                "required": True,
                "required_readback": True,
            }
        ],
        source_packet_ref="source-packet://runner-parity-test",
        promise_reason="runner_parity_surface_gate",
    )
    return ShadowLaunchStore(store).create_plan(
        install_preflight=READY_INSTALL,
        package_verification=package_verification,
        approval_id="approval-runner-parity-test",
        egress_mode="none",
        runtime_surface_ids=[surface["runtime_surface_id"]],
        surface_binding_ids=[binding["surface_binding_id"]],
        surface_promise_ids=[promise["surface_promise_id"]],
    )


def _live_preflight(store: JsonStore, envelope: dict, plan: dict) -> dict:
    result = runner_preflight(
        envelope,
        store,
        live=True,
        shadow_launch_plan_id=plan["shadow_launch_plan_id"],
        shadow_launch_plan_sha256=plan["shadow_launch_plan_sha256"],
    )
    assert result["allowed"], result
    return result


def _signed_package_fixture(root: Path, store: JsonStore) -> dict:
    key_path = root / "signer"
    manifest_path = root / "package.json"
    manifest = build_package_manifest(store.load())
    validate_record("package_manifest.schema.json", manifest, location="package")
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
    return {
        "manifest_path": manifest_path,
        "manifest_json": manifest,
        "verification": verification,
    }


def _manifest_hash(manifest: dict) -> str:
    material = dict(manifest)
    material.pop("manifest_sha256", None)
    return sha256_text(canonical_json(material))


if __name__ == "__main__":
    unittest.main()
