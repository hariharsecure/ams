from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .package_manifest import validate_package_manifest
from .schema_validation import SchemaValidationError, validate_record
from .semantic_hook_install_plan import validate_semantic_hook_install_plan_record
from .store import JsonStore
from .workspace import repo_root


SCHEMA_VERSION = "ams.ams_codex.semantic_hook_approval_binding.v0"
STATUSES = {"ready_for_operator_approval", "blocked"}

REQUIRED_READBACK_PHRASES = [
    "hook files remain unwritten until approval",
    "no provider hook will execute from this packet",
    "egress mode is none",
    "rollback is restore previous hook files",
]

LIVE_BOUNDARIES = {
    "hook_file_written": False,
    "hook_installed": False,
    "hook_trusted": False,
    "provider_hook_executed": False,
    "discord_call_performed": False,
    "terminal_attach_performed": False,
    "terminal_capture_performed": False,
    "terminal_injection_performed": False,
    "persistent_process_started": False,
    "provider_call_performed": False,
    "embedding_call_performed": False,
    "vector_write_performed": False,
    "network_call_performed": False,
    "raw_content_stored": False,
    "secret_stored": False,
}


class SemanticHookApprovalBindingStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        semantic_hook_install_plan_id: str,
        source_root: str | Path | None = None,
        package_verification: dict[str, Any] | None = None,
        package_manifest: dict[str, Any] | None = None,
        rollback_proof_ref: str | None = None,
        rollback_proof_sha256: str | None = None,
        rollback_preflight_passed: bool = False,
        operator_readback_ref: str | None = None,
        operator_readback_text: str = "",
        label: str = "manual-semantic-hook-approval-binding",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            install_plan = (state.get("semantic_hook_install_plans") or {}).get(semantic_hook_install_plan_id)
            if not install_plan:
                raise KeyError(f"semantic hook install plan not found: {semantic_hook_install_plan_id}")
            record = build_semantic_hook_approval_binding(
                install_plan=install_plan,
                source_root=source_root,
                package_verification=package_verification,
                package_manifest=package_manifest,
                rollback_proof_ref=rollback_proof_ref,
                rollback_proof_sha256=rollback_proof_sha256,
                rollback_preflight_passed=rollback_preflight_passed,
                operator_readback_ref=operator_readback_ref,
                operator_readback_text=operator_readback_text,
                label=label,
            )
            binding_id = record["semantic_hook_approval_binding_id"]
            state.setdefault("semantic_hook_approval_bindings", {})[binding_id] = record
            state.setdefault("indexes", {}).setdefault("semantic_hook_approval_binding_ids", {})[binding_id] = binding_id
            return deepcopy(record)


def build_semantic_hook_approval_binding(
    *,
    install_plan: dict[str, Any],
    source_root: str | Path | None = None,
    package_verification: dict[str, Any] | None = None,
    package_manifest: dict[str, Any] | None = None,
    rollback_proof_ref: str | None = None,
    rollback_proof_sha256: str | None = None,
    rollback_preflight_passed: bool = False,
    operator_readback_ref: str | None = None,
    operator_readback_text: str = "",
    label: str = "manual-semantic-hook-approval-binding",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False) if source_root else repo_root()
    provenance = _package_provenance(
        install_plan=install_plan,
        package_verification=package_verification,
        package_manifest=package_manifest,
    )
    rollback = _rollback_evidence(
        rollback_proof_ref=rollback_proof_ref,
        rollback_proof_sha256=rollback_proof_sha256,
        rollback_preflight_passed=rollback_preflight_passed,
    )
    readback = _operator_readback(
        readback_ref=operator_readback_ref,
        readback_text=operator_readback_text,
        now=now,
    )
    required_gates = _required_gates(
        install_plan=install_plan,
        provenance=provenance,
        rollback=rollback,
        readback=readback,
    )
    reason_codes = _reason_codes(required_gates, readback)
    status = "ready_for_operator_approval" if reason_codes == ["semantic_hook_approval.ready_for_operator_approval"] else "blocked"
    install_plan_sha = install_plan.get("semantic_hook_install_plan_sha256")
    record = {
        "schema_version": SCHEMA_VERSION,
        "semantic_hook_approval_binding_id": stable_id(
            "semhookapproval",
            label,
            install_plan.get("semantic_hook_install_plan_id"),
            install_plan_sha,
            provenance.get("verification_result_sha256"),
            provenance.get("package_manifest_payload_sha256"),
            rollback.get("rollback_proof_sha256"),
            readback.get("readback_sha256"),
            now,
        ),
        "label": label,
        "source_root": str(root),
        "semantic_hook_install_plan_id": install_plan.get("semantic_hook_install_plan_id"),
        "semantic_hook_install_plan_sha256": install_plan_sha,
        "semantic_hook_run_id": install_plan.get("semantic_hook_run_id"),
        "semantic_hook_run_sha256": install_plan.get("semantic_hook_run_sha256"),
        "semantic_oracle_review_id": install_plan.get("semantic_oracle_review_id"),
        "codex_hook_config_preview_sha256": install_plan.get("codex_hook_config_preview_sha256"),
        "claude_hook_contract_preview_sha256": install_plan.get("claude_hook_contract_preview_sha256"),
        "semantic_hook_record_set_sha256": install_plan.get("semantic_hook_record_set_sha256"),
        "install_target_count": len(install_plan.get("install_targets") or []),
        "package_manifest": deepcopy(package_manifest or {}),
        "package_manifest_sha256": (package_manifest or {}).get("manifest_sha256"),
        "package_verification": deepcopy(package_verification or {}),
        "package_verification_sha256": sha256_text(canonical_json(package_verification or {})),
        "package_provenance": provenance,
        "rollback_evidence": rollback,
        "no_egress_controls": _no_egress_controls(),
        "operator_readback": readback,
        "required_readback_phrases": list(REQUIRED_READBACK_PHRASES),
        "required_gates": required_gates,
        "approval_granted": False,
        "live_install_allowed": False,
        "hook_file_write_allowed": False,
        "hook_trust_allowed": False,
        "provider_hook_execution_allowed": False,
        "start_actions": [],
        "live_boundaries": dict(LIVE_BOUNDARIES),
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["semantic_hook_approval_binding_sha256"] = _hash_without(
        record,
        "semantic_hook_approval_binding_sha256",
    )
    return deepcopy(record)


def validate_semantic_hook_approval_binding_record(
    record: dict[str, Any],
    *,
    install_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("semantic_hook_approval_binding.schema.json", record, location="semantic_hook_approval_binding")
    except SchemaValidationError:
        reason_codes.append("semantic_hook_approval.schema_invalid")
    expected_hash = record.get("semantic_hook_approval_binding_sha256")
    if expected_hash and expected_hash != _hash_without(record, "semantic_hook_approval_binding_sha256"):
        reason_codes.append("semantic_hook_approval.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("semantic_hook_approval.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("semantic_hook_approval.status_invalid")
    for key, expected in LIVE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"semantic_hook_approval.{key}_not_false")
    for key in (
        "approval_granted",
        "live_install_allowed",
        "hook_file_write_allowed",
        "hook_trust_allowed",
        "provider_hook_execution_allowed",
    ):
        if record.get(key) is not False:
            reason_codes.append(f"semantic_hook_approval.{key}_not_false")
    if record.get("start_actions") != []:
        reason_codes.append("semantic_hook_approval.start_actions_not_empty")
    provenance = record.get("package_provenance") or {}
    package_manifest = record.get("package_manifest") or {}
    package_verification = record.get("package_verification") or {}
    if package_manifest:
        try:
            validate_record("package_manifest.schema.json", package_manifest, location="semantic_hook_approval.package_manifest")
        except SchemaValidationError:
            reason_codes.append("semantic_hook_approval.package_manifest_schema_invalid")
        manifest_validation = validate_package_manifest(package_manifest)
        if not manifest_validation["ok"]:
            reason_codes.extend(
                f"semantic_hook_approval.package_manifest:{reason}" for reason in manifest_validation["reason_codes"]
            )
    if record.get("package_manifest_sha256") != package_manifest.get("manifest_sha256"):
        reason_codes.append("semantic_hook_approval.package_manifest_hash_mismatch")
    if record.get("package_verification_sha256") != sha256_text(canonical_json(package_verification)):
        reason_codes.append("semantic_hook_approval.package_verification_hash_mismatch")
    if provenance.get("raw_manifest_stored") is not False:
        reason_codes.append("semantic_hook_approval.raw_manifest_stored_not_false")
    if provenance.get("raw_signature_stored") is not False:
        reason_codes.append("semantic_hook_approval.raw_signature_stored_not_false")
    if provenance.get("raw_verification_result_stored") is not False:
        reason_codes.append("semantic_hook_approval.raw_verification_result_stored_not_false")
    readback = record.get("operator_readback") or {}
    if readback.get("raw_readback_stored") is not False:
        reason_codes.append("semantic_hook_approval.raw_readback_stored_not_false")
    if readback.get("required_phrases_present") != (not readback.get("missing_required_phrases")):
        reason_codes.append("semantic_hook_approval.readback_phrase_flag_mismatch")
    if readback.get("readback_text_sha256") != readback.get("readback_sha256"):
        reason_codes.append("semantic_hook_approval.readback_hash_alias_mismatch")
    no_egress = record.get("no_egress_controls") or {}
    expected_no_egress = _no_egress_controls()
    if no_egress != expected_no_egress:
        reason_codes.append("semantic_hook_approval.no_egress_controls_mismatch")
    if install_plan is not None:
        if record.get("semantic_hook_install_plan_sha256") != install_plan.get("semantic_hook_install_plan_sha256"):
            reason_codes.append("semantic_hook_approval.install_plan_hash_mismatch")
        if record.get("semantic_hook_run_id") != install_plan.get("semantic_hook_run_id"):
            reason_codes.append("semantic_hook_approval.semantic_hook_run_id_mismatch")
        if record.get("semantic_hook_run_sha256") != install_plan.get("semantic_hook_run_sha256"):
            reason_codes.append("semantic_hook_approval.semantic_hook_run_hash_mismatch")
        if record.get("semantic_oracle_review_id") != install_plan.get("semantic_oracle_review_id"):
            reason_codes.append("semantic_hook_approval.semantic_oracle_review_id_mismatch")
        if record.get("codex_hook_config_preview_sha256") != install_plan.get("codex_hook_config_preview_sha256"):
            reason_codes.append("semantic_hook_approval.codex_hook_preview_hash_mismatch")
        if record.get("claude_hook_contract_preview_sha256") != install_plan.get("claude_hook_contract_preview_sha256"):
            reason_codes.append("semantic_hook_approval.claude_hook_preview_hash_mismatch")
        if record.get("semantic_hook_record_set_sha256") != install_plan.get("semantic_hook_record_set_sha256"):
            reason_codes.append("semantic_hook_approval.hook_record_set_hash_mismatch")
        if record.get("install_target_count") != len(install_plan.get("install_targets") or []):
            reason_codes.append("semantic_hook_approval.install_target_count_mismatch")
        plan_validation = validate_semantic_hook_install_plan_record(install_plan)
        if not plan_validation["ok"]:
            reason_codes.extend(f"semantic_hook_approval.install_plan:{reason}" for reason in plan_validation["reason_codes"])
        expected_gates = _required_gates(
            install_plan=install_plan,
            provenance=provenance,
            rollback=record.get("rollback_evidence") or {},
            readback=readback,
        )
        if record.get("required_gates") != expected_gates:
            reason_codes.append("semantic_hook_approval.required_gates_mismatch")
        expected_reasons = _reason_codes(expected_gates, readback)
        expected_status = (
            "ready_for_operator_approval"
            if expected_reasons == ["semantic_hook_approval.ready_for_operator_approval"]
            else "blocked"
        )
        if record.get("status") != expected_status:
            reason_codes.append("semantic_hook_approval.status_reason_mismatch")
        if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
            reason_codes.append("semantic_hook_approval.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _package_provenance(
    *,
    install_plan: dict[str, Any],
    package_verification: dict[str, Any] | None,
    package_manifest: dict[str, Any] | None,
) -> dict[str, Any]:
    verification = package_verification or {}
    manifest = package_manifest or {}
    signature = verification.get("signature") or {}
    manifest_summary = verification.get("manifest") or {}
    verification_sha = sha256_text(canonical_json(verification)) if verification else None
    manifest_payload_sha = sha256_text(canonical_json(manifest)) if manifest else None
    manifest_sha = (
        verification.get("manifest_sha256")
        or manifest.get("manifest_sha256")
        or None
    )
    required_artifacts = _required_manifest_artifacts(install_plan)
    artifact_matches = _artifact_matches(manifest, required_artifacts)
    signed_package_verified = verification.get("allowed") is True and verification.get("status") == "allow"
    signature_verified = signature.get("reason_code") == "signature.verified"
    signer_fingerprint = signature.get("signer_fingerprint")
    return {
        "verification_result_present": bool(verification),
        "verification_result_sha256": verification_sha,
        "raw_verification_result_stored": False,
        "signed_package_verified": bool(signed_package_verified),
        "verification_status": verification.get("status"),
        "verification_reason_code": verification.get("reason_code"),
        "signature_verified": bool(signature_verified),
        "signer_identity": signature.get("signer_identity"),
        "signer_fingerprint": signer_fingerprint,
        "signer_fingerprint_pinned": bool(signed_package_verified and signer_fingerprint),
        "signature_namespace": signature.get("namespace"),
        "package_manifest_id": manifest_summary.get("package_manifest_id") or manifest.get("package_manifest_id"),
        "package_manifest_sha256": manifest_sha,
        "package_manifest_payload_sha256": manifest_payload_sha,
        "package_mode": manifest_summary.get("package_mode") or manifest.get("package_mode"),
        "raw_manifest_stored": False,
        "raw_signature_stored": False,
        "manifest_required_artifacts": required_artifacts,
        "manifest_artifact_matches": artifact_matches,
        "manifest_declares_exact_install_plan": artifact_matches["semantic_hook_install_plan"]["matched"],
        "manifest_declares_exact_hook_run": artifact_matches["semantic_hook_run"]["matched"],
        "manifest_declares_exact_codex_preview": artifact_matches["codex_hook_config_preview"]["matched"],
        "manifest_declares_exact_claude_preview": artifact_matches["claude_hook_contract_preview"]["matched"],
    }


def _required_manifest_artifacts(install_plan: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "artifact_id": "semantic_hook_install_plan",
            "artifact_type": "hook_install_plan",
            "artifact_sha256": install_plan.get("semantic_hook_install_plan_sha256"),
        },
        {
            "artifact_id": "semantic_hook_run",
            "artifact_type": "semantic_hook_run",
            "artifact_sha256": install_plan.get("semantic_hook_run_sha256"),
        },
        {
            "artifact_id": "codex_hook_config_preview",
            "artifact_type": "hook_config_preview",
            "artifact_sha256": install_plan.get("codex_hook_config_preview_sha256"),
        },
        {
            "artifact_id": "claude_hook_contract_preview",
            "artifact_type": "hook_contract_preview",
            "artifact_sha256": install_plan.get("claude_hook_contract_preview_sha256"),
        },
    ]


def _artifact_matches(manifest: dict[str, Any], required_artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    artifacts = {
        artifact.get("artifact_id"): artifact
        for artifact in manifest.get("gate_artifacts") or []
    }
    matches: dict[str, Any] = {}
    for required in required_artifacts:
        artifact_id = str(required.get("artifact_id"))
        found = artifacts.get(artifact_id) or {}
        matches[artifact_id] = {
            "expected_sha256": required.get("artifact_sha256"),
            "actual_sha256": found.get("artifact_sha256"),
            "expected_type": required.get("artifact_type"),
            "actual_type": found.get("artifact_type"),
            "status": found.get("status"),
            "matched": found.get("artifact_sha256") == required.get("artifact_sha256")
            and found.get("artifact_type") == required.get("artifact_type")
            and found.get("status") == "packaged",
        }
    return matches


def _rollback_evidence(
    *,
    rollback_proof_ref: str | None,
    rollback_proof_sha256: str | None,
    rollback_preflight_passed: bool,
) -> dict[str, Any]:
    return {
        "rollback_proof_ref": rollback_proof_ref,
        "rollback_proof_sha256": rollback_proof_sha256,
        "rollback_preflight_passed": bool(rollback_preflight_passed),
        "hook_files_backed_up": False,
        "hook_files_restored": False,
        "write_performed": False,
        "raw_rollback_material_stored": False,
    }


def _operator_readback(*, readback_ref: str | None, readback_text: str, now: str) -> dict[str, Any]:
    missing = _missing_phrases(readback_text)
    text_sha = sha256_text(readback_text)
    return {
        "readback_ref": readback_ref,
        "readback_present": bool(readback_ref or readback_text),
        "readback_sha256": text_sha,
        "readback_text_sha256": text_sha,
        "raw_readback_stored": False,
        "required_phrases_present": not missing,
        "missing_required_phrases": missing,
        "created_at": now,
    }


def _required_gates(
    *,
    install_plan: dict[str, Any],
    provenance: dict[str, Any],
    rollback: dict[str, Any],
    readback: dict[str, Any],
) -> dict[str, bool]:
    return {
        "install_plan_ready": install_plan.get("status") == "ready_for_operator_review"
        and validate_semantic_hook_install_plan_record(install_plan)["ok"],
        "install_plan_inert": _install_plan_inert(install_plan),
        "signed_package_verified": provenance.get("signed_package_verified") is True,
        "signature_verified": provenance.get("signature_verified") is True,
        "pinned_signer_verified": provenance.get("signer_fingerprint_pinned") is True,
        "manifest_declares_exact_install_plan": provenance.get("manifest_declares_exact_install_plan") is True,
        "manifest_declares_exact_hook_run": provenance.get("manifest_declares_exact_hook_run") is True,
        "manifest_declares_exact_codex_preview": provenance.get("manifest_declares_exact_codex_preview") is True,
        "manifest_declares_exact_claude_preview": provenance.get("manifest_declares_exact_claude_preview") is True,
        "rollback_proof_present": bool(rollback.get("rollback_proof_ref") and rollback.get("rollback_proof_sha256")),
        "rollback_preflight_passed": rollback.get("rollback_preflight_passed") is True,
        "rollback_inert": rollback.get("write_performed") is False
        and rollback.get("hook_files_backed_up") is False
        and rollback.get("hook_files_restored") is False
        and rollback.get("raw_rollback_material_stored") is False,
        "no_egress_controls_present": True,
        "operator_readback_present": readback.get("readback_present") is True,
        "operator_readback_required_phrases": readback.get("required_phrases_present") is True,
        "approval_granted_false": True,
        "live_install_allowed_false": True,
    }


def _install_plan_inert(install_plan: dict[str, Any]) -> bool:
    if any((install_plan.get("live_boundaries") or {}).values()):
        return False
    for target in install_plan.get("install_targets") or []:
        if target.get("write_performed") is not False or target.get("installed") is not False:
            return False
    approval = install_plan.get("operator_approval") or {}
    return approval.get("approval_granted") is False


def _reason_codes(gates: dict[str, bool], readback: dict[str, Any]) -> list[str]:
    reasons = [f"semantic_hook_approval.{key}_missing" for key, ok in gates.items() if not ok]
    reasons.extend(
        f"semantic_hook_approval.readback_phrase_missing:{phrase}"
        for phrase in readback.get("missing_required_phrases") or []
    )
    return sorted(set(reasons)) or ["semantic_hook_approval.ready_for_operator_approval"]


def _missing_phrases(text: str) -> list[str]:
    normalized = " ".join(text.lower().replace(",", " ").replace(";", " ").split())
    return [phrase for phrase in REQUIRED_READBACK_PHRASES if phrase not in normalized]


def _no_egress_controls() -> dict[str, Any]:
    return {
        "egress_mode": "none",
        "discord_send_allowed": False,
        "terminal_attach_allowed": False,
        "terminal_capture_allowed": False,
        "terminal_injection_allowed": False,
        "provider_call_allowed": False,
        "provider_hook_execution_allowed": False,
        "persistent_process_allowed": False,
        "network_allowed": False,
    }
