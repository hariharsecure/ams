from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from .models import hash_without as _hash_without, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .semantic_hook_approval import validate_semantic_hook_approval_binding_record
from .semantic_hook_install_plan import validate_semantic_hook_install_plan_record
from .semantic_hook_install_transaction import validate_semantic_hook_install_transaction_record
from .semantic_hook_run import validate_semantic_hook_run_record
from .semantic_hook_target_snapshot import validate_semantic_hook_target_snapshot_record
from .store import JsonStore
from .workspace import repo_root


SCHEMA_VERSION = "ams.ams_codex.semantic_hook_operator_approval_packet.v0"
STATUSES = {"ready_for_operator_review", "blocked"}

REQUIRED_REVIEW_STEPS = [
    "review_signed_package_provenance",
    "review_target_snapshot_freshness",
    "review_payload_hashes",
    "review_atomic_install_plan",
    "review_rollback_plan",
    "review_trust_review_steps",
    "confirm_no_live_authority_granted",
]

REQUIRED_READBACK_PHRASES = [
    "i reviewed the semantic hook install transaction",
    "hook writes remain disabled",
    "hook trust remains disabled",
    "provider hook execution remains disabled",
    "a later explicit approval is required",
]

LIVE_BOUNDARIES = {
    "approval_granted": False,
    "hook_file_written": False,
    "hook_installed": False,
    "hook_trusted": False,
    "provider_hook_executed": False,
    "backup_file_written": False,
    "restore_performed": False,
    "discord_call_performed": False,
    "terminal_attach_performed": False,
    "terminal_capture_performed": False,
    "terminal_injection_performed": False,
    "persistent_process_started": False,
    "provider_call_performed": False,
    "network_call_performed": False,
    "raw_payload_stored": False,
    "raw_readback_stored": False,
    "secret_stored": False,
}


class SemanticHookOperatorApprovalPacketStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        semantic_hook_install_transaction_id: str,
        source_root: str | Path | None = None,
        label: str = "manual-semantic-hook-operator-approval",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            transaction = (state.get("semantic_hook_install_transactions") or {}).get(
                semantic_hook_install_transaction_id
            )
            if not transaction:
                raise KeyError(f"semantic hook install transaction not found: {semantic_hook_install_transaction_id}")
            snapshot = (state.get("semantic_hook_target_snapshots") or {}).get(
                transaction.get("semantic_hook_target_snapshot_id")
            )
            if not snapshot:
                raise KeyError(f"semantic hook target snapshot not found: {transaction.get('semantic_hook_target_snapshot_id')}")
            binding = (state.get("semantic_hook_approval_bindings") or {}).get(
                transaction.get("semantic_hook_approval_binding_id")
            )
            if not binding:
                raise KeyError(f"semantic hook approval binding not found: {transaction.get('semantic_hook_approval_binding_id')}")
            install_plan = (state.get("semantic_hook_install_plans") or {}).get(
                transaction.get("semantic_hook_install_plan_id")
            )
            if not install_plan:
                raise KeyError(f"semantic hook install plan not found: {transaction.get('semantic_hook_install_plan_id')}")
            hook_run = (state.get("semantic_hook_runs") or {}).get(transaction.get("semantic_hook_run_id"))
            if not hook_run:
                raise KeyError(f"semantic hook run not found: {transaction.get('semantic_hook_run_id')}")
            record = build_semantic_hook_operator_approval_packet(
                transaction=transaction,
                target_snapshot=snapshot,
                binding=binding,
                install_plan=install_plan,
                hook_run=hook_run,
                source_root=source_root,
                label=label,
            )
            packet_id = record["semantic_hook_operator_approval_packet_id"]
            state.setdefault("semantic_hook_operator_approval_packets", {})[packet_id] = record
            state.setdefault("indexes", {}).setdefault("semantic_hook_operator_approval_packet_ids", {})[
                packet_id
            ] = packet_id
            return deepcopy(record)


def build_semantic_hook_operator_approval_packet(
    *,
    transaction: dict[str, Any],
    target_snapshot: dict[str, Any],
    binding: dict[str, Any],
    install_plan: dict[str, Any],
    hook_run: dict[str, Any],
    source_root: str | Path | None = None,
    label: str = "manual-semantic-hook-operator-approval",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False) if source_root else repo_root()
    transaction_summary = _transaction_summary(transaction)
    provenance_summary = _provenance_summary(binding)
    freshness = _freshness(
        transaction=transaction,
        target_snapshot=target_snapshot,
        binding=binding,
        install_plan=install_plan,
        hook_run=hook_run,
    )
    approval_request = _approval_request()
    required_gates = _required_gates(
        transaction=transaction,
        target_snapshot=target_snapshot,
        binding=binding,
        install_plan=install_plan,
        hook_run=hook_run,
        transaction_summary=transaction_summary,
        provenance_summary=provenance_summary,
        freshness=freshness,
        approval_request=approval_request,
    )
    reason_codes = _reason_codes(required_gates)
    status = (
        "ready_for_operator_review"
        if reason_codes == ["semantic_hook_operator_approval.ready_for_operator_review"]
        else "blocked"
    )
    record = {
        "schema_version": SCHEMA_VERSION,
        "semantic_hook_operator_approval_packet_id": stable_id(
            "semhookopapproval",
            label,
            transaction.get("semantic_hook_install_transaction_id"),
            transaction.get("semantic_hook_install_transaction_sha256"),
            target_snapshot.get("semantic_hook_target_snapshot_sha256"),
            binding.get("semantic_hook_approval_binding_sha256"),
            install_plan.get("semantic_hook_install_plan_sha256"),
            hook_run.get("semantic_hook_run_sha256"),
            now,
        ),
        "label": label,
        "source_root": str(root),
        "semantic_hook_install_transaction_id": transaction.get("semantic_hook_install_transaction_id"),
        "semantic_hook_install_transaction_sha256": transaction.get("semantic_hook_install_transaction_sha256"),
        "semantic_hook_target_snapshot_id": target_snapshot.get("semantic_hook_target_snapshot_id"),
        "semantic_hook_target_snapshot_sha256": target_snapshot.get("semantic_hook_target_snapshot_sha256"),
        "semantic_hook_approval_binding_id": binding.get("semantic_hook_approval_binding_id"),
        "semantic_hook_approval_binding_sha256": binding.get("semantic_hook_approval_binding_sha256"),
        "semantic_hook_install_plan_id": install_plan.get("semantic_hook_install_plan_id"),
        "semantic_hook_install_plan_sha256": install_plan.get("semantic_hook_install_plan_sha256"),
        "semantic_hook_run_id": hook_run.get("semantic_hook_run_id"),
        "semantic_hook_run_sha256": hook_run.get("semantic_hook_run_sha256"),
        "transaction_summary": transaction_summary,
        "provenance_summary": provenance_summary,
        "freshness": freshness,
        "approval_request": approval_request,
        "required_gates": required_gates,
        "approval_granted": False,
        "live_install_allowed": False,
        "hook_file_write_allowed": False,
        "hook_trust_allowed": False,
        "provider_hook_execution_allowed": False,
        "backup_write_allowed": False,
        "restore_allowed": False,
        "approval_actions": [],
        "install_actions": [],
        "trust_actions": [],
        "start_actions": [],
        "live_boundaries": dict(LIVE_BOUNDARIES),
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["semantic_hook_operator_approval_packet_sha256"] = _hash_without(
        record,
        "semantic_hook_operator_approval_packet_sha256",
    )
    return deepcopy(record)


def validate_semantic_hook_operator_approval_packet_record(
    record: dict[str, Any],
    *,
    transaction: dict[str, Any] | None = None,
    target_snapshot: dict[str, Any] | None = None,
    binding: dict[str, Any] | None = None,
    install_plan: dict[str, Any] | None = None,
    hook_run: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record(
            "semantic_hook_operator_approval_packet.schema.json",
            record,
            location="semantic_hook_operator_approval_packet",
        )
    except SchemaValidationError:
        reason_codes.append("semantic_hook_operator_approval.schema_invalid")
    expected_hash = record.get("semantic_hook_operator_approval_packet_sha256")
    if expected_hash and expected_hash != _hash_without(record, "semantic_hook_operator_approval_packet_sha256"):
        reason_codes.append("semantic_hook_operator_approval.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("semantic_hook_operator_approval.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("semantic_hook_operator_approval.status_invalid")
    for key, expected in LIVE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"semantic_hook_operator_approval.{key}_not_false")
    for key in (
        "approval_granted",
        "live_install_allowed",
        "hook_file_write_allowed",
        "hook_trust_allowed",
        "provider_hook_execution_allowed",
        "backup_write_allowed",
        "restore_allowed",
    ):
        if record.get(key) is not False:
            reason_codes.append(f"semantic_hook_operator_approval.{key}_not_false")
    for key in ("approval_actions", "install_actions", "trust_actions", "start_actions"):
        if record.get(key) != []:
            reason_codes.append(f"semantic_hook_operator_approval.{key}_not_empty")
    approval_request = record.get("approval_request") or {}
    if approval_request.get("operator_readback_captured") is not False:
        reason_codes.append("semantic_hook_operator_approval.operator_readback_captured_not_false")
    if approval_request.get("raw_readback_stored") is not False:
        reason_codes.append("semantic_hook_operator_approval.raw_readback_stored_not_false")
    if approval_request.get("required_review_steps") != REQUIRED_REVIEW_STEPS:
        reason_codes.append("semantic_hook_operator_approval.required_review_steps_mismatch")
    if approval_request.get("required_readback_phrases") != REQUIRED_READBACK_PHRASES:
        reason_codes.append("semantic_hook_operator_approval.required_readback_phrases_mismatch")
    if transaction is not None:
        if record.get("semantic_hook_install_transaction_sha256") != transaction.get("semantic_hook_install_transaction_sha256"):
            reason_codes.append("semantic_hook_operator_approval.transaction_hash_mismatch")
        transaction_validation = validate_semantic_hook_install_transaction_record(
            transaction,
            target_snapshot=target_snapshot,
            binding=binding,
            install_plan=install_plan,
            hook_run=hook_run,
        )
        if not transaction_validation["ok"]:
            reason_codes.extend(
                f"semantic_hook_operator_approval.transaction:{reason}"
                for reason in transaction_validation["reason_codes"]
            )
    if target_snapshot is not None:
        if record.get("semantic_hook_target_snapshot_sha256") != target_snapshot.get("semantic_hook_target_snapshot_sha256"):
            reason_codes.append("semantic_hook_operator_approval.target_snapshot_hash_mismatch")
        snapshot_validation = validate_semantic_hook_target_snapshot_record(
            target_snapshot,
            binding=binding,
            install_plan=install_plan,
        )
        if not snapshot_validation["ok"]:
            reason_codes.extend(
                f"semantic_hook_operator_approval.target_snapshot:{reason}"
                for reason in snapshot_validation["reason_codes"]
            )
    if binding is not None:
        if record.get("semantic_hook_approval_binding_sha256") != binding.get("semantic_hook_approval_binding_sha256"):
            reason_codes.append("semantic_hook_operator_approval.approval_binding_hash_mismatch")
        binding_validation = validate_semantic_hook_approval_binding_record(binding, install_plan=install_plan)
        if not binding_validation["ok"]:
            reason_codes.extend(
                f"semantic_hook_operator_approval.binding:{reason}" for reason in binding_validation["reason_codes"]
            )
    if install_plan is not None:
        if record.get("semantic_hook_install_plan_sha256") != install_plan.get("semantic_hook_install_plan_sha256"):
            reason_codes.append("semantic_hook_operator_approval.install_plan_hash_mismatch")
        install_validation = validate_semantic_hook_install_plan_record(install_plan)
        if not install_validation["ok"]:
            reason_codes.extend(
                f"semantic_hook_operator_approval.install_plan:{reason}" for reason in install_validation["reason_codes"]
            )
    if hook_run is not None:
        if record.get("semantic_hook_run_sha256") != hook_run.get("semantic_hook_run_sha256"):
            reason_codes.append("semantic_hook_operator_approval.hook_run_hash_mismatch")
        hook_run_validation = validate_semantic_hook_run_record(hook_run)
        if not hook_run_validation["ok"]:
            reason_codes.extend(
                f"semantic_hook_operator_approval.hook_run:{reason}" for reason in hook_run_validation["reason_codes"]
            )
    if all(item is not None for item in (transaction, target_snapshot, binding, install_plan, hook_run)):
        expected_summary = _transaction_summary(transaction or {})
        expected_provenance = _provenance_summary(binding or {})
        expected_freshness = _freshness(
            transaction=transaction or {},
            target_snapshot=target_snapshot or {},
            binding=binding or {},
            install_plan=install_plan or {},
            hook_run=hook_run or {},
        )
        expected_request = _approval_request()
        if record.get("transaction_summary") != expected_summary:
            reason_codes.append("semantic_hook_operator_approval.transaction_summary_mismatch")
        if record.get("provenance_summary") != expected_provenance:
            reason_codes.append("semantic_hook_operator_approval.provenance_summary_mismatch")
        if record.get("freshness") != expected_freshness:
            reason_codes.append("semantic_hook_operator_approval.freshness_mismatch")
        if record.get("approval_request") != expected_request:
            reason_codes.append("semantic_hook_operator_approval.approval_request_mismatch")
        expected_gates = _required_gates(
            transaction=transaction or {},
            target_snapshot=target_snapshot or {},
            binding=binding or {},
            install_plan=install_plan or {},
            hook_run=hook_run or {},
            transaction_summary=record.get("transaction_summary") or {},
            provenance_summary=record.get("provenance_summary") or {},
            freshness=record.get("freshness") or {},
            approval_request=record.get("approval_request") or {},
        )
        if record.get("required_gates") != expected_gates:
            reason_codes.append("semantic_hook_operator_approval.required_gates_mismatch")
        expected_reasons = _reason_codes(expected_gates)
        expected_status = (
            "ready_for_operator_review"
            if expected_reasons == ["semantic_hook_operator_approval.ready_for_operator_review"]
            else "blocked"
        )
        if record.get("status") != expected_status:
            reason_codes.append("semantic_hook_operator_approval.status_reason_mismatch")
        if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
            reason_codes.append("semantic_hook_operator_approval.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _transaction_summary(transaction: dict[str, Any]) -> dict[str, Any]:
    payloads = [
        {
            "target": payload.get("target"),
            "resolved_path": payload.get("resolved_path"),
            "payload_source": payload.get("payload_source"),
            "payload_sha256": payload.get("payload_sha256"),
            "expected_config_sha256": payload.get("expected_config_sha256"),
            "raw_payload_stored": payload.get("raw_payload_stored") is True,
            "secret_stored": payload.get("secret_stored") is True,
            "write_performed": payload.get("write_performed") is True,
        }
        for payload in transaction.get("payload_renderings") or []
    ]
    return {
        "target_count": transaction.get("target_count"),
        "payload_rendering_count": len(transaction.get("payload_renderings") or []),
        "install_step_count": len(transaction.get("install_transaction_steps") or []),
        "rollback_step_count": len(transaction.get("rollback_transaction_steps") or []),
        "trust_review_step_count": len(transaction.get("trust_review_steps") or []),
        "payloads": payloads,
        "payload_hashes_match": all(
            payload.get("payload_sha256") == payload.get("expected_config_sha256")
            for payload in transaction.get("payload_renderings") or []
        ),
        "install_steps_atomic": all(
            step.get("atomic_rename_required") is True and step.get("fsync_required") is True
            for step in transaction.get("install_transaction_steps") or []
        ),
        "rollback_steps_inert": all(
            step.get("restore_performed") is False and step.get("backup_file_written") is False
            for step in transaction.get("rollback_transaction_steps") or []
        ),
        "trust_steps_inert": all(
            step.get("trusted") is False and step.get("provider_hook_execution_allowed") is False
            for step in transaction.get("trust_review_steps") or []
        ),
    }


def _provenance_summary(binding: dict[str, Any]) -> dict[str, Any]:
    provenance = binding.get("package_provenance") or {}
    rollback = binding.get("rollback_evidence") or {}
    return {
        "signed_package_verified": provenance.get("signed_package_verified") is True,
        "signature_verified": provenance.get("signature_verified") is True,
        "signer_identity": provenance.get("signer_identity"),
        "signer_fingerprint": provenance.get("signer_fingerprint"),
        "signer_fingerprint_pinned": provenance.get("signer_fingerprint_pinned") is True,
        "package_manifest_sha256": provenance.get("package_manifest_sha256"),
        "manifest_declares_exact_install_plan": provenance.get("manifest_declares_exact_install_plan") is True,
        "manifest_declares_exact_hook_run": provenance.get("manifest_declares_exact_hook_run") is True,
        "manifest_declares_exact_codex_preview": provenance.get("manifest_declares_exact_codex_preview") is True,
        "manifest_declares_exact_claude_preview": provenance.get("manifest_declares_exact_claude_preview") is True,
        "rollback_proof_present": bool(rollback.get("rollback_proof_ref") and rollback.get("rollback_proof_sha256")),
        "rollback_preflight_passed": rollback.get("rollback_preflight_passed") is True,
    }


def _freshness(
    *,
    transaction: dict[str, Any],
    target_snapshot: dict[str, Any],
    binding: dict[str, Any],
    install_plan: dict[str, Any],
    hook_run: dict[str, Any],
) -> dict[str, bool]:
    return {
        "target_snapshot_hash_current": transaction.get("semantic_hook_target_snapshot_sha256")
        == target_snapshot.get("semantic_hook_target_snapshot_sha256"),
        "approval_binding_hash_current": transaction.get("semantic_hook_approval_binding_sha256")
        == binding.get("semantic_hook_approval_binding_sha256"),
        "install_plan_hash_current": transaction.get("semantic_hook_install_plan_sha256")
        == install_plan.get("semantic_hook_install_plan_sha256"),
        "hook_run_hash_current": transaction.get("semantic_hook_run_sha256") == hook_run.get("semantic_hook_run_sha256"),
    }


def _approval_request() -> dict[str, Any]:
    return {
        "requested_decision": "operator_review_required",
        "operator_readback_captured": False,
        "raw_readback_stored": False,
        "required_review_steps": list(REQUIRED_REVIEW_STEPS),
        "required_readback_phrases": list(REQUIRED_READBACK_PHRASES),
        "approval_granted_by_packet": False,
        "live_install_allowed_by_packet": False,
        "hook_write_allowed_by_packet": False,
        "hook_trust_allowed_by_packet": False,
        "provider_hook_execution_allowed_by_packet": False,
    }


def _required_gates(
    *,
    transaction: dict[str, Any],
    target_snapshot: dict[str, Any],
    binding: dict[str, Any],
    install_plan: dict[str, Any],
    hook_run: dict[str, Any],
    transaction_summary: dict[str, Any],
    provenance_summary: dict[str, Any],
    freshness: dict[str, bool],
    approval_request: dict[str, Any],
) -> dict[str, bool]:
    return {
        "transaction_ready": transaction.get("status") == "ready_for_operator_review",
        "transaction_inert": _transaction_inert(transaction),
        "target_snapshot_ready": target_snapshot.get("status") == "ready_for_operator_review",
        "approval_binding_ready": binding.get("status") == "ready_for_operator_approval",
        "install_plan_ready": install_plan.get("status") == "ready_for_operator_review",
        "hook_run_allow": hook_run.get("status") == "allow",
        "target_snapshot_fresh": freshness.get("target_snapshot_hash_current") is True,
        "approval_binding_fresh": freshness.get("approval_binding_hash_current") is True,
        "install_plan_fresh": freshness.get("install_plan_hash_current") is True,
        "hook_run_fresh": freshness.get("hook_run_hash_current") is True,
        "signed_package_verified": provenance_summary.get("signed_package_verified") is True,
        "signature_verified": provenance_summary.get("signature_verified") is True,
        "pinned_signer_verified": provenance_summary.get("signer_fingerprint_pinned") is True,
        "manifest_declares_exact_artifacts": all(
            provenance_summary.get(key) is True
            for key in (
                "manifest_declares_exact_install_plan",
                "manifest_declares_exact_hook_run",
                "manifest_declares_exact_codex_preview",
                "manifest_declares_exact_claude_preview",
            )
        ),
        "rollback_proof_present": provenance_summary.get("rollback_proof_present") is True,
        "rollback_preflight_passed": provenance_summary.get("rollback_preflight_passed") is True,
        "target_count_matches": transaction_summary.get("target_count")
        == transaction_summary.get("payload_rendering_count")
        == transaction_summary.get("install_step_count")
        == transaction_summary.get("rollback_step_count"),
        "payload_hashes_match": transaction_summary.get("payload_hashes_match") is True,
        "install_steps_atomic": transaction_summary.get("install_steps_atomic") is True,
        "rollback_steps_inert": transaction_summary.get("rollback_steps_inert") is True,
        "trust_steps_inert": transaction_summary.get("trust_steps_inert") is True,
        "trust_review_present": int(transaction_summary.get("trust_review_step_count") or 0) > 0,
        "operator_readback_not_captured": approval_request.get("operator_readback_captured") is False,
        "approval_granted_false": True,
        "live_install_allowed_false": True,
    }


def _transaction_inert(transaction: dict[str, Any]) -> bool:
    if any((transaction.get("live_boundaries") or {}).values()):
        return False
    for key in (
        "approval_granted",
        "live_install_allowed",
        "hook_file_write_allowed",
        "hook_trust_allowed",
        "provider_hook_execution_allowed",
        "backup_write_allowed",
        "restore_allowed",
    ):
        if transaction.get(key) is not False:
            return False
    return (
        transaction.get("install_actions") == []
        and transaction.get("trust_actions") == []
        and transaction.get("start_actions") == []
    )


def _reason_codes(gates: dict[str, bool]) -> list[str]:
    reasons = [f"semantic_hook_operator_approval.{key}_missing" for key, ok in gates.items() if not ok]
    return sorted(set(reasons)) or ["semantic_hook_operator_approval.ready_for_operator_review"]
