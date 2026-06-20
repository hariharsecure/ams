from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .provider_auth import provider_auth_is_ready, validate_provider_auth_preflight_record
from .rag_embedding_job import validate_rag_embedding_job_record
from .rag_payload import contains_forbidden_payload_key
from .store import JsonStore


RECEIPT_MODES = {"planned_only", "simulated_success", "external_observed", "failed"}
STATUSES = {"recorded", "blocked", "failed"}


class RAGEmbeddingReceiptStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        rag_embedding_job_id: str,
        provider_auth_preflight_id: str | None = None,
        receipt_mode: str = "planned_only",
        external_vector_store_ref: str | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            job = (state.get("rag_embedding_jobs") or {}).get(rag_embedding_job_id)
            if not isinstance(job, dict):
                raise KeyError(f"unknown rag_embedding_job_id: {rag_embedding_job_id}")
            auth = None
            if provider_auth_preflight_id:
                auth = (state.get("provider_auth_preflights") or {}).get(provider_auth_preflight_id)
                if not isinstance(auth, dict):
                    raise KeyError(f"unknown provider_auth_preflight_id: {provider_auth_preflight_id}")
            record = build_rag_embedding_receipt(
                job=job,
                state=state,
                provider_auth_preflight=auth,
                receipt_mode=receipt_mode,
                external_vector_store_ref=external_vector_store_ref,
            )
            validation = validate_rag_embedding_receipt_record(record, state=state)
            if not validation["ok"]:
                raise ValueError("; ".join(validation["reason_codes"]))
            receipt_id = record["rag_embedding_receipt_id"]
            state.setdefault("rag_embedding_receipts", {})[receipt_id] = record
            state.setdefault("indexes", {}).setdefault("rag_embedding_receipt_ids", {})[receipt_id] = receipt_id
        return deepcopy(record)


def build_rag_embedding_receipt(
    *,
    job: dict[str, Any],
    state: dict[str, Any],
    provider_auth_preflight: dict[str, Any] | None = None,
    receipt_mode: str = "planned_only",
    external_vector_store_ref: str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    batch_receipts = _batch_receipts(job, receipt_mode=receipt_mode)
    vector_receipts = _vector_receipts(job, receipt_mode=receipt_mode, external_vector_store_ref=external_vector_store_ref)
    totals = _totals(job, receipt_mode=receipt_mode)
    status, reason_codes = _status_and_reasons(
        receipt_mode=receipt_mode,
        provider_auth_preflight=provider_auth_preflight,
        external_vector_store_ref=external_vector_store_ref,
    )
    embedding = job.get("embedding") or {}
    vector_store = job.get("vector_store") or {}
    record = {
        "schema_version": "ams.ams_codex.rag_embedding_receipt.v0",
        "rag_embedding_receipt_id": stable_id(
            "ragrec",
            job.get("rag_embedding_job_id"),
            job.get("job_sha256"),
            (provider_auth_preflight or {}).get("provider_auth_preflight_id"),
            receipt_mode,
            external_vector_store_ref,
            now,
        ),
        "rag_embedding_job_id": job.get("rag_embedding_job_id"),
        "rag_embedding_job_sha256": job.get("job_sha256"),
        "rag_index_plan_id": job.get("rag_index_plan_id"),
        "rag_index_plan_sha256": job.get("rag_index_plan_sha256"),
        "provider_auth_preflight_id": (provider_auth_preflight or {}).get("provider_auth_preflight_id"),
        "provider_auth_preflight_sha256": (provider_auth_preflight or {}).get("auth_preflight_sha256"),
        "collection": job.get("collection"),
        "embedding_provider": embedding.get("provider"),
        "embedding_model": embedding.get("model"),
        "vector_store_provider": vector_store.get("provider"),
        "external_vector_store_ref": external_vector_store_ref,
        "receipt_mode": receipt_mode,
        "provider_call_observed": receipt_mode == "external_observed",
        "vector_write_observed": receipt_mode == "external_observed",
        "secret_material_stored": False,
        "raw_content_stored": False,
        "embeddings_stored": False,
        "vectors_stored": False,
        "batch_receipts": batch_receipts,
        "vector_receipts": vector_receipts,
        "totals": totals,
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["receipt_sha256"] = _hash_without(record, "receipt_sha256")
    return deepcopy(record)


def validate_rag_embedding_receipt_record(record: dict[str, Any], *, state: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    expected_hash = record.get("receipt_sha256")
    if expected_hash and expected_hash != _hash_without(record, "receipt_sha256"):
        reason_codes.append("rag_embedding_receipt.hash_mismatch")
    if record.get("receipt_mode") not in RECEIPT_MODES:
        reason_codes.append("rag_embedding_receipt.mode_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("rag_embedding_receipt.status_invalid")
    for key in ("secret_material_stored", "raw_content_stored", "embeddings_stored", "vectors_stored"):
        if record.get(key) is not False:
            reason_codes.append(f"rag_embedding_receipt.{key}_not_false")
    job = (state.get("rag_embedding_jobs") or {}).get(record.get("rag_embedding_job_id"))
    if not isinstance(job, dict):
        reason_codes.append("rag_embedding_receipt.job_missing")
        job = {}
    else:
        job_validation = validate_rag_embedding_job_record(job, state=state)
        if not job_validation["ok"]:
            reason_codes.append("rag_embedding_receipt.job_invalid")
        if record.get("rag_embedding_job_sha256") != job.get("job_sha256"):
            reason_codes.append("rag_embedding_receipt.job_hash_mismatch")
        if record.get("rag_index_plan_id") != job.get("rag_index_plan_id"):
            reason_codes.append("rag_embedding_receipt.plan_id_mismatch")
        if record.get("rag_index_plan_sha256") != job.get("rag_index_plan_sha256"):
            reason_codes.append("rag_embedding_receipt.plan_hash_mismatch")
        embedding = job.get("embedding") or {}
        vector_store = job.get("vector_store") or {}
        if record.get("embedding_provider") != embedding.get("provider"):
            reason_codes.append("rag_embedding_receipt.embedding_provider_mismatch")
        if record.get("embedding_model") != embedding.get("model"):
            reason_codes.append("rag_embedding_receipt.embedding_model_mismatch")
        if record.get("vector_store_provider") != vector_store.get("provider"):
            reason_codes.append("rag_embedding_receipt.vector_store_provider_mismatch")
    auth = None
    auth_id = record.get("provider_auth_preflight_id")
    if auth_id:
        auth = (state.get("provider_auth_preflights") or {}).get(auth_id)
        if not isinstance(auth, dict):
            reason_codes.append("rag_embedding_receipt.provider_auth_missing")
        else:
            auth_validation = validate_provider_auth_preflight_record(auth)
            if not auth_validation["ok"]:
                reason_codes.append("rag_embedding_receipt.provider_auth_invalid")
            if record.get("provider_auth_preflight_sha256") != auth.get("auth_preflight_sha256"):
                reason_codes.append("rag_embedding_receipt.provider_auth_hash_mismatch")
    elif record.get("provider_auth_preflight_sha256") is not None:
        reason_codes.append("rag_embedding_receipt.provider_auth_hash_without_id")
    if contains_forbidden_payload_key(record.get("batch_receipts")):
        reason_codes.append("rag_embedding_receipt.raw_or_vector_payload_stored")
    if contains_forbidden_payload_key(record.get("vector_receipts")):
        reason_codes.append("rag_embedding_receipt.raw_or_vector_payload_stored")
    _validate_batch_coverage(record, job, reason_codes)
    _validate_vector_coverage(record, job, reason_codes)
    expected_totals = _totals(job, receipt_mode=str(record.get("receipt_mode") or ""))
    if record.get("totals") != expected_totals:
        reason_codes.append("rag_embedding_receipt.totals_mismatch")
    expected_status, expected_reasons = _status_and_reasons(
        receipt_mode=str(record.get("receipt_mode") or ""),
        provider_auth_preflight=auth,
        external_vector_store_ref=record.get("external_vector_store_ref"),
    )
    if record.get("status") != expected_status:
        reason_codes.append("rag_embedding_receipt.status_reason_mismatch")
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("rag_embedding_receipt.reason_codes_mismatch")
    external = record.get("receipt_mode") == "external_observed"
    if bool(record.get("provider_call_observed")) != external:
        reason_codes.append("rag_embedding_receipt.provider_call_observed_mismatch")
    if bool(record.get("vector_write_observed")) != external:
        reason_codes.append("rag_embedding_receipt.vector_write_observed_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _batch_receipts(job: dict[str, Any], *, receipt_mode: str) -> list[dict[str, Any]]:
    receipts: list[dict[str, Any]] = []
    for batch in job.get("planned_batches") or []:
        batch_id = str(batch.get("batch_id") or "")
        output_hash = None
        vector_write_hash = None
        provider_request_ref = None
        output_ref = None
        error_code = None
        if receipt_mode in {"simulated_success", "external_observed"}:
            output_hash = sha256_text(canonical_json(["embedding-output", job.get("rag_embedding_job_id"), batch_id]))
            vector_write_hash = sha256_text(canonical_json(["vector-write", job.get("rag_embedding_job_id"), batch_id]))
            provider_request_ref = f"{receipt_mode}://provider-request/{batch_id}"
            output_ref = f"{receipt_mode}://embedding-output/{batch_id}"
        elif receipt_mode == "failed":
            error_code = "not_run"
        receipts.append(
            {
                "batch_id": batch_id,
                "batch_index": batch.get("batch_index"),
                "chunk_ids": list(batch.get("chunk_ids") or []),
                "chunk_count": batch.get("chunk_count"),
                "receipt_status": receipt_mode,
                "embedding_output_sha256": output_hash,
                "vector_write_receipt_sha256": vector_write_hash,
                "provider_request_ref": provider_request_ref,
                "output_ref": output_ref,
                "error_code": error_code,
            }
        )
    return receipts


def _vector_receipts(
    job: dict[str, Any],
    *,
    receipt_mode: str,
    external_vector_store_ref: str | None,
) -> list[dict[str, Any]]:
    receipts: list[dict[str, Any]] = []
    for vector in job.get("planned_vectors") or []:
        vector_ref_id = str(vector.get("vector_ref_id") or "")
        output_hash = None
        vector_write_ref = None
        if receipt_mode == "simulated_success":
            output_hash = sha256_text(canonical_json(["simulated-vector", job.get("rag_embedding_job_id"), vector_ref_id]))
            vector_write_ref = f"simulated_success://vector/{vector_ref_id}"
        elif receipt_mode == "external_observed":
            output_hash = sha256_text(canonical_json(["external-vector", job.get("rag_embedding_job_id"), vector_ref_id]))
            vector_write_ref = f"{external_vector_store_ref or 'external'}://vector/{vector_ref_id}"
        receipts.append(
            {
                "vector_ref_id": vector_ref_id,
                "chunk_id": vector.get("chunk_id"),
                "source_path": vector.get("source_path"),
                "chunk_sha256": vector.get("chunk_sha256"),
                "receipt_status": _vector_status(receipt_mode),
                "embedding_output_sha256": output_hash,
                "vector_write_ref": vector_write_ref,
            }
        )
    return receipts


def _totals(job: dict[str, Any], *, receipt_mode: str) -> dict[str, Any]:
    planned_batches = len(job.get("planned_batches") or [])
    planned_vectors = len(job.get("planned_vectors") or [])
    return {
        "planned_batches": planned_batches,
        "planned_vectors": planned_vectors,
        "observed_embedding_outputs": planned_vectors if receipt_mode == "external_observed" else 0,
        "observed_vector_writes": planned_vectors if receipt_mode == "external_observed" else 0,
        "simulated_vectors": planned_vectors if receipt_mode == "simulated_success" else 0,
        "failed_batches": planned_batches if receipt_mode == "failed" else 0,
    }


def _status_and_reasons(
    *,
    receipt_mode: str,
    provider_auth_preflight: dict[str, Any] | None,
    external_vector_store_ref: str | None,
) -> tuple[str, list[str]]:
    if receipt_mode == "planned_only":
        return "recorded", ["rag_embedding_receipt.planned_only_no_provider_call"]
    if receipt_mode == "simulated_success":
        return "recorded", ["rag_embedding_receipt.simulated_success_no_provider_call"]
    if receipt_mode == "failed":
        return "failed", ["rag_embedding_receipt.failed"]
    if receipt_mode == "external_observed":
        reasons: list[str] = []
        if not provider_auth_is_ready(provider_auth_preflight):
            reasons.append("rag_embedding_receipt.provider_auth_ready_required")
        if not external_vector_store_ref:
            reasons.append("rag_embedding_receipt.external_vector_store_ref_required")
        if reasons:
            return "blocked", reasons
        return "recorded", ["rag_embedding_receipt.external_observed"]
    return "blocked", ["rag_embedding_receipt.mode_invalid"]


def _validate_batch_coverage(record: dict[str, Any], job: dict[str, Any], reason_codes: list[str]) -> None:
    planned = {batch.get("batch_id"): batch for batch in job.get("planned_batches") or []}
    observed = {batch.get("batch_id"): batch for batch in record.get("batch_receipts") or [] if isinstance(batch, dict)}
    if sorted(planned) != sorted(observed):
        reason_codes.append("rag_embedding_receipt.batch_coverage_mismatch")
        return
    for batch_id, batch in observed.items():
        planned_batch = planned[batch_id]
        if batch.get("chunk_ids") != planned_batch.get("chunk_ids"):
            reason_codes.append("rag_embedding_receipt.batch_chunk_ids_mismatch")
        if batch.get("chunk_count") != planned_batch.get("chunk_count"):
            reason_codes.append("rag_embedding_receipt.batch_chunk_count_mismatch")
        if batch.get("receipt_status") != record.get("receipt_mode"):
            reason_codes.append("rag_embedding_receipt.batch_status_mismatch")


def _validate_vector_coverage(record: dict[str, Any], job: dict[str, Any], reason_codes: list[str]) -> None:
    planned = {vector.get("vector_ref_id"): vector for vector in job.get("planned_vectors") or []}
    observed = {vector.get("vector_ref_id"): vector for vector in record.get("vector_receipts") or [] if isinstance(vector, dict)}
    if sorted(planned) != sorted(observed):
        reason_codes.append("rag_embedding_receipt.vector_coverage_mismatch")
        return
    expected_status = _vector_status(str(record.get("receipt_mode") or ""))
    for vector_ref_id, receipt in observed.items():
        planned_vector = planned[vector_ref_id]
        if receipt.get("chunk_id") != planned_vector.get("chunk_id"):
            reason_codes.append("rag_embedding_receipt.vector_chunk_id_mismatch")
        if receipt.get("chunk_sha256") != planned_vector.get("chunk_sha256"):
            reason_codes.append("rag_embedding_receipt.vector_chunk_hash_mismatch")
        if receipt.get("receipt_status") != expected_status:
            reason_codes.append("rag_embedding_receipt.vector_status_mismatch")


def _vector_status(receipt_mode: str) -> str:
    return {
        "planned_only": "not_observed",
        "simulated_success": "simulated",
        "external_observed": "external_observed",
        "failed": "failed",
    }.get(receipt_mode, "failed")
