from __future__ import annotations

from copy import deepcopy
from typing import Any

from .artifact_quarantine import quarantine_is_approved
from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .rag_index_plan import validate_rag_index_plan_record
from .rag_payload import FORBIDDEN_PAYLOAD_KEYS, contains_forbidden_payload_key
from .store import JsonStore


JOB_STATUSES = {"blocked", "ready_for_operator_review"}


class RAGEmbeddingJobStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        rag_index_plan_id: str,
        capability_admission_review_id: str | None = None,
        resource_admission_review_id: str | None = None,
        downloaded_artifact_quarantine_ids: list[str] | None = None,
        batch_size: int = 64,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            plan = (state.get("rag_index_plans") or {}).get(rag_index_plan_id)
            if not isinstance(plan, dict):
                raise KeyError(f"unknown rag_index_plan_id: {rag_index_plan_id}")
            record = build_rag_embedding_job(
                plan=plan,
                state=state,
                capability_admission_review_id=capability_admission_review_id,
                resource_admission_review_id=resource_admission_review_id,
                downloaded_artifact_quarantine_ids=downloaded_artifact_quarantine_ids or [],
                batch_size=batch_size,
                idempotency_key=idempotency_key,
            )
            validation = validate_rag_embedding_job_record(record, state=state)
            if not validation["ok"]:
                raise ValueError("; ".join(validation["reason_codes"]))
            job_id = record["rag_embedding_job_id"]
            state.setdefault("rag_embedding_jobs", {})[job_id] = record
            state.setdefault("indexes", {}).setdefault("rag_embedding_job_ids", {})[job_id] = job_id
        return deepcopy(record)


def build_rag_embedding_job(
    *,
    plan: dict[str, Any],
    state: dict[str, Any],
    capability_admission_review_id: str | None = None,
    resource_admission_review_id: str | None = None,
    downloaded_artifact_quarantine_ids: list[str] | None = None,
    batch_size: int = 64,
    idempotency_key: str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    downloaded_artifact_quarantine_ids = list(downloaded_artifact_quarantine_ids or [])
    batch_size = max(1, int(batch_size or 1))
    embedding = plan.get("embedding") or {}
    vector_store = plan.get("vector_store") or {}
    chunks = list(plan.get("chunks") or [])
    reason_codes = _reason_codes(
        plan=plan,
        state=state,
        capability_admission_review_id=capability_admission_review_id,
        resource_admission_review_id=resource_admission_review_id,
        downloaded_artifact_quarantine_ids=downloaded_artifact_quarantine_ids,
    )
    status = "ready_for_operator_review" if not reason_codes else "blocked"
    idempotency_key = idempotency_key or stable_id(
        "ragembidem",
        plan.get("rag_index_plan_id"),
        plan.get("plan_sha256"),
        capability_admission_review_id,
        resource_admission_review_id,
        downloaded_artifact_quarantine_ids,
        batch_size,
    )
    planned_vectors = _planned_vectors(
        plan_id=str(plan.get("rag_index_plan_id") or ""),
        plan_sha256=str(plan.get("plan_sha256") or ""),
        chunks=chunks,
    )
    planned_batches = _planned_batches(
        planned_vectors=planned_vectors,
        job_seed=idempotency_key,
        batch_size=batch_size,
    )
    record = {
        "schema_version": "ams.ams.rag_embedding_job.v0",
        "rag_embedding_job_id": stable_id(
            "ragemb",
            plan.get("rag_index_plan_id"),
            plan.get("plan_sha256"),
            idempotency_key,
            now,
        ),
        "rag_index_plan_id": plan.get("rag_index_plan_id"),
        "rag_index_plan_sha256": plan.get("plan_sha256"),
        "collection": plan.get("collection"),
        "embedding": {
            "provider": embedding.get("provider"),
            "model": embedding.get("model"),
            "dimensions": embedding.get("dimensions"),
            "status": "planned" if embedding.get("provider") != "none" else "not_requested",
        },
        "vector_store": {
            "provider": vector_store.get("provider"),
            "name": vector_store.get("name"),
            "external_store_id": None,
            "status": "not_created",
        },
        "provider_gate": {
            "capability_admission_review_id": capability_admission_review_id,
            "resource_admission_review_id": resource_admission_review_id,
            "capability_allowed": _review_allows(
                state,
                capability_admission_review_id,
                subject_id=str(plan.get("rag_index_plan_id") or ""),
                operation_prefix="capability.rag_embedding",
            ),
            "resource_allowed": _review_allows(
                state,
                resource_admission_review_id,
                subject_id=str(plan.get("rag_index_plan_id") or ""),
                operation_prefix="resource.rag_embedding",
            ),
            "provider_call_allowed": False,
            "vector_write_allowed": False,
            "process_start_allowed": False,
        },
        "downloaded_artifact_quarantine_ids": downloaded_artifact_quarantine_ids,
        "planned_batches": planned_batches,
        "planned_vectors": planned_vectors,
        "batch_count": len(planned_batches),
        "chunk_count": len(chunks),
        "idempotency_key": idempotency_key,
        "status": status,
        "reason_codes": reason_codes or ["rag_embedding_job.ready_for_operator_review"],
        "created_at": now,
    }
    record["job_sha256"] = _hash_without(record, "job_sha256")
    return deepcopy(record)


def validate_rag_embedding_job_record(record: dict[str, Any], *, state: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    expected_hash = record.get("job_sha256")
    if expected_hash and expected_hash != _hash_without(record, "job_sha256"):
        reason_codes.append("rag_embedding_job.hash_mismatch")
    if record.get("status") not in JOB_STATUSES:
        reason_codes.append("rag_embedding_job.status_invalid")
    if record.get("rag_embedding_job_id") is None:
        reason_codes.append("rag_embedding_job.id_missing")
    plan_id = record.get("rag_index_plan_id")
    plan = (state.get("rag_index_plans") or {}).get(plan_id)
    if not isinstance(plan, dict):
        reason_codes.append("rag_embedding_job.plan_missing")
        plan = {}
    else:
        plan_validation = validate_rag_index_plan_record(plan)
        if not plan_validation["ok"]:
            reason_codes.append("rag_embedding_job.plan_invalid")
        if record.get("rag_index_plan_sha256") != plan.get("plan_sha256"):
            reason_codes.append("rag_embedding_job.plan_hash_mismatch")
    if contains_forbidden_payload_key(record.get("planned_batches")):
        reason_codes.append("rag_embedding_job.raw_or_vector_payload_stored")
    if contains_forbidden_payload_key(record.get("planned_vectors")):
        reason_codes.append("rag_embedding_job.raw_or_vector_payload_stored")
    gate = record.get("provider_gate") or {}
    for key in ("provider_call_allowed", "vector_write_allowed", "process_start_allowed"):
        if gate.get(key) is not False:
            reason_codes.append(f"rag_embedding_job.{key}_not_false")
    expected_reasons = _reason_codes(
        plan=plan,
        state=state,
        capability_admission_review_id=gate.get("capability_admission_review_id"),
        resource_admission_review_id=gate.get("resource_admission_review_id"),
        downloaded_artifact_quarantine_ids=record.get("downloaded_artifact_quarantine_ids") or [],
    )
    expected_status = "ready_for_operator_review" if not expected_reasons else "blocked"
    if record.get("status") != expected_status:
        reason_codes.append("rag_embedding_job.status_reason_mismatch")
    if record.get("status") == "ready_for_operator_review":
        if gate.get("capability_allowed") is not True or gate.get("resource_allowed") is not True:
            reason_codes.append("rag_embedding_job.ready_without_allowed_reviews")
    planned_vectors = record.get("planned_vectors") or []
    planned_batches = record.get("planned_batches") or []
    plan_chunks = plan.get("chunks") or []
    chunk_by_id = {chunk.get("chunk_id"): chunk for chunk in plan_chunks if isinstance(chunk, dict)}
    if record.get("chunk_count") != len(plan_chunks):
        reason_codes.append("rag_embedding_job.chunk_count_mismatch")
    if len(planned_vectors) != len(plan_chunks):
        reason_codes.append("rag_embedding_job.planned_vector_count_mismatch")
    seen_vectors: set[str] = set()
    for vector_ref in planned_vectors:
        if not isinstance(vector_ref, dict):
            reason_codes.append("rag_embedding_job.planned_vector_not_object")
            continue
        chunk = chunk_by_id.get(vector_ref.get("chunk_id"))
        if not chunk:
            reason_codes.append("rag_embedding_job.planned_vector_chunk_missing")
            continue
        if vector_ref.get("chunk_sha256") != chunk.get("chunk_sha256"):
            reason_codes.append("rag_embedding_job.planned_vector_chunk_hash_mismatch")
        if vector_ref.get("embedding_status") != "planned":
            reason_codes.append("rag_embedding_job.planned_vector_embedding_status_invalid")
        if vector_ref.get("vector_status") != "not_written":
            reason_codes.append("rag_embedding_job.planned_vector_status_invalid")
        vector_id = str(vector_ref.get("vector_ref_id") or "")
        if vector_id in seen_vectors:
            reason_codes.append("rag_embedding_job.duplicate_vector_ref")
        seen_vectors.add(vector_id)
    flattened = [
        chunk_id
        for batch in planned_batches
        if isinstance(batch, dict)
        for chunk_id in (batch.get("chunk_ids") or [])
    ]
    if sorted(flattened) != sorted(chunk_by_id):
        reason_codes.append("rag_embedding_job.batch_chunk_coverage_mismatch")
    return {"ok": not reason_codes, "reason_codes": reason_codes}


def _reason_codes(
    *,
    plan: dict[str, Any],
    state: dict[str, Any],
    capability_admission_review_id: str | None,
    resource_admission_review_id: str | None,
    downloaded_artifact_quarantine_ids: list[str],
) -> list[str]:
    codes: list[str] = []
    plan_validation = validate_rag_index_plan_record(plan) if plan else {"ok": False}
    if not plan or not plan_validation["ok"]:
        codes.append("rag_embedding_job.plan_invalid")
        return codes
    embedding = plan.get("embedding") or {}
    vector_store = plan.get("vector_store") or {}
    if embedding.get("provider") == "none":
        codes.append("rag_embedding_job.embedding_provider_not_requested")
    if vector_store.get("provider") == "none":
        codes.append("rag_embedding_job.vector_store_provider_not_requested")
    policy = plan.get("source_policy") or {}
    if policy.get("downloaded_files_allowed") is not False or plan.get("downloaded_artifacts") != []:
        codes.append("rag_embedding_job.downloaded_artifacts_in_plan")
    if not _review_allows(
        state,
        capability_admission_review_id,
        subject_id=str(plan.get("rag_index_plan_id") or ""),
        operation_prefix="capability.rag_embedding",
    ):
        codes.append("rag_embedding_job.capability_review_required")
    if not _review_allows(
        state,
        resource_admission_review_id,
        subject_id=str(plan.get("rag_index_plan_id") or ""),
        operation_prefix="resource.rag_embedding",
    ):
        codes.append("rag_embedding_job.resource_review_required")
    quarantines = state.get("downloaded_artifact_quarantines") or {}
    for quarantine_id in downloaded_artifact_quarantine_ids:
        quarantine = quarantines.get(quarantine_id)
        if not isinstance(quarantine, dict):
            codes.append("rag_embedding_job.quarantine_missing")
        elif not quarantine_is_approved(quarantine):
            codes.append("rag_embedding_job.quarantine_not_approved")
    return sorted(set(codes))


def _review_allows(
    state: dict[str, Any],
    review_id: str | None,
    *,
    subject_id: str,
    operation_prefix: str,
) -> bool:
    if not review_id:
        return False
    review = (state.get("admission_reviews") or {}).get(review_id)
    if not isinstance(review, dict):
        return False
    response = review.get("response") or {}
    return (
        review.get("subject_kind") == "rag_index_plan"
        and review.get("subject_id") == subject_id
        and str(review.get("operation") or "").startswith(operation_prefix)
        and response.get("allowed") is True
        and response.get("status") == "allow"
    )


def _planned_vectors(
    *,
    plan_id: str,
    plan_sha256: str,
    chunks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for chunk in chunks:
        refs.append(
            {
                "vector_ref_id": stable_id("ragvec", plan_id, plan_sha256, chunk.get("chunk_id")),
                "chunk_id": chunk.get("chunk_id"),
                "source_path": chunk.get("source_path"),
                "chunk_index": chunk.get("chunk_index"),
                "chunk_sha256": chunk.get("chunk_sha256"),
                "embedding_status": "planned",
                "vector_status": "not_written",
            }
        )
    return refs


def _planned_batches(
    *,
    planned_vectors: list[dict[str, Any]],
    job_seed: str,
    batch_size: int,
) -> list[dict[str, Any]]:
    batches: list[dict[str, Any]] = []
    for index in range(0, len(planned_vectors), batch_size):
        window = planned_vectors[index : index + batch_size]
        batch_index = len(batches)
        chunk_ids = [str(item.get("chunk_id") or "") for item in window]
        batches.append(
            {
                "batch_id": stable_id("ragbatch", job_seed, batch_index, chunk_ids),
                "batch_index": batch_index,
                "chunk_ids": chunk_ids,
                "chunk_count": len(chunk_ids),
                "status": "planned",
            }
        )
    return batches
