from __future__ import annotations

from copy import deepcopy
import re
from typing import Any

from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore


CLAIM_SCHEMA_VERSION = "ams.ams_codex.memory_claim.v0"
REVIEW_SCHEMA_VERSION = "ams.ams_codex.memory_promotion_review.v0"
SUPERSESSION_SCHEMA_VERSION = "ams.ams_codex.memory_supersession_record.v0"
CONFLICT_SCHEMA_VERSION = "ams.ams_codex.memory_conflict_record.v0"

TRUST_CLASSES = {
    "user_asserted",
    "operator_asserted",
    "system_record",
    "generated_surface",
    "provider_evidence",
    "retrieved_evidence",
}
SUPERSESSION_MODES = {"correction", "temporal_update", "scope_refinement", "revocation", "duplicate"}
REVIEW_DECISIONS = {"promote", "duplicate", "needs_operator", "blocked"}
REVIEW_STATUSES = {"promoted", "duplicate", "needs_operator", "blocked"}
FORBIDDEN_VALUE_PATTERNS = (
    re.compile(r"(?i)\b(api[_-]?key|authorization|password|secret|session_cookie|token)\b\s*[:=]\s*\S+"),
)


class MemorySupersessionStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create_review(
        self,
        *,
        domain: str,
        subject: str,
        predicate: str,
        value_sha256: str,
        source_ref: str,
        source_kind: str = "prompt",
        scope: str = "global",
        value_ref: str | None = None,
        value_summary: str = "",
        trust_class: str = "user_asserted",
        valid_from: str | None = None,
        valid_until: str | None = None,
        supersedes_claim_id: str | None = None,
        supersession_mode: str = "correction",
        operator_confirmed: bool = False,
        operator_confirmation_ref: str | None = None,
        operator_confirmation_sha256: str | None = None,
        rag_retrieval_refs: list[dict[str, Any]] | None = None,
        label: str = "manual-memory-promotion-review",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            record_set = build_memory_promotion_review_set(
                state=state,
                domain=domain,
                subject=subject,
                predicate=predicate,
                value_sha256=value_sha256,
                source_ref=source_ref,
                source_kind=source_kind,
                scope=scope,
                value_ref=value_ref,
                value_summary=value_summary,
                trust_class=trust_class,
                valid_from=valid_from,
                valid_until=valid_until,
                supersedes_claim_id=supersedes_claim_id,
                supersession_mode=supersession_mode,
                operator_confirmed=operator_confirmed,
                operator_confirmation_ref=operator_confirmation_ref,
                operator_confirmation_sha256=operator_confirmation_sha256,
                rag_retrieval_refs=rag_retrieval_refs,
                label=label,
            )
            review = record_set["review"]
            review_id = review["memory_promotion_review_id"]
            state.setdefault("memory_promotion_reviews", {})[review_id] = review
            state.setdefault("indexes", {}).setdefault("memory_promotion_review_ids", {})[review_id] = review_id
            claim = record_set.get("claim")
            if claim:
                claim_id = claim["memory_claim_id"]
                state.setdefault("memory_claims", {})[claim_id] = claim
                state.setdefault("indexes", {}).setdefault("memory_claim_ids", {})[claim_id] = claim_id
            supersession = record_set.get("supersession")
            if supersession:
                supersession_id = supersession["memory_supersession_record_id"]
                state.setdefault("memory_supersession_records", {})[supersession_id] = supersession
                state.setdefault("indexes", {}).setdefault("memory_supersession_record_ids", {})[
                    supersession_id
                ] = supersession_id
            conflict = record_set.get("conflict")
            if conflict:
                conflict_id = conflict["memory_conflict_record_id"]
                state.setdefault("memory_conflict_records", {})[conflict_id] = conflict
                state.setdefault("indexes", {}).setdefault("memory_conflict_record_ids", {})[conflict_id] = conflict_id
            return deepcopy(record_set)


def build_memory_promotion_review_set(
    *,
    state: dict[str, Any],
    domain: str,
    subject: str,
    predicate: str,
    value_sha256: str,
    source_ref: str,
    source_kind: str = "prompt",
    scope: str = "global",
    value_ref: str | None = None,
    value_summary: str = "",
    trust_class: str = "user_asserted",
    valid_from: str | None = None,
    valid_until: str | None = None,
    supersedes_claim_id: str | None = None,
    supersession_mode: str = "correction",
    operator_confirmed: bool = False,
    operator_confirmation_ref: str | None = None,
    operator_confirmation_sha256: str | None = None,
    rag_retrieval_refs: list[dict[str, Any]] | None = None,
    label: str = "manual-memory-promotion-review",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    candidate = _candidate_claim(
        domain=domain,
        subject=subject,
        predicate=predicate,
        value_sha256=value_sha256,
        source_ref=source_ref,
        source_kind=source_kind,
        scope=scope,
        value_ref=value_ref,
        value_summary=value_summary,
        trust_class=trust_class,
        valid_from=valid_from,
        valid_until=valid_until,
    )
    prior_claims = _active_claim_refs(state, candidate)
    conflicting = [
        claim for claim in prior_claims if claim.get("value_sha256") != candidate.get("value_sha256")
    ]
    duplicate = next(
        (claim for claim in prior_claims if claim.get("value_sha256") == candidate.get("value_sha256")),
        None,
    )
    blocked_reasons = _blocked_reasons(
        candidate,
        trust_class,
        supersession_mode,
        rag_retrieval_refs or [],
        state=state,
    )
    superseded_claim = (state.get("memory_claims") or {}).get(supersedes_claim_id or "")
    unresolved_conflicts = [
        claim for claim in conflicting if claim.get("memory_claim_id") != (supersedes_claim_id or "")
    ]
    decision = "promote"
    if blocked_reasons:
        decision = "blocked"
    elif conflicting and not supersedes_claim_id:
        decision = "needs_operator"
        blocked_reasons.append("memory_promotion.conflict_requires_operator")
    elif duplicate:
        decision = "duplicate"
    elif supersedes_claim_id:
        if not superseded_claim:
            decision = "needs_operator"
            blocked_reasons.append("memory_promotion.superseded_claim_missing")
        elif not _claim_conflicts_with_candidate(superseded_claim, candidate):
            decision = "needs_operator"
            blocked_reasons.append("memory_promotion.superseded_claim_key_mismatch")
        elif unresolved_conflicts:
            decision = "needs_operator"
            blocked_reasons.append("memory_promotion.unresolved_active_conflicts")
        elif operator_confirmed and operator_confirmation_ref and operator_confirmation_sha256:
            decision = "promote"
        else:
            decision = "needs_operator"
            blocked_reasons.append("memory_promotion.operator_confirmation_proof_required")
    status = {
        "promote": "promoted",
        "duplicate": "duplicate",
        "needs_operator": "needs_operator",
        "blocked": "blocked",
    }[decision]
    claim = None
    supersession = None
    conflict = None
    if decision == "promote":
        claim = _memory_claim(candidate, label=label, now=now)
        if superseded_claim:
            supersession = _supersession_record(
                old_claim=superseded_claim,
                new_claim=claim,
                mode=supersession_mode,
                operator_confirmed=operator_confirmed,
                operator_confirmation_ref=operator_confirmation_ref,
                operator_confirmation_sha256=operator_confirmation_sha256,
                now=now,
            )
    elif decision == "needs_operator":
        conflict = _conflict_record(
            candidate=candidate,
            conflicting_claim_refs=conflicting or ([superseded_claim] if superseded_claim else []),
            reason_codes=blocked_reasons,
            now=now,
        )
    review = _promotion_review(
        candidate=candidate,
        prior_claim_refs=prior_claims,
        duplicate_claim_ref=duplicate,
        conflicting_claim_refs=conflicting,
        rag_retrieval_refs=rag_retrieval_refs or [],
        supersedes_claim_id=supersedes_claim_id,
        supersession_mode=supersession_mode,
        operator_confirmed=operator_confirmed,
        operator_confirmation_ref=operator_confirmation_ref,
        operator_confirmation_sha256=operator_confirmation_sha256,
        decision=decision,
        status=status,
        reason_codes=_reason_codes(decision, blocked_reasons),
        created_claim=claim,
        supersession=supersession,
        conflict=conflict,
        label=label,
        now=now,
    )
    return {
        "review": review,
        **({"claim": claim} if claim else {}),
        **({"supersession": supersession} if supersession else {}),
        **({"conflict": conflict} if conflict else {}),
    }


def validate_memory_claim_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("memory_claim.schema.json", record, location="memory_claim")
    except SchemaValidationError:
        reason_codes.append("memory_claim.schema_invalid")
    if record.get("memory_claim_sha256") != _hash_without(record, "memory_claim_sha256"):
        reason_codes.append("memory_claim.hash_mismatch")
    if record.get("schema_version") != CLAIM_SCHEMA_VERSION:
        reason_codes.append("memory_claim.schema_version_invalid")
    if record.get("semantic_key") != _semantic_key(record):
        reason_codes.append("memory_claim.semantic_key_mismatch")
    if record.get("base_semantic_key") != _base_semantic_key(record):
        reason_codes.append("memory_claim.base_semantic_key_mismatch")
    if record.get("raw_value_stored") is not False:
        reason_codes.append("memory_claim.raw_value_stored_not_false")
    if record.get("retrieval_is_authority") is not False:
        reason_codes.append("memory_claim.retrieval_is_authority_not_false")
    if record.get("trust_class") not in TRUST_CLASSES:
        reason_codes.append("memory_claim.trust_class_invalid")
    if _contains_forbidden_value(record):
        reason_codes.append("memory_claim.forbidden_value_pattern")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def validate_memory_promotion_review_record(record: dict[str, Any], *, state: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("memory_promotion_review.schema.json", record, location="memory_promotion_review")
    except SchemaValidationError:
        reason_codes.append("memory_promotion_review.schema_invalid")
    if record.get("memory_promotion_review_sha256") != _hash_without(
        record,
        "memory_promotion_review_sha256",
    ):
        reason_codes.append("memory_promotion_review.hash_mismatch")
    if record.get("schema_version") != REVIEW_SCHEMA_VERSION:
        reason_codes.append("memory_promotion_review.schema_version_invalid")
    if record.get("decision") not in REVIEW_DECISIONS:
        reason_codes.append("memory_promotion_review.decision_invalid")
    if record.get("status") not in REVIEW_STATUSES:
        reason_codes.append("memory_promotion_review.status_invalid")
    candidate = record.get("candidate_claim") or {}
    if candidate.get("candidate_claim_sha256") != _hash_without(candidate, "candidate_claim_sha256"):
        reason_codes.append("memory_promotion_review.candidate_hash_mismatch")
    if candidate.get("semantic_key") != _semantic_key(candidate):
        reason_codes.append("memory_promotion_review.candidate_semantic_key_mismatch")
    if candidate.get("base_semantic_key") != _base_semantic_key(candidate):
        reason_codes.append("memory_promotion_review.candidate_base_semantic_key_mismatch")
    if candidate.get("raw_value_stored") is not False:
        reason_codes.append("memory_promotion_review.candidate_raw_value_stored")
    if record.get("rag_policy", {}).get("retrieval_is_authority") is not False:
        reason_codes.append("memory_promotion_review.retrieval_is_authority_not_false")
    if record.get("quiet_build_allowed") is not (record.get("decision") == "promote"):
        reason_codes.append("memory_promotion_review.quiet_build_flag_mismatch")
    expected_status = {
        "promote": "promoted",
        "duplicate": "duplicate",
        "needs_operator": "needs_operator",
        "blocked": "blocked",
    }.get(str(record.get("decision") or ""))
    if expected_status and record.get("status") != expected_status:
        reason_codes.append("memory_promotion_review.status_decision_mismatch")
    claim_id = record.get("created_memory_claim_id")
    if claim_id:
        claim = (state.get("memory_claims") or {}).get(claim_id)
        if not claim:
            reason_codes.append("memory_promotion_review.created_claim_missing")
        elif record.get("created_memory_claim_sha256") != claim.get("memory_claim_sha256"):
            reason_codes.append("memory_promotion_review.created_claim_hash_mismatch")
        elif claim.get("candidate_claim_sha256") != candidate.get("candidate_claim_sha256"):
            reason_codes.append("memory_promotion_review.created_claim_candidate_mismatch")
    if record.get("decision") == "promote" and not claim_id:
        reason_codes.append("memory_promotion_review.promote_without_claim")
    if record.get("decision") == "duplicate" and record.get("duplicate_claim_ref") is None:
        reason_codes.append("memory_promotion_review.duplicate_without_ref")
    if record.get("decision") in {"duplicate", "blocked"} and claim_id:
        reason_codes.append("memory_promotion_review.non_promote_created_claim")
    conflict_id = record.get("memory_conflict_record_id")
    if conflict_id and conflict_id not in (state.get("memory_conflict_records") or {}):
        reason_codes.append("memory_promotion_review.conflict_record_missing")
    if record.get("decision") == "needs_operator" and not conflict_id:
        reason_codes.append("memory_promotion_review.needs_operator_without_conflict")
    supersession_id = record.get("memory_supersession_record_id")
    if supersession_id and supersession_id not in (state.get("memory_supersession_records") or {}):
        reason_codes.append("memory_promotion_review.supersession_record_missing")
    if supersession_id and not (
        record.get("operator_confirmed")
        and record.get("operator_confirmation_ref")
        and record.get("operator_confirmation_sha256")
    ):
        reason_codes.append("memory_promotion_review.supersession_without_operator_proof")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def validate_memory_supersession_record(record: dict[str, Any], *, state: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("memory_supersession_record.schema.json", record, location="memory_supersession_record")
    except SchemaValidationError:
        reason_codes.append("memory_supersession.schema_invalid")
    if record.get("memory_supersession_record_sha256") != _hash_without(
        record,
        "memory_supersession_record_sha256",
    ):
        reason_codes.append("memory_supersession.hash_mismatch")
    if record.get("schema_version") != SUPERSESSION_SCHEMA_VERSION:
        reason_codes.append("memory_supersession.schema_version_invalid")
    if record.get("supersession_mode") not in SUPERSESSION_MODES:
        reason_codes.append("memory_supersession.mode_invalid")
    if record.get("operator_confirmed") is not True:
        reason_codes.append("memory_supersession.operator_confirmed_not_true")
    if not record.get("operator_confirmation_ref") or not record.get("operator_confirmation_sha256"):
        reason_codes.append("memory_supersession.operator_confirmation_proof_missing")
    old_claim = (state.get("memory_claims") or {}).get(record.get("old_memory_claim_id"))
    new_claim = (state.get("memory_claims") or {}).get(record.get("new_memory_claim_id"))
    if not old_claim:
        reason_codes.append("memory_supersession.old_claim_missing")
    elif record.get("old_memory_claim_sha256") != old_claim.get("memory_claim_sha256"):
        reason_codes.append("memory_supersession.old_claim_hash_mismatch")
    if not new_claim:
        reason_codes.append("memory_supersession.new_claim_missing")
    elif record.get("new_memory_claim_sha256") != new_claim.get("memory_claim_sha256"):
        reason_codes.append("memory_supersession.new_claim_hash_mismatch")
    if old_claim and new_claim and old_claim.get("semantic_key") != new_claim.get("semantic_key"):
        reason_codes.append("memory_supersession.semantic_key_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def validate_memory_conflict_record(record: dict[str, Any], *, state: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("memory_conflict_record.schema.json", record, location="memory_conflict_record")
    except SchemaValidationError:
        reason_codes.append("memory_conflict.schema_invalid")
    if record.get("memory_conflict_record_sha256") != _hash_without(
        record,
        "memory_conflict_record_sha256",
    ):
        reason_codes.append("memory_conflict.hash_mismatch")
    if record.get("schema_version") != CONFLICT_SCHEMA_VERSION:
        reason_codes.append("memory_conflict.schema_version_invalid")
    if record.get("build_quietly_allowed") is not False:
        reason_codes.append("memory_conflict.build_quietly_allowed_not_false")
    if record.get("requires_operator_resolution") is not True:
        reason_codes.append("memory_conflict.requires_operator_resolution_not_true")
    for ref in record.get("conflicting_claim_refs") or []:
        claim = (state.get("memory_claims") or {}).get(ref.get("memory_claim_id"))
        if not claim:
            reason_codes.append("memory_conflict.claim_missing")
        elif ref.get("memory_claim_sha256") != claim.get("memory_claim_sha256"):
            reason_codes.append("memory_conflict.claim_hash_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _candidate_claim(
    *,
    domain: str,
    subject: str,
    predicate: str,
    value_sha256: str,
    source_ref: str,
    source_kind: str,
    scope: str,
    value_ref: str | None,
    value_summary: str,
    trust_class: str,
    valid_from: str | None,
    valid_until: str | None,
) -> dict[str, Any]:
    claim = {
        "domain": str(domain),
        "subject": str(subject),
        "predicate": str(predicate),
        "scope": str(scope or "global"),
        "valid_from": valid_from,
        "valid_until": valid_until,
        "value_sha256": str(value_sha256),
        "value_ref": value_ref,
        "value_summary": str(value_summary or ""),
        "value_summary_sha256": sha256_text(str(value_summary or "")),
        "raw_value_stored": False,
        "source_ref": str(source_ref),
        "source_kind": str(source_kind or "prompt"),
        "trust_class": str(trust_class or "user_asserted"),
        "retrieval_is_authority": False,
    }
    claim["base_semantic_key"] = _base_semantic_key(claim)
    claim["semantic_key"] = _semantic_key(claim)
    claim["candidate_claim_sha256"] = _hash_without(claim, "candidate_claim_sha256")
    return claim


def _memory_claim(candidate: dict[str, Any], *, label: str, now: str) -> dict[str, Any]:
    claim = {
        "schema_version": CLAIM_SCHEMA_VERSION,
        "memory_claim_id": stable_id("memclaim", label, candidate, now),
        "label": label,
        **deepcopy(candidate),
        "status": "active",
        "created_at": now,
    }
    claim["memory_claim_sha256"] = _hash_without(claim, "memory_claim_sha256")
    return claim


def _promotion_review(
    *,
    candidate: dict[str, Any],
    prior_claim_refs: list[dict[str, Any]],
    duplicate_claim_ref: dict[str, Any] | None,
    conflicting_claim_refs: list[dict[str, Any]],
    rag_retrieval_refs: list[dict[str, Any]],
    supersedes_claim_id: str | None,
    supersession_mode: str,
    operator_confirmed: bool,
    operator_confirmation_ref: str | None,
    operator_confirmation_sha256: str | None,
    decision: str,
    status: str,
    reason_codes: list[str],
    created_claim: dict[str, Any] | None,
    supersession: dict[str, Any] | None,
    conflict: dict[str, Any] | None,
    label: str,
    now: str,
) -> dict[str, Any]:
    review = {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "memory_promotion_review_id": stable_id("memreview", label, candidate, decision, now),
        "label": label,
        "candidate_claim": deepcopy(candidate),
        "prior_claim_refs": [_claim_ref(claim) for claim in prior_claim_refs],
        "duplicate_claim_ref": _claim_ref(duplicate_claim_ref) if duplicate_claim_ref else None,
        "conflicting_claim_refs": [_claim_ref(claim) for claim in conflicting_claim_refs],
        "rag_retrieval_refs": deepcopy(rag_retrieval_refs),
        "rag_policy": {
            "rag_used_for_recall": bool(rag_retrieval_refs),
            "retrieval_is_authority": False,
            "raw_retrieval_content_stored": False,
            "raw_embedding_stored": False,
            "vector_payload_stored": False,
        },
        "supersedes_claim_id": supersedes_claim_id,
        "supersession_mode": supersession_mode,
        "operator_confirmed": bool(operator_confirmed),
        "operator_confirmation_ref": operator_confirmation_ref,
        "operator_confirmation_sha256": operator_confirmation_sha256,
        "decision": decision,
        "status": status,
        "quiet_build_allowed": decision == "promote",
        "created_memory_claim_id": (created_claim or {}).get("memory_claim_id"),
        "created_memory_claim_sha256": (created_claim or {}).get("memory_claim_sha256"),
        "memory_supersession_record_id": (supersession or {}).get("memory_supersession_record_id"),
        "memory_conflict_record_id": (conflict or {}).get("memory_conflict_record_id"),
        "reason_codes": sorted(set(reason_codes)),
        "created_at": now,
    }
    review["memory_promotion_review_sha256"] = _hash_without(review, "memory_promotion_review_sha256")
    return review


def _supersession_record(
    *,
    old_claim: dict[str, Any],
    new_claim: dict[str, Any],
    mode: str,
    operator_confirmed: bool,
    operator_confirmation_ref: str | None,
    operator_confirmation_sha256: str | None,
    now: str,
) -> dict[str, Any]:
    record = {
        "schema_version": SUPERSESSION_SCHEMA_VERSION,
        "memory_supersession_record_id": stable_id("memsupersede", old_claim, new_claim, mode, now),
        "old_memory_claim_id": old_claim.get("memory_claim_id"),
        "old_memory_claim_sha256": old_claim.get("memory_claim_sha256"),
        "new_memory_claim_id": new_claim.get("memory_claim_id"),
        "new_memory_claim_sha256": new_claim.get("memory_claim_sha256"),
        "semantic_key": new_claim.get("semantic_key"),
        "supersession_mode": mode,
        "operator_confirmed": bool(operator_confirmed),
        "operator_confirmation_ref": operator_confirmation_ref,
        "operator_confirmation_sha256": operator_confirmation_sha256,
        "reviewed_claim_ids": [old_claim.get("memory_claim_id"), new_claim.get("memory_claim_id")],
        "raw_value_stored": False,
        "created_at": now,
    }
    record["memory_supersession_record_sha256"] = _hash_without(
        record,
        "memory_supersession_record_sha256",
    )
    return record


def _conflict_record(
    *,
    candidate: dict[str, Any],
    conflicting_claim_refs: list[dict[str, Any]],
    reason_codes: list[str],
    now: str,
) -> dict[str, Any]:
    record = {
        "schema_version": CONFLICT_SCHEMA_VERSION,
        "memory_conflict_record_id": stable_id("memconflict", candidate, conflicting_claim_refs, reason_codes, now),
        "candidate_claim": deepcopy(candidate),
        "conflicting_claim_refs": [_claim_ref(claim) for claim in conflicting_claim_refs if claim],
        "requires_operator_resolution": True,
        "build_quietly_allowed": False,
        "raw_value_stored": False,
        "reason_codes": sorted(set(reason_codes)),
        "created_at": now,
    }
    record["memory_conflict_record_sha256"] = _hash_without(record, "memory_conflict_record_sha256")
    return record


def _active_claim_refs(state: dict[str, Any], candidate: dict[str, Any]) -> list[dict[str, Any]]:
    superseded = {
        record.get("old_memory_claim_id")
        for record in (state.get("memory_supersession_records") or {}).values()
        if record.get("old_memory_claim_id")
    }
    claims = [
        claim
        for claim in (state.get("memory_claims") or {}).values()
        if _claim_conflicts_with_candidate(claim, candidate) and claim.get("memory_claim_id") not in superseded
    ]
    return sorted(claims, key=lambda claim: str(claim.get("created_at") or ""))


def _claim_ref(claim: dict[str, Any] | None) -> dict[str, Any] | None:
    if not claim:
        return None
    return {
        "memory_claim_id": claim.get("memory_claim_id"),
        "memory_claim_sha256": claim.get("memory_claim_sha256"),
        "semantic_key": claim.get("semantic_key"),
        "value_sha256": claim.get("value_sha256"),
        "trust_class": claim.get("trust_class"),
    }


def _semantic_key(claim: dict[str, Any]) -> str:
    material = [
        _norm(claim.get("domain")),
        _norm(claim.get("subject")),
        _norm(claim.get("predicate")),
        _norm(claim.get("scope") or "global"),
        str(claim.get("valid_from") or ""),
        str(claim.get("valid_until") or ""),
    ]
    return sha256_text(canonical_json(material))


def _base_semantic_key(claim: dict[str, Any]) -> str:
    material = [
        _norm(claim.get("domain")),
        _norm(claim.get("subject")),
        _norm(claim.get("predicate")),
        _norm(claim.get("scope") or "global"),
    ]
    return sha256_text(canonical_json(material))


def _norm(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _claim_conflicts_with_candidate(claim: dict[str, Any], candidate: dict[str, Any]) -> bool:
    return (
        _norm(claim.get("domain")) == _norm(candidate.get("domain"))
        and _norm(claim.get("subject")) == _norm(candidate.get("subject"))
        and _norm(claim.get("predicate")) == _norm(candidate.get("predicate"))
        and _scope_conflicts(claim.get("scope"), candidate.get("scope"))
        and _validity_overlaps(claim, candidate)
    )


def _scope_conflicts(left: Any, right: Any) -> bool:
    left_norm = _norm(left or "global")
    right_norm = _norm(right or "global")
    return left_norm == right_norm or left_norm == "global" or right_norm == "global"


def _validity_overlaps(left: dict[str, Any], right: dict[str, Any]) -> bool:
    left_from = str(left.get("valid_from") or "")
    left_until = str(left.get("valid_until") or "")
    right_from = str(right.get("valid_from") or "")
    right_until = str(right.get("valid_until") or "")
    left_start = left_from or "0000"
    right_start = right_from or "0000"
    left_end = left_until or "9999"
    right_end = right_until or "9999"
    return left_start <= right_end and right_start <= left_end


def _blocked_reasons(
    candidate: dict[str, Any],
    trust_class: str,
    supersession_mode: str,
    rag_retrieval_refs: list[dict[str, Any]],
    state: dict[str, Any],
) -> list[str]:
    reasons: list[str] = []
    if trust_class not in TRUST_CLASSES:
        reasons.append("memory_promotion.trust_class_invalid")
    if supersession_mode not in SUPERSESSION_MODES:
        reasons.append("memory_promotion.supersession_mode_invalid")
    if not str(candidate.get("value_sha256") or "").startswith("sha256:"):
        reasons.append("memory_promotion.value_hash_required")
    if not candidate.get("source_ref"):
        reasons.append("memory_promotion.source_ref_required")
    if _contains_forbidden_value(candidate):
        reasons.append("memory_promotion.forbidden_value_pattern")
    reasons.extend(_rag_ref_reasons(rag_retrieval_refs, state=state))
    return reasons


def _contains_forbidden_value(record: dict[str, Any]) -> bool:
    material = " ".join(
        str(record.get(key) or "")
        for key in ("value_summary", "value_ref", "source_ref", "source_kind", "subject", "predicate")
    )
    return any(pattern.search(material) for pattern in FORBIDDEN_VALUE_PATTERNS)


def _rag_ref_reasons(refs: list[dict[str, Any]], *, state: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    for ref in refs:
        if not isinstance(ref, dict):
            reasons.append("memory_promotion.rag_ref_invalid")
            continue
        if ref.get("retrieval_is_authority") is not False:
            reasons.append("memory_promotion.rag_authority_not_allowed")
        query_id = str(ref.get("rag_retrieval_query_id") or "")
        if not query_id:
            reasons.append("memory_promotion.rag_ref_id_required")
            continue
        query = (state.get("rag_retrieval_queries") or {}).get(query_id)
        if not query:
            reasons.append("memory_promotion.rag_ref_missing_query")
            continue
        if ref.get("retrieval_query_sha256") and ref.get("retrieval_query_sha256") != query.get(
            "retrieval_query_sha256"
        ):
            reasons.append("memory_promotion.rag_ref_hash_mismatch")
        if query.get("query_text_stored") is not False or query.get("raw_corpus_stored") is not False:
            reasons.append("memory_promotion.rag_raw_content_not_allowed")
        if "hash_refs" not in set(query.get("taint_labels") or []):
            reasons.append("memory_promotion.rag_hash_refs_taint_required")
    return sorted(set(reasons))


def _reason_codes(decision: str, blocked_reasons: list[str]) -> list[str]:
    if decision == "promote":
        return ["memory_promotion.promoted"]
    if decision == "duplicate":
        return ["memory_promotion.duplicate_noop"]
    return sorted(set(blocked_reasons or [f"memory_promotion.{decision}"]))
