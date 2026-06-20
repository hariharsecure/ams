from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import canonical_json, iso_after, sha256_text, stable_id, utc_now
from .store import JsonStore


def _allowed_from_status(status: str) -> bool:
    return status == "allow"


def build_admission_review(
    *,
    subject_kind: str,
    subject_id: str,
    operation: str,
    request: dict[str, Any],
    verdict: dict[str, Any] | None = None,
    status: str | None = None,
    reason_codes: list[str] | None = None,
    policy_refs: list[str] | None = None,
    reviewer: str = "ams.local",
    ttl_seconds: int = 900,
) -> dict[str, Any]:
    status = status or (verdict or {}).get("status") or "defer"
    reason_codes = reason_codes or list((verdict or {}).get("reason_codes") or [])
    uid = stable_id("admuid", subject_kind, subject_id, operation, request, verdict)
    now = utc_now()
    review = {
        "schema_version": "ams.ams.admission_review.v0",
        "admission_review_id": stable_id("adm", uid, now),
        "request_uid": uid,
        "subject_kind": subject_kind,
        "subject_id": subject_id,
        "operation": operation,
        "request": request,
        "request_sha256": sha256_text(canonical_json(request)),
        "response": {
            "uid": uid,
            "allowed": _allowed_from_status(status),
            "status": status,
            "reason_codes": reason_codes,
            "warnings": list((verdict or {}).get("warnings") or []),
            "verdict_ref": (verdict or {}).get("resource_verdict_id")
            or (verdict or {}).get("capability_verdict_id")
            or (verdict or {}).get("verdict_id"),
            "expires_at": iso_after(ttl_seconds),
        },
        "policy_refs": policy_refs or _policy_refs_from_verdict(verdict or {}),
        "reviewer": reviewer,
        "created_at": now,
    }
    review["review_sha256"] = sha256_text(canonical_json(review))
    return review


def _policy_refs_from_verdict(verdict: dict[str, Any]) -> list[str]:
    policy_id = verdict.get("policy_id")
    policy_sha256 = verdict.get("policy_sha256")
    if not policy_id and not policy_sha256:
        return []
    return [":".join(str(part) for part in (policy_id, policy_sha256) if part)]


class AdmissionReviewStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        subject_kind: str,
        subject_id: str,
        operation: str,
        request: dict[str, Any],
        verdict: dict[str, Any] | None = None,
        status: str | None = None,
        reason_codes: list[str] | None = None,
        policy_refs: list[str] | None = None,
        reviewer: str = "ams.local",
        ttl_seconds: int = 900,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            if subject_kind == "task_run" and subject_id not in state.get("task_runs", {}):
                raise KeyError(f"unknown task_run_id: {subject_id}")
            review = build_admission_review(
                subject_kind=subject_kind,
                subject_id=subject_id,
                operation=operation,
                request=request,
                verdict=verdict,
                status=status,
                reason_codes=reason_codes,
                policy_refs=policy_refs,
                reviewer=reviewer,
                ttl_seconds=ttl_seconds,
            )
            state.setdefault("admission_reviews", {})[review["admission_review_id"]] = review
        return deepcopy(review)
