from __future__ import annotations

from typing import Any


def evaluate_shadow_readiness(
    *,
    install_preflight: dict[str, Any],
    package_verification: dict[str, Any],
    approval_id: str | None = None,
    egress_mode: str = "none",
) -> dict[str, Any]:
    reason_codes: list[str] = []
    if not install_preflight.get("ready_for_live"):
        reason_codes.append("shadow.install_preflight_not_ready")
    if package_verification.get("allowed") is not True:
        reason_codes.append("shadow.package_not_verified")
    if not approval_id:
        reason_codes.append("shadow.explicit_approval_missing")
    if egress_mode != "none":
        reason_codes.append("shadow.egress_must_be_none")
    allowed = not reason_codes
    return {
        "schema_version": "ams.ams.shadow_readiness.v0",
        "allowed": allowed,
        "status": "allow" if allowed else "defer",
        "reason_code": "shadow.ready" if allowed else reason_codes[0],
        "reason_codes": ["shadow.ready"] if allowed else reason_codes,
        "approval_id": approval_id,
        "egress_mode": egress_mode,
        "checks": {
            "install_preflight_ready": bool(install_preflight.get("ready_for_live")),
            "package_verified": package_verification.get("allowed") is True,
            "explicit_approval": bool(approval_id),
            "egress_none": egress_mode == "none",
        },
    }
