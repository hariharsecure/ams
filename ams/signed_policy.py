from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
import tempfile
from typing import Any

from .models import canonical_json, sha256_text


@dataclass(frozen=True)
class SignedPolicyConfig:
    allowed_signers_path: Path
    signer_identity: str
    pinned_fingerprints: tuple[str, ...]
    namespace: str = "ams-policy"
    ssh_keygen: str = "ssh-keygen"


def verify_signed_policy(
    policy_path: str | Path,
    signature_path: str | Path,
    config: SignedPolicyConfig,
) -> dict[str, Any]:
    policy_path = Path(policy_path)
    signature_path = Path(signature_path)
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return _deny("policy.invalid_json", error=f"{type(exc).__name__}: {exc}")
    if not isinstance(policy, dict):
        return _deny("policy.not_object")

    canonical = canonical_json(policy).encode("utf-8")
    policy_sha256 = sha256_text(canonical.decode("utf-8"))
    fingerprint_result = _fingerprint_for_identity(config)
    if not fingerprint_result["ok"]:
        extra = dict(fingerprint_result)
        reason_code = str(extra.pop("reason_code"))
        return _deny(reason_code, policy_sha256=policy_sha256, **extra)
    signer_fingerprint = fingerprint_result["fingerprint"]
    if signer_fingerprint not in set(config.pinned_fingerprints):
        return _deny(
            "signer.not_pinned",
            policy_sha256=policy_sha256,
            signer_fingerprint=signer_fingerprint,
        )
    if not signature_path.exists():
        return _deny(
            "signature.missing",
            policy_sha256=policy_sha256,
            signer_fingerprint=signer_fingerprint,
        )

    cmd = [
        config.ssh_keygen,
        "-Y",
        "verify",
        "-f",
        str(config.allowed_signers_path),
        "-I",
        config.signer_identity,
        "-n",
        config.namespace,
        "-s",
        str(signature_path),
    ]
    completed = subprocess.run(cmd, input=canonical, capture_output=True, check=False)
    payload = {
        "allowed": completed.returncode == 0,
        "status": "allow" if completed.returncode == 0 else "deny",
        "reason_code": "signature.verified" if completed.returncode == 0 else "signature.verify_failed",
        "policy_sha256": policy_sha256,
        "signer_identity": config.signer_identity,
        "signer_fingerprint": signer_fingerprint,
        "namespace": config.namespace,
        "exit_code": completed.returncode,
        "stdout": completed.stdout.decode("utf-8", errors="replace"),
        "stderr": completed.stderr.decode("utf-8", errors="replace"),
    }
    return payload


def _fingerprint_for_identity(config: SignedPolicyConfig) -> dict[str, Any]:
    try:
        lines = config.allowed_signers_path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        return {"ok": False, "reason_code": "allowed_signers.unreadable", "error": f"{type(exc).__name__}: {exc}"}
    public_key = None
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 3 or parts[0] != config.signer_identity:
            continue
        for index, part in enumerate(parts):
            if part.startswith("ssh-") and index + 1 < len(parts):
                public_key = " ".join(parts[index:index + 2])
                break
        if public_key:
            break
    if not public_key:
        return {"ok": False, "reason_code": "signer.not_found"}
    with tempfile.TemporaryDirectory() as td:
        pub_path = Path(td) / "signer.pub"
        pub_path.write_text(public_key + "\n", encoding="utf-8")
        completed = subprocess.run(
            [config.ssh_keygen, "-lf", str(pub_path), "-E", "sha256"],
            capture_output=True,
            check=False,
        )
    if completed.returncode != 0:
        return {
            "ok": False,
            "reason_code": "signer.fingerprint_failed",
            "stdout": completed.stdout.decode("utf-8", errors="replace"),
            "stderr": completed.stderr.decode("utf-8", errors="replace"),
        }
    text = completed.stdout.decode("utf-8", errors="replace").strip()
    fields = text.split()
    if len(fields) < 2:
        return {"ok": False, "reason_code": "signer.fingerprint_parse_failed", "stdout": text}
    return {"ok": True, "fingerprint": fields[1]}


def _deny(reason_code: str, **extra: Any) -> dict[str, Any]:
    payload = {"allowed": False, "status": "deny", "reason_code": reason_code}
    payload.update(extra)
    return payload
