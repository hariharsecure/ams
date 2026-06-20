from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from ams_codex.models import canonical_json
from ams_codex.signed_policy import SignedPolicyConfig, verify_signed_policy


SSH_KEYGEN = shutil.which("ssh-keygen")


@unittest.skipUnless(SSH_KEYGEN, "ssh-keygen required for signed policy tests")
class SignedPolicyTest(unittest.TestCase):
    def test_valid_signed_policy_allows_with_pinned_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fixture = _signed_policy_fixture(Path(td), identity="signer@example.test")

            result = verify_signed_policy(
                fixture["policy"],
                fixture["signature"],
                SignedPolicyConfig(
                    allowed_signers_path=fixture["allowed_signers"],
                    signer_identity="signer@example.test",
                    pinned_fingerprints=(fixture["fingerprint"],),
                    ssh_keygen=SSH_KEYGEN or "ssh-keygen",
                ),
            )

            self.assertTrue(result["allowed"], result)
            self.assertEqual(result["reason_code"], "signature.verified")
            self.assertEqual(result["signer_fingerprint"], fixture["fingerprint"])
            self.assertEqual(result["stderr"], "")

    def test_tampered_policy_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fixture = _signed_policy_fixture(Path(td), identity="signer@example.test")
            fixture["policy"].write_text(
                canonical_json({"policy_id": "test", "protected": ["ams_codex/replay.py"]}) + "\n",
                encoding="utf-8",
            )

            result = verify_signed_policy(
                fixture["policy"],
                fixture["signature"],
                SignedPolicyConfig(
                    allowed_signers_path=fixture["allowed_signers"],
                    signer_identity="signer@example.test",
                    pinned_fingerprints=(fixture["fingerprint"],),
                    ssh_keygen=SSH_KEYGEN or "ssh-keygen",
                ),
            )

            self.assertFalse(result["allowed"])
            self.assertEqual(result["reason_code"], "signature.verify_failed")
            self.assertIn("stderr", result)
            self.assertIn("stdout", result)

    def test_unpinned_signer_fails_before_signature_authority(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fixture = _signed_policy_fixture(Path(td), identity="signer@example.test")

            result = verify_signed_policy(
                fixture["policy"],
                fixture["signature"],
                SignedPolicyConfig(
                    allowed_signers_path=fixture["allowed_signers"],
                    signer_identity="signer@example.test",
                    pinned_fingerprints=("SHA256:not-the-signer",),
                    ssh_keygen=SSH_KEYGEN or "ssh-keygen",
                ),
            )

            self.assertFalse(result["allowed"])
            self.assertEqual(result["reason_code"], "signer.not_pinned")

    def test_invalid_policy_json_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _signed_policy_fixture(root, identity="signer@example.test")
            fixture["policy"].write_text("{not json", encoding="utf-8")

            result = verify_signed_policy(
                fixture["policy"],
                fixture["signature"],
                SignedPolicyConfig(
                    allowed_signers_path=fixture["allowed_signers"],
                    signer_identity="signer@example.test",
                    pinned_fingerprints=(fixture["fingerprint"],),
                    ssh_keygen=SSH_KEYGEN or "ssh-keygen",
                ),
            )

            self.assertFalse(result["allowed"])
            self.assertEqual(result["reason_code"], "policy.invalid_json")


def _signed_policy_fixture(root: Path, *, identity: str) -> dict[str, Path | str]:
    key_path = root / "signer"
    policy_path = root / "policy.json"
    policy = {
        "policy_id": "test",
        "protected": ["ams_codex/policy.py"],
        "mode": "shadow_only",
    }
    policy_path.write_text(canonical_json(policy), encoding="utf-8")
    subprocess.run(
        [SSH_KEYGEN or "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", identity, "-f", str(key_path)],
        check=True,
        capture_output=True,
    )
    fingerprint_output = subprocess.run(
        [SSH_KEYGEN or "ssh-keygen", "-lf", str(key_path.with_suffix(".pub")), "-E", "sha256"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    fingerprint = fingerprint_output.split()[1]
    allowed_signers = root / "allowed_signers"
    allowed_signers.write_text(
        f"{identity} {key_path.with_suffix('.pub').read_text(encoding='utf-8')}",
        encoding="utf-8",
    )
    subprocess.run(
        [SSH_KEYGEN or "ssh-keygen", "-Y", "sign", "-f", str(key_path), "-n", "ams-policy", str(policy_path)],
        check=True,
        capture_output=True,
    )
    return {
        "policy": policy_path,
        "signature": policy_path.with_suffix(policy_path.suffix + ".sig"),
        "allowed_signers": allowed_signers,
        "fingerprint": fingerprint,
    }


if __name__ == "__main__":
    unittest.main()
