from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from ams.definition_registry import DefinitionRegistryStore
from ams.models import canonical_json
from ams.package_manifest import build_package_manifest, verify_package_manifest
from ams.schema_validation import validate_record
from ams.signed_policy import SignedPolicyConfig
from ams.store import JsonStore


SSH_KEYGEN = shutil.which("ssh-keygen")


@unittest.skipUnless(SSH_KEYGEN, "ssh-keygen required for package manifest tests")
class PackageManifestTest(unittest.TestCase):
    def test_valid_signed_package_allows_and_schema_validates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            DefinitionRegistryStore(store).install_defaults()
            fixture = _signed_package_fixture(root, store)

            result = verify_package_manifest(
                fixture["manifest"],
                fixture["signature"],
                _config(fixture),
                store=store,
            )

            self.assertTrue(result["allowed"], result)
            self.assertEqual(result["reason_code"], "package.verified")
            self.assertEqual(result["registry"]["reason_codes"], [])

    def test_tampered_package_signature_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            DefinitionRegistryStore(store).install_defaults()
            fixture = _signed_package_fixture(root, store)
            manifest = fixture["manifest_json"]
            manifest["version"] = "9.9.9"
            fixture["manifest"].write_text(canonical_json(manifest), encoding="utf-8")

            result = verify_package_manifest(
                fixture["manifest"],
                fixture["signature"],
                _config(fixture),
                store=store,
            )

            self.assertFalse(result["allowed"])
            self.assertEqual(result["reason_code"], "package.signature_failed")
            self.assertIn("signature.verify_failed", result["reason_codes"])

    def test_package_catches_missing_unused_registry_definition(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            DefinitionRegistryStore(store).install_defaults()
            fixture = _signed_package_fixture(root, store)
            state = store.load()
            disabled = next(
                definition_id for definition_id, definition in state["tool_definitions"].items()
                if definition["name"] == "discord_client.send"
            )
            state["tool_definitions"].pop(disabled)
            store.save(state)

            result = verify_package_manifest(
                fixture["manifest"],
                fixture["signature"],
                _config(fixture),
                store=store,
            )

            self.assertFalse(result["allowed"])
            self.assertEqual(result["reason_code"], "package.validation_failed")
            self.assertIn("registry.tool_missing:discord_client.send", result["reason_codes"])

    def test_enforced_package_requires_packaged_gate_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            DefinitionRegistryStore(store).install_defaults()
            fixture = _signed_package_fixture(root, store, package_mode="enforced")

            result = verify_package_manifest(
                fixture["manifest"],
                fixture["signature"],
                _config(fixture),
                store=store,
            )

            self.assertFalse(result["allowed"])
            self.assertIn("package.enforced_gate_missing_artifact", result["reason_codes"])


def _config(fixture: dict[str, Path | str]) -> SignedPolicyConfig:
    return SignedPolicyConfig(
        allowed_signers_path=fixture["allowed_signers"],
        signer_identity="signer@example.test",
        pinned_fingerprints=(str(fixture["fingerprint"]),),
        namespace="ams-package",
        ssh_keygen=SSH_KEYGEN or "ssh-keygen",
    )


def _signed_package_fixture(root: Path, store: JsonStore, *, package_mode: str = "shadow_only") -> dict[str, Path | str | dict]:
    key_path = root / "signer"
    manifest_path = root / "package.json"
    manifest = build_package_manifest(store.load(), package_mode=package_mode)
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
    return {
        "manifest": manifest_path,
        "manifest_json": manifest,
        "signature": manifest_path.with_suffix(manifest_path.suffix + ".sig"),
        "allowed_signers": allowed_signers,
        "fingerprint": fingerprint,
    }


if __name__ == "__main__":
    unittest.main()
