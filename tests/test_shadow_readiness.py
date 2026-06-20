from __future__ import annotations

import unittest

from ams.shadow_readiness import evaluate_shadow_readiness


READY_INSTALL = {"ready_for_live": True}
VERIFIED_PACKAGE = {"allowed": True}


class ShadowReadinessTest(unittest.TestCase):
    def test_missing_approval_defers(self) -> None:
        result = evaluate_shadow_readiness(
            install_preflight=READY_INSTALL,
            package_verification=VERIFIED_PACKAGE,
        )

        self.assertFalse(result["allowed"])
        self.assertIn("shadow.explicit_approval_missing", result["reason_codes"])

    def test_install_not_ready_defers(self) -> None:
        result = evaluate_shadow_readiness(
            install_preflight={"ready_for_live": False},
            package_verification=VERIFIED_PACKAGE,
            approval_id="approval-local-test",
        )

        self.assertFalse(result["allowed"])
        self.assertIn("shadow.install_preflight_not_ready", result["reason_codes"])

    def test_unverified_package_defers(self) -> None:
        result = evaluate_shadow_readiness(
            install_preflight=READY_INSTALL,
            package_verification={"allowed": False},
            approval_id="approval-local-test",
        )

        self.assertFalse(result["allowed"])
        self.assertIn("shadow.package_not_verified", result["reason_codes"])

    def test_direct_egress_is_not_shadow_ready(self) -> None:
        result = evaluate_shadow_readiness(
            install_preflight=READY_INSTALL,
            package_verification=VERIFIED_PACKAGE,
            approval_id="approval-local-test",
            egress_mode="discord_send",
        )

        self.assertFalse(result["allowed"])
        self.assertIn("shadow.egress_must_be_none", result["reason_codes"])

    def test_all_gates_allow_shadow_readiness(self) -> None:
        result = evaluate_shadow_readiness(
            install_preflight=READY_INSTALL,
            package_verification=VERIFIED_PACKAGE,
            approval_id="approval-local-test",
            egress_mode="none",
        )

        self.assertTrue(result["allowed"], result)
        self.assertEqual(result["reason_code"], "shadow.ready")


if __name__ == "__main__":
    unittest.main()
