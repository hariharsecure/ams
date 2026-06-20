from __future__ import annotations

import unittest

from ams.self_eval import run_self_eval


class SelfEvalTest(unittest.TestCase):
    def test_self_eval_detects_injected_faults_without_ams_silent_failures(self) -> None:
        result = run_self_eval(cases=20)
        metrics = result["metrics"]

        self.assertTrue(result["predicate_audit"]["audited"])
        self.assertEqual(metrics["total_cases"], 20)
        self.assertEqual(metrics["faulted_cases"], 16)
        self.assertEqual(metrics["raw_silent_failures"], 16)
        self.assertEqual(metrics["ams_silent_failures"], 0)
        self.assertEqual(metrics["ams_detected_faults"], 16)
        self.assertEqual(metrics["ams_fault_detection_rate"], 1.0)
        self.assertEqual(metrics["ams_clean_verified_success_rate"], 1.0)
        self.assertEqual(metrics["ams_pass3_clean"], 1.0)

    def test_self_eval_rejects_too_few_cases(self) -> None:
        with self.assertRaises(ValueError):
            run_self_eval(cases=4)


if __name__ == "__main__":
    unittest.main()
