from __future__ import annotations

import tempfile
import unittest

from ams.storage_probe import run_storage_probe


class StorageProbeTest(unittest.TestCase):
    def test_storage_probe_reports_m8h_decision_fields(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            result = run_storage_probe(iterations=3, payload_bytes=16, directory=td)

            self.assertEqual(result["iterations"], 3)
            self.assertIn("p95_write_ms", result["json"])
            self.assertIn("p95_write_ms", result["sqlite_wal"])
            self.assertIn(result["sqlite_wal"]["journal_mode"], {"wal", "memory"})
            self.assertIn(
                result["decision"]["recommendation"],
                {"keep_json_for_m8h_shadow", "plan_sqlite_wal"},
            )
            self.assertEqual(result["decision"]["json_p95_write_ms_threshold"], 50.0)
            self.assertEqual(result["decision"]["json_size_bytes_threshold"], 5 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
