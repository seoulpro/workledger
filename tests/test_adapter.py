from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from workledger.adapter import SessionAdapter


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "mixed"


class SessionAdapterTests(unittest.TestCase):
    def test_handles_malformed_duplicate_compacted_and_old_records(self) -> None:
        adapted = SessionAdapter(FIXTURE_ROOT).scan()

        self.assertEqual(adapted.stats.files_seen, 3)
        self.assertEqual(adapted.stats.files_fully_scanned, 3)
        self.assertEqual(adapted.stats.metadata_only_files, 0)
        self.assertEqual(adapted.stats.index_files_seen, 1)
        self.assertEqual(adapted.stats.index_records, 2)
        self.assertEqual(adapted.stats.malformed_records, 1)
        self.assertGreaterEqual(adapted.stats.duplicate_records, 2)
        self.assertEqual(adapted.stats.compacted_records, 1)
        self.assertTrue(any(record.kind == "compaction_summary" for record in adapted.records))
        self.assertTrue(any(record.project_path and "legacy" in record.project_path for record in adapted.records))

    def test_missing_root_is_a_diagnostic_not_an_exception(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing"
            adapted = SessionAdapter(missing).scan()

        self.assertEqual(adapted.records, [])
        self.assertIn("source_missing", {item.code for item in adapted.diagnostics})

    def test_source_references_do_not_expose_file_paths(self) -> None:
        adapted = SessionAdapter(FIXTURE_ROOT).scan()

        for record in adapted.records:
            self.assertRegex(record.location, r"^s-[0-9a-f]{10}#L\d+$")
            self.assertNotIn(str(FIXTURE_ROOT), record.location)

if __name__ == "__main__":
    unittest.main()
