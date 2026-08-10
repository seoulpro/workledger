from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

    def test_symlinked_source_outside_root_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            sessions = source / "sessions"
            sessions.mkdir(parents=True)
            outside = root / "outside.jsonl"
            outside.write_text(
                json.dumps(
                    {
                        "timestamp": "2026-01-01T00:00:00Z",
                        "type": "session_meta",
                        "payload": {"id": "outside-session", "cwd": "/tmp/outside"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            linked = sessions / "rollout-link.jsonl"
            try:
                linked.symlink_to(outside)
            except OSError as error:
                self.skipTest(f"symbolic links are unavailable: {error}")

            adapted = SessionAdapter(source).scan()

        self.assertEqual(adapted.records, [])
        self.assertEqual(adapted.stats.files_seen, 0)
        self.assertIn("unsafe_source_path", {item.code for item in adapted.diagnostics})

    def test_oversized_line_is_drained_before_next_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            valid = json.dumps(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "type": "session_meta",
                    "payload": {"id": "bounded-session", "cwd": "/tmp/project"},
                }
            )
            (sessions / "rollout.jsonl").write_text(
                ("x" * 513) + "\n" + valid + "\n",
                encoding="utf-8",
            )

            with mock.patch("workledger.adapter.MAX_LINE_CHARS", 256):
                adapted = SessionAdapter(root).scan()

        self.assertEqual(adapted.stats.malformed_records, 1)
        self.assertEqual(adapted.stats.canonical_records, 1)
        self.assertIn("oversized_record", {item.code for item in adapted.diagnostics})

if __name__ == "__main__":
    unittest.main()
