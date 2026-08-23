from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import workledger.adapter as adapter_module
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

    def test_unresolvable_source_root_is_reported_safely(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "loop"
            try:
                root.symlink_to(root)
            except OSError as error:
                self.skipTest(f"symbolic links are unavailable: {error}")

            adapted = SessionAdapter(root).scan()

        self.assertEqual(adapted.records, [])
        self.assertIn("unsafe_source_root", {item.code for item in adapted.diagnostics})

    def test_replaced_source_inode_is_rejected_after_open(self) -> None:
        with mock.patch("workledger.adapter._same_file", return_value=False):
            adapted = SessionAdapter(FIXTURE_ROOT).scan()

        self.assertEqual(adapted.records, [])
        self.assertIn("unreadable_file", {item.code for item in adapted.diagnostics})

    def test_source_replacement_between_identity_and_full_scan_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            session_id = "indexed-session"
            (root / "session_index.jsonl").write_text(
                json.dumps({"id": session_id}) + "\n",
                encoding="utf-8",
            )
            rollout = sessions / "rollout.jsonl"
            rollout.write_text(
                json.dumps(
                    {
                        "type": "session_meta",
                        "payload": {"id": session_id, "cwd": "/tmp/original"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            adapter = SessionAdapter(root)
            original_identity = adapter._file_identity_from_path

            def replace_after_identity(path: Path):
                identity = original_identity(path)
                replacement = path.with_suffix(".replacement")
                replacement.write_text(
                    json.dumps(
                        {
                            "type": "session_meta",
                            "payload": {"id": session_id, "cwd": "/tmp/replaced"},
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                replacement.replace(path)
                return identity

            with mock.patch.object(
                adapter,
                "_file_identity_from_path",
                side_effect=replace_after_identity,
            ):
                adapted = adapter.scan()

        self.assertEqual(adapted.records, [])
        self.assertIn("unreadable_file", {item.code for item in adapted.diagnostics})

    def test_in_place_source_rewrite_after_identity_selection_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            session_id = "indexed-session"
            (root / "session_index.jsonl").write_text(
                json.dumps({"id": session_id}) + "\n",
                encoding="utf-8",
            )
            rollout = sessions / "rollout.jsonl"
            rollout.write_text(
                json.dumps(
                    {
                        "type": "session_meta",
                        "payload": {"id": session_id, "cwd": "/tmp/original"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            adapter = SessionAdapter(root)
            original_identity = adapter._file_identity_from_path

            def rewrite_after_identity(path: Path):
                identity = original_identity(path)
                path.write_text(
                    json.dumps(
                        {
                            "type": "session_meta",
                            "payload": {"id": "foreign-session", "cwd": "/tmp/replaced"},
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                return identity

            with mock.patch.object(
                adapter,
                "_file_identity_from_path",
                side_effect=rewrite_after_identity,
            ):
                adapted = adapter.scan()

        self.assertEqual(adapted.records, [])
        self.assertIn("unreadable_file", {item.code for item in adapted.diagnostics})

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

    def test_deep_json_is_skipped_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            nested = "[" * 1_200 + "0" + "]" * 1_200
            (sessions / "rollout.jsonl").write_text(
                '{"type":"synthetic","payload":' + nested + "}\n",
                encoding="utf-8",
            )

            adapted = SessionAdapter(root).scan()

        self.assertEqual(adapted.records, [])
        self.assertEqual(adapted.stats.malformed_records, 1)
        self.assertIn("json_depth_exceeded", {item.code for item in adapted.diagnostics})

    def test_flat_json_token_budget_is_checked_before_materialization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            (sessions / "rollout.jsonl").write_text(
                json.dumps(
                    {
                        "type": "turn_context",
                        "payload": {"turn_id": [{} for _ in range(20)]},
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            with (
                mock.patch("workledger.adapter.MAX_JSON_TOKENS", 20),
                mock.patch(
                    "workledger.adapter._load_bounded_json",
                    side_effect=AssertionError("over-budget JSON must not be materialized"),
                ),
            ):
                adapted = SessionAdapter(root).scan()

        self.assertEqual(adapted.records, [])
        self.assertIn("json_budget_exceeded", {item.code for item in adapted.diagnostics})

    def test_container_metadata_is_not_retained(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            records = [
                {
                    "type": "session_meta",
                    "payload": {"id": "metadata-session", "cwd": "/tmp/project"},
                },
                {
                    "type": "turn_context",
                    "payload": {"turn_id": [{"nested": "value"}]},
                },
            ]
            (sessions / "rollout.jsonl").write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )

            adapted = SessionAdapter(root).scan()

        turn_context = next(record for record in adapted.records if record.kind == "turn_context")
        self.assertEqual(turn_context.metadata, {})
        self.assertIn("metadata_value_skipped", {item.code for item in adapted.diagnostics})

    def test_unstable_file_state_is_rolled_back_before_stable_sibling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            first = sessions / "a.jsonl"
            second = sessions / "b.jsonl"
            records = [
                {
                    "type": "session_meta",
                    "payload": {"id": "shared-session", "cwd": "/tmp/project"},
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "message",
                        "role": "assistant",
                        "content": "TODO: stable sibling evidence",
                    },
                },
            ]
            serialized = "".join(json.dumps(record) + "\n" for record in records)
            first.write_text(serialized, encoding="utf-8")
            second.write_text(serialized, encoding="utf-8")
            adapter = SessionAdapter(root)
            original_candidate_lines = adapter._candidate_lines
            mutated = False

            def mutate_first_after_one_record(path: Path):
                nonlocal mutated
                for line_number, line in original_candidate_lines(path):
                    yield line_number, line
                    if path == first and line_number == 1 and not mutated:
                        metadata = os.stat(first, follow_symlinks=False)
                        os.utime(
                            first,
                            ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 2_000_000_000),
                        )
                        mutated = True

            with mock.patch.object(
                adapter,
                "_candidate_lines",
                side_effect=mutate_first_after_one_record,
            ):
                adapted = adapter.scan()

        self.assertTrue(mutated)
        self.assertEqual(len(adapted.records), 2)
        self.assertEqual(adapted.stats.canonical_records, 2)
        self.assertEqual(adapted.stats.duplicate_records, 0)
        self.assertEqual(len(adapter._fingerprints), 2)
        self.assertIn("unreadable_file", {item.code for item in adapted.diagnostics})

    def test_unstable_index_does_not_commit_transient_selection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            index = root / "session_index.jsonl"
            transient_id = "transient-session"
            index.write_text(
                json.dumps({"id": transient_id, "updated_at": "2026-01-01T00:00:00Z"})
                + "\n",
                encoding="utf-8",
            )
            (sessions / "rollout.jsonl").write_text(
                "".join(
                    json.dumps(record) + "\n"
                    for record in (
                        {
                            "type": "session_meta",
                            "payload": {"id": transient_id, "cwd": "/tmp/private-project"},
                        },
                        {
                            "type": "response_item",
                            "payload": {
                                "type": "message",
                                "role": "assistant",
                                "content": "TODO: private transient marker",
                            },
                        },
                    )
                ),
                encoding="utf-8",
            )
            original_bounded_lines = adapter_module._bounded_lines
            mutated = False
            calls = 0

            def mutate_index_after_first_record(handle, *, max_chars=None):
                nonlocal calls, mutated
                calls += 1
                is_index_read = calls == 1
                for item in original_bounded_lines(handle, max_chars=max_chars):
                    yield item
                    if is_index_read and item[0] == 1 and not mutated:
                        index.write_text(
                            json.dumps(
                                {
                                    "id": "different-session",
                                    "updated_at": "2026-01-01T00:00:00Z",
                                }
                            )
                            + "\n",
                            encoding="utf-8",
                        )
                        mutated = True

            with mock.patch(
                "workledger.adapter._bounded_lines",
                side_effect=mutate_index_after_first_record,
            ):
                adapted = SessionAdapter(root).scan()

        self.assertTrue(mutated)
        self.assertEqual(adapted.stats.index_records, 0)
        self.assertEqual(adapted.stats.files_fully_scanned, 0)
        self.assertEqual(adapted.stats.metadata_only_files, 1)
        self.assertNotIn(
            "private transient marker",
            " ".join(record.text or "" for record in adapted.records),
        )
        self.assertIn("unreadable_index", {item.code for item in adapted.diagnostics})

    def test_adversarial_scalar_types_numbers_and_timestamps_are_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            records = (
                json.dumps(
                    {
                        "type": "session_meta",
                        "payload": {"id": "parser-session", "cwd": "/tmp/project"},
                    }
                )
                + "\n"
                + '{"type":"response_item","payload":{"type":"message","n":'
                + ("9" * 5_000)
                + "}}\n"
                + '{"type":[],"payload":{}}\n'
                + json.dumps(
                    {
                        "timestamp": "9999-12-31T23:59:59-23:59",
                        "type": "response_item",
                        "payload": {
                            "type": "message",
                            "role": "assistant",
                            "content": "TODO: retain a safe partial result.",
                        },
                    }
                )
                + "\n"
            )
            (sessions / "rollout.jsonl").write_text(records, encoding="utf-8")

            adapted = SessionAdapter(root).scan()

        self.assertEqual(adapted.stats.canonical_records, 2)
        self.assertGreaterEqual(adapted.stats.malformed_records, 1)
        self.assertIn("malformed_json", {item.code for item in adapted.diagnostics})
        self.assertTrue(any(record.timestamp is None for record in adapted.records))

    def test_large_integer_in_index_is_skipped_without_stopping_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            session_id = "indexed-session"
            (root / "session_index.jsonl").write_text(
                '{"id":"bad","n":' + ("9" * 5_000) + "}\n" + json.dumps({"id": session_id}) + "\n",
                encoding="utf-8",
            )
            (sessions / "rollout.jsonl").write_text(
                json.dumps(
                    {
                        "type": "session_meta",
                        "payload": {"id": session_id, "cwd": "/tmp/project"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            adapted = SessionAdapter(root).scan()

        self.assertEqual(adapted.stats.index_records, 1)
        self.assertEqual(adapted.stats.canonical_records, 1)
        self.assertIn("malformed_index_json", {item.code for item in adapted.diagnostics})

    def test_aggregate_record_budget_stops_scan_with_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            records = [
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "type": "session_meta",
                    "payload": {"id": "budget-session", "cwd": "/tmp/project"},
                },
                {
                    "timestamp": "2026-01-01T00:00:01Z",
                    "type": "response_item",
                    "payload": {"type": "message", "role": "assistant", "content": "TODO: later"},
                },
            ]
            (sessions / "rollout.jsonl").write_text(
                "".join(json.dumps(item) + "\n" for item in records),
                encoding="utf-8",
            )

            with mock.patch("workledger.adapter.MAX_SOURCE_RECORDS", 1):
                adapted = SessionAdapter(root).scan()

        self.assertEqual(adapted.stats.records_seen, 1)
        self.assertEqual(adapted.stats.canonical_records, 1)
        self.assertIn("source_record_budget_exceeded", {item.code for item in adapted.diagnostics})

    def test_discovery_entry_budget_bounds_directory_only_trees(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            (sessions / "a").mkdir(parents=True)
            (sessions / "b").mkdir()

            with mock.patch("workledger.adapter.MAX_DISCOVERY_ENTRIES", 1):
                adapted = SessionAdapter(root).scan()

        self.assertEqual(adapted.records, [])
        self.assertIn(
            "source_discovery_budget_exceeded",
            {item.code for item in adapted.diagnostics},
        )

    def test_discovery_depth_is_bounded_without_recursive_walking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nested = root / "sessions" / "one" / "two"
            nested.mkdir(parents=True)

            with mock.patch("workledger.adapter.MAX_DISCOVERY_DEPTH", 1):
                adapted = SessionAdapter(root).scan()

        self.assertIn(
            "source_discovery_depth_exceeded",
            {item.code for item in adapted.diagnostics},
        )

if __name__ == "__main__":
    unittest.main()
