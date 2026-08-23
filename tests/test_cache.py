from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from workledger.cache import CacheError, cache_path, load_report, write_report
from workledger.cli import main
from workledger.scanner import scan


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "mixed"


@unittest.skipUnless(os.name == "posix", "secure snapshots currently require POSIX descriptors")
class CacheTests(unittest.TestCase):
    def test_round_trip_contains_only_derived_report(self) -> None:
        report = scan(FIXTURE_ROOT, probe_git=False)
        with tempfile.TemporaryDirectory() as temporary:
            state_home = Path(temporary)
            path = write_report(
                report,
                FIXTURE_ROOT,
                probe_git=False,
                include_unindexed=False,
                state_home=state_home,
            )
            loaded = load_report(
                FIXTURE_ROOT,
                probe_git=False,
                include_unindexed=False,
                state_home=state_home,
            )
            serialized = path.read_text(encoding="utf-8")

            self.assertEqual(loaded.status, "hit")
            assert loaded.report is not None
            self.assertEqual(loaded.report.to_dict(), report.to_dict())
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(str(FIXTURE_ROOT.resolve()), serialized)
            self.assertNotIn("thread_name", serialized)
            self.assertNotIn("/home/example", serialized)

    def test_invalid_cache_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_home = Path(temporary)
            path = cache_path(
                FIXTURE_ROOT,
                probe_git=False,
                include_unindexed=False,
                state_home=state_home,
            )
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("not json\n", encoding="utf-8")

            loaded = load_report(
                FIXTURE_ROOT,
                probe_git=False,
                include_unindexed=False,
                state_home=state_home,
            )

        self.assertEqual(loaded.status, "invalid")
        self.assertIsNone(loaded.report)

    @unittest.skipUnless(os.name == "posix", "permission bits are POSIX-specific")
    def test_cache_with_broad_permissions_is_rejected(self) -> None:
        report = scan(FIXTURE_ROOT, probe_git=False)
        with tempfile.TemporaryDirectory() as temporary:
            state_home = Path(temporary)
            path = write_report(
                report,
                FIXTURE_ROOT,
                probe_git=False,
                include_unindexed=False,
                state_home=state_home,
            )
            path.chmod(0o644)

            loaded = load_report(
                FIXTURE_ROOT,
                probe_git=False,
                include_unindexed=False,
                state_home=state_home,
            )

        self.assertEqual(loaded.status, "invalid")

    def test_cache_cannot_be_written_inside_source(self) -> None:
        report = scan(FIXTURE_ROOT, probe_git=False)

        with self.assertRaises(CacheError):
            write_report(
                report,
                FIXTURE_ROOT,
                probe_git=False,
                include_unindexed=False,
                state_home=FIXTURE_ROOT / "derived-state",
            )

    def test_cache_inside_source_is_rejected_on_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            sessions = source / "sessions"
            sessions.mkdir(parents=True)
            (sessions / "rollout.jsonl").write_text(
                json.dumps(
                    {
                        "type": "session_meta",
                        "payload": {"id": "cache-source-session", "cwd": "/tmp/project"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            report = scan(source, probe_git=False)
            external_state = root / "external-state"
            valid_path = write_report(
                report,
                source,
                probe_git=False,
                include_unindexed=False,
                state_home=external_state,
            )
            in_source_state = source / "derived-state"
            in_source_state.mkdir()
            crafted_path = cache_path(
                source,
                probe_git=False,
                include_unindexed=False,
                state_home=in_source_state,
            )
            crafted_path.write_bytes(valid_path.read_bytes())
            crafted_path.chmod(0o600)

            loaded = load_report(
                source,
                probe_git=False,
                include_unindexed=False,
                state_home=in_source_state,
            )

        self.assertEqual(loaded.status, "invalid")
        self.assertIsNone(loaded.report)

    def test_case_alias_of_source_cannot_hold_a_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            sessions = source / "sessions"
            sessions.mkdir(parents=True)
            (sessions / "rollout.jsonl").write_text(
                json.dumps(
                    {
                        "type": "session_meta",
                        "payload": {"id": "case-alias-session", "cwd": "/tmp/project"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            source_alias = root / "SOURCE"
            try:
                aliases_source = source_alias.exists() and os.path.samefile(source, source_alias)
            except OSError:
                aliases_source = False
            if not aliases_source:
                self.skipTest("filesystem is case-sensitive")

            report = scan(source, probe_git=False)
            state_alias = source_alias / "derived-state"
            with self.assertRaises(CacheError):
                write_report(
                    report,
                    source,
                    probe_git=False,
                    include_unindexed=False,
                    state_home=state_alias,
                )

            valid_path = write_report(
                report,
                source,
                probe_git=False,
                include_unindexed=False,
                state_home=root / "external-state",
            )
            (source / "derived-state").mkdir()
            crafted_path = cache_path(
                source,
                probe_git=False,
                include_unindexed=False,
                state_home=state_alias,
            )
            crafted_path.write_bytes(valid_path.read_bytes())
            crafted_path.chmod(0o600)

            loaded = load_report(
                source,
                probe_git=False,
                include_unindexed=False,
                state_home=state_alias,
            )

        self.assertEqual(loaded.status, "invalid")
        self.assertIsNone(loaded.report)

    def test_oversized_derived_snapshot_is_not_published(self) -> None:
        report = scan(FIXTURE_ROOT, probe_git=False)
        with tempfile.TemporaryDirectory() as temporary:
            state_home = Path(temporary)
            expected = cache_path(
                FIXTURE_ROOT,
                probe_git=False,
                include_unindexed=False,
                state_home=state_home,
            )
            with mock.patch("workledger.cache.MAX_CACHE_BYTES", 100):
                with self.assertRaises(CacheError):
                    write_report(
                        report,
                        FIXTURE_ROOT,
                        probe_git=False,
                        include_unindexed=False,
                        state_home=state_home,
                    )

            self.assertFalse(expected.exists())

    def test_deeply_nested_cache_is_rejected_before_model_loading(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_home = Path(temporary)
            path = cache_path(
                FIXTURE_ROOT,
                probe_git=False,
                include_unindexed=False,
                state_home=state_home,
            )
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("[" * 65 + "]" * 65, encoding="utf-8")
            path.chmod(0o600)

            loaded = load_report(
                FIXTURE_ROOT,
                probe_git=False,
                include_unindexed=False,
                state_home=state_home,
            )

        self.assertEqual(loaded.status, "invalid")
        self.assertIsNone(loaded.report)

    def test_flat_cache_token_budget_is_checked_before_json_materialization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_home = Path(temporary)
            path = cache_path(
                FIXTURE_ROOT,
                probe_git=False,
                include_unindexed=False,
                state_home=state_home,
            )
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("[" + ",".join("0" for _ in range(20)) + "]", encoding="utf-8")
            path.chmod(0o600)

            with (
                mock.patch("workledger.cache.MAX_CACHE_TOKENS", 10),
                mock.patch(
                    "workledger.cache.json.loads",
                    side_effect=AssertionError("JSON must not be materialized"),
                ),
            ):
                loaded = load_report(
                    FIXTURE_ROOT,
                    probe_git=False,
                    include_unindexed=False,
                    state_home=state_home,
                )

        self.assertEqual(loaded.status, "invalid")

    def test_huge_cache_number_is_rejected_safely(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_home = Path(temporary)
            path = cache_path(
                FIXTURE_ROOT,
                probe_git=False,
                include_unindexed=False,
                state_home=state_home,
            )
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"number":' + ("9" * 5_000) + "}", encoding="utf-8")
            path.chmod(0o600)

            loaded = load_report(
                FIXTURE_ROOT,
                probe_git=False,
                include_unindexed=False,
                state_home=state_home,
            )

        self.assertEqual(loaded.status, "invalid")
        self.assertIsNone(loaded.report)

    @unittest.skipUnless(os.name == "posix", "descriptor-relative creation is POSIX-specific")
    def test_nested_state_directory_is_created_without_path_based_mkdir(self) -> None:
        report = scan(FIXTURE_ROOT, probe_git=False)
        with tempfile.TemporaryDirectory() as temporary:
            state_home = Path(temporary) / "nested" / "state"
            with mock.patch.object(
                Path,
                "mkdir",
                side_effect=AssertionError("path-based directory creation is unsafe"),
            ):
                path = write_report(
                    report,
                    FIXTURE_ROOT,
                    probe_git=False,
                    include_unindexed=False,
                    state_home=state_home,
                )

            self.assertTrue(path.is_file())

    def test_cache_cardinality_and_scalar_types_are_validated(self) -> None:
        report = scan(FIXTURE_ROOT, probe_git=False)
        with tempfile.TemporaryDirectory() as temporary:
            state_home = Path(temporary)
            path = write_report(
                report,
                FIXTURE_ROOT,
                probe_git=False,
                include_unindexed=False,
                state_home=state_home,
            )
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["report"]["diagnostics"] = [
                {"code": "synthetic", "count": 1, "severity": "warning"}
            ] * 1_001
            path.write_text(json.dumps(payload), encoding="utf-8")
            path.chmod(0o600)

            cardinality = load_report(
                FIXTURE_ROOT,
                probe_git=False,
                include_unindexed=False,
                state_home=state_home,
            )

            payload["report"]["diagnostics"] = []
            payload["report"]["stats"]["files_seen"] = True
            path.write_text(json.dumps(payload), encoding="utf-8")
            path.chmod(0o600)
            scalar = load_report(
                FIXTURE_ROOT,
                probe_git=False,
                include_unindexed=False,
                state_home=state_home,
            )

        self.assertEqual(cardinality.status, "invalid")
        self.assertEqual(scalar.status, "invalid")

    @unittest.skipUnless(os.name == "posix", "symbolic-link semantics are POSIX-specific")
    def test_cache_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_home = Path(temporary) / "state"
            state_home.mkdir()
            path = cache_path(
                FIXTURE_ROOT,
                probe_git=False,
                include_unindexed=False,
                state_home=state_home,
            )
            target = Path(temporary) / "target.json"
            target.write_text("{}", encoding="utf-8")
            target.chmod(0o600)
            path.symlink_to(target)

            loaded = load_report(
                FIXTURE_ROOT,
                probe_git=False,
                include_unindexed=False,
                state_home=state_home,
            )

        self.assertEqual(loaded.status, "invalid")

    def test_replaced_cache_inode_is_rejected_after_open(self) -> None:
        report = scan(FIXTURE_ROOT, probe_git=False)
        with tempfile.TemporaryDirectory() as temporary:
            state_home = Path(temporary)
            write_report(
                report,
                FIXTURE_ROOT,
                probe_git=False,
                include_unindexed=False,
                state_home=state_home,
            )
            with mock.patch("workledger.cache._same_file", return_value=False):
                loaded = load_report(
                    FIXTURE_ROOT,
                    probe_git=False,
                    include_unindexed=False,
                    state_home=state_home,
                )

        self.assertEqual(loaded.status, "invalid")

    def test_query_command_reuses_scan_snapshot_without_touching_source(self) -> None:
        before = self.fixture_hashes()
        with tempfile.TemporaryDirectory() as temporary:
            environment = {"WORKLEDGER_STATE_HOME": temporary}
            with mock.patch.dict(os.environ, environment, clear=False):
                first_stdout = io.StringIO()
                with contextlib.redirect_stdout(first_stdout):
                    first_result = main(
                        ["scan", "--root", str(FIXTURE_ROOT), "--no-git-probe", "--json"]
                    )
                with mock.patch("workledger.cli.scan", side_effect=AssertionError("unexpected rescan")):
                    second_stdout = io.StringIO()
                    with contextlib.redirect_stdout(second_stdout):
                        second_result = main(
                            ["projects", "--root", str(FIXTURE_ROOT), "--no-git-probe", "--json"]
                        )

            second_payload = json.loads(second_stdout.getvalue())

        self.assertEqual(first_result, 0)
        self.assertEqual(second_result, 0)
        self.assertEqual(second_payload["cache_status"], "hit")
        self.assertEqual(before, self.fixture_hashes())

    @staticmethod
    def fixture_hashes() -> dict[str, str]:
        return {
            str(path.relative_to(FIXTURE_ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in FIXTURE_ROOT.rglob("*")
            if path.is_file()
        }


if __name__ == "__main__":
    unittest.main()
