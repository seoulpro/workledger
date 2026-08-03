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
