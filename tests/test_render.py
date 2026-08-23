from __future__ import annotations

import unittest

from workledger.model import Category, Finding, ProjectLedger, ScanReport, ScanStats
from workledger.render import render_project, render_projects


class RenderTests(unittest.TestCase):
    def test_dynamic_markdown_is_escaped(self) -> None:
        project = ProjectLedger(
            name="alpha|#*",
            key="alpha-`key`",
            session_count=1,
            last_activity="2026-01-01T00:00:00Z",
            findings=[
                Finding(
                    id="tas-1234567890",
                    category=Category.TASK,
                    status="open",
                    summary="[synthetic](https://example.invalid) *task*",
                    confidence=0.9,
                )
            ],
        )
        report = ScanReport(projects=[project], stats=ScanStats())

        detail = render_project(project)
        table = render_projects(report)

        self.assertIn(r"# alpha\|\#\*", detail)
        self.assertIn("`alpha-ˋkeyˋ`", detail)
        self.assertNotIn("`alpha-`key``", detail)
        self.assertIn(r"\[synthetic\](https://example.invalid) \*task\*", detail)
        self.assertIn(r"alpha\|\#\*", table)
        self.assertNotIn("| alpha|#* |", table)

    def test_character_references_cannot_recreate_bidi_controls(self) -> None:
        project = ProjectLedger(
            name="safe&#x202E;txt",
            key="safe",
            session_count=0,
            last_activity=None,
        )

        rendered = render_project(project)

        self.assertIn(r"safe\&\#x202E;txt", rendered)
        self.assertNotIn("# safe&#x202E;txt", rendered)

    def test_project_key_cannot_split_markdown_table_columns(self) -> None:
        project = ProjectLedger(
            name="safe",
            key="safe|999|999",
            session_count=1,
            last_activity=None,
        )

        rendered = render_projects(ScanReport(projects=[project], stats=ScanStats()))

        self.assertIn(r"`safe\|999\|999`", rendered)
        self.assertNotIn("`safe|999|999`", rendered)


if __name__ == "__main__":
    unittest.main()
