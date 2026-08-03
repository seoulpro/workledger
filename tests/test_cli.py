from __future__ import annotations

import contextlib
import io
import json
import unittest
from pathlib import Path

from workledger.cli import main


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "mixed"


class CliTests(unittest.TestCase):
    def invoke(self, *arguments: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = main([*arguments, "--root", str(FIXTURE_ROOT), "--no-git-probe", "--no-cache"])
        return result, stdout.getvalue(), stderr.getvalue()

    def test_scan_markdown(self) -> None:
        result, output, error = self.invoke("scan")

        self.assertEqual(result, 0)
        self.assertEqual(error, "")
        self.assertIn("# WorkLedger scan", output)
        self.assertIn("malformed_json", output)

    def test_projects_json(self) -> None:
        result, output, _ = self.invoke("projects", "--json")
        payload = json.loads(output)

        self.assertEqual(result, 0)
        self.assertEqual({item["name"] for item in payload["projects"]}, {"alpha", "legacy"})

    def test_project_command(self) -> None:
        result, output, _ = self.invoke("project", "alpha")

        self.assertEqual(result, 0)
        self.assertIn("# alpha", output)
        self.assertIn("## Decision", output)
        self.assertIn("confidence", json.dumps({"confidence": 0.9}))

    def test_unfinished_json_contains_only_open_states(self) -> None:
        result, output, _ = self.invoke("unfinished", "--json")
        payload = json.loads(output)
        findings = [finding for project in payload["projects"] for finding in project["findings"]]

        self.assertEqual(result, 0)
        self.assertTrue(findings)
        self.assertNotIn("granted", {item["status"] for item in findings})
        self.assertNotIn("resolved", {item["status"] for item in findings})

    def test_unknown_project_returns_two(self) -> None:
        result, _, error = self.invoke("project", "missing")

        self.assertEqual(result, 2)
        self.assertIn("Project not found", error)


if __name__ == "__main__":
    unittest.main()
