from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from workledger.model import Category
from workledger.scanner import scan


@unittest.skipUnless(shutil.which("git"), "Git is required for repository probe tests")
class RepositoryProbeTests(unittest.TestCase):
    def test_probe_verifies_head_without_changing_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "sample-project"
            repository.mkdir()
            self.run_git(repository, "init", "-q", "-b", "main")
            (repository / "sample.txt").write_text("synthetic\n", encoding="utf-8")
            self.run_git(repository, "add", "sample.txt")
            self.run_git(repository, "commit", "-q", "-m", "Add synthetic sample")

            source = root / "source" / "sessions"
            source.mkdir(parents=True)
            record = {
                "timestamp": "2026-01-01T00:00:00Z",
                "type": "session_meta",
                "payload": {"id": "synthetic-probe-session", "cwd": str(repository)},
            }
            (source / "rollout.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
            before = self.run_git(repository, "status", "--porcelain=v1")

            report = scan(root / "source")

            after = self.run_git(repository, "status", "--porcelain=v1")
            project = report.find_project("sample-project")
            assert project is not None
            statuses = {(finding.category, finding.status) for finding in project.findings}
            self.assertEqual(before, after)
            self.assertIn((Category.BRANCH, "current"), statuses)
            self.assertIn((Category.COMMIT, "verified"), statuses)
            self.assertNotIn(str(repository), str(report.to_dict()))

    @staticmethod
    def run_git(repository: Path, *args: str) -> str:
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_AUTHOR_NAME": "Synthetic Author",
                "GIT_AUTHOR_EMAIL": "author@example.invalid",
                "GIT_COMMITTER_NAME": "Synthetic Author",
                "GIT_COMMITTER_EMAIL": "author@example.invalid",
            }
        )
        result = subprocess.run(
            ["git", "-C", str(repository), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
        return result.stdout.strip()


if __name__ == "__main__":
    unittest.main()
