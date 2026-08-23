from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import workledger.scanner as scanner_module
from workledger.model import Category
from workledger.scanner import (
    _git,
    _git_root,
    _local_directory,
    _validated_repository_root,
    scan,
)


@unittest.skipUnless(shutil.which("git"), "Git is required for repository probe tests")
class RepositoryProbeTests(unittest.TestCase):
    def test_probe_verifies_head_without_changing_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = (root / "sample-project").resolve()
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

            default_report = scan(root / "source")
            report = scan(root / "source", probe_git=True)

            after = self.run_git(repository, "status", "--porcelain=v1")
            project = report.find_project("sample-project")
            assert project is not None
            statuses = {(finding.category, finding.status) for finding in project.findings}
            default_project = default_report.find_project("sample-project")
            assert default_project is not None
            default_statuses = {
                (finding.category, finding.status) for finding in default_project.findings
            }
            self.assertEqual(before, after)
            self.assertNotIn((Category.BRANCH, "current"), default_statuses)
            self.assertIn((Category.BRANCH, "current"), statuses)
            self.assertIn((Category.COMMIT, "verified"), statuses)
            self.assertNotIn(str(repository), str(report.to_dict()))

            (repository / "untracked.txt").write_text("new\n", encoding="utf-8")
            unknown_report = scan(root / "source", probe_git=True)
            unknown_project = unknown_report.find_project("sample-project")
            assert unknown_project is not None
            self.assertIn(
                "cleanliness unknown",
                " ".join(finding.summary for finding in unknown_project.findings),
            )

    def test_probe_rejects_relative_and_network_style_paths(self) -> None:
        with mock.patch("workledger.scanner._git", side_effect=AssertionError("Git must not run")):
            self.assertIsNone(_git_root("."))
            self.assertIsNone(_git_root("//server/share"))
            self.assertIsNone(_git_root(r"\\server\share"))

    def test_path_preflight_is_lexical_and_rejects_tilde_lookup(self) -> None:
        absolute = Path(Path.cwd().anchor) / "synthetic-project"
        with mock.patch.object(
            Path,
            "is_dir",
            side_effect=AssertionError("path preflight must not perform filesystem I/O"),
        ):
            self.assertEqual(_local_directory(str(absolute)), absolute)
            self.assertIsNone(_local_directory("~other/project"))

    def test_unencodable_surrogate_path_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            unsafe_path = "/tmp/synthetic-\ud800"
            (sessions / "rollout.jsonl").write_text(
                json.dumps(
                    {
                        "type": "session_meta",
                        "payload": {"id": "surrogate-session", "cwd": unsafe_path},
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            report = scan(root, probe_git=True)

        self.assertIsNone(_local_directory(unsafe_path))
        self.assertEqual(len(report.projects), 1)

    @unittest.skipUnless(os.name == "posix", "surrogate-escaped paths are POSIX-specific")
    def test_surrogateescaped_byte_path_remains_lexically_valid(self) -> None:
        value = "/tmp/synthetic-\udc80"

        self.assertEqual(_local_directory(value), Path(value))

    @unittest.skipUnless(os.name == "posix", "symbolic-link semantics are POSIX-specific")
    def test_probe_rejects_symlinked_paths_and_gitfile_redirection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repository = root / "repository"
            repository.mkdir()
            self.run_git(repository, "init", "-q", "-b", "main")
            linked = root / "linked"
            linked.symlink_to(repository, target_is_directory=True)
            redirected = root / "redirected"
            redirected.mkdir()
            (redirected / ".git").write_text(
                f"gitdir: {repository / '.git'}\n",
                encoding="utf-8",
            )

            with mock.patch(
                "workledger.scanner._git",
                side_effect=AssertionError("Git must not inspect an unsafe path"),
            ):
                self.assertIsNone(_git_root(str(linked)))
                self.assertIsNone(_git_root(str(redirected)))

    @unittest.skipUnless(os.name == "posix", "repository replacement uses POSIX symlinks")
    def test_probe_discards_repository_replaced_after_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repository = root / "preflight-project"
            replacement = root / "replacement-project"
            parked = root / "parked-project"
            for path, branch in (
                (repository, "preflight-main"),
                (replacement, "replacement-secret"),
            ):
                path.mkdir()
                self.run_git(path, "init", "-q", "-b", branch)
                (path / "sample.txt").write_text(branch + "\n", encoding="utf-8")
                self.run_git(path, "add", "sample.txt")
                self.run_git(path, "commit", "-q", "-m", "Add synthetic sample")

            source = root / "source" / "sessions"
            source.mkdir(parents=True)
            (source / "rollout.jsonl").write_text(
                json.dumps(
                    {
                        "type": "session_meta",
                        "payload": {
                            "id": "replacement-race-session",
                            "cwd": str(repository),
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            real_git_root = scanner_module._git_root
            replaced = False

            def replace_after_preflight(path: str | None, *, deadline=None):
                nonlocal replaced
                result = real_git_root(path, deadline=deadline)
                if result is not None and not replaced:
                    repository.rename(parked)
                    repository.symlink_to(replacement, target_is_directory=True)
                    replaced = True
                return result

            with mock.patch(
                "workledger.scanner._git_root",
                side_effect=replace_after_preflight,
            ):
                report = scan(root / "source", probe_git=True)

        self.assertTrue(replaced)
        project = report.find_project("preflight-project")
        assert project is not None
        self.assertNotIn(
            "replacement-secret",
            " ".join(finding.summary for finding in project.findings),
        )
        self.assertNotIn(
            (Category.BRANCH, "current"),
            {(finding.category, finding.status) for finding in project.findings},
        )

    @unittest.skipUnless(os.name == "posix", "descriptor-bound probing is POSIX-specific")
    def test_probe_stays_bound_during_transient_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repository = root / "bound-project"
            replacement = root / "replacement-project"
            parked = root / "parked-project"
            for path, branch in (
                (repository, "bound-main"),
                (replacement, "replacement-secret"),
            ):
                path.mkdir()
                self.run_git(path, "init", "-q", "-b", branch)
                (path / "sample.txt").write_text(branch + "\n", encoding="utf-8")
                self.run_git(path, "add", "sample.txt")
                self.run_git(path, "commit", "-q", "-m", "Add synthetic sample")

            binding = scanner_module._git_root(str(repository))
            assert binding is not None
            real_run = scanner_module._run_bounded_command
            replaced = False

            def replace_only_while_git_runs(command, **kwargs):
                nonlocal replaced
                if not replaced and "--git-dir=." in command:
                    repository.rename(parked)
                    repository.symlink_to(replacement, target_is_directory=True)
                    replaced = True
                    try:
                        return real_run(command, **kwargs)
                    finally:
                        repository.unlink()
                        parked.rename(repository)
                return real_run(command, **kwargs)

            with mock.patch(
                "workledger.scanner._run_bounded_command",
                side_effect=replace_only_while_git_runs,
            ):
                record = scanner_module._probe_repository(binding, order=1)

        self.assertTrue(replaced)
        assert record is not None
        self.assertEqual(record.metadata["branch"], "bound-main")
        self.assertNotEqual(record.metadata["branch"], "replacement-secret")

    def test_root_resolution_obeys_the_repository_count_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            for index in range(2):
                (sessions / f"rollout-{index}.jsonl").write_text(
                    json.dumps(
                        {
                            "type": "session_meta",
                            "payload": {
                                "id": f"budget-session-{index}",
                                "cwd": f"/tmp/project-{index}",
                            },
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )

            with (
                mock.patch("workledger.scanner.MAX_GIT_REPOSITORIES", 1),
                mock.patch("workledger.scanner._git_root", return_value=None) as git_root,
            ):
                report = scan(root, probe_git=True)

        self.assertEqual(git_root.call_count, 1)
        diagnostic = next(
            item for item in report.diagnostics if item.code == "git_probe_budget_exceeded"
        )
        self.assertEqual(diagnostic.count, 1)

    def test_expired_aggregate_deadline_does_not_launch_git(self) -> None:
        with mock.patch("workledger.scanner.subprocess.Popen") as popen:
            self.assertIsNone(_git(Path("/tmp"), "rev-parse", "HEAD", deadline=0.0))

        popen.assert_not_called()

    def test_non_utf8_path_worker_output_fails_closed(self) -> None:
        with mock.patch(
            "workledger.scanner._run_bounded_command",
            return_value=b"/tmp/repository-\xff",
        ):
            repository = _validated_repository_root(Path("/tmp"))

        self.assertIsNone(repository)

    @unittest.skipUnless(os.name == "posix", "synthetic executable is POSIX-specific")
    def test_git_output_is_rejected_at_the_byte_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "synthetic-git"
            executable.write_text(
                "#!/bin/sh\nprintf '%064d' 0\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            with (
                mock.patch("workledger.scanner.shutil.which", return_value=str(executable)),
                mock.patch("workledger.scanner.MAX_GIT_OUTPUT_BYTES", 32),
            ):
                output = _git(Path("/tmp"), "rev-parse", "HEAD")

        self.assertIsNone(output)

    @unittest.skipUnless(os.name == "posix", "executable fsmonitor hooks are POSIX-specific")
    def test_probe_disables_repository_fsmonitor_hook(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = (root / "hooked-project").resolve()
            repository.mkdir()
            self.run_git(repository, "init", "-q", "-b", "main")
            (repository / "sample.txt").write_text("synthetic\n", encoding="utf-8")
            self.run_git(repository, "add", "sample.txt")
            self.run_git(repository, "commit", "-q", "-m", "Add synthetic sample")
            marker = root / "hook-ran"
            hook = root / "fsmonitor-hook"
            hook.write_text(
                "#!/bin/sh\n"
                f"printf ran > '{marker}'\n"
                "printf '{}\n'\n",
                encoding="utf-8",
            )
            hook.chmod(0o700)
            self.run_git(repository, "config", "core.fsmonitor", str(hook))

            source = root / "source" / "sessions"
            source.mkdir(parents=True)
            record = {
                "timestamp": "2026-01-01T00:00:00Z",
                "type": "session_meta",
                "payload": {"id": "synthetic-hook-session", "cwd": str(repository)},
            }
            (source / "rollout.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")

            report = scan(root / "source", probe_git=True)

            self.assertIsNotNone(report.find_project("hooked-project"))
            self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "posix", "executable filters are POSIX-specific")
    def test_probe_never_runs_repository_content_filters(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = (root / "filtered-project").resolve()
            repository.mkdir()
            self.run_git(repository, "init", "-q", "-b", "main")
            (repository / "sample.txt").write_text("synthetic\n", encoding="utf-8")
            self.run_git(repository, "add", "sample.txt")
            self.run_git(repository, "commit", "-q", "-m", "Add synthetic sample")
            marker = root / "filter-ran"
            filter_command = root / "content-filter"
            filter_command.write_text(
                "#!/bin/sh\n"
                f"printf ran > '{marker}'\n"
                "cat\n",
                encoding="utf-8",
            )
            filter_command.chmod(0o700)
            (repository / ".gitattributes").write_text("sample.txt filter=unsafe\n", encoding="utf-8")
            self.run_git(repository, "config", "filter.unsafe.clean", str(filter_command))
            (repository / "sample.txt").write_text("changed\n", encoding="utf-8")

            source = root / "source" / "sessions"
            source.mkdir(parents=True)
            record = {
                "timestamp": "2026-01-01T00:00:00Z",
                "type": "session_meta",
                "payload": {"id": "synthetic-filter-session", "cwd": str(repository)},
            }
            (source / "rollout.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")

            report = scan(root / "source", probe_git=True)

            self.assertIsNotNone(report.find_project("filtered-project"))
            self.assertFalse(marker.exists())

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
