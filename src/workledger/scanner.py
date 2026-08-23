"""Project grouping and read-only repository verification."""

from __future__ import annotations

import hashlib
import os
import re
import signal
import shutil
import stat
import subprocess
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from .adapter import CanonicalRecord, SessionAdapter
from .extract import ExtractionBudget, extract_findings
from .model import MAX_PROJECTS, MAX_TOTAL_FINDINGS, Diagnostic, ProjectLedger, ScanReport
from .redact import safe_project_name, safe_ref


MAX_GIT_REPOSITORIES = 1_000
MAX_GIT_PROBE_SECONDS = 30.0
GIT_COMMAND_TIMEOUT_SECONDS = 3.0
MAX_GIT_OUTPUT_BYTES = 4 * 1024
MAX_PATH_PROBE_OUTPUT_BYTES = 4 * 1024


@dataclass(frozen=True, slots=True)
class _RepositoryBinding:
    path: str
    identity: tuple[tuple[int, int, int, int], ...]


_GIT_DESCRIPTOR_EXEC_CODE = (
    "import os,sys; "
    "descriptor=int(sys.argv[1]); executable=sys.argv[2]; "
    "os.fchdir(descriptor); "
    "os.execve(executable, [executable, *sys.argv[3:]], os.environ)"
)
_PATH_PROBE_CODE = r"""
import os
import stat
import sys
from pathlib import Path

value = sys.argv[1]
candidate = Path(value)
if not candidate.is_absolute() or any(part in {".", ".."} for part in candidate.parts):
    raise SystemExit(2)
reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)

def unsafe(metadata):
    return stat.S_ISLNK(metadata.st_mode) or bool(
        reparse_flag and getattr(metadata, "st_file_attributes", 0) & reparse_flag
    )

current = Path(candidate.anchor)
for component in candidate.parts[1:]:
    current = current / component
    metadata = os.lstat(current)
    if unsafe(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise SystemExit(3)

cursor = candidate
while True:
    marker = cursor / ".git"
    try:
        metadata = os.lstat(marker)
    except FileNotFoundError:
        pass
    else:
        if unsafe(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise SystemExit(4)
        sys.stdout.write(str(cursor))
        raise SystemExit(0)
    parent = cursor.parent
    if parent == cursor:
        raise SystemExit(5)
    cursor = parent
"""


def resolve_source_root(root: Path | str | None = None) -> Path:
    return Path(root).expanduser() if root is not None else Path.home() / ".codex"


def scan(
    root: Path | str | None = None,
    *,
    probe_git: bool = False,
    include_unindexed: bool = False,
) -> ScanReport:
    """Scan local sessions in memory and return a privacy-preserving report."""

    source_root = resolve_source_root(root)
    adapted = SessionAdapter(source_root, include_unindexed=include_unindexed).scan()
    normalized_paths: dict[str | None, str | None] = {}
    git_roots: dict[str, _RepositoryBinding] = {}
    git_paths_considered = 0
    skipped_git_paths = 0
    git_deadline = time.monotonic() + MAX_GIT_PROBE_SECONDS if probe_git else None

    for record in adapted.records:
        path = record.project_path
        if path not in normalized_paths:
            repository_binding = None
            if probe_git and path:
                if (
                    git_paths_considered >= MAX_GIT_REPOSITORIES
                    or _git_timeout(git_deadline) is None
                ):
                    skipped_git_paths += 1
                else:
                    git_paths_considered += 1
                    repository_binding = _git_root(path, deadline=git_deadline)
            repository_root = repository_binding.path if repository_binding else None
            normalized_paths[path] = repository_root or path
            if repository_binding:
                git_roots.setdefault(repository_binding.path, repository_binding)
        record.project_path = normalized_paths[path]

    grouped: dict[str | None, list[CanonicalRecord]] = defaultdict(list)
    for record in adapted.records:
        grouped[record.project_path].append(record)

    diagnostics = list(adapted.diagnostics)
    if probe_git:
        selected_git_roots = [git_roots[path] for path in sorted(git_roots)]
        probed_git_roots = 0
        for binding in selected_git_roots:
            if _git_timeout(git_deadline) is None:
                break
            repository_record = _probe_repository(
                binding,
                order=len(adapted.records) + len(grouped) + 1,
                deadline=git_deadline,
            )
            probed_git_roots += 1
            if repository_record:
                grouped[binding.path].append(repository_record)
        unprobed = skipped_git_paths + len(selected_git_roots) - probed_git_roots
        if unprobed:
            diagnostics.append(
                Diagnostic(
                    code="git_probe_budget_exceeded",
                    count=unprobed,
                    severity="warning",
                    detail="Additional repository paths were not probed after the count or time safety limit was reached.",
                )
            )

    names = defaultdict(list)
    for project_path in grouped:
        names[safe_project_name(project_path)].append(project_path)

    project_groups = [
        (
            max((record.timestamp for record in records if record.timestamp), default=""),
            project_path,
            records,
        )
        for project_path, records in grouped.items()
    ]
    project_groups.sort(
        key=lambda item: (item[0], safe_project_name(item[1]).casefold()),
        reverse=True,
    )
    if len(project_groups) > MAX_PROJECTS:
        diagnostics.append(
            Diagnostic(
                code="project_budget_exceeded",
                count=len(project_groups) - MAX_PROJECTS,
                severity="warning",
                detail="Additional projects were skipped after the report safety limit was reached.",
            )
        )

    projects: list[ProjectLedger] = []
    finding_slots = MAX_TOTAL_FINDINGS
    extraction_budget = ExtractionBudget()
    for latest_activity, project_path, records in project_groups[:MAX_PROJECTS]:
        name = safe_project_name(project_path)
        key = _project_key(name, project_path, collision=len(names[name]) > 1)
        session_origins = {
            record.origin_key or record.session_ref
            for record in records
            if record.kind != "repository_state"
        }
        if not finding_slots:
            findings = []
        elif extraction_budget.remaining_candidates:
            findings = extract_findings(
                records,
                diagnostics=diagnostics,
                budget=extraction_budget,
            )
        else:
            findings = []
            if records and not any(item.code == "candidate_budget_exceeded" for item in diagnostics):
                diagnostics.append(
                    Diagnostic(
                        code="candidate_budget_exceeded",
                        count=1,
                        severity="warning",
                        detail="Additional finding candidates were skipped.",
                    )
                )
        report_budget_truncated = not finding_slots and bool(records)
        if len(findings) > finding_slots:
            findings = findings[:finding_slots]
            report_budget_truncated = True
        finding_slots -= len(findings)
        if report_budget_truncated and not any(
            item.code == "report_finding_budget_exceeded" for item in diagnostics
        ):
            diagnostics.append(
                Diagnostic(
                    code="report_finding_budget_exceeded",
                    count=1,
                    severity="warning",
                    detail="Additional project findings were skipped after the report safety limit was reached.",
                )
            )
        projects.append(
            ProjectLedger(
                name=name,
                key=key,
                session_count=len(session_origins),
                last_activity=latest_activity or None,
                findings=findings,
            )
        )

    projects.sort(key=lambda item: ((item.last_activity or ""), item.name.casefold()), reverse=True)
    if not projects and source_root.is_dir():
        diagnostics.append(
            Diagnostic(
                code="no_projects",
                count=1,
                severity="info",
                detail="No project-associated session records were found.",
            )
        )
    return ScanReport(projects=projects, stats=adapted.stats, diagnostics=diagnostics)


def _git_root(
    path: str | None,
    *,
    deadline: float | None = None,
) -> _RepositoryBinding | None:
    if not path:
        return None
    candidate = _local_directory(path)
    if candidate is None:
        return None
    repository = _validated_repository_root(candidate, deadline=deadline)
    if repository is None:
        return None
    binding = _bind_repository(repository)
    return binding


def _probe_repository(
    binding: _RepositoryBinding,
    *,
    order: int,
    deadline: float | None = None,
) -> CanonicalRecord | None:
    path = binding.path
    repository = Path(path)
    if not _repository_is_current(binding):
        return None
    branch = _git(
        repository,
        "branch",
        "--show-current",
        deadline=deadline,
        binding=binding,
    )
    if not _repository_is_current(binding):
        return None
    commit_hash = _git(
        repository,
        "rev-parse",
        "HEAD",
        deadline=deadline,
        binding=binding,
    )
    if not _repository_is_current(binding):
        return None
    if branch is None and commit_hash is None:
        return None
    return CanonicalRecord(
        session_ref=safe_ref(path, prefix="repo"),
        origin_key=hashlib.sha256(path.encode("utf-8", errors="surrogatepass")).hexdigest(),
        line=0,
        timestamp=None,
        kind="repository_state",
        project_path=path,
        metadata={
            "branch": branch.strip() if branch else None,
            "commit_hash": commit_hash.strip() if commit_hash else None,
            "clean": None,
        },
        order=order,
    )


def _git(
    repository: Path,
    *args: str,
    deadline: float | None = None,
    binding: _RepositoryBinding | None = None,
) -> str | None:
    timeout = _git_timeout(deadline)
    if timeout is None:
        return None
    directory_descriptor: int | None = None
    if binding is not None and os.name == "posix":
        directory_descriptor = _open_bound_git_directory(binding)
        if directory_descriptor is None:
            return None
    try:
        command = _git_command(
            repository,
            *args,
            directory_descriptor=directory_descriptor,
        )
        if command is None:
            return None
        encoded = _run_bounded_command(
            command,
            timeout=timeout,
            max_output_bytes=MAX_GIT_OUTPUT_BYTES,
            environment=_git_environment(),
            pass_fds=(directory_descriptor,) if directory_descriptor is not None else (),
        )
    finally:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
    if encoded is None:
        return None
    return encoded.decode("utf-8", errors="replace").rstrip("\n")


def _validated_repository_root(
    candidate: Path,
    *,
    deadline: float | None = None,
) -> Path | None:
    timeout = _git_timeout(deadline)
    if timeout is None:
        return None
    encoded = _run_bounded_command(
        [sys.executable, "-I", "-c", _PATH_PROBE_CODE, str(candidate)],
        timeout=timeout,
        max_output_bytes=MAX_PATH_PROBE_OUTPUT_BYTES,
        environment=_worker_environment(),
    )
    if encoded is None:
        return None
    try:
        value = encoded.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    return _local_directory(value)


def _bind_repository(repository: Path) -> _RepositoryBinding | None:
    identity = _repository_identity(repository)
    if identity is None:
        return None
    return _RepositoryBinding(path=str(repository), identity=identity)


def _repository_is_current(binding: _RepositoryBinding) -> bool:
    return _repository_identity(Path(binding.path)) == binding.identity


def _repository_identity(
    repository: Path,
) -> tuple[tuple[int, int, int, int], ...] | None:
    """Bind every repository path component and its Git directory by identity."""

    if not repository.is_absolute():
        return None
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    identities: list[tuple[int, int, int, int]] = []

    try:
        current = Path(repository.anchor)
        paths = [current]
        for component in repository.parts[1:]:
            current = current / component
            paths.append(current)
        paths.append(repository / ".git")
        for path in paths:
            metadata = os.lstat(path)
            identity = _directory_identity(metadata, reparse_flag=reparse_flag)
            if identity is None:
                return None
            identities.append(identity)
    except OSError:
        return None
    return tuple(identities)


def _directory_identity(
    metadata: os.stat_result,
    *,
    reparse_flag: int | None = None,
) -> tuple[int, int, int, int] | None:
    flag = (
        getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if reparse_flag is None
        else reparse_flag
    )
    reparse_attributes = (
        getattr(metadata, "st_file_attributes", 0) & flag if flag else 0
    )
    if (
        stat.S_ISLNK(metadata.st_mode)
        or reparse_attributes
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        return None
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        reparse_attributes,
    )


def _open_bound_git_directory(binding: _RepositoryBinding) -> int | None:
    """Open the validated Git directory relative to its bound repository descriptor."""

    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        return None
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    repository_descriptor = -1
    git_descriptor = -1
    try:
        repository_descriptor = os.open(binding.path, flags)
        if _directory_identity(os.fstat(repository_descriptor)) != binding.identity[-2]:
            return None
        git_descriptor = os.open(".git", flags, dir_fd=repository_descriptor)
        if _directory_identity(os.fstat(git_descriptor)) != binding.identity[-1]:
            return None
        result = git_descriptor
        git_descriptor = -1
        return result
    except OSError:
        return None
    finally:
        if git_descriptor >= 0:
            os.close(git_descriptor)
        if repository_descriptor >= 0:
            os.close(repository_descriptor)


def _run_bounded_command(
    command: list[str],
    *,
    timeout: float,
    max_output_bytes: int,
    environment: dict[str, str],
    pass_fds: tuple[int, ...] = (),
) -> bytes | None:
    process_options: dict[str, object] = {}
    if os.name == "posix":
        process_options["start_new_session"] = True
        if pass_fds:
            process_options["pass_fds"] = pass_fds
    elif pass_fds:
        return None
    elif hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
        process_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            **process_options,
        )
    except (OSError, UnicodeError):
        return None
    captured: list[bytes] = []

    def read_bounded_output() -> None:
        try:
            assert process.stdout is not None
            captured.append(process.stdout.read(max_output_bytes + 1))
        except OSError:
            captured.append(b"")

    reader = threading.Thread(target=read_bounded_output, daemon=True)
    reader.start()
    reader.join(timeout=timeout)
    try:
        if reader.is_alive():
            _stop_process(process)
            reader.join(timeout=0.5)
            return None
        if not captured or len(captured[0]) > max_output_bytes:
            _stop_process(process)
            return None
        try:
            if process.wait(timeout=0.2) != 0:
                return None
        except subprocess.TimeoutExpired:
            _stop_process(process)
            return None
        return captured[0]
    finally:
        if process.stdout is not None:
            process.stdout.close()


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=0.2)
            return
        except (OSError, subprocess.SubprocessError):
            try:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=0.2)
                return
            except (OSError, subprocess.SubprocessError):
                pass
    try:
        process.terminate()
        process.wait(timeout=0.2)
    except (OSError, subprocess.SubprocessError):
        try:
            process.kill()
            process.wait(timeout=0.2)
        except (OSError, subprocess.SubprocessError):
            pass


def _git_timeout(deadline: float | None) -> float | None:
    if deadline is None:
        return GIT_COMMAND_TIMEOUT_SECONDS
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    return min(GIT_COMMAND_TIMEOUT_SECONDS, remaining)


def _git_command(
    repository: Path,
    *args: str,
    directory_descriptor: int | None = None,
) -> list[str] | None:
    executable = shutil.which("git")
    if executable is None:
        return None
    git_arguments = [
        executable,
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "credential.helper=",
    ]
    if directory_descriptor is not None:
        return [
            sys.executable,
            "-I",
            "-c",
            _GIT_DESCRIPTOR_EXEC_CODE,
            str(directory_descriptor),
            *git_arguments,
            "--git-dir=.",
            *args,
        ]
    return [*git_arguments, "-C", str(repository), *args]


def _git_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _worker_environment() -> dict[str, str]:
    allowed = ("HOME", "LANG", "LC_ALL", "SYSTEMROOT", "TMP", "TEMP")
    return {key: os.environ[key] for key in allowed if key in os.environ}


def _local_directory(value: str) -> Path | None:
    """Apply only lexical checks; bounded workers perform all filesystem access."""

    if (
        not value
        or "\0" in value
        or value.startswith(("~", "//", "\\\\", "\\\\?\\", "\\\\.\\"))
    ):
        return None
    try:
        os.fsencode(value)
    except UnicodeEncodeError:
        return None
    candidate = Path(value)
    if not candidate.is_absolute() or any(part == ".." for part in candidate.parts):
        return None
    return candidate


def _project_key(name: str, path: str | None, *, collision: bool) -> str:
    slug = re.sub(r"[^a-z0-9가-힣]+", "-", name.casefold()).strip("-") or "unassigned"
    if not collision:
        return slug
    digest = hashlib.sha256((path or "").encode("utf-8", errors="replace")).hexdigest()[:6]
    return f"{slug}-{digest}"
