"""Project grouping and read-only repository verification."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from collections import defaultdict
from pathlib import Path

from .adapter import CanonicalRecord, SessionAdapter
from .extract import extract_findings
from .model import Diagnostic, ProjectLedger, ScanReport
from .redact import safe_project_name, safe_ref


def resolve_source_root(root: Path | str | None = None) -> Path:
    return Path(root).expanduser() if root is not None else Path.home() / ".codex"


def scan(
    root: Path | str | None = None,
    *,
    probe_git: bool = True,
    include_unindexed: bool = False,
) -> ScanReport:
    """Scan local sessions in memory and return a privacy-preserving report."""

    source_root = resolve_source_root(root)
    adapted = SessionAdapter(source_root, include_unindexed=include_unindexed).scan()
    normalized_paths: dict[str | None, str | None] = {}
    git_roots: set[str] = set()

    for record in adapted.records:
        path = record.project_path
        if path not in normalized_paths:
            repository_root = _git_root(path) if probe_git else None
            normalized_paths[path] = repository_root or path
            if repository_root:
                git_roots.add(repository_root)
        record.project_path = normalized_paths[path]

    grouped: dict[str | None, list[CanonicalRecord]] = defaultdict(list)
    for record in adapted.records:
        grouped[record.project_path].append(record)

    if probe_git:
        for path in sorted(git_roots):
            repository_record = _probe_repository(path, order=len(adapted.records) + len(grouped) + 1)
            if repository_record:
                grouped[path].append(repository_record)

    names = defaultdict(list)
    for project_path in grouped:
        names[safe_project_name(project_path)].append(project_path)

    projects: list[ProjectLedger] = []
    for project_path, records in grouped.items():
        name = safe_project_name(project_path)
        key = _project_key(name, project_path, collision=len(names[name]) > 1)
        session_refs = {record.session_ref for record in records if record.kind != "repository_state"}
        timestamps = [record.timestamp for record in records if record.timestamp]
        projects.append(
            ProjectLedger(
                name=name,
                key=key,
                session_count=len(session_refs),
                last_activity=max(timestamps) if timestamps else None,
                findings=extract_findings(records),
            )
        )

    projects.sort(key=lambda item: ((item.last_activity or ""), item.name.casefold()), reverse=True)
    diagnostics = list(adapted.diagnostics)
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


def _git_root(path: str | None) -> str | None:
    if not path:
        return None
    candidate = Path(path).expanduser()
    if not candidate.is_dir():
        return None
    result = _git(candidate, "rev-parse", "--show-toplevel")
    if result is None:
        return None
    value = result.strip()
    return value if value else None


def _probe_repository(path: str, *, order: int) -> CanonicalRecord | None:
    repository = Path(path)
    branch = _git(repository, "branch", "--show-current")
    commit_hash = _git(repository, "rev-parse", "HEAD")
    status = _git(repository, "status", "--porcelain=v1", "--untracked-files=normal")
    if branch is None and commit_hash is None and status is None:
        return None
    return CanonicalRecord(
        session_ref=safe_ref(path, prefix="repo"),
        line=0,
        timestamp=None,
        kind="repository_state",
        project_path=path,
        metadata={
            "branch": branch.strip() if branch else None,
            "commit_hash": commit_hash.strip() if commit_hash else None,
            "clean": status == "" if status is not None else None,
        },
        order=order,
    )


def _git(repository: Path, *args: str) -> str | None:
    environment = os.environ.copy()
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.rstrip("\n") if result.returncode == 0 else None


def _project_key(name: str, path: str | None, *, collision: bool) -> str:
    slug = re.sub(r"[^a-z0-9가-힣]+", "-", name.casefold()).strip("-") or "unassigned"
    if not collision:
        return slug
    digest = hashlib.sha256((path or "").encode("utf-8", errors="replace")).hexdigest()[:6]
    return f"{slug}-{digest}"
