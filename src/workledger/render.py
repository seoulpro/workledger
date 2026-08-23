"""Deterministic terminal/Markdown rendering."""

from __future__ import annotations

import re

from .model import Finding, ProjectLedger, ScanReport


_MARKDOWN_META = re.compile(r"([\\`*_[\]<>#|&])")


def render_scan(report: ScanReport) -> str:
    sessions = sum(project.session_count for project in report.projects)
    unfinished = sum(len(project.unfinished) for project in report.projects)
    lines = [
        "# WorkLedger scan",
        "",
        f"Projects: {len(report.projects)} | Sessions: {sessions} | Unfinished: {unfinished}",
        f"Records: {report.stats.canonical_records} canonical / {report.stats.records_seen} read",
    ]
    if report.diagnostics:
        lines.extend(["", "## Source quality", ""])
        for diagnostic in report.diagnostics:
            detail = f" — {_markdown(diagnostic.detail)}" if diagnostic.detail else ""
            lines.append(
                f"- {diagnostic.severity}: {diagnostic.code} × "
                f"{diagnostic.count}{detail}"
            )
    lines.extend(["", "## Projects", ""])
    if not report.projects:
        lines.append("No projects found.")
    else:
        lines.extend(_project_rows(report.projects))
    return "\n".join(lines) + "\n"


def render_projects(report: ScanReport) -> str:
    lines = ["# Projects", ""]
    if not report.projects:
        lines.append("No projects found.")
    else:
        lines.extend(_project_rows(report.projects))
    return "\n".join(lines) + "\n"


def render_project(project: ProjectLedger) -> str:
    lines = [
        f"# {_markdown(project.name)}",
        "",
        f"Key: `{_code(project.key)}` | Sessions: {project.session_count} | "
        f"Last activity: {_markdown(project.last_activity or 'unknown')}",
    ]
    if not project.findings:
        lines.extend(["", "No findings."])
        return "\n".join(lines) + "\n"
    by_category: dict[str, list[Finding]] = {}
    for finding in project.findings:
        by_category.setdefault(finding.category.value, []).append(finding)
    for category, findings in by_category.items():
        lines.extend(["", f"## {category.title()}", ""])
        for finding in findings:
            lines.append(_finding_line(finding))
            for evidence in finding.evidence:
                observed = f" at {evidence.observed_at}" if evidence.observed_at else ""
                excerpt = f" — {_markdown(evidence.excerpt)}" if evidence.excerpt else ""
                lines.append(
                    f"  - `{_code(evidence.location)}`{_markdown(observed)} "
                    f"[{_markdown(evidence.kind)}]{excerpt}"
                )
    return "\n".join(lines) + "\n"


def render_unfinished(report: ScanReport) -> str:
    lines = ["# Unfinished work", ""]
    found = False
    for project in report.projects:
        if not project.unfinished:
            continue
        found = True
        lines.extend([f"## {_markdown(project.name)}", ""])
        lines.extend(_finding_line(finding) for finding in project.unfinished)
        lines.append("")
    if not found:
        lines.append("No unfinished findings.")
    return "\n".join(lines).rstrip() + "\n"


def _project_rows(projects: list[ProjectLedger]) -> list[str]:
    lines = ["| Project | Key | Sessions | Findings | Unfinished | Last activity |", "|---|---|---:|---:|---:|---|"]
    for project in projects:
        lines.append(
            f"| {_table_cell(project.name)} | `{_table_cell(_code(project.key))}` | "
            f"{project.session_count} | "
            f"{len(project.findings)} | {len(project.unfinished)} | "
            f"{_table_cell(project.last_activity or 'unknown')} |"
        )
    return lines


def _finding_line(finding: Finding) -> str:
    confidence = f"{round(finding.confidence * 100)}%"
    return (
        f"- **{_markdown(finding.status)}** ({confidence}, `{_code(finding.id)}`) — "
        f"{_markdown(finding.summary)}"
    )


def _markdown(value: str) -> str:
    return _MARKDOWN_META.sub(r"\\\1", value)


def _table_cell(value: str) -> str:
    return _markdown(value).replace("\r", " ").replace("\n", " ")


def _code(value: str) -> str:
    return value.replace("`", "ˋ").replace("\r", " ").replace("\n", " ")
