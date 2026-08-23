"""Command-line interface for WorkLedger."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .cache import CacheError, cache_supported, load_report, write_report
from .redact import redact
from .render import render_project, render_projects, render_scan, render_unfinished
from .scanner import resolve_source_root, scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workledger",
        description="Reconstruct project decisions and unfinished work from local Codex sessions.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    _add_common(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("scan", "scan sources and show source quality"),
        ("projects", "list reconstructed projects"),
        ("unfinished", "show open tasks, approvals, blockers, and deployments"),
    ):
        command = subparsers.add_parser(name, help=help_text)
        _add_common(command, suppress_defaults=True)
    project = subparsers.add_parser("project", help="show one project ledger")
    project.add_argument("name", help="project name or key")
    _add_common(project, suppress_defaults=True)
    return parser


def _add_common(parser: argparse.ArgumentParser, *, suppress_defaults: bool = False) -> None:
    default = argparse.SUPPRESS if suppress_defaults else None
    parser.add_argument(
        "--root",
        type=Path,
        default=default,
        help="session data root (default: the local Codex data directory)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS if suppress_defaults else False,
        help="emit machine-readable JSON",
    )
    git_probe = parser.add_mutually_exclusive_group()
    git_probe.add_argument(
        "--git-probe",
        dest="git_probe",
        action="store_true",
        default=argparse.SUPPRESS if suppress_defaults else False,
        help="opt in to hardened current Git state verification",
    )
    git_probe.add_argument(
        "--no-git-probe",
        dest="git_probe",
        action="store_false",
        default=argparse.SUPPRESS if suppress_defaults else False,
        help="disable Git state verification (the default; retained for compatibility)",
    )
    parser.add_argument(
        "--include-unindexed",
        action="store_true",
        default=argparse.SUPPRESS if suppress_defaults else False,
        help="fully scan rollout files absent from the session index",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        default=argparse.SUPPRESS if suppress_defaults else False,
        help="ignore a derived snapshot and scan source records again",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        default=argparse.SUPPRESS if suppress_defaults else False,
        help="do not read or write WorkLedger's derived snapshot",
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    source_root = resolve_source_root(args.root)
    probe_git = args.git_probe
    cache_available = cache_supported()
    cache_status = "disabled" if args.no_cache else ("refreshed" if cache_available else "unsupported")
    report = None
    if args.command != "scan" and not args.no_cache and not args.refresh and cache_available:
        cached = load_report(
            source_root,
            probe_git=probe_git,
            include_unindexed=args.include_unindexed,
        )
        report = cached.report
        cache_status = cached.status
        if cached.status == "invalid":
            print("Ignoring an invalid derived snapshot and rescanning.", file=sys.stderr)
    if report is None:
        report = scan(
            source_root,
            probe_git=probe_git,
            include_unindexed=args.include_unindexed,
        )
        source_has_errors = any(item.severity == "error" for item in report.diagnostics)
        if not args.no_cache and cache_available:
            if not source_root.is_dir() or source_has_errors:
                cache_status = "not_written"
            else:
                try:
                    write_report(
                        report,
                        source_root,
                        probe_git=probe_git,
                        include_unindexed=args.include_unindexed,
                    )
                except (OSError, CacheError):
                    cache_status = "write_failed"
                    print("Could not write the derived snapshot; results are still available.", file=sys.stderr)
                else:
                    cache_status = "refreshed"

    if args.command == "scan":
        payload = report.to_dict()
        payload["cache_status"] = cache_status
        rendered = render_scan(report)
    elif args.command == "projects":
        payload = {
            "schema_version": report.schema_version,
            "generated_at": report.generated_at,
            "cache_status": cache_status,
            "projects": [project.to_dict() for project in report.projects],
        }
        rendered = render_projects(report)
    elif args.command == "unfinished":
        projects = list(report.unfinished_projects())
        payload = {
            "schema_version": report.schema_version,
            "generated_at": report.generated_at,
            "cache_status": cache_status,
            "projects": [project.to_dict(unfinished_only=True) for project in projects],
        }
        rendered = render_unfinished(report)
    else:
        project = report.find_project(args.name)
        if project is None:
            error = {
                "error": "project_not_found_or_ambiguous",
                "query": redact(args.name),
                "available_keys": [item.key for item in report.projects],
            }
            if args.json:
                print(json.dumps(error, ensure_ascii=False, indent=2))
            else:
                print(f"Project not found or ambiguous: {redact(args.name)}", file=sys.stderr)
            return 1 if any(item.severity == "error" for item in report.diagnostics) else 2
        payload = {
            "schema_version": report.schema_version,
            "generated_at": report.generated_at,
            "cache_status": cache_status,
            "project": project.to_dict(),
        }
        rendered = render_project(project)

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        sys.stdout.write(rendered)
    return 1 if any(item.severity == "error" for item in report.diagnostics) else 0


if __name__ == "__main__":
    raise SystemExit(main())
