#!/usr/bin/env python3
"""Evaluate exact findings on the repository's synthetic labeled fixture."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / "src"))

from workledger.scanner import scan  # noqa: E402


DEFAULT_ROOT = REPOSITORY / "tests" / "fixtures" / "mixed"
DEFAULT_EXPECTATIONS = DEFAULT_ROOT / "expected_findings.json"


def evaluate(root: Path, expectations_path: Path) -> dict[str, Any]:
    with expectations_path.open("r", encoding="utf-8") as handle:
        expected_payload = json.load(handle)
    expected = _expected_labels(expected_payload)
    report = scan(root, probe_git=False, include_unindexed=True)
    actual = {
        (project.name, finding.category.value, finding.status, finding.summary)
        for project in report.projects
        for finding in project.findings
    }
    true_positive = len(expected & actual)
    false_positive = len(actual - expected)
    false_negative = len(expected - actual)
    precision = true_positive / len(actual) if actual else 1.0
    recall = true_positive / len(expected) if expected else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "scope": "synthetic regression fixture; not a real-world accuracy estimate",
        "expected": len(expected),
        "actual": len(actual),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def _expected_labels(payload: Any) -> set[tuple[str, str, str, str]]:
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("unsupported expectation schema")
    projects = payload.get("projects")
    if not isinstance(projects, dict):
        raise ValueError("expected projects object")
    labels: set[tuple[str, str, str, str]] = set()
    for project, findings in projects.items():
        if not isinstance(project, str) or not isinstance(findings, list):
            raise ValueError("invalid expectation project")
        for finding in findings:
            if not isinstance(finding, dict):
                raise ValueError("invalid expected finding")
            labels.add(
                (
                    project,
                    str(finding["category"]),
                    str(finding["status"]),
                    str(finding["summary"]),
                )
            )
    return labels


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--expectations", type=Path, default=DEFAULT_EXPECTATIONS)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = evaluate(args.root, args.expectations)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("# Synthetic extraction evaluation")
        print()
        print(result["scope"])
        print()
        print(f"Precision: {result['precision']:.4f}")
        print(f"Recall: {result['recall']:.4f}")
        print(f"F1: {result['f1']:.4f}")
        print(f"False positives: {result['false_positive']}")
        print(f"False negatives: {result['false_negative']}")
    return 0 if result["false_positive"] == 0 and result["false_negative"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
