"""Serializable state model for WorkLedger findings.

The model deliberately contains source references, not source paths or full messages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
import re
from enum import Enum
from typing import Any, Iterable

from .redact import redact


_EVIDENCE_LOCATION = re.compile(r"^(?:s|repo)-[0-9a-f]{10}#(?:L[1-9][0-9]*|current)$")


class Category(str, Enum):
    DECISION = "decision"
    TASK = "task"
    APPROVAL = "approval"
    BLOCKER = "blocker"
    BRANCH = "branch"
    COMMIT = "commit"
    DEPLOYMENT = "deployment"


UNFINISHED_STATUSES: dict[Category, frozenset[str]] = {
    Category.TASK: frozenset({"open", "unknown"}),
    Category.APPROVAL: frozenset({"pending"}),
    Category.BLOCKER: frozenset({"active"}),
    Category.DEPLOYMENT: frozenset({"attempted", "pending", "failed", "unknown"}),
}


@dataclass(frozen=True, slots=True)
class Evidence:
    """A privacy-preserving pointer to one observation."""

    location: str
    observed_at: str | None
    kind: str
    excerpt: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "location": self.location,
            "observed_at": self.observed_at,
            "kind": self.kind,
        }
        if self.excerpt:
            result["excerpt"] = self.excerpt
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Evidence":
        location = _required_string(data, "location")
        if not _EVIDENCE_LOCATION.fullmatch(location):
            raise ValueError("invalid evidence location")
        return cls(
            location=location,
            observed_at=_optional_timestamp(data.get("observed_at")),
            kind=redact(_required_string(data, "kind"), limit=80),
            excerpt=_redacted_optional(data.get("excerpt")),
        )


@dataclass(slots=True)
class Finding:
    """A reduced state backed by one or more observations."""

    id: str
    category: Category
    status: str
    summary: str
    confidence: float
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category.value,
            "status": self.status,
            "summary": self.summary,
            "confidence": round(max(0.0, min(self.confidence, 1.0)), 2),
            "evidence": [item.to_dict() for item in self.evidence],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        evidence = data.get("evidence", [])
        if not isinstance(evidence, list) or not all(isinstance(item, dict) for item in evidence):
            raise ValueError("finding evidence must be a list")
        confidence = float(data["confidence"])
        if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise ValueError("finding confidence must be between zero and one")
        return cls(
            id=_required_string(data, "id"),
            category=Category(_required_string(data, "category")),
            status=_required_string(data, "status"),
            summary=redact(_required_string(data, "summary")),
            confidence=confidence,
            evidence=[Evidence.from_dict(item) for item in evidence],
        )

    @property
    def unfinished(self) -> bool:
        return self.status in UNFINISHED_STATUSES.get(self.category, frozenset())


@dataclass(frozen=True, slots=True)
class Diagnostic:
    code: str
    count: int
    severity: str = "warning"
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "code": self.code,
            "count": self.count,
            "severity": self.severity,
        }
        if self.detail:
            result["detail"] = self.detail
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Diagnostic":
        return cls(
            code=_required_string(data, "code"),
            count=int(data["count"]),
            severity=_required_string(data, "severity"),
            detail=_redacted_optional(data.get("detail")),
        )


@dataclass(slots=True)
class ProjectLedger:
    name: str
    key: str
    session_count: int
    last_activity: str | None
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self, *, unfinished_only: bool = False) -> dict[str, Any]:
        findings = self.unfinished if unfinished_only else self.findings
        return {
            "name": self.name,
            "key": self.key,
            "session_count": self.session_count,
            "last_activity": self.last_activity,
            "finding_count": len(findings),
            "findings": [item.to_dict() for item in findings],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProjectLedger":
        findings = data.get("findings", [])
        if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
            raise ValueError("project findings must be a list")
        return cls(
            name=redact(_required_string(data, "name"), limit=80),
            key=redact(_required_string(data, "key"), limit=100),
            session_count=int(data["session_count"]),
            last_activity=_optional_timestamp(data.get("last_activity")),
            findings=[Finding.from_dict(item) for item in findings],
        )

    @property
    def unfinished(self) -> list[Finding]:
        return [item for item in self.findings if item.unfinished]


@dataclass(slots=True)
class ScanStats:
    files_seen: int = 0
    files_fully_scanned: int = 0
    metadata_only_files: int = 0
    index_files_seen: int = 0
    index_records: int = 0
    records_seen: int = 0
    canonical_records: int = 0
    malformed_records: int = 0
    duplicate_records: int = 0
    compacted_records: int = 0
    unsupported_records: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "files_seen": self.files_seen,
            "files_fully_scanned": self.files_fully_scanned,
            "metadata_only_files": self.metadata_only_files,
            "index_files_seen": self.index_files_seen,
            "index_records": self.index_records,
            "records_seen": self.records_seen,
            "canonical_records": self.canonical_records,
            "malformed_records": self.malformed_records,
            "duplicate_records": self.duplicate_records,
            "compacted_records": self.compacted_records,
            "unsupported_records": self.unsupported_records,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanStats":
        fields = (
            "files_seen",
            "files_fully_scanned",
            "metadata_only_files",
            "index_files_seen",
            "index_records",
            "records_seen",
            "canonical_records",
            "malformed_records",
            "duplicate_records",
            "compacted_records",
            "unsupported_records",
        )
        return cls(**{name: int(data.get(name, 0)) for name in fields})


@dataclass(slots=True)
class ScanReport:
    projects: list[ProjectLedger]
    stats: ScanStats
    diagnostics: list[Diagnostic] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "stats": self.stats.to_dict(),
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "project_count": len(self.projects),
            "projects": [item.to_dict() for item in self.projects],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanReport":
        if int(data.get("schema_version", -1)) != 1:
            raise ValueError("unsupported report schema")
        projects = data.get("projects", [])
        diagnostics = data.get("diagnostics", [])
        stats = data.get("stats")
        if (
            not isinstance(projects, list)
            or not all(isinstance(item, dict) for item in projects)
            or not isinstance(diagnostics, list)
            or not all(isinstance(item, dict) for item in diagnostics)
            or not isinstance(stats, dict)
        ):
            raise ValueError("invalid report structure")
        return cls(
            projects=[ProjectLedger.from_dict(item) for item in projects],
            stats=ScanStats.from_dict(stats),
            diagnostics=[Diagnostic.from_dict(item) for item in diagnostics],
            generated_at=_required_timestamp(data, "generated_at"),
            schema_version=1,
        )

    def find_project(self, query: str) -> ProjectLedger | None:
        folded = query.casefold()
        exact_key = next((item for item in self.projects if item.key.casefold() == folded), None)
        if exact_key:
            return exact_key
        matches = [item for item in self.projects if item.name.casefold() == folded]
        return matches[0] if len(matches) == 1 else None

    def unfinished_projects(self) -> Iterable[ProjectLedger]:
        return (item for item in self.projects if item.unfinished)


def _required_string(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("optional value must be a string or null")
    return value


def _redacted_optional(value: Any) -> str | None:
    optional = _optional_string(value)
    return redact(optional) if optional is not None else None


def _required_timestamp(data: dict[str, Any], key: str) -> str:
    value = _required_string(data, key)
    if _optional_timestamp(value) is None:
        raise ValueError(f"{key} must be an ISO timestamp")
    return value


def _optional_timestamp(value: Any) -> str | None:
    optional = _optional_string(value)
    if optional is None:
        return None
    candidate = optional[:-1] + "+00:00" if optional.endswith("Z") else optional
    try:
        datetime.fromisoformat(candidate)
    except ValueError as error:
        raise ValueError("invalid timestamp") from error
    return optional
