"""Evidence-backed extraction and state reduction."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable

from .adapter import CanonicalRecord
from .model import Category, Evidence, Finding
from .redact import redact, safe_branch


@dataclass(slots=True)
class Candidate:
    category: Category
    status: str
    summary: str
    subject: str
    confidence: float
    evidence: Evidence
    order: int


_MARKERS: tuple[tuple[re.Pattern[str], Category, str, float], ...] = (
    (re.compile(r"(?i)^\s*(?:[-*]\s*)?DECISION\s*:\s*(.+)$"), Category.DECISION, "accepted", 0.9),
    (re.compile(r"^\s*(?:[-*]\s*)?결정\s*:\s*(.+)$"), Category.DECISION, "accepted", 0.9),
    (re.compile(r"(?i)^\s*[-*]\s*\[\s\]\s*(.+)$"), Category.TASK, "open", 0.94),
    (re.compile(r"(?i)^\s*[-*]\s*\[[xX]\]\s*(.+)$"), Category.TASK, "done", 0.94),
    (
        re.compile(r"(?i)^\s*(?:[-*]\s*)?(?:TODO|TASK|REMAINING|NEXT ACTION)\s*:\s*(.+)$"),
        Category.TASK,
        "open",
        0.88,
    ),
    (re.compile(r"^\s*(?:[-*]\s*)?(?:할 일|남은 작업|미완료)\s*:\s*(.+)$"), Category.TASK, "open", 0.88),
    (re.compile(r"(?i)^\s*(?:[-*]\s*)?(?:DONE|COMPLETED)\s*:\s*(.+)$"), Category.TASK, "done", 0.9),
    (re.compile(r"^\s*(?:[-*]\s*)?완료\s*:\s*(.+)$"), Category.TASK, "done", 0.9),
    (
        re.compile(r"(?i)^\s*(?:[-*]\s*)?(?:APPROVAL PENDING|AWAITING APPROVAL)\s*:\s*(.+)$"),
        Category.APPROVAL,
        "pending",
        0.92,
    ),
    (re.compile(r"^\s*(?:[-*]\s*)?승인 대기\s*:\s*(.+)$"), Category.APPROVAL, "pending", 0.92),
    (re.compile(r"(?i)^\s*(?:[-*]\s*)?APPROVED\s*:\s*(.+)$"), Category.APPROVAL, "granted", 0.94),
    (re.compile(r"^\s*(?:[-*]\s*)?승인 완료\s*:\s*(.+)$"), Category.APPROVAL, "granted", 0.94),
    (re.compile(r"(?i)^\s*(?:[-*]\s*)?BLOCKED\s*:\s*(.+)$"), Category.BLOCKER, "active", 0.92),
    (re.compile(r"^\s*(?:[-*]\s*)?차단\s*:\s*(.+)$"), Category.BLOCKER, "active", 0.92),
    (re.compile(r"(?i)^\s*(?:[-*]\s*)?UNBLOCKED\s*:\s*(.+)$"), Category.BLOCKER, "resolved", 0.94),
    (re.compile(r"^\s*(?:[-*]\s*)?차단 해제\s*:\s*(.+)$"), Category.BLOCKER, "resolved", 0.94),
    (
        re.compile(r"(?i)^\s*(?:[-*]\s*)?DEPLOYMENT PENDING\s*:\s*(.+)$"),
        Category.DEPLOYMENT,
        "pending",
        0.88,
    ),
    (
        re.compile(r"(?i)^\s*(?:[-*]\s*)?DEPLOYMENT (?:SUCCEEDED|COMPLETE)\s*:\s*(.+)$"),
        Category.DEPLOYMENT,
        "succeeded",
        0.9,
    ),
    (
        re.compile(r"(?i)^\s*(?:[-*]\s*)?DEPLOYMENT FAILED\s*:\s*(.+)$"),
        Category.DEPLOYMENT,
        "failed",
        0.9,
    ),
)

_NATURAL: tuple[tuple[re.Pattern[str], Category, str, float, str], ...] = (
    (
        re.compile(r"(?i)^\s*(?:[-*]\s+)?(?:we (?:decided to|chose|selected)|chosen approach\b|decision\b)"),
        Category.DECISION,
        "accepted",
        0.68,
        "Potential decision",
    ),
    (
        re.compile(r"^\s*(?:[-*]\s+)?(?:.+하기로 (?:했습니다|결정)|.+을? 선택했습니다|결정했습니다)"),
        Category.DECISION,
        "accepted",
        0.68,
        "잠재적 결정",
    ),
    (
        re.compile(
            r"(?i)^\s*(?:[-*]\s+)?(?:still needs?|remains? to be|not yet (?:done|implemented)|unfinished\b)"
        ),
        Category.TASK,
        "open",
        0.62,
        "Potential unfinished work",
    ),
    (
        re.compile(r"^\s*(?:[-*]\s+)?(?:(?:아직|추가로).*(?:필요|해야|남아)|미완료\b|남아 있습니다)"),
        Category.TASK,
        "open",
        0.62,
        "잠재적 미완료 작업",
    ),
    (
        re.compile(r"(?i)^\s*(?:[-*]\s+)?(?:requires?|needs?|awaiting) (?:user )?approval\b"),
        Category.APPROVAL,
        "pending",
        0.7,
        "Approval may be pending",
    ),
    (
        re.compile(r"^\s*(?:[-*]\s+)?(?:사용자 )?승인(?:이|을)? (?:필요|대기)"),
        Category.APPROVAL,
        "pending",
        0.7,
        "승인이 대기 중일 수 있음",
    ),
    (
        re.compile(r"(?i)^\s*(?:[-*]\s+)?(?:cannot proceed|blocked by|is blocking)\b"),
        Category.BLOCKER,
        "active",
        0.68,
        "A blocker may be active",
    ),
    (
        re.compile(r"^\s*(?:[-*]\s+)?(?:진행할 수 없|.+때문에 차단|.+가로막)"),
        Category.BLOCKER,
        "active",
        0.68,
        "차단 요인이 있을 수 있음",
    ),
)

_COMMIT_COMMAND = re.compile(r"(?:^|[;&|]\s*)git\s+(?:-[^\s]+\s+)*commit\b", re.IGNORECASE)
_DEPLOY_COMMAND = re.compile(
    r"\b(?:vercel|render|netlify|fly)\s+(?:deploy|up)\b|\bnpm\s+publish\b|"
    r"\bgh\s+release\b|\bkubectl\s+(?:apply|rollout)\b",
    re.IGNORECASE,
)
_FAILURE = re.compile(r"(?i)\b(?:error|failed|failure|fatal|denied|not deployed|exit code [1-9])\b")
_COMMIT_SUCCESS = re.compile(r"\[[^\]\r\n]+\s+([0-9a-f]{7,40})\]")
_HASH_ONLY = re.compile(r"^\s*([0-9a-f]{7,64})\s*$", re.IGNORECASE)
_DEPLOY_SUCCESS = re.compile(r"(?i)\b(?:deployed|deployment (?:succeeded|complete)|published|ready)\b")
_APPROVAL_REQUIRED = re.compile(r"(?i)\b(?:approval required|needs approval|awaiting approval)\b|승인(?:이|을)? 필요")


def extract_findings(records: Iterable[CanonicalRecord]) -> list[Finding]:
    ordered = sorted(records, key=lambda record: (_time_key(record.timestamp), record.order))
    candidates: list[Candidate] = []
    calls: dict[str, CanonicalRecord] = {}

    for record in ordered:
        if record.kind == "tool_call" and record.call_id:
            calls[record.call_id] = record
            continue
        if record.kind in {"tool_output", "tool_result"}:
            call = calls.get(record.call_id or "")
            candidates.extend(_tool_candidates(call, record))
            continue
        if record.kind in {"message", "compaction_summary"} and record.text:
            candidates.extend(_text_candidates(record))
        elif record.kind == "session_meta":
            candidates.extend(_metadata_candidates(record))
        elif record.kind == "turn_aborted":
            reason = redact(record.text or "Turn aborted before completion")
            candidates.append(
                _candidate(record, Category.TASK, "unknown", reason, reason, 0.74, "turn_aborted")
            )
        elif record.kind == "repository_state":
            candidates.extend(_repository_candidates(record))

    return _reduce(candidates)


def _text_candidates(record: CanonicalRecord) -> list[Candidate]:
    result: list[Candidate] = []
    base_penalty = 0.18 if record.kind == "compaction_summary" else 0.0
    for raw_line in record.text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        matched = False
        for pattern, category, status, confidence in _MARKERS:
            match = pattern.match(line)
            if not match:
                continue
            summary = redact(match.group(1))
            if summary:
                result.append(
                    _candidate(
                        record,
                        category,
                        status,
                        summary,
                        summary,
                        confidence - base_penalty,
                        "compaction_summary" if base_penalty else "explicit_marker",
                    )
                )
            matched = True
            break
        if matched or record.role != "assistant":
            continue
        for pattern, category, status, confidence, label in _NATURAL:
            if pattern.search(line):
                excerpt = redact(line)
                result.append(
                    _candidate(
                        record,
                        category,
                        status,
                        excerpt,
                        excerpt,
                        confidence - base_penalty,
                        "heuristic_text",
                        excerpt=excerpt,
                    )
                )
                break
    return result


def _metadata_candidates(record: CanonicalRecord) -> list[Candidate]:
    result: list[Candidate] = []
    branch = record.metadata.get("branch")
    if isinstance(branch, str) and branch:
        summary = f"Git branch observed: {safe_branch(branch)}"
        result.append(_candidate(record, Category.BRANCH, "observed", summary, "git-branch", 0.96, "session_metadata"))
    commit_hash = record.metadata.get("commit_hash")
    if isinstance(commit_hash, str) and re.fullmatch(r"[0-9a-fA-F]{7,64}", commit_hash):
        summary = f"Session Git commit observed: {commit_hash[:12]}"
        result.append(_candidate(record, Category.COMMIT, "observed", summary, "current-head", 0.96, "session_metadata"))
    if record.metadata.get("forked_from") or record.metadata.get("parent_thread"):
        result.append(
            _candidate(
                record,
                Category.BRANCH,
                "observed",
                "Session fork relationship observed",
                "session-fork",
                0.98,
                "session_metadata",
            )
        )
    return result


def _repository_candidates(record: CanonicalRecord) -> list[Candidate]:
    result: list[Candidate] = []
    branch = record.metadata.get("branch")
    if isinstance(branch, str) and branch:
        result.append(
            _candidate(
                record,
                Category.BRANCH,
                "current",
                f"Current Git branch: {safe_branch(branch)}",
                "git-branch",
                1.0,
                "repository_probe",
            )
        )
    commit_hash = record.metadata.get("commit_hash")
    if isinstance(commit_hash, str) and re.fullmatch(r"[0-9a-fA-F]{7,64}", commit_hash):
        cleanliness = "clean" if record.metadata.get("clean") is True else "has local changes"
        result.append(
            _candidate(
                record,
                Category.COMMIT,
                "verified",
                f"Current Git HEAD: {commit_hash[:12]} ({cleanliness})",
                "current-head",
                1.0,
                "repository_probe",
            )
        )
    return result


def _tool_candidates(call: CanonicalRecord | None, output_record: CanonicalRecord) -> list[Candidate]:
    result: list[Candidate] = []
    command = _command_from_input(call.tool_input) if call else ""
    output = _flatten(output_record.tool_output)
    tool_name = (call.tool_name if call else output_record.tool_name) or ""
    combined_action = f"{tool_name} {command}"

    if _COMMIT_COMMAND.search(command):
        match = _COMMIT_SUCCESS.search(output)
        if match and not _FAILURE.search(output):
            short_hash = match.group(1)[:12]
            result.append(
                _candidate(
                    output_record,
                    Category.COMMIT,
                    "verified",
                    f"Git commit completed: {short_hash}",
                    f"commit-{short_hash}",
                    0.99,
                    "tool_result",
                    excerpt=f"git commit reported {short_hash}",
                )
            )
        elif _FAILURE.search(output):
            result.append(
                _candidate(
                    output_record,
                    Category.COMMIT,
                    "failed",
                    "Git commit attempt failed",
                    "commit-attempt",
                    0.94,
                    "tool_result",
                    excerpt="git commit returned a failure indicator",
                )
            )
        else:
            result.append(
                _candidate(
                    output_record,
                    Category.COMMIT,
                    "attempted",
                    "Git commit command observed; outcome unclear",
                    "commit-attempt",
                    0.72,
                    "tool_result",
                    excerpt="git commit outcome could not be verified",
                )
            )

    if re.search(r"\bgit\s+rev-parse\s+HEAD\b", command, re.IGNORECASE):
        match = _HASH_ONLY.match(output)
        if match:
            short_hash = match.group(1)[:12]
            result.append(
                _candidate(
                    output_record,
                    Category.COMMIT,
                    "verified",
                    f"Git HEAD verified: {short_hash}",
                    "current-head",
                    0.99,
                    "tool_result",
                    excerpt=f"git rev-parse reported {short_hash}",
                )
            )

    is_deploy = bool(_DEPLOY_COMMAND.search(command)) or bool(re.search(r"deploy|publish|release", tool_name, re.IGNORECASE))
    if is_deploy:
        if _FAILURE.search(output):
            status, confidence, summary = "failed", 0.95, "Deployment action failed"
        elif _DEPLOY_SUCCESS.search(output):
            status, confidence, summary = "succeeded", 0.95, "Deployment action succeeded"
        else:
            status, confidence, summary = "attempted", 0.72, "Deployment action observed; outcome unclear"
        result.append(
            _candidate(
                output_record,
                Category.DEPLOYMENT,
                status,
                summary,
                "deployment-action",
                confidence,
                "tool_result",
                excerpt="deployment tool result classified without retaining raw output",
            )
        )

    if _APPROVAL_REQUIRED.search(output):
        result.append(
            _candidate(
                output_record,
                Category.APPROVAL,
                "pending",
                "A tool action may be awaiting approval",
                f"tool-approval-{tool_name.casefold()}",
                0.78,
                "tool_result",
                excerpt="tool output contained an approval-required indicator",
            )
        )
    return result


def _candidate(
    record: CanonicalRecord,
    category: Category,
    status: str,
    summary: str,
    subject: str,
    confidence: float,
    kind: str,
    *,
    excerpt: str | None = None,
) -> Candidate:
    safe_summary = redact(summary)
    safe_excerpt = redact(excerpt if excerpt is not None else summary)
    return Candidate(
        category=category,
        status=status,
        summary=safe_summary,
        subject=_subject(subject),
        confidence=max(0.0, min(confidence, 1.0)),
        evidence=Evidence(
            location=record.location,
            observed_at=record.timestamp,
            kind=kind,
            excerpt=safe_excerpt or None,
        ),
        order=record.order,
    )


def _reduce(candidates: list[Candidate]) -> list[Finding]:
    findings: list[tuple[str, Finding]] = []
    for candidate in candidates:
        match_index = _matching_finding(findings, candidate)
        if match_index is None:
            finding_id = _finding_id(candidate.category, candidate.subject)
            findings.append(
                (
                    candidate.subject,
                    Finding(
                        id=finding_id,
                        category=candidate.category,
                        status=candidate.status,
                        summary=candidate.summary,
                        confidence=candidate.confidence,
                        evidence=[candidate.evidence],
                    ),
                )
            )
            continue
        subject, finding = findings[match_index]
        finding.status = candidate.status
        finding.summary = candidate.summary
        finding.confidence = candidate.confidence
        if candidate.evidence not in finding.evidence:
            finding.evidence.append(candidate.evidence)
            finding.evidence = finding.evidence[-6:]

    result = [finding for _, finding in findings]
    result.sort(key=lambda item: (item.category.value, item.status, item.summary.casefold()))
    return result


def _matching_finding(findings: list[tuple[str, Finding]], candidate: Candidate) -> int | None:
    for index in range(len(findings) - 1, -1, -1):
        subject, finding = findings[index]
        if finding.category != candidate.category:
            continue
        if subject == candidate.subject:
            return index
        if candidate.category in {Category.TASK, Category.APPROVAL, Category.BLOCKER, Category.DEPLOYMENT}:
            if _similarity(subject, candidate.subject) >= 0.72:
                return index
    return None


def _subject(value: str) -> str:
    lowered = redact(value, limit=240).casefold()
    lowered = re.sub(r"\b(?:todo|task|done|completed|blocked|unblocked|approval|pending|approved)\b", " ", lowered)
    lowered = re.sub(r"(?:할 일|남은 작업|미완료|완료|차단 해제|차단|승인 대기|승인 완료)", " ", lowered)
    return " ".join(re.findall(r"[\w가-힣.-]+", lowered)) or "unspecified"


def _similarity(left: str, right: str) -> float:
    left_tokens = set(left.split())
    right_tokens = set(right.split())
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / len(left_tokens | right_tokens)


def _finding_id(category: Category, subject: str) -> str:
    digest = hashlib.sha256(f"{category.value}\0{subject}".encode("utf-8")).hexdigest()[:10]
    return f"{category.value[:3]}-{digest}"


def _command_from_input(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("cmd", "command", "script"):
            candidate = value.get(key)
            if isinstance(candidate, str):
                return candidate
        return ""
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return value
        return _command_from_input(parsed) if isinstance(parsed, dict) else value
    return ""


def _flatten(value: Any, *, limit: int = 500_000) -> str:
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                for key in ("text", "output", "content"):
                    if isinstance(item.get(key), str):
                        parts.append(item[key])
                        break
            if sum(map(len, parts)) >= limit:
                break
        return "\n".join(parts)[:limit]
    if isinstance(value, dict):
        try:
            return json.dumps(value, ensure_ascii=False)[:limit]
        except (TypeError, ValueError):
            return ""
    return "" if value is None else str(value)[:limit]


def _time_key(value: str | None) -> tuple[int, str]:
    return (0, value) if value else (1, "")
