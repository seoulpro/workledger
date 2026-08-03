"""Conservative masking for snippets and identifiers."""

from __future__ import annotations

import re
from pathlib import PurePath


_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|auth(?:orization)?|"
            r"password|passwd|secret|cookie)\b\s*[:=]\s*(['\"]?)[^\s,;]+\2"
        ),
        r"\1=[REDACTED]",
    ),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer [REDACTED]"),
    (re.compile(r"\b(?:sk|pk|ghp|github_pat|glpat)-[A-Za-z0-9_-]{8,}\b"), "[TOKEN]"),
    (
        re.compile(r"(?i)([?&](?:token|key|secret|signature|auth)=)[^&#\s]+"),
        r"\1[REDACTED]",
    ),
    (re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])"), "[EMAIL]"),
    (re.compile(r"(?<!\w)/(?:Users|home)/[^/\s]+(?:/[^\s:;,)]*)?"), "[PATH]"),
    (re.compile(r"(?i)\b[A-Z]:\\Users\\[^\s:;,)]*(?:\\[^\s:;,)]*)?"), "[PATH]"),
    (
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
            r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
        ),
        "[ID]",
    ),
    (re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"), "[OPAQUE]"),
)


def redact(text: str, *, limit: int = 180) -> str:
    """Mask common secrets and personal paths, then bound retained text."""

    compact = " ".join(text.replace("\x00", " ").split())
    for pattern, replacement in _RULES:
        compact = pattern.sub(replacement, compact)
    if len(compact) <= limit:
        return compact
    return compact[: max(0, limit - 1)].rstrip() + "…"


def safe_project_name(path: str | None) -> str:
    """Return only a path basename, never the personal path itself."""

    if not path:
        return "unassigned"
    normalized = path.rstrip("/\\")
    if re.fullmatch(r"/(?:Users|home)/[^/]+", normalized, re.IGNORECASE):
        return "home"
    if re.fullmatch(r"[A-Za-z]:\\Users\\[^\\]+", normalized, re.IGNORECASE):
        return "home"
    name = re.split(r"[/\\]", normalized)[-1]
    if not name or name in {".", ".."}:
        return "unassigned"
    return redact(name, limit=80)


def safe_ref(value: str, *, prefix: str = "s") -> str:
    import hashlib

    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:10]
    return f"{prefix}-{digest}"


def safe_branch(value: str) -> str:
    """Retain an ordinary branch name after applying general masking."""

    return redact(value, limit=100)


def basename_only(value: str) -> str:
    return PurePath(value.replace("\\", "/")).name
