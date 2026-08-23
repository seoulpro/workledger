"""Conservative masking for snippets and identifiers."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable
from pathlib import PurePath


_SECRET_KEY = r"[A-Za-z0-9_-]{1,256}"
_SECRET_PARTS = frozenset(
    {
        "apikey",
        "accesstoken",
        "refreshtoken",
        "authorization",
        "authtoken",
        "auth",
        "password",
        "passwd",
        "secret",
        "clientsecret",
        "privatekey",
        "cookie",
    }
)
_PRIVATE_KEY_BEGIN = re.compile(
    r"-----BEGIN(?: [A-Z0-9]{1,32})? PRIVATE KEY-----",
    re.IGNORECASE,
)
_PRIVATE_KEY_END = re.compile(
    r"-----END(?: [A-Z0-9]{1,32})? PRIVATE KEY-----",
    re.IGNORECASE,
)
_SECRET_VALUE = r'''(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,;]+)'''


def _is_secret_name(value: str) -> bool:
    parts = [part for part in re.split(r"[_-]+", value.casefold()) if part]
    for index, part in enumerate(parts):
        if part in _SECRET_PARTS:
            return True
        if index + 1 < len(parts) and part + parts[index + 1] in _SECRET_PARTS:
            return True
    return False


def _mask_quoted_secret(match: re.Match[str]) -> str:
    key = match.group(2)
    return f'"{key}":"[REDACTED]"' if _is_secret_name(key) else match.group(0)


def _mask_unquoted_secret(match: re.Match[str]) -> str:
    key = match.group(1)
    return f"{key}=[REDACTED]" if _is_secret_name(key) else match.group(0)


def _mask_private_key_blocks(value: str) -> str:
    """Mask complete key blocks with one forward pass over delimiter pairs."""

    pieces: list[str] = []
    cursor = 0
    while True:
        begin = _PRIVATE_KEY_BEGIN.search(value, cursor)
        if begin is None:
            pieces.append(value[cursor:])
            break
        end = _PRIVATE_KEY_END.search(value, begin.end())
        if end is None:
            pieces.append(value[cursor : begin.start()])
            pieces.append("[PRIVATE KEY]")
            break
        pieces.append(value[cursor : begin.start()])
        pieces.append("[PRIVATE KEY]")
        cursor = end.end()
    return "".join(pieces)


_RuleReplacement = str | Callable[[re.Match[str]], str]
_RULES: tuple[tuple[re.Pattern[str], _RuleReplacement], ...] = (
    (
        re.compile(
            rf'''(?i)(["'])({_SECRET_KEY})\1\s*:\s*{_SECRET_VALUE}'''
        ),
        _mask_quoted_secret,
    ),
    (
        re.compile(
            r"(?i)\b((?:Proxy-)?Authorization\s*:\s*)(Digest)\s+.*"
        ),
        r"\1\2 [REDACTED]",
    ),
    (
        re.compile(
            r"(?i)\b((?:Proxy-)?Authorization\s*:\s*)(Basic|Bearer)\s+[^\s,;]+"
        ),
        r"\1\2 [REDACTED]",
    ),
    (
        re.compile(
            rf"(?i)\b({_SECRET_KEY})\b\s*[:=]\s*"
            rf"(?!(?:Basic|Bearer|Digest)\b){_SECRET_VALUE}"
        ),
        _mask_unquoted_secret,
    ),
    (re.compile(r"(?i)\b(Basic|Bearer)\s+[A-Za-z0-9._~+/=-]+"), r"\1 [REDACTED]"),
    (
        re.compile(
            r"\b(?:"
            r"gh[pousr]_[A-Za-z0-9]{20,}|"
            r"github_pat_[A-Za-z0-9_]{20,}|"
            r"npm_[A-Za-z0-9]{20,}|"
            r"(?:AKIA|ASIA)[A-Z0-9]{16}|"
            r"AIza[0-9A-Za-z_-]{35}|"
            r"xox[baprs]-[A-Za-z0-9-]{10,}|"
            r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|"
            r"(?:sk|pk|glpat)-[A-Za-z0-9_-]{8,}"
            r")\b"
        ),
        "[TOKEN]",
    ),
    (
        re.compile(r"(?i)([?&](?:token|key|secret|signature|auth)=)[^&#\s]+"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)\b([a-z][a-z0-9+.-]{0,63}://)[^/\s:@]*:[^/\s@]+@"),
        r"\1[REDACTED]@",
    ),
    (re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])"), "[EMAIL]"),
    (re.compile(r'''(?i)(["'])file://.*?\1'''), "[PATH]"),
    (re.compile(r'''(["'])/(?!/).*?\1'''), "[PATH]"),
    (re.compile(r'''(?i)(["'])[A-Z]:[\\/].*?\1'''), "[PATH]"),
    (re.compile(r'''(["'])(?:\\\\|//).*?\1'''), "[PATH]"),
    (re.compile(r"(?i)\bfile:///?[^\s;,)>\]}]+"), "[PATH]"),
    (re.compile(r"(?<!\w)(?:\.\.[\\/])+(?:[^\\/\s:;,)>\]}]+[\\/]?)+"), "[PATH]"),
    (re.compile(r"(?<![A-Za-z0-9+.-]:)(?<![/:\w])/(?:[^/\s:;,)>\]}]+/?)+"), "[PATH]"),
    (re.compile(r"(?i)(?<!\w)[A-Z]:[\\/](?:[^\\/\s:;,)>\]}]+[\\/]?)+"), "[PATH]"),
    (re.compile(r"(?<![:\w])(?:\\\\|//)[^\\/\s]+[\\/][^\s:;,)>\]}]+"), "[PATH]"),
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

    sanitized = "".join(
        " " if unicodedata.category(character) in {"Cc", "Cf", "Cs"} else character
        for character in text
    )
    compact = " ".join(sanitized.split())
    compact = _mask_private_key_blocks(compact)
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

    digest = hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()[:10]
    return f"{prefix}-{digest}"


def safe_branch(value: str) -> str:
    """Retain an ordinary branch name after applying general masking."""

    return redact(value, limit=100)


def basename_only(value: str) -> str:
    return PurePath(value.replace("\\", "/")).name
