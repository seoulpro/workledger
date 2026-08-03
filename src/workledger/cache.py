"""Private derived-result cache; source sessions remain read-only."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .model import ScanReport
from .redact import safe_ref


CACHE_SCHEMA_VERSION = 1
STATE_HOME_ENV = "WORKLEDGER_STATE_HOME"
MAX_CACHE_BYTES = 64 * 1024 * 1024


class CacheError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CacheLoad:
    report: ScanReport | None
    status: str


def load_report(
    source_root: Path,
    *,
    probe_git: bool,
    include_unindexed: bool,
    state_home: Path | None = None,
) -> CacheLoad:
    path = cache_path(
        source_root,
        probe_git=probe_git,
        include_unindexed=include_unindexed,
        state_home=state_home,
    )
    if not path.is_file():
        return CacheLoad(report=None, status="missing")
    try:
        if path.is_symlink() or path.stat().st_size > MAX_CACHE_BYTES:
            raise ValueError("unsafe cache file")
        if os.name == "posix" and path.stat().st_mode & 0o077:
            raise ValueError("cache permissions are too broad")
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict) or payload.get("cache_schema_version") != CACHE_SCHEMA_VERSION:
            raise ValueError("unsupported cache schema")
        if payload.get("source_ref") != _source_ref(source_root):
            raise ValueError("source identity mismatch")
        if payload.get("options") != _options(probe_git, include_unindexed):
            raise ValueError("scan option mismatch")
        report = payload.get("report")
        if not isinstance(report, dict):
            raise ValueError("report is missing")
        return CacheLoad(report=ScanReport.from_dict(report), status="hit")
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return CacheLoad(report=None, status="invalid")


def write_report(
    report: ScanReport,
    source_root: Path,
    *,
    probe_git: bool,
    include_unindexed: bool,
    state_home: Path | None = None,
) -> Path:
    path = cache_path(
        source_root,
        probe_git=probe_git,
        include_unindexed=include_unindexed,
        state_home=state_home,
    )
    if _is_within(path, source_root):
        raise CacheError("cache directory must be outside the source root")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    payload = {
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "source_ref": _source_ref(source_root),
        "options": _options(probe_git, include_unindexed),
        "report": report.to_dict(),
    }
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    return path


def cache_path(
    source_root: Path,
    *,
    probe_git: bool,
    include_unindexed: bool,
    state_home: Path | None = None,
) -> Path:
    directory = state_home or default_state_home()
    identity = "\0".join(
        (
            str(source_root.expanduser().resolve(strict=False)),
            f"git={int(probe_git)}",
            f"unindexed={int(include_unindexed)}",
        )
    )
    return directory / f"{safe_ref(identity, prefix='ledger')}.json"


def default_state_home() -> Path:
    override = os.environ.get(STATE_HOME_ENV)
    if override:
        return Path(override).expanduser()
    xdg_state = os.environ.get("XDG_STATE_HOME")
    if xdg_state:
        return Path(xdg_state).expanduser() / "workledger"
    return Path.home() / ".local" / "state" / "workledger"


def _source_ref(source_root: Path) -> str:
    return safe_ref(str(source_root.expanduser().resolve(strict=False)), prefix="source")


def _options(probe_git: bool, include_unindexed: bool) -> dict[str, bool]:
    return {"probe_git": probe_git, "include_unindexed": include_unindexed}


def _is_within(path: Path, directory: Path) -> bool:
    try:
        path.expanduser().resolve(strict=False).relative_to(directory.expanduser().resolve(strict=False))
    except ValueError:
        return False
    return True
