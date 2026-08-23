"""Private derived-result cache; source sessions remain read-only."""

from __future__ import annotations

import json
import math
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from .model import ScanReport
from .redact import safe_ref


CACHE_SCHEMA_VERSION = 1
STATE_HOME_ENV = "WORKLEDGER_STATE_HOME"
MAX_CACHE_BYTES = 64 * 1024 * 1024
MAX_CACHE_DEPTH = 64
MAX_CACHE_TOKENS = 2_000_000
MAX_CACHE_STRING_BYTES = 16 * 1024
MAX_CACHE_NUMBER_BYTES = 256


class CacheError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CacheLoad:
    report: ScanReport | None
    status: str


def cache_supported() -> bool:
    return (
        os.name == "posix"
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
    )


def load_report(
    source_root: Path,
    *,
    probe_git: bool,
    include_unindexed: bool,
    state_home: Path | None = None,
) -> CacheLoad:
    if not cache_supported():
        return CacheLoad(report=None, status="unsupported")
    try:
        path = cache_path(
            source_root,
            probe_git=probe_git,
            include_unindexed=include_unindexed,
            state_home=state_home,
        )
        if _is_within(path, source_root):
            raise CacheError("cache directory must be outside the source root")
        payload = _read_payload(path)
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
    except FileNotFoundError:
        return CacheLoad(report=None, status="missing")
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        OverflowError,
        RecursionError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        CacheError,
    ):
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
    payload = {
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "source_ref": _source_ref(source_root),
        "options": _options(probe_git, include_unindexed),
        "report": report.to_dict(),
    }
    if cache_supported():
        _write_report_posix(path, payload, source_root)
    else:
        raise CacheError("secure derived snapshots are unavailable on this platform")
    return path


def _write_report_posix(path: Path, payload: dict[str, object], source_root: Path) -> None:
    expected_parent = _canonical_path(path.parent)
    directory_descriptor = _open_private_directory(expected_parent, source_root)
    temporary_name: str | None = None
    try:
        _validate_bound_directory(directory_descriptor, expected_parent, source_root)
        os.fchmod(directory_descriptor, 0o700)

        descriptor = -1
        for _ in range(10):
            temporary_name = f".{path.name}.{secrets.token_hex(8)}"
            try:
                descriptor = os.open(
                    temporary_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=directory_descriptor,
                )
                break
            except FileExistsError:
                continue
        if descriptor < 0 or temporary_name is None:
            raise CacheError("could not reserve a cache temporary file")
        try:
            write_descriptor = descriptor
            descriptor = -1
            _write_payload(write_descriptor, payload)
            _validate_bound_directory(directory_descriptor, expected_parent, source_root)
            os.replace(
                temporary_name,
                path.name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            temporary_name = None
            try:
                os.fsync(directory_descriptor)
            except OSError:
                pass
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
            except OSError:
                pass
        os.close(directory_descriptor)


def _open_private_directory(directory: Path, source_root: Path) -> int:
    """Create and bind a state directory one no-follow component at a time."""

    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise CacheError("secure directory traversal is unavailable")
    if not directory.is_absolute():
        raise CacheError("cache directory must resolve to an absolute path")
    if _is_within(directory, source_root):
        raise CacheError("cache directory must be outside the source root")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(directory.anchor, flags)
    try:
        for component in directory.parts[1:]:
            if component in {"", ".", ".."}:
                raise CacheError("cache directory contains an unsafe component")
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = os.open(component, flags, dir_fd=descriptor)
            metadata = os.fstat(child)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(child)
                raise CacheError("cache path component is not a directory")
            os.close(descriptor)
            descriptor = child
        _validate_bound_directory(descriptor, directory, source_root)
        result = descriptor
        descriptor = -1
        return result
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _validate_bound_directory(
    descriptor: int,
    expected_directory: Path,
    source_root: Path,
) -> None:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise CacheError("cache parent is not a directory")
    if metadata.st_uid != os.getuid():
        raise CacheError("cache directory must be owned by the current user")
    try:
        expected_metadata = os.stat(expected_directory, follow_symlinks=False)
    except OSError as error:
        raise CacheError("cache directory changed during validation") from error
    if not _same_file(metadata, expected_metadata):
        raise CacheError("cache directory changed during validation")
    if _is_within(expected_directory, source_root):
        raise CacheError("cache directory must be outside the source root")


def _write_payload(descriptor: int, payload: dict[str, object]) -> None:
    try:
        os.fchmod(descriptor, 0o600)
    except BaseException:
        os.close(descriptor)
        raise
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        if os.fstat(handle.fileno()).st_size > MAX_CACHE_BYTES:
            raise CacheError("derived snapshot exceeds the cache size limit")
        os.fsync(handle.fileno())


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
            str(_canonical_path(source_root)),
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
    return safe_ref(str(_canonical_path(source_root)), prefix="source")


def _options(probe_git: bool, include_unindexed: bool) -> dict[str, bool]:
    return {"probe_git": probe_git, "include_unindexed": include_unindexed}


def _is_within(path: Path, directory: Path) -> bool:
    try:
        candidate = path.expanduser().resolve(strict=False)
        boundary = directory.expanduser().resolve(strict=False)
        candidate.relative_to(boundary)
    except ValueError:
        pass
    except (OSError, RuntimeError) as error:
        raise CacheError("path could not be compared safely") from error
    else:
        return True

    try:
        boundary_metadata = os.stat(boundary, follow_symlinks=False)
    except OSError as error:
        raise CacheError("source root identity could not be inspected") from error

    current = candidate
    while True:
        try:
            metadata = os.stat(current, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise CacheError("path identity could not be inspected") from error
        else:
            if _same_file(metadata, boundary_metadata):
                return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


def _canonical_path(path: Path) -> Path:
    try:
        return path.expanduser().resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise CacheError("path could not be resolved safely") from error


def _read_payload(path: Path) -> object:
    if not cache_supported():
        raise CacheError("secure derived snapshots are unavailable on this platform")
    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError("cache symbolic links are not allowed")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not _same_file(before, metadata)
            or metadata.st_size > MAX_CACHE_BYTES
        ):
            raise ValueError("unsafe cache file")
        if os.name == "posix":
            if metadata.st_uid != os.getuid():
                raise ValueError("cache file is not owned by the current user")
            if metadata.st_mode & 0o077:
                raise ValueError("cache permissions are too broad")
        encoded = bytearray()
        remaining = MAX_CACHE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            encoded.extend(chunk)
            remaining -= len(chunk)
        if len(encoded) > MAX_CACHE_BYTES:
            raise ValueError("cache file is too large")
    finally:
        os.close(descriptor)
    if not _json_budget_is_bounded(encoded):
        raise ValueError("cache JSON exceeds its structural safety budget")
    return json.loads(
        encoded.decode("utf-8"),
        parse_int=_bounded_json_int,
        parse_float=_bounded_json_float,
        parse_constant=_reject_json_constant,
    )


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _json_budget_is_bounded(encoded: bytes | bytearray) -> bool:
    depth = 0
    tokens = 0
    in_string = False
    escaped = False
    string_bytes = 0
    primitive_bytes = 0
    for character in encoded:
        if in_string:
            string_bytes += 1
            if string_bytes > MAX_CACHE_STRING_BYTES:
                return False
            if escaped:
                escaped = False
            elif character == 0x5C:
                escaped = True
            elif character == 0x22:
                in_string = False
            continue
        if character in (0x20, 0x09, 0x0A, 0x0D):
            if primitive_bytes:
                tokens += 1
                primitive_bytes = 0
            if tokens > MAX_CACHE_TOKENS:
                return False
            continue
        if character == 0x22:
            if primitive_bytes:
                return False
            in_string = True
            string_bytes = 0
            tokens += 1
        elif character in (0x7B, 0x5B):
            if primitive_bytes:
                return False
            depth += 1
            tokens += 1
            if depth > MAX_CACHE_DEPTH:
                return False
        elif character in (0x7D, 0x5D):
            if primitive_bytes:
                tokens += 1
                primitive_bytes = 0
            depth -= 1
            tokens += 1
            if depth < 0:
                return False
        elif character in (0x2C, 0x3A):
            if primitive_bytes:
                tokens += 1
                primitive_bytes = 0
            tokens += 1
        else:
            primitive_bytes += 1
            if primitive_bytes > MAX_CACHE_NUMBER_BYTES:
                return False
        if tokens > MAX_CACHE_TOKENS:
            return False
    if primitive_bytes:
        tokens += 1
    return (
        depth == 0
        and not in_string
        and not escaped
        and tokens <= MAX_CACHE_TOKENS
    )


def _bounded_json_int(value: str) -> int:
    if len(value) > MAX_CACHE_NUMBER_BYTES:
        raise ValueError("cache integer is too long")
    return int(value)


def _bounded_json_float(value: str) -> float:
    if len(value) > MAX_CACHE_NUMBER_BYTES:
        raise ValueError("cache number is too long")
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("cache number must be finite")
    return parsed


def _reject_json_constant(_: str) -> float:
    raise ValueError("non-standard cache number is not allowed")
