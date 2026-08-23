"""Version-tolerant, read-only adapters for Codex JSONL session records."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, TextIO

from .model import Diagnostic, ScanStats
from .redact import safe_ref


MAX_LINE_CHARS = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_TOKENS = 250_000
MAX_JSON_NUMBER_CHARS = 256
MAX_TEXT_CHARS = 256 * 1024
MAX_TOOL_OUTPUT_CHARS = 512 * 1024
MAX_METADATA_CHARS = 4 * 1024
MAX_SOURCE_FILES = 25_000
MAX_DISCOVERY_ENTRIES = 100_000
MAX_DISCOVERY_DEPTH = 128
MAX_SOURCE_RECORDS = 250_000
MAX_SOURCE_CHARS = 256 * 1024 * 1024
MAX_FILE_CHARS = 64 * 1024 * 1024
MAX_INDEX_RECORDS = 50_000
MAX_INDEX_CHARS = 32 * 1024 * 1024
MAX_CANONICAL_RECORDS = 100_000
MAX_CONTENT_ITEMS = 20_000
MAX_IDENTITY_LINES = 20
MAX_IDENTITY_CHARS = 64 * 1024
MAX_IDENTITY_SCAN_CHARS = 64 * 1024 * 1024
_TYPE_TOKEN = re.compile(r'"type"\s*:\s*"([^"\\]+)"')
_INDEX_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_IGNORED_EVENT_TYPES = frozenset(
    {
        "agent_reasoning",
        "context_compacted",
        "image_generation_end",
        "patch_apply_end",
        "task_complete",
        "task_started",
        "thread_settings_applied",
        "token_count",
        "web_search_end",
    }
)
_IGNORED_RESPONSE_TYPES = frozenset({"reasoning", "tool_search_call", "tool_search_output"})


def _bounded_lines(
    handle: TextIO,
    *,
    max_chars: int | None = None,
) -> Iterator[tuple[int, str | None, int]]:
    line_number = 0
    total_chars = 0
    while True:
        remaining = max_chars - total_chars if max_chars is not None else MAX_LINE_CHARS + 1
        if remaining <= 0:
            return
        chunk = handle.readline(min(MAX_LINE_CHARS + 1, remaining))
        if not chunk:
            return
        line_number += 1
        consumed = len(chunk)
        total_chars += consumed
        budget_ended_mid_line = (
            max_chars is not None and total_chars >= max_chars and not chunk.endswith("\n")
        )
        if len(chunk) > MAX_LINE_CHARS or budget_ended_mid_line:
            while chunk and not chunk.endswith("\n"):
                remaining = max_chars - total_chars if max_chars is not None else MAX_LINE_CHARS + 1
                if remaining <= 0:
                    yield line_number, None, consumed
                    return
                chunk = handle.readline(min(MAX_LINE_CHARS + 1, remaining))
                consumed += len(chunk)
                total_chars += len(chunk)
            yield line_number, None, consumed
            continue
        yield line_number, chunk, consumed


def _open_source_file(
    path: Path,
    *,
    root_boundary: Path | None = None,
    expected_signature: tuple[int, int, int, int, int] | None = None,
) -> TextIO:
    """Open one regular source file and bind validation to the opened descriptor."""

    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise OSError("source symbolic links are not allowed")
    if expected_signature is not None and _stat_signature(before) != expected_signature:
        raise OSError("source file changed after identity selection")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode) or not _same_file(before, after):
            raise OSError("source path is not a regular file")
        if expected_signature is not None and _stat_signature(after) != expected_signature:
            raise OSError("source file changed after identity selection")
        if root_boundary is not None:
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(root_boundary)
                current = os.stat(resolved, follow_symlinks=False)
            except (OSError, RuntimeError, ValueError) as error:
                raise OSError("source path escaped its configured root") from error
            if not _same_file(after, current):
                raise OSError("source path changed during boundary validation")
        return os.fdopen(descriptor, "r", encoding="utf-8", errors="replace")
    except BaseException:
        os.close(descriptor)
        raise


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    if os.name == "nt":
        return left.st_ino != 0 and left.st_ino == right.st_ino
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _stat_signature(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        0 if os.name == "nt" else metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _origin_key(value: str) -> str:
    """Return a lossless, non-exported identity for security-sensitive correlation."""

    return hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()


def _json_depth_is_bounded(value: str) -> bool:
    depth = 0
    in_string = False
    escaped = False
    for character in value:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return False
        elif character in "]}":
            depth -= 1
            if depth < 0:
                return False
    return True


def _json_budget_is_bounded(value: str) -> bool:
    """Bound shallow container cardinality before materializing JSON objects."""

    tokens = 0
    in_string = False
    escaped = False
    primitive_chars = 0
    for character in value:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character in " \t\r\n":
            if primitive_chars:
                tokens += 1
                primitive_chars = 0
        elif character == '"':
            if primitive_chars:
                return False
            in_string = True
            tokens += 1
        elif character in "[{]}:,":
            if primitive_chars:
                tokens += 1
                primitive_chars = 0
            tokens += 1
        else:
            primitive_chars += 1
        if tokens > MAX_JSON_TOKENS:
            return False
    if primitive_chars:
        tokens += 1
    return not in_string and not escaped and tokens <= MAX_JSON_TOKENS


def _load_bounded_json(value: str) -> Any:
    return json.loads(
        value,
        parse_int=_bounded_json_int,
        parse_float=_bounded_json_float,
        parse_constant=_reject_json_constant,
    )


def _bounded_json_int(value: str) -> int:
    if len(value) > MAX_JSON_NUMBER_CHARS:
        raise ValueError("JSON integer is too long")
    return int(value)


def _bounded_json_float(value: str) -> float:
    if len(value) > MAX_JSON_NUMBER_CHARS:
        raise ValueError("JSON number is too long")
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("JSON number must be finite")
    return parsed


def _reject_json_constant(_: str) -> float:
    raise ValueError("non-standard JSON number is not allowed")


@dataclass(slots=True)
class CanonicalRecord:
    session_ref: str
    line: int
    timestamp: str | None
    kind: str
    origin_key: str | None = None
    role: str | None = None
    text: str | None = None
    tool_name: str | None = None
    tool_input: Any = None
    tool_output: Any = None
    call_id: str | None = None
    project_path: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    order: int = 0

    @property
    def location(self) -> str:
        suffix = f"L{self.line}" if self.line > 0 else "current"
        return f"{self.session_ref}#{suffix}"


@dataclass(slots=True)
class AdaptedSessions:
    records: list[CanonicalRecord]
    stats: ScanStats
    diagnostics: list[Diagnostic]


class SessionAdapter:
    """Discover and normalize supported session layouts without writing to them."""

    def __init__(self, root: Path, *, include_unindexed: bool = False):
        self.root = root.expanduser()
        self._root_resolution_failed = self.root.is_symlink()
        try:
            self._root_boundary = (
                self.root.absolute()
                if self._root_resolution_failed
                else self.root.resolve(strict=False)
            )
        except (OSError, RuntimeError):
            self._root_boundary = self.root.absolute()
            self._root_resolution_failed = True
        self.include_unindexed = include_unindexed
        self.stats = ScanStats()
        self._diagnostics: Counter[tuple[str, str, str | None]] = Counter()
        self._fingerprints: set[str] = set()
        self._index: dict[str, str | None] = {}
        self._index_present = False
        self._encountered_session_ids: set[str] = set()
        self._order = 0
        self._source_chars = 0
        self._identity_chars = 0
        self._file_identities: dict[Path, tuple[str | None, str | None]] = {}
        self._file_signatures: dict[Path, tuple[int, int, int, int, int]] = {}
        self._stop_requested = False

    def scan(self) -> AdaptedSessions:
        records: list[CanonicalRecord] = []
        if self._root_resolution_failed:
            self._note(
                "unsafe_source_root",
                "error",
                "The session source root could not be resolved safely.",
            )
            diagnostics = [
                Diagnostic(code=code, severity=severity, detail=detail, count=count)
                for (code, severity, detail), count in sorted(self._diagnostics.items())
            ]
            return AdaptedSessions(records=[], stats=self.stats, diagnostics=diagnostics)
        self._read_indexes()
        files = self._discover_files()
        self.stats.files_seen = len(files)
        if not self.root.is_dir():
            self._note("source_missing", "error", "The session source directory does not exist.")
        full_files, metadata_only_files = self._partition_files(files)
        self.stats.files_fully_scanned = 0
        self.stats.metadata_only_files = 0
        for path in full_files:
            if self._stop_requested:
                break
            self.stats.files_fully_scanned += 1
            records.extend(self._adapt_file(path))
        for path in metadata_only_files:
            if self._stop_requested:
                break
            self.stats.metadata_only_files += 1
            records.extend(self._adapt_metadata_only(path))
            self._note(
                "unindexed_rollout_metadata_only",
                "info",
                "An unindexed rollout contributed metadata but its message history was not scanned.",
            )
        missing_rollouts = set(self._index) - self._encountered_session_ids
        for _ in missing_rollouts:
            self._note(
                "indexed_session_without_rollout",
                "info",
                "An index entry had no discovered rollout file.",
            )
        diagnostics = [
            Diagnostic(code=code, severity=severity, detail=detail, count=count)
            for (code, severity, detail), count in sorted(self._diagnostics.items())
        ]
        return AdaptedSessions(records=records, stats=self.stats, diagnostics=diagnostics)

    def _partition_files(self, files: list[Path]) -> tuple[list[Path], list[Path]]:
        if self.include_unindexed or not self._index_present:
            return files, []
        full: list[Path] = []
        metadata_only: list[Path] = []
        for path in files:
            session_id, _ = self._identity_for(path)
            if session_id is not None and session_id in self._index:
                full.append(path)
            else:
                metadata_only.append(path)
        return full, metadata_only

    def _discover_files(self) -> list[Path]:
        candidates: set[Path] = set()
        entries_seen = 0
        for directory_name in ("sessions", "archived_sessions", "rollouts"):
            directory = self.root / directory_name
            if not self._is_source_directory(directory):
                continue
            stack: list[tuple[Path, int]] = [(directory, 0)]
            while stack:
                current, depth = stack.pop()
                entries: list[tuple[str, bool, bool, bool]] = []
                try:
                    with os.scandir(current) as iterator:
                        for entry in iterator:
                            entries_seen += 1
                            if entries_seen > MAX_DISCOVERY_ENTRIES:
                                self._note(
                                    "source_discovery_budget_exceeded",
                                    "warning",
                                    "Additional source entries were skipped after the traversal safety limit was reached.",
                                )
                                return sorted(candidates, key=lambda item: item.as_posix())
                            try:
                                entries.append(
                                    (
                                        entry.name,
                                        entry.is_symlink(),
                                        entry.is_dir(follow_symlinks=False),
                                        entry.is_file(follow_symlinks=False),
                                    )
                                )
                            except OSError:
                                self._note(
                                    "unreadable_source_entry",
                                    "warning",
                                    "A session source entry could not be inspected.",
                                )
                except OSError:
                    self._note(
                        "unreadable_source_directory",
                        "error",
                        "A session source directory could not be traversed.",
                    )
                    continue

                child_directories: list[Path] = []
                for name, is_symlink, is_directory, is_file in sorted(entries):
                    child = current / name
                    if is_symlink:
                        self._note(
                            "unsafe_source_path",
                            "warning",
                            "A symlinked or out-of-root session source path was skipped.",
                        )
                        continue
                    if is_directory:
                        if depth >= MAX_DISCOVERY_DEPTH:
                            self._note(
                                "source_discovery_depth_exceeded",
                                "warning",
                                "A deeply nested source directory was skipped after the traversal safety limit was reached.",
                            )
                        else:
                            child_directories.append(child)
                        continue
                    if not is_file or not name.endswith(".jsonl"):
                        continue
                    if len(candidates) >= MAX_SOURCE_FILES:
                        self._note(
                            "source_file_budget_exceeded",
                            "warning",
                            "Additional session files were skipped after the safety limit was reached.",
                        )
                        return sorted(candidates, key=lambda item: item.as_posix())
                    if self._is_source_file(child):
                        candidates.add(child)
                stack.extend((child, depth + 1) for child in reversed(child_directories))
        for filename in ("rollout.jsonl", "sessions.jsonl"):
            if len(candidates) >= MAX_SOURCE_FILES:
                self._note(
                    "source_file_budget_exceeded",
                    "warning",
                    "Additional session files were skipped after the safety limit was reached.",
                )
                break
            path = self.root / filename
            if self._is_source_file(path):
                candidates.add(path)
        return sorted(candidates, key=lambda path: path.as_posix())

    def _read_indexes(self) -> None:
        candidates = [self.root / "session_index.jsonl", self.root / "sessions" / "index.jsonl"]
        for path in candidates:
            if path.exists() or path.is_symlink():
                self._index_present = True
            if not self._is_source_file(path):
                continue
            self.stats.index_files_seen += 1
            semantic_snapshot = self._file_semantic_snapshot()
            pending_index: dict[str, str | None] = {}
            pending_records = 0
            stop_after_file = False
            try:
                expected_signature = _stat_signature(os.lstat(path))
                with _open_source_file(
                    path,
                    root_boundary=self._root_boundary,
                    expected_signature=expected_signature,
                ) as handle:
                    consumed = 0
                    physical_records = 0
                    for _, line, line_chars in _bounded_lines(handle, max_chars=MAX_INDEX_CHARS):
                        consumed += line_chars
                        physical_records += 1
                        if physical_records > MAX_INDEX_RECORDS:
                            self._note(
                                "index_record_budget_exceeded",
                                "warning",
                                "Additional session index records were skipped after the safety limit was reached.",
                            )
                            stop_after_file = True
                            break
                        if line is None:
                            self.stats.malformed_records += 1
                            self._note("oversized_index_record", "warning", "An oversized index record was skipped.")
                            continue
                        if not _json_depth_is_bounded(line):
                            self.stats.malformed_records += 1
                            self._note(
                                "json_depth_exceeded",
                                "warning",
                                "A deeply nested index record was skipped.",
                            )
                            continue
                        if not _json_budget_is_bounded(line):
                            self.stats.malformed_records += 1
                            self._note(
                                "json_budget_exceeded",
                                "warning",
                                "An index record exceeded the JSON token safety limit.",
                            )
                            continue
                        try:
                            obj = _load_bounded_json(line)
                        except (ValueError, RecursionError):
                            self.stats.malformed_records += 1
                            self._note("malformed_index_json", "warning", "Malformed index JSONL was skipped.")
                            continue
                        if not isinstance(obj, dict):
                            self.stats.unsupported_records += 1
                            self._note("unsupported_index_record", "warning", "An unsupported index record was skipped.")
                            continue
                        payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else obj
                        session_id = payload.get("id") or payload.get("session_id") or payload.get("thread_id")
                        if not isinstance(session_id, str) or not _INDEX_ID.fullmatch(session_id):
                            self.stats.unsupported_records += 1
                            self._note(
                                "index_id_invalid",
                                "warning",
                                "An index record with a missing or unsafe session id was skipped.",
                            )
                            continue
                        updated = payload.get("updated_at") or payload.get("updatedAt") or payload.get("timestamp")
                        pending_index[session_id] = updated if isinstance(updated, str) else None
                        pending_records += 1
                    if consumed >= MAX_INDEX_CHARS:
                        self._note(
                            "index_size_budget_exceeded",
                            "warning",
                            "Additional session index data was skipped after the safety limit was reached.",
                        )
                    if _stat_signature(os.fstat(handle.fileno())) != expected_signature:
                        raise OSError("session index changed during parsing")
            except OSError:
                self._restore_file_semantic_state(semantic_snapshot)
                self._note("unreadable_index", "error", "A session index could not be read.")
                continue
            self._index.update(pending_index)
            self.stats.index_records += pending_records
            if stop_after_file:
                return

    def _adapt_file(self, path: Path) -> list[CanonicalRecord]:
        fallback_ref = safe_ref(str(path), prefix="s")
        session_id, initial_cwd = self._identity_for(path)
        session_ref = safe_ref(session_id, prefix="s") if session_id else fallback_ref
        origin_key = _origin_key(session_id if session_id else str(path))
        index_timestamp = self._index.get(session_id) if session_id else None
        current_cwd = initial_cwd
        result: list[CanonicalRecord] = []
        pending_fingerprints: set[str] = set()
        pending_stop = False
        semantic_snapshot = self._file_semantic_snapshot()
        try:
            lines = self._candidate_lines(path)
            try:
                for line_number, line in lines:
                    if self._fast_ignored(line):
                        self.stats.unsupported_records += 1
                        continue
                    if not _json_depth_is_bounded(line):
                        self.stats.malformed_records += 1
                        self._note(
                            "json_depth_exceeded",
                            "warning",
                            "A deeply nested JSONL record was skipped.",
                        )
                        continue
                    if not _json_budget_is_bounded(line):
                        self.stats.malformed_records += 1
                        self._note(
                            "json_budget_exceeded",
                            "warning",
                            "A JSONL record exceeded the token safety limit.",
                        )
                        continue
                    try:
                        obj = _load_bounded_json(line)
                    except (ValueError, RecursionError):
                        self.stats.malformed_records += 1
                        self._note("malformed_json", "warning", "Malformed or partial JSONL was skipped.")
                        continue
                    if not isinstance(obj, dict):
                        self.stats.unsupported_records += 1
                        self._note("non_object_record", "warning", "A non-object JSONL record was skipped.")
                        continue
                    if not self._supported_record(obj):
                        self.stats.unsupported_records += 1
                        continue
                    try:
                        fingerprint = hashlib.sha256(
                            json.dumps(
                                obj,
                                sort_keys=True,
                                separators=(",", ":"),
                                ensure_ascii=True,
                            ).encode("ascii")
                        ).hexdigest()
                    except (TypeError, ValueError, RecursionError):
                        self.stats.malformed_records += 1
                        self._note(
                            "unserializable_json",
                            "warning",
                            "A structurally unsafe JSON record was skipped.",
                        )
                        continue
                    deduplication_key = f"{origin_key}:{fingerprint}"
                    if (
                        deduplication_key in self._fingerprints
                        or deduplication_key in pending_fingerprints
                    ):
                        self.stats.duplicate_records += 1
                        continue
                    pending_fingerprints.add(deduplication_key)
                    payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else obj
                    raw_root_type = obj.get("type", payload.get("type", "unknown"))
                    root_type = raw_root_type if isinstance(raw_root_type, str) else "unknown"
                    subtype = payload.get("type")
                    if root_type == "session_meta" or subtype == "session_meta":
                        observed_session_id = (
                            payload.get("id") or payload.get("session_id") or obj.get("session_id")
                        )
                        if session_id is not None and observed_session_id != session_id:
                            raise OSError("source session identity changed during full parsing")
                    if root_type in {"session_meta", "turn_context"}:
                        cwd = payload.get("cwd")
                        if isinstance(cwd, str) and cwd:
                            current_cwd = self._bounded_string(cwd, limit=MAX_METADATA_CHARS)
                    record = self._normalize(
                        obj=obj,
                        payload=payload,
                        root_type=root_type,
                        line=line_number,
                        session_ref=session_ref,
                        origin_key=origin_key,
                        project_path=current_cwd,
                        fallback_timestamp=index_timestamp,
                    )
                    if record is not None:
                        if self.stats.canonical_records + len(result) >= MAX_CANONICAL_RECORDS:
                            self._note(
                                "canonical_record_budget_exceeded",
                                "warning",
                                "Additional canonical records were skipped after the safety limit was reached.",
                            )
                            pending_stop = True
                            break
                        record.order = self._order + len(result) + 1
                        result.append(record)
            finally:
                lines.close()
        except BaseException as error:
            self._restore_file_semantic_state(semantic_snapshot)
            if isinstance(error, OSError):
                self._note("unreadable_file", "error", "A session file could not be read.")
                return []
            raise
        self._fingerprints.update(pending_fingerprints)
        self._order += len(result)
        self.stats.canonical_records += len(result)
        if session_id:
            self._encountered_session_ids.add(session_id)
        if pending_stop:
            self._stop_requested = True
        return result

    def _file_semantic_snapshot(
        self,
    ) -> tuple[int, int, int, int, Counter[tuple[str, str, str | None]], bool]:
        return (
            self.stats.malformed_records,
            self.stats.duplicate_records,
            self.stats.compacted_records,
            self.stats.unsupported_records,
            self._diagnostics.copy(),
            self._stop_requested,
        )

    def _restore_file_semantic_state(
        self,
        snapshot: tuple[
            int,
            int,
            int,
            int,
            Counter[tuple[str, str, str | None]],
            bool,
        ],
    ) -> None:
        (
            self.stats.malformed_records,
            self.stats.duplicate_records,
            self.stats.compacted_records,
            self.stats.unsupported_records,
            diagnostics,
            self._stop_requested,
        ) = snapshot
        self._diagnostics = diagnostics

    def _candidate_lines(self, path: Path):
        remaining = MAX_SOURCE_CHARS - self._source_chars
        if remaining <= 0:
            self._stop_requested = True
            self._note(
                "source_size_budget_exceeded",
                "warning",
                "Additional source data was skipped after the aggregate safety limit was reached.",
            )
            return
        allowance = min(MAX_FILE_CHARS, remaining)
        consumed = 0
        expected_signature = self._file_signatures.get(path)
        if expected_signature is None:
            raise OSError("source identity was not validated")
        with _open_source_file(
            path,
            root_boundary=self._root_boundary,
            expected_signature=expected_signature,
        ) as handle:
            try:
                for line_number, line, line_chars in _bounded_lines(handle, max_chars=allowance):
                    consumed += line_chars
                    self._source_chars += line_chars
                    if self.stats.records_seen >= MAX_SOURCE_RECORDS:
                        self._stop_requested = True
                        self._note(
                            "source_record_budget_exceeded",
                            "warning",
                            "Additional source records were skipped after the safety limit was reached.",
                        )
                        return
                    self.stats.records_seen += 1
                    if line is None:
                        self.stats.malformed_records += 1
                        self._note("oversized_record", "warning", "An oversized JSONL record was skipped.")
                        continue
                    yield line_number, line
            finally:
                if _stat_signature(os.fstat(handle.fileno())) != expected_signature:
                    raise OSError("source file changed during full parsing")
        if consumed >= allowance:
            if allowance == remaining:
                self._stop_requested = True
                self._note(
                    "source_size_budget_exceeded",
                    "warning",
                    "Additional source data was skipped after the aggregate safety limit was reached.",
                )
            else:
                self._note(
                    "file_size_budget_exceeded",
                    "warning",
                    "A session file exceeded the per-file safety limit and was partially scanned.",
                )

    def _adapt_metadata_only(self, path: Path) -> list[CanonicalRecord]:
        selected_record: CanonicalRecord | None = None
        selected_fingerprint: str | None = None
        selected_session_id: str | None = None
        duplicate = False
        semantic_snapshot = self._file_semantic_snapshot()
        try:
            lines = self._candidate_lines(path)
            try:
                for line_number, line in lines:
                    if line_number > 20:
                        break
                    if line is None:
                        self.stats.malformed_records += 1
                        self._note("oversized_record", "warning", "An oversized JSONL record was skipped.")
                        continue
                    if not _json_depth_is_bounded(line):
                        self.stats.malformed_records += 1
                        self._note(
                            "json_depth_exceeded",
                            "warning",
                            "A deeply nested JSONL record was skipped.",
                        )
                        continue
                    if not _json_budget_is_bounded(line):
                        self.stats.malformed_records += 1
                        self._note(
                            "json_budget_exceeded",
                            "warning",
                            "A JSONL record exceeded the token safety limit.",
                        )
                        continue
                    try:
                        obj = _load_bounded_json(line)
                    except (ValueError, RecursionError):
                        self.stats.malformed_records += 1
                        self._note("malformed_json", "warning", "Malformed or partial JSONL was skipped.")
                        continue
                    if not isinstance(obj, dict) or obj.get("type") != "session_meta":
                        continue
                    payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else obj
                    session_id = payload.get("id") or payload.get("session_id") or obj.get("session_id")
                    session_id = session_id if isinstance(session_id, str) and session_id else str(path)
                    session_ref = safe_ref(session_id, prefix="s")
                    origin_key = _origin_key(session_id)
                    try:
                        fingerprint = hashlib.sha256(
                            json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
                        ).hexdigest()
                    except (TypeError, ValueError, RecursionError):
                        self.stats.malformed_records += 1
                        self._note("unserializable_json", "warning", "A structurally unsafe JSON record was skipped.")
                        continue
                    deduplication_key = f"{origin_key}:{fingerprint}"
                    if deduplication_key in self._fingerprints:
                        duplicate = True
                        selected_session_id = session_id
                        break
                    cwd = self._bounded_string(payload.get("cwd"), limit=MAX_METADATA_CHARS)
                    record = self._normalize(
                        obj=obj,
                        payload=payload,
                        root_type="session_meta",
                        line=line_number,
                        session_ref=session_ref,
                        origin_key=origin_key,
                        project_path=cwd,
                        fallback_timestamp=self._index.get(session_id),
                    )
                    if record is not None:
                        selected_record = record
                        selected_fingerprint = deduplication_key
                        selected_session_id = session_id
                        break
            finally:
                lines.close()
        except BaseException as error:
            self._restore_file_semantic_state(semantic_snapshot)
            if isinstance(error, OSError):
                self._note("unreadable_file", "error", "A session file could not be read.")
                return []
            raise
        if selected_session_id:
            self._encountered_session_ids.add(selected_session_id)
        if duplicate:
            self.stats.duplicate_records += 1
            return []
        if selected_record is not None and selected_fingerprint is not None:
            if self.stats.canonical_records >= MAX_CANONICAL_RECORDS:
                self._stop_requested = True
                self._note(
                    "canonical_record_budget_exceeded",
                    "warning",
                    "Additional canonical records were skipped after the safety limit was reached.",
                )
                return []
            self._fingerprints.add(selected_fingerprint)
            self._order += 1
            selected_record.order = self._order
            self.stats.canonical_records += 1
            return [selected_record]
        self._note("metadata_missing", "warning", "An unindexed rollout had no readable session metadata.")
        return []

    def _is_source_directory(self, path: Path) -> bool:
        if not path.exists() and not path.is_symlink():
            return False
        if path.is_symlink() or not path.is_dir() or not self._is_within_root(path):
            self._note(
                "unsafe_source_path",
                "warning",
                "A symlinked or out-of-root session source path was skipped.",
            )
            return False
        return True

    def _is_source_file(self, path: Path) -> bool:
        if not path.exists() and not path.is_symlink():
            return False
        if path.is_symlink() or not path.is_file() or not self._is_within_root(path):
            self._note(
                "unsafe_source_path",
                "warning",
                "A symlinked or out-of-root session source path was skipped.",
            )
            return False
        return True

    def _is_within_root(self, path: Path) -> bool:
        try:
            path.resolve(strict=True).relative_to(self._root_boundary)
        except (OSError, RuntimeError, ValueError):
            return False
        return True

    @staticmethod
    def _file_identity(parsed: list[tuple[int, dict[str, Any], str]]) -> tuple[str | None, str | None]:
        session_id = None
        cwd = None
        for _, obj, _ in parsed:
            payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else obj
            root_type = obj.get("type")
            if root_type == "session_meta" or payload.get("type") == "session_meta":
                candidate = payload.get("id") or payload.get("session_id") or obj.get("session_id")
                if isinstance(candidate, str) and _INDEX_ID.fullmatch(candidate):
                    session_id = candidate
                candidate_cwd = payload.get("cwd") or obj.get("cwd")
                if isinstance(candidate_cwd, str) and candidate_cwd:
                    cwd = candidate_cwd[:MAX_METADATA_CHARS]
                break
        return session_id, cwd

    def _file_identity_from_path(self, path: Path) -> tuple[str | None, str | None]:
        parsed: list[tuple[int, dict[str, Any], str]] = []
        remaining = MAX_IDENTITY_SCAN_CHARS - self._identity_chars
        if remaining <= 0:
            self._note(
                "identity_scan_budget_exceeded",
                "warning",
                "Additional file identities were not inspected after the safety limit was reached.",
            )
            return None, None
        allowance = min(MAX_IDENTITY_CHARS, remaining)
        consumed = 0
        try:
            with _open_source_file(path, root_boundary=self._root_boundary) as handle:
                initial_signature = _stat_signature(os.fstat(handle.fileno()))
                for line_number, line, line_chars in _bounded_lines(handle, max_chars=allowance):
                    consumed += line_chars
                    if line_number > MAX_IDENTITY_LINES:
                        break
                    if line is None:
                        continue
                    if not _json_depth_is_bounded(line):
                        continue
                    if not _json_budget_is_bounded(line):
                        continue
                    try:
                        obj = _load_bounded_json(line)
                    except (ValueError, RecursionError):
                        continue
                    if not isinstance(obj, dict):
                        continue
                    parsed.append((line_number, obj, ""))
                    payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else obj
                    if obj.get("type") == "session_meta" or payload.get("type") == "session_meta":
                        break
                final_signature = _stat_signature(os.fstat(handle.fileno()))
                if final_signature != initial_signature:
                    raise OSError("source file changed during identity selection")
                self._file_signatures[path] = final_signature
        except OSError:
            self._file_signatures.pop(path, None)
            return None, None
        finally:
            self._identity_chars += consumed
        if consumed >= allowance:
            self._note(
                "identity_probe_truncated",
                "warning",
                "A file identity was not found within the bounded metadata prefix.",
            )
        return self._file_identity(parsed)

    def _identity_for(self, path: Path) -> tuple[str | None, str | None]:
        identity = self._file_identities.get(path)
        if identity is None:
            identity = self._file_identity_from_path(path)
            self._file_identities[path] = identity
        return identity

    def _normalize(
        self,
        *,
        obj: dict[str, Any],
        payload: dict[str, Any],
        root_type: str,
        line: int,
        session_ref: str,
        origin_key: str,
        project_path: str | None,
        fallback_timestamp: str | None,
    ) -> CanonicalRecord | None:
        timestamp = (
            self._timestamp(obj.get("timestamp"))
            or self._timestamp(payload.get("timestamp"))
            or self._timestamp(fallback_timestamp)
        )
        subtype = self._string(payload.get("type"))
        base = dict(
            session_ref=session_ref,
            origin_key=origin_key,
            line=line,
            timestamp=timestamp,
            project_path=project_path,
        )

        if root_type == "session_meta" or subtype == "session_meta":
            git = payload.get("git") if isinstance(payload.get("git"), dict) else {}
            return CanonicalRecord(
                kind="session_meta",
                metadata={
                    "branch": self._string(git.get("branch")),
                    "commit_hash": self._string(git.get("commit_hash")),
                    "forked_from": self._string(payload.get("forked_from_id")),
                    "parent_thread": self._string(payload.get("parent_thread_id")),
                    "schema_version": self._string(payload.get("cli_version")),
                },
                **base,
            )

        if root_type == "turn_context":
            return CanonicalRecord(
                kind="turn_context",
                metadata=self._bounded_metadata(payload, "turn_id"),
                **base,
            )

        if root_type == "compacted":
            self.stats.compacted_records += 1
            self._note(
                "compaction_observed",
                "info",
                "A compaction summary was used without replaying replacement history.",
            )
            return CanonicalRecord(
                kind="compaction_summary",
                role="assistant",
                text=self._bounded_string(payload.get("message")),
                metadata=self._bounded_metadata(payload, "window_number"),
                **base,
            )

        if root_type == "response_item":
            if subtype in {"message", "agent_message"}:
                return CanonicalRecord(
                    kind="message",
                    role=self._string(payload.get("role")) or ("assistant" if subtype == "agent_message" else None),
                    text=self._content_text(payload.get("content")),
                    **base,
                )
            if subtype in {"function_call", "custom_tool_call", "tool_search_call"}:
                return CanonicalRecord(
                    kind="tool_call",
                    tool_name=self._string(payload.get("name")),
                    tool_input=self._tool_input(payload.get("arguments", payload.get("input"))),
                    call_id=self._string(payload.get("call_id")) or self._string(payload.get("id")),
                    **base,
                )
            if subtype in {"function_call_output", "custom_tool_call_output", "tool_search_output"}:
                return CanonicalRecord(
                    kind="tool_output",
                    tool_output=self._output_text(payload.get("output", payload.get("result"))),
                    call_id=self._string(payload.get("call_id")) or self._string(payload.get("id")),
                    **base,
                )
            return None

        if root_type == "event_msg":
            if subtype == "user_message":
                return CanonicalRecord(
                    kind="message",
                    role="user",
                    text=self._bounded_string(payload.get("message")) or self._bounded_string(payload.get("text")),
                    **base,
                )
            if subtype == "agent_message":
                return CanonicalRecord(
                    kind="message",
                    role="assistant",
                    text=self._bounded_string(payload.get("message")),
                    **base,
                )
            if subtype in {"turn_aborted", "task_started", "task_complete", "sub_agent_activity"}:
                return CanonicalRecord(
                    kind=subtype,
                    text=self._string(payload.get("reason")),
                    metadata=self._bounded_metadata(
                        payload,
                        "status",
                        "success",
                        "kind",
                        "turn_id",
                        "agent_path",
                    ),
                    **base,
                )
            if subtype in {"patch_apply_end", "mcp_tool_call_end", "image_generation_end"}:
                return CanonicalRecord(
                    kind="tool_result",
                    tool_name=self._string(payload.get("action_name")) or subtype,
                    tool_output=self._output_text(payload.get("result", payload.get("stdout", payload.get("status")))),
                    call_id=self._string(payload.get("call_id")),
                    metadata=self._bounded_metadata(payload, "status", "success"),
                    **base,
                )
            return None

        # Older rollouts sometimes stored message records without a payload envelope.
        if root_type in {"message", "user_message", "assistant_message"} or "role" in payload:
            return CanonicalRecord(
                kind="message",
                role=self._string(payload.get("role")) or ("user" if root_type == "user_message" else "assistant"),
                text=self._content_text(payload.get("content")) or self._bounded_string(payload.get("message")),
                **base,
            )

        self.stats.unsupported_records += 1
        return None

    def _content_text(self, content: Any) -> str | None:
        if isinstance(content, str):
            return self._bounded_string(content)
        if isinstance(content, list):
            parts: list[str] = []
            length = 0
            for index, item in enumerate(content):
                if index >= MAX_CONTENT_ITEMS:
                    self._note("content_item_budget_exceeded", "warning", "Additional content items were skipped.")
                    break
                selected = None
                if isinstance(item, str):
                    selected = item
                elif isinstance(item, dict):
                    text = item.get("text")
                    if isinstance(text, str):
                        selected = text
                if selected:
                    remaining = MAX_TEXT_CHARS - length
                    if remaining <= 0:
                        break
                    selected = selected[:remaining]
                    parts.append(selected)
                    length += len(selected)
                if length >= MAX_TEXT_CHARS:
                    break
            return self._bounded_string("\n".join(parts)) if parts else None
        if isinstance(content, dict):
            return self._bounded_string(content.get("text"))
        return None

    def _output_text(self, value: Any) -> str | None:
        if isinstance(value, str):
            return self._bounded_string(value, limit=MAX_TOOL_OUTPUT_CHARS)
        if isinstance(value, list):
            parts: list[str] = []
            length = 0
            for index, item in enumerate(value):
                if index >= MAX_CONTENT_ITEMS:
                    self._note("content_item_budget_exceeded", "warning", "Additional content items were skipped.")
                    break
                selected = None
                if isinstance(item, str):
                    selected = item
                elif isinstance(item, dict):
                    for key in ("text", "output", "content", "result"):
                        candidate = item.get(key)
                        if isinstance(candidate, str):
                            selected = candidate
                            break
                if selected:
                    remaining = MAX_TOOL_OUTPUT_CHARS - length
                    if remaining <= 0:
                        break
                    selected = selected[:remaining]
                    parts.append(selected)
                    length += len(selected)
                if length >= MAX_TOOL_OUTPUT_CHARS:
                    break
            return self._bounded_string("\n".join(parts), limit=MAX_TOOL_OUTPUT_CHARS) if parts else None
        if isinstance(value, dict):
            selected = {
                key: value[key]
                for key in ("status", "success", "message", "output", "result", "error")
                if key in value and isinstance(value[key], (str, bool, int, float, type(None)))
            }
            try:
                encoded = json.dumps(selected, ensure_ascii=False)
            except (TypeError, ValueError, RecursionError):
                return None
            return self._bounded_string(encoded, limit=MAX_TOOL_OUTPUT_CHARS)
        return self._bounded_string(value, limit=MAX_TOOL_OUTPUT_CHARS)

    def _tool_input(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._bounded_string(value, limit=MAX_TEXT_CHARS)
        if isinstance(value, dict):
            selected: dict[str, str] = {}
            for key in ("cmd", "command", "script"):
                candidate = value.get(key)
                if isinstance(candidate, str):
                    selected[key] = candidate[:MAX_TEXT_CHARS]
            return selected or None
        return None

    def _bounded_string(self, value: Any, *, limit: int = MAX_TEXT_CHARS) -> str | None:
        if not isinstance(value, str) or not value:
            return None
        if len(value) <= limit:
            return value
        self._note("text_truncated", "info", "A large text field was truncated during in-memory extraction.")
        return value[:limit]

    def _bounded_metadata(self, payload: dict[str, Any], *keys: str) -> dict[str, Any]:
        selected: dict[str, Any] = {}
        for key in keys:
            if key not in payload:
                continue
            value = self._metadata_scalar(payload[key])
            if value is not None:
                selected[key] = value
        return selected

    def _metadata_scalar(self, value: Any) -> str | bool | int | float | None:
        if isinstance(value, str):
            return self._bounded_string(value, limit=MAX_METADATA_CHARS)
        if isinstance(value, bool):
            return value
        if isinstance(value, int) and -(2**63) <= value <= 2**63 - 1:
            return value
        if isinstance(value, float) and math.isfinite(value):
            return value
        if value is not None:
            self._note(
                "metadata_value_skipped",
                "warning",
                "A non-scalar or out-of-range metadata value was skipped.",
            )
        return None

    @staticmethod
    def _fast_ignored(line: str) -> bool:
        types = _TYPE_TOKEN.findall(line[:4096])
        if not types:
            return False
        root_type = types[0]
        subtype = types[1] if len(types) > 1 else None
        if root_type in {"world_state", "inter_agent_communication_metadata"}:
            return True
        if root_type == "event_msg" and subtype in _IGNORED_EVENT_TYPES:
            return True
        if root_type == "response_item" and subtype in _IGNORED_RESPONSE_TYPES:
            return True
        return False

    @staticmethod
    def _supported_record(obj: dict[str, Any]) -> bool:
        payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else obj
        root_type = obj.get("type")
        subtype = payload.get("type")
        if isinstance(root_type, str) and root_type in {
            "world_state",
            "inter_agent_communication_metadata",
        }:
            return False
        if root_type == "event_msg" and isinstance(subtype, str) and subtype in _IGNORED_EVENT_TYPES:
            return False
        if (
            root_type == "response_item"
            and isinstance(subtype, str)
            and subtype in _IGNORED_RESPONSE_TYPES
        ):
            return False
        return True

    def _string(self, value: Any) -> str | None:
        return self._bounded_string(value, limit=MAX_METADATA_CHARS)

    @staticmethod
    def _timestamp(value: Any) -> str | None:
        if not isinstance(value, str) or not value or len(value) > 80:
            return None
        candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except (ValueError, OverflowError):
            return None

    def _note(self, code: str, severity: str, detail: str | None = None) -> None:
        self._diagnostics[(code, severity, detail)] += 1
