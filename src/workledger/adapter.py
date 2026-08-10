"""Version-tolerant, read-only adapters for Codex JSONL session records."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator, TextIO

from .model import Diagnostic, ScanStats
from .redact import safe_ref


MAX_LINE_CHARS = 4 * 1024 * 1024
MAX_TEXT_CHARS = 256 * 1024
MAX_TOOL_OUTPUT_CHARS = 512 * 1024
_TYPE_TOKEN = re.compile(r'"type"\s*:\s*"([^"\\]+)"')
_UUID_IN_NAME = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
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


def _bounded_lines(handle: TextIO) -> Iterator[tuple[int, str | None]]:
    line_number = 0
    while True:
        chunk = handle.readline(MAX_LINE_CHARS + 1)
        if not chunk:
            return
        line_number += 1
        if len(chunk) > MAX_LINE_CHARS:
            while chunk and not chunk.endswith("\n"):
                chunk = handle.readline(MAX_LINE_CHARS + 1)
            yield line_number, None
            continue
        yield line_number, chunk


@dataclass(slots=True)
class CanonicalRecord:
    session_ref: str
    line: int
    timestamp: str | None
    kind: str
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
        self._root_boundary = self.root.resolve(strict=False)
        self.include_unindexed = include_unindexed
        self.stats = ScanStats()
        self._diagnostics: Counter[tuple[str, str, str | None]] = Counter()
        self._fingerprints: set[str] = set()
        self._index: dict[str, str | None] = {}
        self._encountered_session_ids: set[str] = set()
        self._order = 0

    def scan(self) -> AdaptedSessions:
        records: list[CanonicalRecord] = []
        self._read_indexes()
        files = self._discover_files()
        self.stats.files_seen = len(files)
        if not self.root.is_dir():
            self._note("source_missing", "error", "The session source directory does not exist.")
        full_files, metadata_only_files = self._partition_files(files)
        self.stats.files_fully_scanned = len(full_files)
        self.stats.metadata_only_files = len(metadata_only_files)
        for path in full_files:
            records.extend(self._adapt_file(path))
        for path in metadata_only_files:
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
        if self.include_unindexed or not self._index:
            return files, []
        full: list[Path] = []
        metadata_only: list[Path] = []
        indexed_ids = tuple(self._index)
        for path in files:
            if any(session_id in path.name for session_id in indexed_ids):
                full.append(path)
            elif _UUID_IN_NAME.search(path.name):
                metadata_only.append(path)
            else:
                # Legacy layouts and synthetic sources may not encode an id in the filename.
                full.append(path)
        return full, metadata_only

    def _discover_files(self) -> list[Path]:
        candidates: set[Path] = set()
        for directory_name in ("sessions", "archived_sessions", "rollouts"):
            directory = self.root / directory_name
            if self._is_source_directory(directory):
                candidates.update(
                    path for path in directory.rglob("*.jsonl") if self._is_source_file(path)
                )
        for filename in ("rollout.jsonl", "sessions.jsonl"):
            path = self.root / filename
            if self._is_source_file(path):
                candidates.add(path)
        return sorted(candidates, key=lambda path: path.as_posix())

    def _read_indexes(self) -> None:
        candidates = [self.root / "session_index.jsonl", self.root / "sessions" / "index.jsonl"]
        for path in candidates:
            if not self._is_source_file(path):
                continue
            self.stats.index_files_seen += 1
            try:
                with path.open("r", encoding="utf-8", errors="replace") as handle:
                    for _, line in _bounded_lines(handle):
                        if line is None:
                            self.stats.malformed_records += 1
                            self._note("oversized_index_record", "warning", "An oversized index record was skipped.")
                            continue
                        try:
                            obj = json.loads(line)
                        except json.JSONDecodeError:
                            self.stats.malformed_records += 1
                            self._note("malformed_index_json", "warning", "Malformed index JSONL was skipped.")
                            continue
                        if not isinstance(obj, dict):
                            self.stats.unsupported_records += 1
                            self._note("unsupported_index_record", "warning", "An unsupported index record was skipped.")
                            continue
                        payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else obj
                        session_id = payload.get("id") or payload.get("session_id") or payload.get("thread_id")
                        if not isinstance(session_id, str) or not session_id:
                            self.stats.unsupported_records += 1
                            self._note("index_id_missing", "warning", "An index record without a session id was skipped.")
                            continue
                        updated = payload.get("updated_at") or payload.get("updatedAt") or payload.get("timestamp")
                        self._index[session_id] = updated if isinstance(updated, str) else None
                        self.stats.index_records += 1
            except OSError:
                self._note("unreadable_index", "error", "A session index could not be read.")

    def _adapt_file(self, path: Path) -> list[CanonicalRecord]:
        parsed: list[tuple[int, dict[str, Any], str]] = []
        fallback_ref = safe_ref(str(path), prefix="s")
        try:
            for line_number, line in self._candidate_lines(path):
                if self._fast_ignored(line):
                    self.stats.unsupported_records += 1
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
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
                fingerprint = hashlib.sha256(
                    json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                ).hexdigest()
                parsed.append((line_number, obj, fingerprint))
        except OSError:
            self._note("unreadable_file", "error", "A session file could not be read.")
            return []

        session_id, initial_cwd = self._file_identity(parsed)
        if session_id:
            self._encountered_session_ids.add(session_id)
        session_ref = safe_ref(session_id, prefix="s") if session_id else fallback_ref
        index_timestamp = self._index.get(session_id) if session_id else None
        current_cwd = initial_cwd
        result: list[CanonicalRecord] = []
        for line_number, obj, fingerprint in parsed:
            deduplication_key = f"{session_ref}:{fingerprint}"
            if deduplication_key in self._fingerprints:
                self.stats.duplicate_records += 1
                continue
            self._fingerprints.add(deduplication_key)
            payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else obj
            root_type = str(obj.get("type", payload.get("type", "unknown")))
            if root_type in {"session_meta", "turn_context"}:
                cwd = payload.get("cwd")
                if isinstance(cwd, str) and cwd:
                    current_cwd = cwd
            record = self._normalize(
                obj=obj,
                payload=payload,
                root_type=root_type,
                line=line_number,
                session_ref=session_ref,
                project_path=current_cwd,
                fallback_timestamp=index_timestamp,
            )
            if record is not None:
                self._order += 1
                record.order = self._order
                result.append(record)
                self.stats.canonical_records += 1
        return result

    def _candidate_lines(self, path: Path):
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line_number, line in _bounded_lines(handle):
                self.stats.records_seen += 1
                if line is None:
                    self.stats.malformed_records += 1
                    self._note("oversized_record", "warning", "An oversized JSONL record was skipped.")
                    continue
                yield line_number, line

    def _adapt_metadata_only(self, path: Path) -> list[CanonicalRecord]:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line_number, line in _bounded_lines(handle):
                    self.stats.records_seen += 1
                    if line_number > 20:
                        break
                    if line is None:
                        self.stats.malformed_records += 1
                        self._note("oversized_record", "warning", "An oversized JSONL record was skipped.")
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        self.stats.malformed_records += 1
                        self._note("malformed_json", "warning", "Malformed or partial JSONL was skipped.")
                        continue
                    if not isinstance(obj, dict) or obj.get("type") != "session_meta":
                        continue
                    payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else obj
                    session_id = payload.get("id") or payload.get("session_id") or obj.get("session_id")
                    session_id = session_id if isinstance(session_id, str) and session_id else str(path)
                    self._encountered_session_ids.add(session_id)
                    session_ref = safe_ref(session_id, prefix="s")
                    fingerprint = hashlib.sha256(
                        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                    ).hexdigest()
                    deduplication_key = f"{session_ref}:{fingerprint}"
                    if deduplication_key in self._fingerprints:
                        self.stats.duplicate_records += 1
                        return []
                    self._fingerprints.add(deduplication_key)
                    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
                    record = self._normalize(
                        obj=obj,
                        payload=payload,
                        root_type="session_meta",
                        line=line_number,
                        session_ref=session_ref,
                        project_path=cwd,
                        fallback_timestamp=self._index.get(session_id),
                    )
                    if record is None:
                        return []
                    self._order += 1
                    record.order = self._order
                    self.stats.canonical_records += 1
                    return [record]
        except OSError:
            self._note("unreadable_file", "error", "A session file could not be read.")
            return []
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
                if isinstance(candidate, str) and candidate:
                    session_id = candidate
                candidate_cwd = payload.get("cwd") or obj.get("cwd")
                if isinstance(candidate_cwd, str) and candidate_cwd:
                    cwd = candidate_cwd
                break
        return session_id, cwd

    def _normalize(
        self,
        *,
        obj: dict[str, Any],
        payload: dict[str, Any],
        root_type: str,
        line: int,
        session_ref: str,
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
            return CanonicalRecord(kind="turn_context", metadata={"turn_id": payload.get("turn_id")}, **base)

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
                metadata={"window_number": payload.get("window_number")},
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
                    metadata={
                        key: payload.get(key)
                        for key in ("status", "success", "kind", "turn_id", "agent_path")
                        if key in payload
                    },
                    **base,
                )
            if subtype in {"patch_apply_end", "mcp_tool_call_end", "image_generation_end"}:
                return CanonicalRecord(
                    kind="tool_result",
                    tool_name=self._string(payload.get("action_name")) or subtype,
                    tool_output=self._output_text(payload.get("result", payload.get("stdout", payload.get("status")))),
                    call_id=self._string(payload.get("call_id")),
                    metadata={"status": payload.get("status"), "success": payload.get("success")},
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
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    text = item.get("text")
                    if isinstance(text, str):
                        parts.append(text)
                if sum(map(len, parts)) >= MAX_TEXT_CHARS:
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
            for item in value:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    for key in ("text", "output", "content", "result"):
                        candidate = item.get(key)
                        if isinstance(candidate, str):
                            parts.append(candidate)
                            break
                if sum(map(len, parts)) >= MAX_TOOL_OUTPUT_CHARS:
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
            except (TypeError, ValueError):
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
        if root_type in {"world_state", "inter_agent_communication_metadata"}:
            return False
        if root_type == "event_msg" and subtype in _IGNORED_EVENT_TYPES:
            return False
        if root_type == "response_item" and subtype in _IGNORED_RESPONSE_TYPES:
            return False
        return True

    @staticmethod
    def _string(value: Any) -> str | None:
        return value if isinstance(value, str) and value else None

    @staticmethod
    def _timestamp(value: Any) -> str | None:
        if not isinstance(value, str) or not value or len(value) > 80:
            return None
        candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            datetime.fromisoformat(candidate)
        except ValueError:
            return None
        return value

    def _note(self, code: str, severity: str, detail: str | None = None) -> None:
        self._diagnostics[(code, severity, detail)] += 1
