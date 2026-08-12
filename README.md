# WorkLedger

WorkLedger is a local-first, read-only CLI that reconstructs project state from Codex session
records. It focuses on decisions, unfinished tasks, approvals, blockers, work branches, commits,
and deployments instead of presenting a chronological chat transcript.

**Status: experimental `0.1.0a1`.** The extraction contract and privacy boundary are usable, but
natural-language accuracy has not been calibrated on real-world labeled data. Treat findings as
reviewable leads, not authoritative project state.

WorkLedger does not send messages to other tasks, alter task metadata, archive or pin tasks, or
upload prompts and responses. Source records are always read-only. WorkLedger can persist its own
derived, redacted scan snapshot so repeated queries do not need to parse the complete history.

## Install

WorkLedger requires Python 3.10 or newer and has no runtime dependencies.

```bash
python -m pip install session-workledger==0.1.0a1
```

From a source checkout, install it in editable mode or run it directly:

```bash
python -m pip install -e .
PYTHONPATH=src python -m workledger scan
```

## Commands

```bash
workledger scan
workledger projects
workledger project alpha
workledger unfinished
workledger unfinished --json
```

By default, WorkLedger reads the local Codex data directory. Use `--root` to scan a compatible
directory elsewhere and `--no-git-probe` to skip current Git verification. When a session index is
present, indexed rollouts are scanned fully while unindexed rollout files contribute session and Git
metadata only. Use `--include-unindexed` for an exhaustive scan of their message history:

```bash
workledger scan --root ./synthetic-session-data --no-git-probe
workledger scan --include-unindexed
workledger project alpha --json
workledger unfinished --refresh
workledger projects --no-cache
```

Human-readable output is Markdown that remains legible in a terminal. `--json` emits a stable
top-level `schema_version`, `cache_status`, project records, confidence values, and evidence objects.

### Derived snapshots

`workledger scan` always reads the source and refreshes a derived snapshot. `projects`, `project`,
and `unfinished` reuse that snapshot when the source root and scan options match. `--refresh` forces
a new scan; `--no-cache` disables both reading and writing the snapshot.

The default state directory follows `XDG_STATE_HOME`, falling back to
`~/.local/state/workledger`. `WORKLEDGER_STATE_HOME` overrides it. Snapshot filenames contain only a
one-way source reference. Their contents are the same redacted `ScanReport` exposed by JSON output,
not raw messages, commands, session titles, source filenames, or working directories. Directories
are created with mode `0700` and files with mode `0600`. A configured state directory inside the
session source is rejected.

## State model

Every finding has a category, category-specific status, summary, confidence from `0.0` to `1.0`,
and one or more evidence pointers.

| Category | Statuses used by the MVP | Considered unfinished |
|---|---|---|
| `decision` | `accepted` | no |
| `task` | `open`, `done`, `unknown` | `open`, `unknown` |
| `approval` | `pending`, `granted` | `pending` |
| `blocker` | `active`, `resolved` | `active` |
| `branch` | `observed`, `current` | no |
| `commit` | `observed`, `attempted`, `verified`, `failed` | no |
| `deployment` | `pending`, `attempted`, `succeeded`, `failed`, `unknown` | all except `succeeded` |

An evidence pointer looks like `s-1a2b3c4d5e#L42`. The prefix is a one-way reference derived from
the session identity, and the suffix is the JSONL line. Neither the source filename nor its
absolute path is emitted.

The complete extraction and reduction contract is documented in
[`docs/extraction-contract.md`](https://github.com/seoulpro/workledger/blob/main/docs/extraction-contract.md).

## Extraction behavior

The MVP recognizes explicit English and Korean markers such as `DECISION:`, `TODO:`, `DONE:`,
`APPROVAL PENDING:`, `BLOCKED:`, and their corresponding resolved forms. It also uses conservative
natural-language heuristics at lower confidence.

Structured session metadata and tool results can provide stronger evidence:

- session Git metadata records the branch and commit observed when a session began;
- matching tool calls and outputs distinguish commit or deployment attempts from reported success;
- a live repository probe verifies the current branch, HEAD, and clean/dirty worktree using
  read-only Git commands with optional locking disabled;
- a compaction summary may contribute findings, but its confidence is reduced and replacement
  history is not replayed;
- duplicate records from multiple rollout files are removed only within the same session identity.

Index-first scanning keeps the default useful on large histories. Metadata-only rollouts are counted
in `stats.metadata_only_files` and reported with an `unindexed_rollout_metadata_only` diagnostic, so
reduced coverage is explicit rather than silent.

The adapter accepts payload-enveloped records, older direct message records, current and legacy
session identifiers, multiple rollout directories, active and archived sessions, and both current
and older index timestamp fields. Malformed, partial, oversized, unknown, and missing records are
counted as source-quality diagnostics rather than stopping the scan.

## Privacy and read-only guarantees

WorkLedger retains only bounded excerpts in its output. Before emission it masks common API keys,
tokens, authorization values, passwords, cookies, email addresses, personal home paths, UUIDs,
long opaque strings, and sensitive URL parameters. Project identity is derived from a directory
basename; the full working directory is used only transiently for grouping and optional local Git
verification.

The CLI performs no network requests. It never writes session data and has no command capable of
changing another task. Raw messages and tool output are parsed in process and only redacted findings
enter the derived snapshot. Synthetic JSONL is used by the test suite; real conversation content is
not included in the repository.

Masking is defense in depth, not a proof that arbitrary prose contains no sensitive information.
Review machine-readable output before sharing it. WorkLedger does not protect against another local
process that can read the user's files, a compromised account, or deliberately sensitive prose that
does not match its masking rules.

## Accuracy limits

WorkLedger reconstructs claims from incomplete event logs; it is not a source of ground truth for
all project state. Confidence describes the strength of the observed evidence, not the probability
that a project claim is correct.

- Natural-language findings may be false positives or may fail to correlate with a later update.
- Compaction can omit detail. The MVP uses only its summary and reports that choice as a diagnostic.
- A successful historical deployment result does not prove that a service is currently healthy.
  The MVP does not contact deployment providers.
- Current Git verification is available only when the recorded working directory still resolves to
  a local repository. An empty repository has no verifiable HEAD.
- Session titles are intentionally ignored because they may contain prompt text.
- Project basenames can collide. Collisions receive a short opaque suffix and should be selected by
  their displayed key.
- A snapshot is intentionally stale until `workledger scan` or `--refresh` runs again. Its
  `generated_at` and `cache_status` fields make that boundary visible.
- Cold scans of very large archives can take substantial time. Derived snapshots improve repeated
  queries but are not yet an incremental per-file index.

## Synthetic evaluation

The repository includes exact expected findings for its synthetic current, legacy, duplicate,
compacted, malformed, and multi-rollout cases:

```bash
PYTHONPATH=src python scripts/evaluate.py
```

The current fixture scores precision `1.0000`, recall `1.0000`, and F1 `1.0000`. These numbers are a
regression gate for the labeled synthetic examples only. They are not a claim about accuracy on real
session histories.

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

All fixtures under `tests/fixtures` are synthetic.

## License

MIT
