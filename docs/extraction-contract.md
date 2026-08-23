# Extraction contract

This document defines what the WorkLedger MVP may infer, how it reduces observations into current
state, and what must remain visible to a caller.

## 1. Input boundary

The adapter may read only files selected beneath the configured source root:

- `session_index.jsonl` and the legacy `sessions/index.jsonl`;
- JSONL beneath `sessions`, `archived_sessions`, and `rollouts`;
- the legacy root files `rollout.jsonl` and `sessions.jsonl`.

Discovery is read-only. Selected inputs are reopened through one descriptor, must still be regular
files, and do not follow the final symbolic link where the platform supports that guarantee. The
full file signature used during index selection must still match when full parsing begins and after
parsing completes, the selected session identity is revalidated in the full pass, and the opened
descriptor is rechecked against the configured root. Unknown files are ignored. A bad line does not
invalidate valid lines in the same file. Lines over the safety limit are skipped. Index titles are
never included in the canonical model. A present but rejected index never broadens the default scan
to message histories that would otherwise remain metadata-only.

Discovery is iterative and parsing is streamed under fixed depth, entry, file, character,
physical-record, and canonical-record budgets. Individual content arrays, candidate generation,
fuzzy correlation, and the number of final findings are also bounded. A reached limit is visible as
a source-quality diagnostic and produces a safe partial report.

When an index exists, its session identities define the default full-scan set. Rollouts whose UUID
is absent from the index contribute their first readable session-metadata record only. This preserves
fork, project, branch, and starting-commit observations without forcing every command to parse large
background histories. The output reports this reduction, and `--include-unindexed` opts into a full
scan. Every candidate rollout is checked against its bounded session-metadata prefix using exact
identity comparison; filenames cannot authorize a full scan. Files without a validated indexed
identity also remain metadata-only unless exhaustive scanning is explicitly selected.

## 2. Canonical observation

An accepted record becomes a transient canonical observation with these fields:

| Field | Meaning |
|---|---|
| `session_ref` | one-way, bounded session reference |
| `origin_key` | non-exported, full collision-resistant identity for deduplication and correlation |
| `line` | source JSONL line number |
| `timestamp` | observed source timestamp or compatible index fallback, normalized to UTC |
| `kind` | normalized message, tool, lifecycle, metadata, compaction, or repository kind |
| `role` | user or assistant when applicable |
| `text` | transient message text; never serialized as a canonical log |
| `call_id` | transient key for matching a tool call with its result |
| `project_path` | transient grouping/probing value; never serialized |
| `metadata` | allowlisted fields such as Git branch, commit, status, or parent relation |

The adapter hashes each complete parsed record for duplicate detection without retaining a parsed
copy of the whole file. A duplicate is removed only when its hash and collision-resistant internal
origin identity both match. The short `session_ref` remains display-only. This permits identical
events in distinct sessions while collapsing replayed events across rollout files belonging to one
session.

## 3. Candidate facts

Extractors turn canonical observations into candidates. Each candidate must have:

- one category and one valid status;
- a bounded, redacted summary;
- a normalized subject used only for correlation;
- a confidence value;
- one evidence pointer, timestamp, evidence kind, and optional bounded redacted excerpt.

Evidence strength is ordered as follows:

1. `1.00`: a current read-only repository probe;
2. `0.94–0.99`: structured session metadata or a matched tool result with a recognizable outcome;
3. `0.86–0.94`: an explicit status marker in a message;
4. `0.60–0.78`: natural-language heuristics, unclear tool outcomes, aborted turns, and compaction
   summaries.

These ranges are policy weights, not calibrated probabilities.

Messages from users contribute only explicit markers. Natural-language heuristics are restricted to
assistant messages so that a requested outcome is less likely to be mistaken for completed work.
Raw commands and raw tool output are never used as evidence excerpts.

## 4. Correlation and reduction

Candidates are ordered by normalized UTC timestamp and then by source order. Tool calls and results
correlate only when both their full internal origin identity and call identifier match, and a result
consumes its matching call. Orphan outputs cannot independently assert a commit or deployment.
Exact normalized subjects correlate. Tasks, approvals, blockers, and deployments may also correlate
when their subject-token Jaccard similarity is at least `0.72`. Fuzzy matching considers only a
bounded recent window within the same category, preventing correlation cost from growing
quadratically.

For a correlated item, the latest candidate replaces status, summary, and confidence while retaining
up to six recent evidence pointers. Thus `TODO: add tests` followed by `DONE: add tests` becomes one
`done` finding rather than two contradictory findings. A weak or dissimilar match remains separate;
the reducer does not guess that it resolves another item.

Compaction replacement history is not replayed because it can duplicate prior messages. Only the
compaction summary is eligible for lower-confidence extraction, and the scan reports a source-quality
diagnostic whenever this happens.

## 5. Current repository facts

Git probing is disabled by default. When explicitly enabled and a recorded working directory is an
absolute local path inside a standard Git worktree, a bounded helper first rejects symlinked or
reparse-point path components and `.git` file indirection. The optional probe then runs:

- `git rev-parse --show-toplevel`;
- `git branch --show-current`;
- `git rev-parse HEAD`.

Relative, UNC, other network-style paths, linked worktrees, and gitfile-based submodules are not
probed. The subprocess environment removes inherited `GIT_*` overrides, disables optional locks,
global and system configuration, fsmonitor, hooks, credential helpers, and terminal prompts, and
enforces per-command and aggregate wall-clock timeouts. Every subprocess has a fixed stdout byte
ceiling and runs in an isolated process group on POSIX. Worktree status is deliberately not queried,
because it can invoke repository-configured content filters; commit evidence therefore records
cleanliness as unknown. Root resolution and state inspection share a repository-count ceiling. No
commits, fetches, pushes, deployments, or remote API calls are performed. Probe evidence is marked
`repository_probe` and located at an opaque `repo-…#current` reference.

## 6. Output contract

JSON output has `schema_version: 1`. Every inferred fact exposes its confidence and evidence. Source
quality counters distinguish records read, canonical records, malformed records, duplicates,
compactions, and unsupported records.

No output field may contain a configured source root, full working directory, session filename,
session title, raw prompt, raw response, raw command, or raw tool output. Excerpts pass through the
default redactor and length bound before entering the serializable model. Terminal and
bidirectional controls are removed, common structured secrets and path forms are masked, and dynamic
Markdown values are escaped before human-readable rendering.

Deployment findings describe historical observations only. Without provider access, WorkLedger must
not label a deployment as currently healthy.

## 7. Derived snapshot contract

The source tree remains read-only. A successful scan may atomically write WorkLedger-owned state
outside the source root. The snapshot contains only the serializable report defined above and never
contains canonical observations, raw messages, raw tool input or output, session titles, source
filenames, or working directories.

The snapshot key combines a one-way source reference with the Git-probe and unindexed-rollout
options. A mismatched or malformed snapshot is ignored. Snapshot directories use user-only `0700`
permissions and files use `0600`; a state directory inside the source root is rejected. Cache reads
open a single descriptor without following the final symbolic link, require a regular size-bounded
file, preflight JSON depth, tokens, string sizes, and number sizes, and enforce report structure and
cardinality. Secure snapshots require POSIX descriptor semantics. On other platforms caching reports
`unsupported` and scanning continues without it. On POSIX, state-directory components are created
relative to bound no-follow descriptors and the final verified, user-owned directory descriptor is
retained through temporary-file creation and atomic replacement. Cache reads do not imply freshness:
`generated_at` identifies the observation time, and an explicit scan or `--refresh` replaces the
snapshot.
