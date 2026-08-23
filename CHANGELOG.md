# Changelog

This file records notable user-visible changes to WorkLedger.

## [Unreleased]

## [0.1.0a2] - 2026-08-23

### Changed

- Make live Git verification explicit with `--git-probe`; the default scan no longer executes Git.
- Stream session records instead of retaining each parsed file and bound discovery, parsing,
  candidate correlation, findings, and repository probes.
- Normalize accepted timestamps to UTC before activity ordering and state reduction.
- Return exit status `1` when source diagnostics contain an error.
- Report repository cleanliness as unknown; live probes now verify only branch and HEAD.
- Treat secure derived snapshots as POSIX-only and expose `cache_status: "unsupported"` elsewhere.

### Security

- Disable repository fsmonitor and hooks, clear inherited Git overrides, suppress credential
  helpers and prompts, reject network, symlink, reparse-point and gitfile redirection, bound every
  subprocess output, reject unencodable paths, bind validated repository identities through branch
  and HEAD reads, and terminate timed-out POSIX process groups.
- Remove worktree-status probing so repository-configured content filters cannot execute.
- Scope tool call/result matching to a collision-resistant internal session identity, consume each
  matched call, and ignore orphan results for high-confidence state.
- Reject unsafe index identifiers, validate indexed rollout selection against its actual metadata
  identity exactly, commit index selection only after a stable descriptor signature is verified,
  fail closed when an index is rejected, bind full parsing to a stable file signature, reject
  final-component source/cache symbolic links, and bound iterative discovery.
- Reject excessive cache depth, token count, string size, number size, cardinality, and invalid
  scalar values before or during materialization.
- Bind POSIX snapshot directory creation, temporary writes, and replacement to verified descriptors,
  and reject filesystem-equivalent aliases that would place state inside the source tree.
- Expand secret and path masking across quoted keys, unquoted scalars, escaped quoted values, and
  empty-user URI credentials; keep matching linear, remove terminal and bidirectional controls, and
  neutralize Markdown character references and table delimiters.

### Quality

- Add malformed-input, resource-budget, cache, cross-session, Git-hook, redaction, and rendering
  regression tests; enforce branch coverage and add weekly CodeQL analysis.

## [0.1.0a1] - 2026-08-12

### Added

- Local-first reconstruction of project decisions, tasks, approvals, blockers, commits, and
  deployments from session records.
- Markdown and JSON output for project listings, individual ledgers, and unfinished work.
- Index-aware scanning across current, archived, and legacy session layouts.
- Read-only Git state verification with optional probing.
- Private derived snapshots with source identity hashing and restrictive file permissions.
- Synthetic fixtures and an exact precision and recall regression check.

### Security

- Reject symlinked and out-of-root session sources.
- Bound physical JSONL reads before parsing oversized records.
- Mask common provider tokens and sensitive URL parameters in retained excerpts.

[Unreleased]: https://github.com/seoulpro/workledger/compare/v0.1.0a2...HEAD
[0.1.0a2]: https://github.com/seoulpro/workledger/releases/tag/v0.1.0a2
[0.1.0a1]: https://github.com/seoulpro/workledger/releases/tag/v0.1.0a1
