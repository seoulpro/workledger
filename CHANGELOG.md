# Changelog

This file records notable user-visible changes to WorkLedger.

## [Unreleased]

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

[Unreleased]: https://github.com/seoulpro/workledger/compare/v0.1.0a1...HEAD
[0.1.0a1]: https://github.com/seoulpro/workledger/releases/tag/v0.1.0a1
