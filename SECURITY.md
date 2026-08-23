# Security Policy

## Supported versions

Until the first stable release, security fixes are made on the latest published `0.x` version only.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Email lim@limsumin.com with:

- the affected version or commit;
- a minimal synthetic reproduction or a precise description of the failure;
- the operating system and Python version;
- the likely impact; and
- any suggested mitigation.

Do not include real session records, credentials, private paths, or unnecessary personal
information. You should receive an acknowledgement within seven days. A fix timeline will depend
on severity and compatibility impact.

## Scope

Relevant reports include reading through an unsafe source path, modifying source records,
following an unintended symlink, writing a snapshot inside the source tree, unsafe snapshot file
replacement or permissions, and disclosure of credentials, identities, source paths, or raw
messages through generated output.

WorkLedger is a privacy-conscious reporting tool, not a security boundary. It reads files and runs
read-only Git commands with the invoking user's existing permissions only when `--git-probe` is
explicitly selected. Repository probing ignores Git-specific environment overrides and disables
fsmonitor, hooks, optional locks, credential helpers, and terminal prompts. Relative, network-style,
symlinked, reparse-point, and gitfile-indirected repository paths are not probed. Worktree status is
not inspected, preventing repository-configured clean or process filters from running. The validated
repository path identity is checked again around branch and HEAD reads so replacement paths are
discarded rather than reported.

Parsing, correlation, cache loading, and Git probing have fixed resource ceilings. A ceiling produces
a diagnostic and safe partial result, or an invalid-cache miss, rather than silently continuing.
Masking and Markdown escaping reduce accidental disclosure but cannot recognize every secret that
arbitrary prose may contain. Review generated output before sharing it.

Secure derived snapshots currently require POSIX directory-descriptor and no-follow semantics. On
other platforms the CLI reports caching as unsupported and continues with an in-memory scan.
