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
read-only Git commands with the invoking user's existing permissions. Its masking rules reduce
accidental disclosure but cannot recognize every secret that arbitrary prose may contain. Review
generated output before sharing it.
