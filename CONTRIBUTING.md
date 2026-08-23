# Contributing

Bug reports, focused fixes, and narrowly scoped improvements are welcome. Please open an issue
before changing the extraction model, adding a session layout, or altering the CLI or JSON schema
so compatibility and privacy constraints can be discussed first.

## Development

WorkLedger requires Python 3.10 or newer and has no runtime dependencies.

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python scripts/evaluate.py
python -m pip install ".[test]"
python -m coverage run -m unittest discover -s tests -v
python -m coverage report
```

Add tests for behavior changes. Fixtures must be synthetic and must not contain copied session
records, credentials, personal paths, or other private data. Changes to extraction rules should
also update the expected findings and keep the evaluation results explicit.

To inspect the distributions that would be published:

```sh
python -m pip install build twine
python -m build
python -m twine check dist/*
```

## Compatibility and privacy

CLI flags, exit codes, JSON fields, schema versions, evidence references, cache contents, and
source-discovery rules are compatibility-sensitive. Describe changes to these surfaces in the
pull request and update the changelog when users would notice them.

Source records must remain read-only. Generated output and snapshots must not expose full source
paths, session identifiers, raw messages, tool output, or known credential formats. A change that
widens retained text or reads a new source needs tests for its privacy boundary and malformed input.

Keep commits focused and explain the user-visible reason for each change. By contributing, you
agree that your contribution may be distributed under the MIT License included with this project.
