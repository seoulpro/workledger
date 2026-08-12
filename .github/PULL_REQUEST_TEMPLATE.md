## Summary

<!-- What this change does and why. Link the issue it resolves, if any. -->

## Verification

<!-- List the commands or checks used to verify the change. -->

## Checklist

- [ ] Tests cover the changed behavior and use only synthetic data.
- [ ] `PYTHONPATH=src python -m unittest discover -s tests -v` passes.
- [ ] `PYTHONPATH=src python scripts/evaluate.py` passes when extraction behavior changes.
- [ ] Source records remain read-only and generated output preserves the documented privacy boundary.
- [ ] CLI, JSON, schema, cache, or source-discovery compatibility effects are described above.
- [ ] User-visible changes update the changelog and documentation.
