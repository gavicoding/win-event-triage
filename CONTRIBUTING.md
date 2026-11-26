# Contributing

1. Preserve Windows PowerShell 5.1 compatibility in `WinEventTriage/WinEventTriage.psm1` (no `?:`, no `??`, no `-AsHashtable`) and ensure `PSScriptAnalyzer` passes with 0 errors.
2. Keep zero third-party runtime dependencies in both Python and `docs/`.
3. Run tests locally before submitting changes:

```bash
PYTHONPATH=src python -m unittest discover -s tests/python -v
node --check docs/app.js
node tests/test_web_engine.mjs
```
