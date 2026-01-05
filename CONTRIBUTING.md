# Contributing Guidelines

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](ES/CONTRIBUTING_ES.md)

This is the canonical contributing guide for the repository. A Spanish version is available at `ES/CONTRIBUTING_ES.md`.

If you are reading this from the repository root, use:

- `CONTRIBUTING.md` (English)
- `ES/CONTRIBUTING_ES.md` (Español)

## Optional Integration Checks

To validate parser behavior against real tool output:

```bash
REDAUDIT_REAL_TOOLS=1 pytest tests/integration/test_real_tool_output.py -v
```

Notes:
- Requires `nmap` installed.
- The test spins up a local HTTP server and runs `nmap` against `127.0.0.1`.
