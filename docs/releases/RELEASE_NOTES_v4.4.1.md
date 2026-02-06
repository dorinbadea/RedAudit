# RedAudit v4.4.1 - CI Parity and Python 3.9 Compatibility

[![Ver en Espanol](https://img.shields.io/badge/Ver%20en%20Espanol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.4.1/docs/releases/RELEASE_NOTES_v4.4.1_ES.md)

This release focuses on CI parity and Python 3.9 dependency compatibility to prevent CI-only failures.

## Fixed

- Python 3.9 dev lock now selects compatible versions for iniconfig, pytest-asyncio, markdown-it-py, pycodestyle, and pyflakes to avoid resolver conflicts.
- Runtime lock now selects a Python 3.9 compatible markdown-it-py when running under 3.9.

## Added

- Local CI parity script `scripts/ci_local.sh` to run pre-commit and pytest across Python 3.9-3.12.

## Changed

- Unit tests for complete scan flows disable HyperScan-first to keep runtime bounded while preserving logic coverage.

## Upgrading

```bash
cd RedAudit
git pull origin main
pip install -r requirements.txt
```
