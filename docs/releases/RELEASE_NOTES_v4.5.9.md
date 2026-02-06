# Release Notes v4.5.9

[![Ver en Espanol](https://img.shields.io/badge/Ver%20en%20Espa%C3%B1ol-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.9/docs/releases/RELEASE_NOTES_v4.5.9_ES.md)

**Release Date:** 2026-01-10

## Summary

This is a **CI/Maintenance** release.

It suppresses linter warnings (Bandit) regarding hardcoded credentials in the lab seeder script (`scripts/seed_keyring.py`), ensuring the GitHub Actions pipeline passes green.

## Fixed

- **CI/Lint**: Added `# nosec` annotations to `seed_keyring.py` to handle expected lab credentials.
