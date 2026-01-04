# Release Notes v4.0.1

[![ES](https://img.shields.io/badge/lang-ES-red.svg)](RELEASE_NOTES_v4.0.1_ES.md)

**Release Date:** 2026-01-04
**Codename:** Composition Maintenance

## Summary

RedAudit v4.0.1 is a maintenance release that stabilizes the composition-based auditor
pipeline, tightens the test suite, and aligns documentation around the v4 architecture.

## Highlights

- **Composition Adapter**: The main auditor delegates component behavior through
  `auditor_runtime.py`, keeping orchestration composition-first.
- **Test Suite Hygiene**: Removed coverage filler tests, renamed component-focused tests,
  and hardened OUI lookup import-error handling to avoid external requests.
- **Documentation**: Updated roadmap and release notes to reflect the current architecture.

## Fixes

- **Async Test Noise**: Resolved coroutine warnings in HyperScan edge-case tests.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade Notes

No configuration changes required. Existing reports remain backward compatible.

---

[Full Changelog](../../CHANGELOG.md) | [Documentation Index](../INDEX.md)
