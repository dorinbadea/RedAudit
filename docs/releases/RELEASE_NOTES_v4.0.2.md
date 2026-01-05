# Release Notes v4.0.2

[![ES](https://img.shields.io/badge/lang-ES-red.svg)](https://github.com/dorinbadea/RedAudit/blob/v4.0.2/docs/releases/RELEASE_NOTES_v4.0.2_ES.md)

**Release Date:** 2026-01-05
**Codename:** Test Suite Consolidation

## Summary

RedAudit v4.0.2 is a maintenance release focused on test suite structure, meaningful
coverage improvements, and CI stability.

## Highlights

- **Test Suite Structure**: Reorganized tests under `tests/core`, `tests/cli`,
  `tests/utils`, and `tests/integration` for clearer ownership.
- **Coverage Improvements**: Added meaningful coverage for auditor components,
  vulnerability handling, wizard flows, and HyperScan.
- **Documentation**: Updated `AGENTS.md` guidance around merge and CI hygiene.

## Fixes

- **Terminal Size Patch**: Avoided global patching of `shutil.get_terminal_size` that
  could break `pytest` in CI.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade Notes

No configuration changes required. Existing reports remain backward compatible.

---

[Full Changelog](../../CHANGELOG.md) | [Documentation Index](../INDEX.md)
