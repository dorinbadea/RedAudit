# RedAudit v4.4.5 - The Quality Release

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.4.5/docs/releases/RELEASE_NOTES_v4.4.5_ES.md)

This release focuses entirely on project stability and code quality, marking a significant milestone in test coverage (~89%).

## Code Coverage & Quality

- **100% Core Topology Coverage**: Achieved complete test coverage for `redaudit/core/topology.py`, ensuring reliable route parsing, loop detection, and graphing.
- **>94% Updater Coverage**: Hardened `redaudit/core/updater.py` with robust tests for Git operations, rollback scenarios, and edge-case failures.
- **Project-Wide Coverage ~89%**: The entire codebase now approaches the 90% coverage threshold.
- **Improved Testing Stability**: Resolved flaky tests by implementing dynamic mocking and standardized pre-commit hooks.

## Bug Fixes

- Fixed potential infinite loops in topology discovery when default gateways are missing.
- Resolved various `RuntimeWarning` and `UnboundLocalError` issues in exceptional paths.

## Changes

- None. This is a stability-focused release.

---
[Full Changelog](https://github.com/dorinbadea/RedAudit/compare/v4.4.4...v4.4.5)
