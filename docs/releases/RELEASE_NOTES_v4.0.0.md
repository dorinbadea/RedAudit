# Release Notes v4.0.0

[![ES](https://img.shields.io/badge/lang-ES-red.svg)](RELEASE_NOTES_v4.0.0_ES.md)

**Release Date:** 2026-01-04
**Codename:** Architecture Overhaul & Type Safety

## Summary

RedAudit v4.0.0 marks the most significant architectural evolution in the project's history. This release completes the transition from an inheritance-heavy monolith to a modern, composition-based architecture powered by robust data models. This shift guarantees type safety, eliminates entire classes of dictionary-key bugs, and provides a solid foundation for future extensibility without breaking changes.

## New Features

### Strong Data Models

- **Host Dataclass**: Replaced ad-hoc dictionaries with a formal `Host` object. This single source of truth now governs IP, MAC, Vendor, OS, Ports, and Vulnerabilities throughout the pipeline.
- **Type Safety**: New `Service` and `Vulnerability` dataclasses ensure consistent data handling from scanning to reporting.

### Architectural Composition

- **Legacy Refactor**: The legacy `AuditorScan` and other inherited paths have been refactored into a composed `NetworkScanner` and modular components.
- **Cleaner Core**: The main loop in `auditor.py` is now a clean orchestrator that passes `Host` objects between specialized components.

## Fixes

### Smart Scan & Wizard Stability

- **Smart Scan Metadata**: Fixed an issue where `smart_scan` decision data (scores, escalation reasons) was not correctly persisted to the `Host` object in the new architecture.
- **Wizard UI**: Resolved `AttributeError` and `TypeError` issues in the Wizard's UI color handling by ensuring `UIManager` mocks are correctly typed in tests.
- **Test Suite**: Comprehensive remediation of the test suite to align with the new object-oriented architecture.

## Testing

- 1264+ tests passing
- Full coverage of new `Host` and `NetworkScanner` models
- Coverage: ~84%

## Upgrade Notes

This is a major release with internal architectural changes.

- **Configuration**: Existing `config.json` is compatible.
- **Reports**: JSON report schema remains backward compatible, though internal representation is much stricter.

---

[Full Changelog](../../CHANGELOG.md) | [Documentation Index](../INDEX.md)
