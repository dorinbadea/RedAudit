# RedAudit v4.19.46 - Strategic Coverage & Resilience

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.46/docs/releases/RELEASE_NOTES_v4.19.46_ES.md)

## Summary

This release focuses on industrial-grade reliability with comprehensive test coverage and resilient input parsing in core modules.

## Improved

- **Strategic Coverage**: Boosted test coverage for `updater.py` (99.67%), `jsonl_exporter.py` (100%), `config.py` (99.48%), `auditor_scan.py` (96.30%), and `auditor_vuln.py` (97.48%) targeting edge cases and exception paths.

## Fixed

- **Scope Expansion Resilience**: Resolved a potential crash in `build_leak_follow_targets` when processing malformed or non-numeric port data from candidate sources.

## Testing

- Achieved >99% coverage on modified core modules.
- Pre-commit quality gates passed.

## Upgrade

- No action required.
