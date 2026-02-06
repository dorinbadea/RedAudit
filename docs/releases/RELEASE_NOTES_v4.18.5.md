# RedAudit v4.18.5 - Deep Scan Safety and HyperScan Stability

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.5/docs/releases/RELEASE_NOTES_v4.18.5_ES.md)

## Summary

This release fixes deep-scan output truncation and caps HyperScan batch sizes to prevent file descriptor exhaustion.

## Added

- None.

## Improved

- None.

## Fixed

- Deep Scan now captures full stdout to avoid missing ports in verbose Nmap runs.
- HyperScan TCP batch size now caps to 80% of the system FD soft limit to prevent `Too many open files`.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- No special steps. Update and run as usual.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.5/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.5/docs/INDEX.md)
