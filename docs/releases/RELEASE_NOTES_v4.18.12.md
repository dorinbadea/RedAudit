# RedAudit v4.18.12 - HyperScan Metrics and DHCP Clarity

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.12/docs/releases/RELEASE_NOTES_v4.18.12_ES.md)

## Summary

This release corrects HyperScan-First metrics, refines DHCP timeout hints, and improves report clarity in Spanish output.

## Added

- None.

## Improved

- None.

## Fixed

- HyperScan-First now drives `hyperscan_vs_final` comparisons to avoid undercounting from quick discovery ports.
- HyperScan-First merges any masscan fallback ports instead of replacing RustScan results.
- DHCP timeout hints no longer claim missing IPv4 when a default-route source address exists.
- Spanish HTML reports now translate authenticated scan error messages.
- Auditor IP exclusion now considers local interface and route source IPs.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.18.12 for more accurate HyperScan metrics and clearer DHCP/report messaging.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.12/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.12/docs/INDEX.md)
