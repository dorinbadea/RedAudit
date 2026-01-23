# RedAudit v4.18.10 - DHCP Timeout Hints and SSH Auth Ports

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.10/docs/releases/RELEASE_NOTES_v4.18.10_ES.md)

## Summary

This hotfix clarifies DHCP discovery timeouts and ensures authenticated scans target SSH services on non-standard ports.

## Added

- None.

## Improved

- Troubleshooting guidance now explains common DHCP timeout causes and next steps.

## Fixed

- DHCP discovery now appends best-effort hints when broadcasts time out.
- Authenticated scans now detect SSH running on non-22 ports (for example, 2222).

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.18.10 for clearer DHCP guidance and broader SSH auth coverage.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.18.10/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.18.10/docs/INDEX.md)
