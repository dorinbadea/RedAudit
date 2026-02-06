# RedAudit v4.19.23 - Security Hardening

[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.23/docs/releases/RELEASE_NOTES_v4.19.23_ES.md)

## Summary

Hardens transport safety for webhooks and HTTP probes, and tightens local operations.

## Added

- None.

## Improved

- HTTPS-only webhook delivery with sanitized logs and redirects disabled.
- HTTP enrichment verifies TLS first and only falls back to insecure probes on failure.
- Safer terminal clear and stricter proxy temp file permissions.

## Fixed

- None.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.23.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.23/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.23/docs/INDEX.md)
