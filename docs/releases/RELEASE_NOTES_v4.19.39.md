[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.39/docs/releases/RELEASE_NOTES_v4.19.39_ES.md)

# RedAudit v4.19.39 - Config Resilience Hardening

## Summary

This patch improves runtime resilience by auto-recovering malformed local configuration files instead of failing back silently at runtime.

## Added

- Automatic self-heal flow for invalid `~/.redaudit/config.json` payloads.

## Improved

- Invalid config files are now preserved as `config.json.invalid.<timestamp>` before rebuilding defaults.
- Invalid `defaults` payload types now fall back to the expected schema defaults.

## Fixed

- Startup behavior when the config file contains malformed JSON or an invalid root type.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

1. Pull `v4.19.39` from the official repository.
2. Run one standard scan and verify your stored defaults are still applied as expected.
3. If you had a malformed config, review the generated `config.json.invalid.<timestamp>` backup.
