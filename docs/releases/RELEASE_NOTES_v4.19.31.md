[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.31/docs/releases/RELEASE_NOTES_v4.19.31_ES.md)

# RedAudit v4.19.31 - Installer OUI Seed and Trust Signals

## Summary
- The installer now seeds a local Wireshark OUI database for reliable vendor identification from first run.
- Experimental TestSSL signals are treated as low-confidence and surfaced as possible false positives.

## Added
- Automatic OUI database provisioning to `~/.redaudit/manuf` during installation.

## Improved
- Device-aware remediation now prioritizes device type and hints over vendor lists.
- OUI database overrides via config, environment variables, and auto-discovery under `~/.redaudit/`.

## Fixed
- Experimental TestSSL findings are no longer treated as confirmed exploitable.
- HTML reports now display possible false positives next to technical observations.

## Testing
- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade
- No action required.
