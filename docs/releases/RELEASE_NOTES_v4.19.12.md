# RedAudit v4.19.12 - Installer Python Dependency Bootstrap

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.12/docs/releases/RELEASE_NOTES_v4.19.12.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.12/docs/releases/RELEASE_NOTES_v4.19.12_ES.md)

## Summary

The installer now ensures pip is available and attempts apt-based Impacket to reduce missing Python dependencies on clean Ubuntu installs.

## Added

- None.

## Improved

- Installer toolchain includes `python3-pip` to ensure pip-based dependencies can be installed.

## Fixed

- Clean Ubuntu installs no longer skip Python auth dependencies due to missing pip.
- Impacket availability improves when `python3-impacket` is present in apt repositories.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.12.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.12/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.12/docs/INDEX.md)
