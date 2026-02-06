# RedAudit v4.19.13 - Installer Python Stability

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.13/docs/releases/RELEASE_NOTES_v4.19.13.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.13/docs/releases/RELEASE_NOTES_v4.19.13_ES.md)

## Summary

The installer now avoids pip conflicts by only installing missing Python modules and adds an archive fallback for exploitdb/searchsploit.

## Added

- None.

## Improved

- Optional apt installs now include python3-paramiko and python3-keyrings-alt.

## Fixed

- pip installs are limited to missing modules to avoid conflicts with distro-managed packages.
- exploitdb/searchsploit can be installed from a GitHub archive when git clone fails.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No breaking changes. Update to v4.19.13.

[Full Changelog](https://github.com/dorinbadea/RedAudit/blob/v4.19.13/CHANGELOG.md) | [Documentation](https://github.com/dorinbadea/RedAudit/blob/v4.19.13/docs/INDEX.md)
