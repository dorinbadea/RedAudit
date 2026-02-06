[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.10/docs/releases/RELEASE_NOTES_v4.6.10_ES.md)

# RedAudit v4.6.10 - Flexible Target Entry

## Summary

- Adds wizard and CLI support for comma-separated CIDR/IP/range targets with normalization.

## Added

- Wizard manual target entry accepts CIDR/IP/range lists and expands ranges to CIDR blocks.
- CLI target parsing accepts IP ranges and normalizes single IPs to /32.

## Improved

- Roadmap cleaned of emojis and reordered chronologically.
- README/usage/manual updated to reflect target entry formats.

## Fixed

- None.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- `sudo redaudit` (auto-update)
- `sudo bash redaudit_install.sh -y`
