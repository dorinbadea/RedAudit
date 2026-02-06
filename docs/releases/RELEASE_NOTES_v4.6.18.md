[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.18/docs/releases/RELEASE_NOTES_v4.6.18_ES.md)

# RedAudit v4.6.18 - SSH Credential Spray

## Summary

- Adds credential spraying support for SSH authentication.
- Fixes Nuclei partial output and NVD URL encoding bugs.

## Added

- **SSH Credential Spray**: Try all credentials from keyring spray list until one succeeds. Enables a single list of credentials for networks with multiple hosts requiring different authentication.

## Improved

- None.

## Fixed

- **Nuclei Partial Output**: Persist partial findings when batches timeout at maximum recursive split depth instead of leaving output file empty.
- **NVD URL Encoding**: URL-encode keyword search parameters containing spaces or special characters.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- `sudo redaudit` (auto-update)
- `sudo bash redaudit_install.sh -y`
