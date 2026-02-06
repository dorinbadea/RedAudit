[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.14/docs/releases/RELEASE_NOTES_v4.6.14_ES.md)

# RedAudit v4.6.14 - Wizard Cancel and Keyring Loading

## Summary

- Clarifies wizard navigation and improves authenticated setup under sudo by detecting saved credentials from the invoking user.

## Added

- Auth wizard supports cancelling credential entry prompts to exit auth setup cleanly.

## Improved

- Wizard navigation uses "Cancel" with warning color for back navigation entries.

## Fixed

- Keyring lookup now checks the invoking user's keyring when running under sudo.
- HTML report footer license year updated to 2026.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- `sudo redaudit` (auto-update)
- `sudo bash redaudit_install.sh -y`
