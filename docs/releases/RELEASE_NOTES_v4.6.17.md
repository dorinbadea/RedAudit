[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.17/docs/releases/RELEASE_NOTES_v4.6.17_ES.md)

# RedAudit v4.6.17 - Keyring Sudo Context

## Summary

- Loads saved keyring credentials under sudo by preserving the invoking user's DBus context.

## Added

- None.

## Improved

- None.

## Fixed

- Keyring discovery under sudo now injects `XDG_RUNTIME_DIR`/`DBUS_SESSION_BUS_ADDRESS` for the invoking user to surface saved credentials in the wizard.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- `sudo redaudit` (auto-update)
- `sudo bash redaudit_install.sh -y`
