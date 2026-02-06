[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.17/docs/releases/RELEASE_NOTES_v4.6.17.md)

# RedAudit v4.6.17 - Contexto de keyring con sudo

## Summary

- Carga credenciales guardadas del keyring al ejecutar con sudo preservando el contexto DBus del usuario invocador.

## Added

- None.

## Improved

- None.

## Fixed

- El descubrimiento de credenciales con sudo ahora inyecta `XDG_RUNTIME_DIR`/`DBUS_SESSION_BUS_ADDRESS` para el usuario invocador y mostrar credenciales guardadas en el asistente.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- `sudo redaudit` (auto-update)
- `sudo bash redaudit_install.sh -y`
