[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.14/docs/releases/RELEASE_NOTES_v4.6.14.md)

# RedAudit v4.6.14 - Cancelar en el wizard y keyring con sudo

## Summary

- Aclara la navegacion del asistente y mejora la configuracion autenticada bajo sudo detectando credenciales guardadas del usuario que invoca.

## Added

- El asistente de autenticacion permite cancelar los prompts de credenciales para salir de la configuracion.

## Improved

- La navegacion del asistente usa "Cancelar" con color de advertencia en las entradas de navegacion.

## Fixed

- La busqueda de keyring ahora revisa el keyring del usuario que invoca cuando se ejecuta con sudo.
- El footer de licencia del informe HTML ahora muestra 2026.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

- `sudo redaudit` (auto-update)
- `sudo bash redaudit_install.sh -y`
