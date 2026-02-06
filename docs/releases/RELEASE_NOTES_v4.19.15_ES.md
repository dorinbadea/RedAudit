# RedAudit v4.19.15 - Limpieza de ShellCheck en instalador

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.15/docs/releases/RELEASE_NOTES_v4.19.15.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.15/docs/releases/RELEASE_NOTES_v4.19.15_ES.md)

## Summary

Se eliminaron variables sin uso del instalador para mantener ShellCheck limpio sin cambiar el comportamiento.

## Added

- Sin cambios.

## Improved

- Sin cambios.

## Fixed

- ShellCheck ya no marca variables de distro sin uso en el instalador.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.19.15.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.19.15/ES/CHANGELOG_ES.md) | [Documentación](https://github.com/dorinbadea/RedAudit/blob/v4.19.15/docs/INDEX.md)
