[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.35/docs/releases/RELEASE_NOTES_v4.19.35.md)

# RedAudit v4.19.35 - Reanudación y transparencia de perfiles Nuclei

## Summary

Esta versión facilita diferenciar reanudaciones de Nuclei y muestra en los informes el perfil seleccionado y el perfil efectivo cuando hay cambio automático.

## Added

- Las entradas del menú de reanudación muestran cuántas veces se ha reanudado una ejecución de Nuclei.
- Los informes registran `profile_selected`, `profile_effective` y el estado del cambio automático en Nuclei.

## Improved

- La documentación explica el auto-switch de Nuclei y los nuevos campos del schema de informes.

## Fixed

- Redacción en español ajustada a ES-ES con terminología y acentos correctos.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

No requiere pasos especiales. Los artefactos de reanudación existentes mostrarán el contador en la próxima reanudación.
