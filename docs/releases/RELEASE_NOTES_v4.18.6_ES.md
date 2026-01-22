# RedAudit v4.18.6 - Robustez en autenticado y claridad en informes

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.18.6/docs/releases/RELEASE_NOTES_v4.18.6.md)

## Resumen

Este parche refuerza el almacenamiento del escaneo autenticado, mejora el recuento de PCAPs, ajusta la validación de identity threshold y alinea detalles de documentación.

## Añadido

- Ninguno.

## Mejorado

- La documentación aclara el fallback de hilos, el jitter, el rango de identity threshold y la numeración de secciones en USAGE.

## Corregido

- Los resultados de Lynis se guardan de forma segura en objetos Host durante el escaneo autenticado.
- Eliminada la asignación duplicada de `host_agentless` en el filtro de falsos positivos de Nuclei.
- El resumen CLI ahora cuenta todos los PCAPs, incluido el full capture.
- `--identity-threshold` ahora se limita a 0-100 con fallback seguro.

## Pruebas

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Actualización

Sin cambios incompatibles. Actualiza a v4.18.6 y vuelve a ejecutar escaneos para aplicar los fixes.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.18.6/ES/CHANGELOG_ES.md) | [Documentación](https://github.com/dorinbadea/RedAudit/blob/v4.18.6/docs/INDEX.md)
