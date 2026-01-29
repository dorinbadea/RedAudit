# RedAudit v4.19.9 - Consistencia de UI en reanudacion de Nuclei

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.9/docs/releases/RELEASE_NOTES_v4.19.9.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.9/docs/releases/RELEASE_NOTES_v4.19.9_ES.md)

## Summary

La reanudacion y el progreso de Nuclei ahora reflejan solo los pendientes, informan secuencial/paralelo correctamente y alinean los mensajes con el idioma activo.

## Added

- Sin cambios.

## Improved

- Los mensajes de lotes y heartbeats de Nuclei usan terminologia localizada y consistente.

## Fixed

- Las ejecuciones secuenciales de Nuclei ya no informan lotes paralelos cuando el presupuesto fuerza secuencial.
- El progreso de reanudacion de Nuclei muestra solo objetivos pendientes en lugar del total.
- La salida CLI en español ahora localiza correlacion CVE, prompts de salida y textos de tiempo transcurrido.

## Testing

- `pre-commit run --all-files`
- `pytest tests/ -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.19.9.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.19.9/ES/CHANGELOG_ES.md) | [Documentación](https://github.com/dorinbadea/RedAudit/blob/v4.19.9/docs/INDEX.md)
