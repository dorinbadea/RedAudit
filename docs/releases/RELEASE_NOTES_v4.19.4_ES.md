# RedAudit v4.19.4 - Control de presupuesto en reanudación de Nuclei

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.4/docs/releases/RELEASE_NOTES_v4.19.4.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.4/docs/releases/RELEASE_NOTES_v4.19.4_ES.md)

## Summary

Las reanudaciones de Nuclei ahora permiten cambiar el presupuesto y los lotes con presupuesto reducen reescaneos innecesarios.

## Added

- Los prompts de reanudación permiten cambiar o desactivar el presupuesto de tiempo de Nuclei (0 = ilimitado).
- La reanudación por CLI respeta `--nuclei-max-runtime`.

## Improved

- Con presupuesto, RedAudit evita iniciar un nuevo lote si el tiempo restante no cubre el tiempo estimado del lote.
- El estado de reanudación actualiza el presupuesto guardado cuando se aplica un override.

## Fixed

- Se reducen los reescaneos de objetivos cuando el presupuesto está casi agotado.

## Testing

- `pytest tests/core/test_nuclei_helpers.py tests/core/test_auditor_orchestrator.py tests/cli/test_cli.py -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.19.4.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.19.4/ES/CHANGELOG_ES.md) | [Documentación](https://github.com/dorinbadea/RedAudit/blob/v4.19.4/docs/INDEX.md)
