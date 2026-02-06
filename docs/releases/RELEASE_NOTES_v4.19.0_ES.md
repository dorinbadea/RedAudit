# RedAudit v4.19.0 - Reanudacion de Nuclei por presupuesto

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.0/docs/releases/RELEASE_NOTES_v4.19.0.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.0/docs/releases/RELEASE_NOTES_v4.19.0_ES.md)

## Resumen

Se anade un presupuesto de tiempo para Nuclei con artefactos de reanudacion y un flujo en el wizard para continuar objetivos pendientes sin detener el resto de la auditoria.

## Anadido

- Presupuesto de tiempo de Nuclei con artefactos de reanudacion (`nuclei_resume.json`, `nuclei_pending.txt`) y pregunta de reanudacion con cuenta atras de 15 segundos.
- Flags de reanudacion en CLI: `--nuclei-max-runtime`, `--nuclei-resume`, `--nuclei-resume-latest`.
- Entrada en el menu principal para reanudar Nuclei pendiente.

## Mejorado

- Informes y esquema ahora registran metadatos de reanudacion y `nuclei_max_runtime` en el snapshot.

## Corregido

- Ninguno.

## Pruebas

- `pytest tests/core/test_nuclei_helpers.py tests/core/test_auditor_orchestrator.py tests/core/test_auditor_run_complete_scan.py tests/cli/test_wizard.py tests/cli/test_cli.py tests/utils/test_config.py tests/core/test_auditor_defaults.py tests/core/test_reporter.py -q`

## Actualizacion

Sin cambios incompatibles. Actualiza a v4.19.0.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.19.0/ES/CHANGELOG_ES.md) | [Documentacion](https://github.com/dorinbadea/RedAudit/blob/v4.19.0/docs/INDEX.md)
