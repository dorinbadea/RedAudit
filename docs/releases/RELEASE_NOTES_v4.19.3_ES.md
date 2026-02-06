# RedAudit v4.19.3 - Consistencia de auditoría y ajustes SNMP v3

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.3/docs/releases/RELEASE_NOTES_v4.19.3.md)
[![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.3/docs/releases/RELEASE_NOTES_v4.19.3_ES.md)

## Summary

Esta versión refuerza el manejo de protocolos SNMP v3, alinea defaults y corrige desajustes en diff/reportes y documentación detectados en la auditoría.

## Added

- La búsqueda OUI offline ahora soporta prefijos /28 y /36 desde el manuf local.

## Improved

- Los nombres de protocolos auth/priv de SNMP v3 se mapean a objetos PySNMP y respetan claves auth/priv explícitas.
- La puerta de calidad en CI ahora aplica 80% de cobertura y ShellCheck.

## Fixed

- La topología SNMP con CVE ya no depende de una API key NVD sin inicializar.
- Los informes diferenciales cuentan WhatWeb con la clave correcta.
- El ConfigurationContext usa el timeout por defecto de Nuclei de 300s como el CLI.
- Presets de velocidad ES, fallback de threads y docs Docker/seguridad alineados con la política.
- Avisos de ShellCheck resueltos en instalador y scripts Docker.

## Testing

- `pytest tests/core/test_auth_snmp.py tests/utils/test_oui_offline.py tests/core/test_diff.py tests/core/test_config_context.py tests/core/test_auditor_run_complete_scan.py -v`

## Upgrade

Sin cambios incompatibles. Actualiza a v4.19.3.

[Changelog Completo](https://github.com/dorinbadea/RedAudit/blob/v4.19.3/ES/CHANGELOG_ES.md) | [Documentación](https://github.com/dorinbadea/RedAudit/blob/v4.19.3/docs/INDEX.md)
