# RedAudit v4.4.2 Notas de la Version

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/main/docs/releases/RELEASE_NOTES_v4.4.2.md)

**Fecha de lanzamiento**: 2026-01-08

## Resumen

Este hotfix soluciona un problema critico de falso positivo donde los routers FRITZ!Box eran incorrectamente marcados como vulnerables a CVE-2022-26143 (Mitel MiCollab Information Disclosure).

## Corregido

### Falso Positivo CVE-2022-26143 en Routers FRITZ!Box

El filtro de falsos positivos de Nuclei no estaba recibiendo los datos completos del host, causando que la validacion Smart-Check fallara para dispositivos AVM FRITZ!Box.

**Causa raiz**: La funcion `filter_nuclei_false_positives()` en `auditor.py` no pasaba `host_records` al pipeline de filtrado, impidiendo que la validacion basada en CPE y cabecera Server funcionara correctamente.

**Cambios**:

- Anadido `fritz!os` a la lista explicita de vendors de falso positivo para mejorar la deteccion de cabeceras
- Eliminada asignacion duplicada de variable `server_header` en `check_nuclei_false_positive()`
- Nuevo parametro `host_records` en `filter_nuclei_false_positives()` permite el flujo completo de datos del host para validacion precisa
- Actualizado `auditor.py` para pasar `host_records=results` a la funcion de filtrado

## Testing

- Pre-commit: Todos los hooks pasaron
- Suite de tests: 1467 pasados en Python 3.9, 3.10, 3.11, 3.12

## Actualizacion

Actualizacion estandar via pip o el script de instalacion:

```bash
pip install --upgrade redaudit
# o
bash redaudit_install.sh
```

## Changelog Completo

Ver [CHANGELOG.md](https://github.com/dorinbadea/RedAudit/blob/v4.4.2/CHANGELOG.md) para la lista completa de cambios.
