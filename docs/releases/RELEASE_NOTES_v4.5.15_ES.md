# Version v4.5.15

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.15/docs/releases/RELEASE_NOTES_v4.5.15.md)

## Resumen

Este hotfix corrige los arreglos de v4.5.14 que fueron aplicados a la ruta de codigo incorrecta. La deteccion de Identidad Fantasma ahora funciona correctamente para hosts con cero puertos abiertos, y la confianza de claves SSH esta habilitada por defecto para escaneo automatizado.

## Corregido

- **Smart Scan (Identidad Fantasma)**: Agregada condicion de activacion `ghost_identity` a `auditor_scan.py:_should_trigger_deep()` para hosts con `total_ports == 0` e identidad debil. El arreglo de v4.5.14 fue aplicado incorrectamente a `network_scanner.py` que no se usa en el flujo de orquestacion real.
- **Autenticacion SSH**: Cambiado valor por defecto de `auth_ssh_trust_keys` de `False` a `True` en `auditor_scan.py`, asegurando que `PermissivePolicy` se use por defecto en entornos de escaneo automatizado.

## Pruebas

Verificado con:

- **Pruebas Unitarias**: 17/17 pruebas de deep scan aprobadas.
- **Analisis de Escaneo**: Identificada causa raiz via escaneo `RedAudit_2026-01-10_19-38-50` mostrando Host .40 con `trigger_deep: false` a pesar de `identity_score: 3 < threshold: 4`.

## Actualizacion

```bash
git pull origin main
pip install -e .
```
