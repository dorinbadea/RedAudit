# RedAudit v4.20.6 - Remediacion de Seguridad en Cryptography

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.6/docs/releases/RELEASE_NOTES_v4.20.6.md)

## Resumen

Este parche remedia una vulnerabilidad upstream de cryptography actualizando los lockfiles a la version corregida.

## Anadido

- No se anaden nuevas funcionalidades de runtime en esta version.

## Mejorado

- Consistencia de lockfiles de dependencias entre entornos de produccion y desarrollo.

## Corregido

- Actualizacion de `cryptography` a `46.0.5` en:
  - `poetry.lock`
  - `requirements.lock`
  - `requirements-dev.lock`
- Esto corrige la incidencia de seguridad publicada para versiones `<=46.0.4`.

## Pruebas

Validacion interna completada.

## Actualizacion

No se requiere ninguna accion.
