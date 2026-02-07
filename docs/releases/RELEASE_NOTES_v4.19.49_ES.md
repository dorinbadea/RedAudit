# RedAudit v4.19.49 - Baseline Python 3.10+ y alineacion de seguridad de dependencias

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.19.49/docs/releases/RELEASE_NOTES_v4.19.49.md)

## Resumen

Esta version parche alinea RedAudit con una base de runtime Python moderna y soportada, y elimina ruido residual de alertas de dependencias ligado a Python 3.9 (fin de vida).

## Anadido

- No hay nuevas funcionalidades de usuario final en esta version.

## Mejorado

- La base oficial de runtime y CI pasa a Python 3.10-3.12.
- Metadatos del proyecto, tooling de paridad local y guias de contribucion quedan alineados al mismo baseline.

## Corregido

- Los lockfiles de dependencias ya no incluyen la rama de `filelock` exclusiva de Python 3.9.
- El minimo de `cryptography` se mantiene endurecido y coherente con versiones seguras actuales en lockfiles.

## Pruebas

- Validacion interna completada.

## Actualizacion

- No se requiere ninguna accion.
