# RedAudit v4.20.1 - Composicion del Wizard y UX de Interrupcion

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.20.1/docs/releases/RELEASE_NOTES_v4.20.1.md)

## Resumen

Esta version finaliza la pista de endurecimiento por composicion del wizard y mejora la claridad de interrupcion para operadores durante escaneos activos.

## Anadido

- No se introducen nuevas funcionalidades de runtime en este parche.

## Mejorado

- Los controles de Scope Expansion por perfil en el wizard interactivo quedan documentados de forma explicita y alineada en EN/ES.
- El mensaje de interrupcion ahora indica claramente que, tras `Ctrl+C`, se guarda progreso parcial y se ejecuta limpieza.
- Las referencias de arquitectura documental reflejan ya la separacion wizard-first por composicion (`wizard_service.py` y `scan_wizard_flow.py`).

## Corregido

- Deriva documental entre los cambios de composicion ya implementados y las referencias en roadmap/changelog/readme.
- Inconsistencias de metadatos de release tras cambios posteriores a `v4.20.0`, sincronizando fuentes de version y documentacion de release.

## Pruebas

- Validacion interna completada.

## Actualizacion

- No se requiere ninguna accion.
