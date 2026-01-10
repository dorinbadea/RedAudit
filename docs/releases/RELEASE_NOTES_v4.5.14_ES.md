# Versión v4.5.14

[![View in English](https://img.shields.io/badge/lang-en-blue)](https://github.com/dorinbadea/RedAudit/blob/v4.5.14/docs/releases/RELEASE_NOTES_v4.5.14.md)

## Resumen

Esta versión de mantenimiento resuelve dos problemas críticos de escaneo identificados en entornos de producción: un fallo de conexión SSH causado por políticas estrictas de clave de host, y una brecha lógica en el motor Smart Scan que impedía escaneos profundos en hosts con señales de identidad válidas pero cero puertos abiertos ("Identidades Fantasma").

## Corregido

- **Autenticación SSH**: Implementada `PermissivePolicy` para `paramiko` que acepta forzosamente claves de host en memoria sin intentar escribir en `known_hosts`. Esto soluciona el error `SSH error: Server not found in known_hosts` en entornos de solo lectura o restringidos (Docker/CI).
- **Lógica Smart Scan**: Ajustada `should_trigger_deep_scan` para forzar un Deep Scan (UDP) cuando un host tiene una puntuación de identidad alta (ej. pistas SNMP/Broadcast de Fase 0) pero cero puertos abiertos detectados. Esto resuelve el problema de "Identidad Fantasma" donde activos alcanzables eran omitidos.

## Pruebas

Verificado con:

- **Pruebas Unitarias**: Aprobadas (60 pruebas), incluyendo nuevas pruebas de regresión para la lógica de `NetworkScanner`.
- **Verificación Manual**: Validada lógica usando `scripts/verify_fix_scanner.py` simulando condiciones de "Identidad Fantasma" (Puntuación 4, Puertos 0).

## Actualización

Actualizar vía git:

```bash
git pull origin main
pip install -e .
```
