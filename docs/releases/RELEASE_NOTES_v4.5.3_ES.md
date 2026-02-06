# Notas de la Version v4.5.3

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.3/docs/releases/RELEASE_NOTES_v4.5.3.md)

**Fecha de lanzamiento:** 2026-01-10

## Resumen

Esta version anade almacenamiento seguro de credenciales via keychain del SO y corrige bugs de auditoria de escaneo identificados durante pruebas en laboratorio Docker.

## Anadido

- **Almacenamiento Seguro de Credenciales (Keyring)**: Paquete `keyring` ahora incluido como dependencia principal.
  - Usa keychain nativo del SO: Linux Secret Service, macOS Keychain, Windows Credential Vault.
  - Anadido a dependencias principales (`pyproject.toml`) e instalador (`python3-keyring` apt + pip).
  - Ninguna credencial almacenada en texto plano.

## Corregido

- **B2 - Barras de Progreso de Vulnerabilidades**: Las barras de progreso ahora siempre llegan al 100% tras completar el escaneo. Anadido bucle final para asegurar que todas las tareas se actualizan correctamente.

- **B3 - Color INFO del Heartbeat**: Cambiado el mensaje heartbeat de grey50 a cyan para visibilidad adecuada durante escaneos largos.

- **B4 - Fallo de Deteccion SSH**: Corregido falso negativo "No se encontraron hosts con SSH para escaneo autenticado". La funcion `has_ssh_port()` ahora maneja correctamente objetos Pydantic `Host` (no solo dicts).

## Tests

- 18 tests especificos de keyring pasando
- Validacion completa de pre-commit
- Todos los flujos de proveedor de credenciales probados

## Actualizacion

```bash
cd ~/RedAudit && git pull && sudo bash redaudit_install.sh
```

El instalador ahora instala automaticamente `python3-keyring` (apt) y `keyring` (pip) para almacenamiento seguro de credenciales.
