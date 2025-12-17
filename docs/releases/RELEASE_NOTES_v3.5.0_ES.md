# Notas de la versión v3.5.0 - Fiabilidad y Ejecución

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.5.0.md)

RedAudit v3.5.0 es una release menor centrada en estabilidad durante auditorías largas y una ejecución más segura de comandos externos.

## Highlights

- **Evitar reposo durante escaneos (por defecto)**: RedAudit intenta una inhibición best-effort del reposo del sistema/pantalla mientras el escaneo está en curso. Opt-out con `--no-prevent-sleep`.
- **CommandRunner centralizado**: Nuevo módulo interno (`redaudit/core/command_runner.py`) para centralizar ejecución de comandos externos (args-only, timeouts, reintentos, redacción).
- **Mejor cobertura de `--dry-run`**: Más módulos respetan `--dry-run`. Sigue siendo un **despliegue incremental**: hasta completar la migración, algunas herramientas externas pueden seguir ejecutándose.

## Cambios en CLI

- Añadido: `--no-prevent-sleep`
- Mejorado: `--dry-run` (despliegue incremental)

## Notas

- Si actualizas y el banner sigue mostrando una versión antigua, reinicia el terminal o ejecuta `hash -r` (zsh/bash).

