# Notas de la versión v3.5.1 - Finalización Dry-run (Hotfix)

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.5.1.md)

RedAudit v3.5.1 es una hotfix centrada en completar el comportamiento de `--dry-run` y mejorar la UX del updater.

## Highlights

- **Soporte completo de `--dry-run`**: `--dry-run` ahora se propaga por los módulos para que **no se ejecute ningún comando externo**, mostrando igualmente los comandos planificados.
- **Fiabilidad del updater**: Si el system install se actualiza pero `~/RedAudit` tiene cambios locales git, RedAudit ahora omite actualizar la copia en home en vez de fallar toda la actualización.
- **Nota post-actualización**: Tras actualizar, RedAudit recuerda reiniciar el terminal o ejecutar `hash -r` si el banner/versión no se refresca.
