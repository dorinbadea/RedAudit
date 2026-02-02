# RedAudit v3.5.4

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.5.4.md)

**Fecha**: 2025-12-18
**Tipo**: Patch Release (Hotfix)

##  Novedades

### Corrección de detección de versión en instalaciones del sistema

Esta versión corrige un bucle del actualizador donde RedAudit podía mostrar `v0.0.0-dev` tras actualizar una instalación del sistema (instalaciones vía script en `/usr/local/lib/redaudit` sin metadata de paquete Python).

- RedAudit ahora incluye un fichero interno `redaudit/VERSION` y lo usa como fallback cuando `importlib.metadata` no está disponible.
- Resultado: el banner muestra la versión correcta y las comprobaciones de actualización dejan de repetirse.
