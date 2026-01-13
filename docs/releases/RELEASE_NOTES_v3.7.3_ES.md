# Notas de Versión RedAudit v3.7.3

**Fecha de lanzamiento:** 2025-12-20

[![View in English](https://img.shields.io/badge/🇬🇧_English-blue?style=flat-square)](RELEASE_NOTES_v3.7.3.md)

## Resumen

RedAudit v3.7.3 es un release patch enfocado en **confiabilidad del escaneo** y **precisión de informes**, especialmente
para redes mixtas con routers e IoT.

## Corregido

### Parsing XML de Nmap y Timeouts

- Se conserva el XML completo de Nmap y se extrae el bloque `<nmaprun>` antes de parsear para evitar errores XML.
- Si no se especifica `--host-timeout`, el fallback respeta el modo de escaneo (completo = 300s).

### Continuidad de Identidad de Hosts

- Si Nmap falla, RedAudit usa datos MAC/vendor de topología/vecinos para mantener la identidad del host en informes.

### Precisión de Informes

- "Hosts Descubiertos" ahora deduplica objetivos para reflejar el conjunto único real.

## Documentación

- [Registro de cambios completo](../../ES/CHANGELOG_ES.md)
- [Roadmap](docs/ROADMAP.es.md)
