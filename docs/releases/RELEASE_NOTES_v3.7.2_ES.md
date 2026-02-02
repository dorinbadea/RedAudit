# Notas de Versión RedAudit v3.7.2

**Fecha de Lanzamiento:** 2025-12-19

[![View in English](https://img.shields.io/badge/_English-blue?style=flat-square)](RELEASE_NOTES_v3.7.2.md)

## Descripción

RedAudit v3.7.2 es una versión patch enfocada en la **experiencia del operador**: prompts más claros en el wizard y un
progreso más estable (especialmente durante HyperScan en Net Discovery y en los escaneos de templates Nuclei).

## Corregido

### Estabilidad del Progreso en Net Discovery (HyperScan)

- Se reduce el flickering limitando (throttling) las actualizaciones de progreso durante el descubrimiento paralelo.

### Progreso y ETA en Nuclei

- El escaneo de Nuclei ahora muestra progreso/ETA sin competir con otras UIs Rich (Live), mejorando visibilidad y
  evitando conflictos de renderizado.

### UX del Wizard (Defaults + Net Discovery)

- Si eliges revisar/modificar defaults y omites el resumen, RedAudit ya no pregunta si quieres iniciar inmediatamente con
  esos defaults.
- Los prompts de Net Discovery ahora indican explícitamente cuándo ENTER conserva el valor por defecto o cuándo omite un
  campo opcional (comunidad SNMP / zona DNS).

## Documentación

- [Registro de cambios completo](../../ES/CHANGELOG_ES.md)
- [Roadmap](docs/ROADMAP.es.md)
