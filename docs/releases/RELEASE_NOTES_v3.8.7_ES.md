# Notas de Versión v3.8.7 — Correcciones de informes y clasificación

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.8.7.md)

**Fecha de lanzamiento:** 2025-12-23

## Resumen

Este hotfix mejora la precisión de los informes corrigiendo la atribución de fuentes de vulnerabilidades y la clasificación del estado de host. También mejora el probe HTTP en hosts silenciosos y refina el tipo de activo para dispositivos media y hosts Android.

---

## Corregido

### Resumen de fuentes de vulnerabilidades

Las fuentes del pipeline ahora se infieren desde señales del tool cuando faltan campos explícitos.

### Estado de host

Hosts con puertos abiertos ahora se marcan como `up` aunque exista MAC/vendor.

### Detección de tipo de activo

Fingerprints Chromecast/cast se clasifican como `media`, pistas de Android se asignan a `mobile`, y el gateway por defecto de topología se etiqueta como `router` para la resolución de entidades.

### Identidad HTTP en hosts silenciosos

Las pantallas de login sin título/encabezado ahora usan metatítulos y texto alt común para mejorar la detección de modelo.

---

## Actualización

```bash
cd /ruta/a/RedAudit
git pull origin main
```

No se requieren cambios de configuración.

---

[Volver al README](../../ES/README_ES.md) | [Registro completo](../../ES/CHANGELOG_ES.md)
