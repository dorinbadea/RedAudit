# Release Notes v3.8.5 — Identidad en Hosts Silenciosos

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.8.5.md)

**Fecha de lanzamiento:** 2025-12-22

## Resumen

Este release mejora el enriquecimiento de identidad en hosts silenciosos con un probe HTTP/HTTPS breve y usa el titulo capturado para nombrar activos sin hostname. Ademas, refina la clasificacion para evitar falsos positivos de router y reconocer modelos de switch a partir de vendor/titulo.

---

## Aniadido

### Probe HTTP en Hosts Silenciosos

Probe HTTP/HTTPS breve en puertos comunes cuando un host tiene vendor pero cero puertos abiertos. Captura el titulo y header Server para aportar contexto de modelo sin un deep scan completo.

---

## Corregido

### Prioridad de Clasificacion

Coincidencias de hostname especificas (p. ej. `iphone`, `msi`) ahora tienen prioridad sobre sufijos de router como `fritz`, reduciendo falsos positivos.

### Nombre de Activos con HTTP Title

Activos sin hostname usan `http_title` como etiqueta legible, y los modelos de switch se clasifican mediante patrones de vendor/titulo (p. ej. Zyxel `GS`).

---

## Detalles Tecnicos

- **Archivos modificados:** `redaudit/core/auditor_scan.py`, `redaudit/core/entity_resolver.py`, `redaudit/core/scanner.py`, `redaudit/core/siem.py`
- **Salidas afectadas:** columna "Agentless" en HTML, JSON `agentless_fingerprint`, `unified_assets.asset_name`, `asset_type`

---

## Actualizacion

```bash
cd /path/to/RedAudit
git pull origin main
```

No se requieren cambios de configuracion.

---

[Volver al README](../../README_ES.md) | [Registro completo](../../CHANGELOG_ES.md)
