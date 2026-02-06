# RedAudit v3.1.2 - Notas de versión

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.1.2.md)

**Fecha de release**: 14 de diciembre de 2025
**Tipo**: Patch Release - UX de actualización y formato CLI
**Versión anterior**: v3.1.1

---

## Visión general

La versión 3.1.2 mejora la experiencia de auto-actualización:

- Vista previa “Novedades” legible en terminal (limpia Markdown + wrap de líneas).
- Reinicio más fiable tras actualizar (PATH-aware) con instrucciones claras si falla.

Este release es compatible hacia atrás con v3.1.1 y no requiere pasos de migración.

---

## Novedades en v3.1.2

### 1. Notas de actualización legibles en CLI

- La vista previa de novedades se renderiza para terminal (sin ruido Markdown).
- Para español, se prefiere `ES/CHANGELOG_ES.md` al previsualizar novedades.

### 2. Reinicio más fiable tras actualizar

- El reinicio intenta relanzar el entrypoint original primero.
- Si el reinicio falla, RedAudit sale y muestra el comando exacto para relanzar.

### 3. Prompts interactivos más claros

- La cobertura UDP en modo COMPLETO ofrece presets simples (50/100/200/500) y opción personalizada.
- El texto de “solo topología” aclara que **NO** mantiene el escaneo normal de hosts/puertos + topología.
- Guardar valores por defecto incluye confirmación y explica qué implica, tanto si eliges sí como no.

---

## Enlaces útiles

- **Changelog**: [CHANGELOG.md](../../CHANGELOG.md) / [CHANGELOG_ES.md](../../ES/CHANGELOG_ES.md)
- **Notas para GitHub Release**: [GitHub Release Draft](DRAFT_TEMPLATE.md)
- **Manual (EN)**: [docs/MANUAL.es.md](../MANUAL.es.md)
- **Manual (ES)**: [docs/MANUAL.es.md](../MANUAL.es.md)
- **Esquema de informe (EN)**: [docs/REPORT_SCHEMA.es.md](../REPORT_SCHEMA.es.md)
- **Esquema de informe (ES)**: [docs/REPORT_SCHEMA.es.md](../REPORT_SCHEMA.es.md)
