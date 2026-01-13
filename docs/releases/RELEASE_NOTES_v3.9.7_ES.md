# RedAudit v3.9.7 Notas de Lanzamiento

[![English Version](https://img.shields.io/badge/English-blue)](./RELEASE_NOTES_v3.9.7.md)

**Fecha de Lanzamiento:** 2025-12-29

## Mejoras de Calidad de Auditoría

Este hotfix se centra en **reducir falsos positivos** y **alinear conteos** entre CLI y informes.

### Filtrado de Falsos Positivos en Nuclei

- Los hallazgos sospechosos se filtran antes de consolidar.
- El resumen de Nuclei ahora expone total vs sospechosos.

### Conteo Consistente de Vulnerabilidades Web

- Summary + run_manifest ahora incluyen conteos **raw vs consolidado**.
- CLI muestra el total consolidado y el raw si difiere.

### Títulos en JSONL

- `findings.jsonl` ahora incluye `descriptive_title` para mejor visualización downstream.

### Banner dinámico de SO

- El banner del CLI refleja el SO detectado con fallback seguro a `LINUX`.

---

**Changelog Completo**: [CHANGELOG_ES.md](../../ES/CHANGELOG_ES.md)
