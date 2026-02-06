# RedAudit v3.9.1a Notas de Lanzamiento

[![English Version](https://img.shields.io/badge/English-blue)](./RELEASE_NOTES_v3.9.1a.md)

**Fecha de lanzamiento**: 2025-12-27

## Highlights

Este hotfix se centra en la **fidelidad de informes** y en **metadatos para dashboards**.

---

## Correcciones

### Títulos de hallazgos en HTML ES

- Se corrigió el regex para localizar correctamente títulos comunes en `report_es.html`.

### Metadatos en summary.json

- Se añadieron `scan_mode_cli`, `options` compacto y el alias `severity_counts` para dashboards e integraciones.

---

## Instalación

```bash
pip install --upgrade redaudit
# o
pip install git+https://github.com/dorinbadea/RedAudit.git@v3.9.1a
```

---

## Enlaces

- [Changelog completo](../../ES/CHANGELOG_ES.md)
- [Documentación](../../docs/INDEX.md)
- [GitHub Releases](https://github.com/dorinbadea/RedAudit/releases)
