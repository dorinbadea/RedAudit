# RedAudit v3.9.9 Notas de Lanzamiento

[![English Version](https://img.shields.io/badge/English-blue)](./RELEASE_NOTES_v3.9.9.md)

**Fecha de lanzamiento:** 2025-12-29

## Fix de heurística de impresoras

Este hotfix corrige un caso borde introducido por las heurísticas de workstation.

### Hostnames de impresora

- Los tokens de impresora tienen prioridad sobre marcas de workstation.
- Evita que hostnames como `hp-printer-01` se clasifiquen como workstation.

---

**Changelog completo**: [CHANGELOG_ES.md](../../CHANGELOG_ES.md)
