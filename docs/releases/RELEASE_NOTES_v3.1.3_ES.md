# RedAudit v3.1.3 - Notas de versión

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.1.3.md)

**Fecha de release**: 15 de diciembre de 2025
**Tipo**: Patch Release - UDP y topología asíncronos
**Versión anterior**: v3.1.2

---

## Visión general

La versión 3.1.3 se centra en mejoras de velocidad con asyncio, manteniendo un comportamiento best-effort y sin romper compatibilidad:

- Probing UDP concurrente rápido (puertos prioritarios) durante deep scan.
- Descubrimiento de topología más rápido ejecutando pasos independientes en paralelo.

Este release es compatible hacia atrás con v3.1.2 y no requiere pasos de migración.

---

## Novedades en v3.1.3

### 1. Probe UDP asíncrono (Best-Effort)

- El deep scan ejecuta un probe UDP rápido con asyncio sobre puertos prioritarios (timeout acotado + límite de concurrencia).
- Los resultados se registran como `deep_scan.udp_priority_probe` para evidencia y triage rápido.

### 2. Descubrimiento de topología asíncrono (Best-Effort)

- La recolección de topología ejecuta comandos independientes en paralelo (rutas/gateway, LLDP, ARP, pistas de VLAN).
- Mejora la UX cuando se activa `--topology` o `--topology-only`, sin cambiar el esquema JSON.

---

## Enlaces útiles

- **Changelog**: [CHANGELOG.md](../../CHANGELOG.md) / [CHANGELOG_ES.md](../../CHANGELOG_ES.md)
- **Notas para GitHub Release**: [GitHub Release Draft](DRAFT_TEMPLATE.md)
- **Manual (EN)**: [docs/en/MANUAL.es.md](../MANUAL.es.md)
- **Manual (ES)**: [docs/es/MANUAL.es.md](../MANUAL.es.md)
- **Esquema de reporte (EN)**: [docs/en/REPORT_SCHEMA.es.md](../REPORT_SCHEMA.es.md)
- **Esquema de reporte (ES)**: [docs/es/REPORT_SCHEMA.es.md](../REPORT_SCHEMA.es.md)
