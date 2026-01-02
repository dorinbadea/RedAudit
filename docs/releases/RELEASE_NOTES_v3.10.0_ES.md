# RedAudit v3.10.0 Notas de Lanzamiento

[![English Version](https://img.shields.io/badge/English-blue)](./RELEASE_NOTES_v3.10.0.md)

**Fecha de lanzamiento:** 2026-01-01

## Gobernanza SmartScan y Enriquecimiento Fase 0

Esta versión añade enriquecimiento de identidad opt-in y un escalado más estricto para mantener los deep scans conservadores por defecto.

### Enriquecimiento Fase 0 de bajo impacto (Opt-in)

- Sondas opcionales y de timeout corto para reverse DNS, mDNS unicast y SNMP sysDescr.
- Mejor esfuerzo: sin reintentos, sin esperas largas y sin cambios de timeout global.

### Escalado guiado por identidad

- La puntuación de identidad queda explícita y trazable en SmartScan.
- El deep scan solo se dispara cuando la identidad es débil respecto al umbral configurado.
- La prioridad UDP solo aplica en hosts con poca visibilidad y muy baja identidad; nunca en modo stealth.

### Controles de gobernanza

- Nuevos flags para ajustar el comportamiento sin cambiar los defaults:
  - `--low-impact-enrichment`
  - `--identity-threshold`
  - `--deep-scan-budget`
- El presupuesto de deep scan se aplica de forma segura bajo concurrencia.

### Wizard y localización

- Los flujos Express/Standard/Exhaustive/Personalizado pueden activar Fase 0 con defaults persistentes.
- Los nuevos flags muestran ayuda localizada en inglés y español.

---

**Changelog completo**: [CHANGELOG_ES.md](../../ES/CHANGELOG_ES.md)
