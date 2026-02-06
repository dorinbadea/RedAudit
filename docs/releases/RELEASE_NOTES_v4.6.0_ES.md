# RedAudit v4.6.0 - Optimización Trust HyperScan

**Fecha:** 11-01-2026
**Tipo:** Release de Funcionalidad

Esta versión introduce una optimización crítica para auditorías sensibles al tiempo: **Trust HyperScan**.

### ⚡ Modo Trust HyperScan

Anteriormente, el modelo de seguridad paranoica de RedAudit forzaba un escaneo completo de 65.535 puertos (`nmap -p-`) para cualquier host en Deep Scan, independientemente de los resultados previos. Esto garantizaba máxima precisión a costa de retrasos significativos (20-30 mins) en routers domésticos lentos.

**Nueva Funcionalidad (`--trust-hyperscan`):**

- Permite al motor de Deep Scan **reutilizar** los puertos descubiertos por HyperScan (Fase 2).
- Omite el barrido redundante `-p-`, reduciendo tiempos de ~25 mins a <2 mins por host.
- **Opcional**: Desactivado por defecto para mantener el rigor profesional. Activable vía CLI o Asistente interactivo.

### Cambios CLI

- Añadido flag `--trust-hyperscan` (alias `--trust-discovery`).

### Cambios Asistente

- Añadido prompt interactivo: *"¿Activar 'Trust HyperScan'? (Reutilizar descubrimiento para Deep Scan rápido)"*.

### Infraestructura

- Actualizada build y versionado a v4.6.0.

---
**Full Changelog**: <https://github.com/dorinbadea/RedAudit/compare/v4.5.18...v4.6.0>
