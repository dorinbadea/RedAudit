# RedAudit v3.1.1 - Notas de versión

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.1.1.md)

**Fecha de release**: 14 de diciembre de 2025
**Tipo**: Patch Release - Topología, defaults persistentes y cobertura UDP
**Versión anterior**: v3.1.0

---

## Visión general

La versión 3.1.1 es un patch release centrado en mejorar el flujo operativo y aportar más contexto de red:

- Descubrimiento de topología best-effort (ARP/VLAN/LLDP + gateway/rutas) para ayudar a detectar “redes ocultas”.
- Defaults persistentes en `~/.redaudit/config.json` para no repetir flags comunes.
- Cobertura UDP configurable (`--udp-ports`) para la fase UDP full de identidad.

Este release es compatible hacia atrás con v3.1.0 y no requiere pasos de migración. Los campos nuevos son opcionales.

---

## Novedades en v3.1.1

### 1. Descubrimiento de topología (Best-Effort)

- Nuevo bloque `topology` en el objeto raíz del informe JSON cuando está activado.
- Nuevos flags CLI:
  - `--topology` (activar)
  - `--no-topology` (desactivar, anulando defaults persistentes)
  - `--topology-only` (solo topología, sin escaneo de hosts)
- Contexto best-effort (depende de herramientas/privilegios/tráfico):
  - Rutas + gateway por defecto
  - ARP discovery (activo con `arp-scan` + caché de vecinos)
  - Pistas de VLAN (detalles del link + captura limitada con tcpdump)
  - LLDP (si está disponible) y observaciones raw de CDP (best-effort)

### 2. Defaults persistentes (`~/.redaudit/config.json`)

- Nuevo bloque `defaults` en el config:
  - `threads`, `output_dir`, `rate_limit`
  - `udp_mode`, `udp_top_ports`
  - `topology_enabled`, `lang`
- Guardar defaults mediante:
  - CLI: `--save-defaults`
  - Interactivo: prompt opcional “¿guardar defaults?”

### 3. Cobertura UDP configurable (`--udp-ports`)

- Nuevo flag: `--udp-ports N` (rango: 50-500; defecto: 100).
- Solo aplica en `--udp-mode full` para la fase 2b de identidad.
- Se registra en `deep_scan.udp_top_ports` cuando se ejecuta la fase 2b.

---

## Enlaces útiles

- **Changelog**: [CHANGELOG.md](../../CHANGELOG.md) / [CHANGELOG_ES.md](../../ES/CHANGELOG_ES.md)
- **Notas para GitHub Release**: [GitHub Release Draft](DRAFT_TEMPLATE.md)
- **Manual (EN)**: [docs/MANUAL.es.md](../MANUAL.es.md)
- **Manual (ES)**: [docs/MANUAL.es.md](../MANUAL.es.md)
- **Esquema de informe (EN)**: [docs/REPORT_SCHEMA.es.md](../REPORT_SCHEMA.es.md)
- **Esquema de informe (ES)**: [docs/REPORT_SCHEMA.es.md](../REPORT_SCHEMA.es.md)
