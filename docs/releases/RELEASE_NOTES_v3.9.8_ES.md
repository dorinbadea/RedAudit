# RedAudit v3.9.8 Notas de Lanzamiento

[![English Version](https://img.shields.io/badge/English-blue)](./RELEASE_NOTES_v3.9.8.md)

**Fecha de lanzamiento:** 2025-12-29

## Ajuste de identidad de descubrimiento

Esta versión mejora la **precisión del tipado de activos** en redes heterogéneas sin depender de sufijos DNS locales.

### Normalización de hostnames

- El tipado de activos ahora elimina sufijos locales comunes (ej. `.fritz.box`, `.local`, `.lan`).
- La detección por hostname funciona de forma consistente con routers empresariales (Cisco, Meraki, Ubiquiti, etc.).

### Identificación de routers y repetidores

- Sercomm/Sagemcom se mapean como router/CPE.
- El fingerprint HTTP de FRITZ!Repeater lo clasifica como router.
- Se respetan hints HTTP/agentless de tipo de dispositivo (router/repeater/access point).

### Ajustes media vs móvil

- Dispositivos Android con señales cast/SSDP se clasifican como **media**.
- Samsung queda en **media** salvo indicadores móviles explícitos.

### Overrides de workstation

- Hostnames con marcas de workstation (MSI/Dell/Lenovo/HP/Asus/Acer) sobrescriben la heurística de RDP server.

---

**Changelog completo**: [CHANGELOG_ES.md](../../CHANGELOG_ES.md)
