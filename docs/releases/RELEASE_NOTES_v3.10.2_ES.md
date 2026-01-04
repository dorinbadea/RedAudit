# Notas de la Versión RedAudit v3.10.2

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.10.2.md)

**Fecha de lanzamiento:** 2026-01-04

## Resumen

Detección VPN por Vendor y Precisión de Documentación

## Novedades

### Detección de Vendors VPN/Firewall

Nueva heurística en `entity_resolver.py` clasifica dispositivos de 12 vendors conocidos:

- Palo Alto, Fortinet, Cisco, Juniper, SonicWall
- Check Point, WatchGuard, Sophos, Pulse Secure
- F5 Networks, Barracuda

**Lógica:**

- Vendor + puertos VPN (500/4500/1194/51820) → `"vpn"`
- Vendor + puertos Web (80/443/8443) → `"firewall"`

### Limpieza de Documentación

- **Eliminadas flags zombie de prescan** (`--prescan`, `--prescan-ports`, `--prescan-timeout`) - superadas por HyperScan desde v3.0
- **Documentadas flags CLI ocultas** en READMEs: `--max-hosts`, `--no-deep-scan`, `--no-txt-report`, `--nvd-key`
- **Corregido wording "Subnet Leak"** → "Indicios de Fuga de Red" para reflejar detección basada en DHCP
- **Corregida descripción VPN** → "OUI de vendor" en lugar de "heurísticas MAC"

## Actualización

```bash
sudo bash redaudit_install.sh
```

---

[Changelog Completo](../../ES/CHANGELOG_ES.md)
