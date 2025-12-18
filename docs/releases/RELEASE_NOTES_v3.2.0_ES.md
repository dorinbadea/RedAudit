# RedAudit v3.2.0 - Notas de versión

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.2.0.md)

**Fecha de lanzamiento**: 15 de diciembre de 2025
**Enfoque**: Descubrimiento de red mejorado + Recon Red Team con guardas

---

## Visión general

La versión 3.2.0 introduce una fase opcional de **Descubrimiento de Red Mejorado** (`--net-discovery`) orientada a detectar redes de invitados, servidores DHCP adicionales y señales broadcast/L2 que pueden quedar fuera de un escaneo basado solo en hosts.

Cuando se habilita explícitamente, un bloque adicional de **recon Red Team con guardas** (`--redteam`) ejecuta enumeración best-effort y captura pasiva de señales L2 para mejorar el descubrimiento de activos y el contexto de hardening.

---

## Novedades en v3.2.0

### Descubrimiento de red mejorado (`--net-discovery`)

Nuevo módulo: `redaudit/core/net_discovery.py`

Técnicas implementadas (best-effort; dependen de herramientas del sistema):

- Descubrimiento DHCP (script broadcast de nmap)
- Descubrimiento NetBIOS (nbtscan/nmap)
- Descubrimiento mDNS/Bonjour
- Descubrimiento UPNP
- Descubrimiento ARP (netdiscover)
- Sweep ICMP (fping)
- Análisis de VLANs candidatas basado en señales multi-DHCP

### Recon Red Team con guardas (`--redteam`)

Cuando se activa `--redteam`, los resultados se guardan en `net_discovery.redteam` e incluyen best-effort:

- SNMP walking (solo lectura)
- Enumeración SMB (solo lectura)
- Enumeración RPC
- Descubrimiento LDAP RootDSE
- Descubrimiento de realm Kerberos (+ userenum opcional cuando se aporta una lista explícita)
- Intento de transferencia de zona DNS (AXFR) cuando hay una pista de zona
- Captura pasiva de señales L2 para VLAN/STP/HSRP/VRRP/LLMNR/NBT-NS (requiere root + tcpdump)
- Descubrimiento de routers (script broadcast IGMP / pistas pasivas)
- Descubrimiento de vecinos IPv6 (best-effort)

### Nuevos flags CLI (v3.2)

Además de `--net-discovery` y `--redteam`, v3.2 añade flags de tuning:

- `--net-discovery-interface IFACE`
- `--redteam-max-targets N`
- `--snmp-community COMMUNITY`
- `--dns-zone ZONE`
- `--kerberos-realm REALM`
- `--kerberos-userlist PATH`
- `--redteam-active-l2`

---

## Nuevos campos en reportes

- `net_discovery`: Bloque opcional a nivel raíz cuando se activa `--net-discovery`
- `net_discovery.dhcp_servers[].domain` / `domain_search`: Pistas de dominio best-effort desde DHCP
- `net_discovery.redteam`: Salida de recon extendida cuando se activa `--redteam`

Consulta `docs/es/REPORT_SCHEMA.es.md` para el esquema detallado.

---

## Notas de actualización

- **Compatible hacia atrás**: Los campos nuevos son aditivos y solo aparecen cuando se habilitan estas funciones.
- **Nota operativa**: Algunas capturas L2 requieren root y una interfaz correcta (`--net-discovery-interface`).

---

## Testing

```bash
# Verificar versión
redaudit --version  # Debe mostrar: RedAudit v3.2.0

# Descubrimiento de red mejorado básico
sudo redaudit --target 192.168.1.0/24 --net-discovery --yes

# Con recon redteam con guardas (best-effort)
sudo redaudit --target 192.168.1.0/24 --net-discovery --redteam --net-discovery-interface eth0 --yes
```
