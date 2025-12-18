# RedAudit v3.2.0 - Release Notes

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](RELEASE_NOTES_v3.2.0_ES.md)

**Release Date**: December 15, 2025
**Focus**: Enhanced Network Discovery + Guarded Red Team Recon

---

## Overview

Version 3.2.0 introduces an optional **Enhanced Network Discovery** phase (`--net-discovery`) designed to surface guest networks, additional DHCP servers, and broadcast/L2 signals that traditional host-only scanning can miss.

When explicitly enabled, an additional **guarded Red Team recon** block (`--redteam`) performs best-effort enumeration and passive L2 signal capture to improve asset discovery and hardening context.

---

## What's New in v3.2.0

### Enhanced Network Discovery (`--net-discovery`)

New module: `redaudit/core/net_discovery.py`

Implemented techniques (best-effort; depends on system tools):

- DHCP discovery (nmap broadcast script)
- NetBIOS discovery (nbtscan/nmap)
- mDNS/Bonjour discovery
- UPNP discovery
- ARP discovery (netdiscover)
- ICMP sweep (fping)
- VLAN candidate analysis based on multi-DHCP signals

### Guarded Red Team Recon (`--redteam`)

When `--redteam` is enabled, results are stored under `net_discovery.redteam` and include best-effort:

- SNMP walking (read-only)
- SMB enumeration (read-only)
- RPC enumeration
- LDAP RootDSE discovery
- Kerberos realm discovery (+ optional userenum when an explicit userlist is provided)
- DNS zone transfer attempt (AXFR) when a zone hint is available
- Passive L2 signal capture for VLAN/STP/HSRP/VRRP/LLMNR/NBT-NS (requires root + tcpdump)
- Router discovery (IGMP broadcast script / passive hints)
- IPv6 neighbor discovery (best-effort)

### New CLI Flags (v3.2)

In addition to `--net-discovery` and `--redteam`, v3.2 adds tuning flags:

- `--net-discovery-interface IFACE`
- `--redteam-max-targets N`
- `--snmp-community COMMUNITY`
- `--dns-zone ZONE`
- `--kerberos-realm REALM`
- `--kerberos-userlist PATH`
- `--redteam-active-l2`

---

## New Report Fields

- `net_discovery`: Optional root-level block when `--net-discovery` is enabled
- `net_discovery.dhcp_servers[].domain` / `domain_search`: Best-effort DHCP domain hints
- `net_discovery.redteam`: Extended recon output when `--redteam` is enabled

See `docs/en/REPORT_SCHEMA.en.md` for the detailed schema.

---

## Upgrade Notes

- **Backward compatible**: New fields are additive and only appear when features are enabled.
- **Operational note**: Some L2 captures require root and a correct interface selection (`--net-discovery-interface`).

---

## Testing

```bash
# Verify version
redaudit --version  # Should show: RedAudit v3.2.0

# Basic enhanced network discovery
sudo redaudit --target 192.168.1.0/24 --net-discovery --yes

# With guarded redteam recon (best-effort)
sudo redaudit --target 192.168.1.0/24 --net-discovery --redteam --net-discovery-interface eth0 --yes
```
