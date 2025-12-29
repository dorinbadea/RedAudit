# RedAudit v3.9.8 Release Notes

[![Versión en Español](https://img.shields.io/badge/Español-blue)](./RELEASE_NOTES_v3.9.8_ES.md)

**Release Date:** 2025-12-29

## Discovery Identity Tuning

This release improves **asset typing accuracy** across heterogeneous networks without relying on local DNS suffixes.

### Hostname Normalization

- Asset typing now strips common local suffixes (e.g., `.fritz.box`, `.local`, `.lan`).
- Hostname-based detection works consistently across enterprise routers (Cisco, Meraki, Ubiquiti, etc.).

### Router & Repeater Identification

- Added Sercomm/Sagemcom vendor mapping to router/CPE.
- FRITZ!Repeater HTTP fingerprinting maps repeaters as routers.
- HTTP/agentless device-type hints (router/repeater/access point) are respected.

### Media vs Mobile Refinements

- Android devices with cast/SSDP signals classify as **media**.
- Samsung defaults to **media** unless mobile indicators are present.

### Workstation Overrides

- Hostnames with workstation brands (MSI/Dell/Lenovo/HP/Asus/Acer) override RDP server heuristics.

---

**Full Changelog**: [CHANGELOG.md](../../CHANGELOG.md)
