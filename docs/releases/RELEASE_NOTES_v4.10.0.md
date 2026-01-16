# RedAudit v4.10.0 - Advanced L2/L3 Discovery & Critical Fixes

This release introduces powerful new network topology discovery capabilities, bridging the gap between local scanning and routed network visibility. It also addresses a critical bug in the auditing engine.

## New Features

### 🔍 Advanced L2/L3 Discovery

- **SNMP Topology Discovery** (`--snmp-topology`):
  - Queries SNMP-enabled routers for routing tables, ARP caches, and interface lists.
  - Automatically identifies new subnets reachable from the audit host.
- **Route Following** (`--follow-routes`):
  - Optional flag to automatically expand the scan scope to include discovered subnets.
  - Enables recursive network discovery in segmented environments.
- **Passive Layer 2 Discovery**:
  - **LLDP**: Captures Link Layer Discovery Protocol frames using `tcpdump` (cross-platform) or `lldpctl` to identify connected switches and port information.
  - **CDP**: Captures Cisco Discovery Protocol frames via `tcpdump`.
  - **VLAN Detection**: Identifies 802.1Q VLAN tags on the local interface using `ifconfig`/`ip link` and passive packet sniffing.

### 🪄 Wizard Enhancements

- Integrated new interactive prompts in the auditing wizard to easily enable SNMP topology discovery and route following without remembering CLI flags.

## Bug Fixes

- **CRITICAL**: Fixed an `AttributeError: 'set' object has no attribute 'append'` in the Host object tagging logic. This issue caused crashes during the HyperScan phase when attempting to tag IoT devices.

## Verification

To verify the new topology features:

```bash
# Passive L2 Discovery (Root required for tcpdump)
sudo redaudit --target <IP> --topology --verbose

# Active SNMP Topology (requires SNMP credentials)
redaudit --target <ROUTER_IP> --snmp-user <USER> --snmp-pass <PASS> --snmp-topology
```

## Contributors

- @DorinBadea (Architecture & Implementation)
