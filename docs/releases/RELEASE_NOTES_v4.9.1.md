# RedAudit v4.9.1 Release Notes

**Launch Date:** January 16, 2026
**Theme:** Quick Wins & Reliability (IoT Visibility + Enhanced Tagging)

## Quick Wins Implementation

This release polishes the discovery accuracy and reporting granularity with high-impact "low-hanging fruit" improvements.

- **IoT UDP Visibility**: Specialized UDP ports (e.g., WiZ 38899) discovered during the HyperScan phase are now correctly injected into final reports. Previously, these were detected but not formally attributed to the host asset.
- **Honeypot Detection**: New `honeypot` tag added for hosts exposing an excessive number of open ports (>100), helping to quickly identify deceptive nodes.
- **No-Response Granularity**: Hosts that are discovered but fail the Deep Scan (Nmap) phase are now tagged with `no_response:nmap_failed` instead of a generic status, aiding troubleshooting.

## Bug Fixes

- **Nuclei Wizard Prompt**: Fixed a missing internationalization key (`nuclei_enable_q`) that caused raw key text to appear in the interactive wizard instead of the translated question.
- **Code Cleanup**: Removed legacy `masscan_scanner.py`, completing the migration to the pure RustScan architecture.

## Documentation

- **VLAN Limitations**: Explicitly documented the limitation regarding 802.1Q VLAN detection when scanning from an access port (L2 isolation), clarifying scanning scope expectations.
