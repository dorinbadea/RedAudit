# RedAudit v4.10.1 Release Notes

##  Overview

RedAudit v4.10.1 is a hotfix release addressing a critical incongruency in how newly discovered hosts (via Route Following/SNMP Topology) were processed. In v4.10.0, these hosts were added to the report but missed the CVE enrichment phase, leading to incomplete risk assessments compared to the primary targets.

This release ensures all discovered hosts receive the same deep analysis, maintaining the "Audit Quality" standard of the framework.

##  Bug Fixes

- **Inconsistent Host Enrichment**: Fixed an issue where hosts originating from `snmp_topology` (Route Following) were skipped during the CVE correlation phase.
  - **Impact**: Newly discovered hosts showed open ports but zero CVEs, even if vulnerable services were present.
  - **Fix**: The auditor now explicitly triggers `enrich_host_with_cves` on all new findings from the topology module.

- **Auditor Implementation Error**: Resolved a potential `NameError` caused by a local import of `enrich_host_with_cves` inside the main scan loop.
  - **Fix**: Moved critical imports to the module top-level to ensure availability across all methods (including the new topology logic).

##  Usage

No changes to CLI flags. The fix is automatic for all scans using `--follow-routes` or having SNMP topology enabled.

```bash
# Standard scan with route following (now fully enriched)
sudo redaudit -t 10.0.0.0/24 --follow-routes
```
