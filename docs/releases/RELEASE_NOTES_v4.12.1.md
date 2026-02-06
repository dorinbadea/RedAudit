# Release Notes v4.12.1

## Overview

This patch release focuses on **Nuclei performance optimization**, ensuring consistent topology data through **OUI enrichment**, and clarifying scan profiles in the Wizard. It also improves type safety and fixes parameter precedence issues.

## Detailed Changes

### Performance Optimization

* **Nuclei Fast Profile**: Optimized the `fast` profile for significantly higher throughput.
  * **Rate Limit**: Increased from 150 to **300 requests/second**.
  * **Batch Size**: Increased from 10 to **15 templates/batch**.
  * These changes reduce scan duration for large CVE sets without compromising stability.

### Data Quality

* **Topology Enrichment**: The topology phase (`arp-scan`) now automatically performs OUI lookups for vendors reported as "(Unknown)". This ensures consistent vendor identification across all modules.

### User Experience

* **Wizard Clarity**: Updated profile descriptions to clearly distinguish between discovery-only modes and vulnerability scanning modes.
  * **Express**: Explicitly marked as "Discovery only, no vuln scanning (~10 min)".
  * **Standard**: Explicitly marked as "Discovery + vulnerability scanning (~30 min)".

### Bug Fixes

* **Parameter Precedence**: Fixed an issue where explicit Nuclei parameters (CLI flags or internal overrides) were being ignored in favor of profile defaults. Explicit values now correctly take precedence.
* **Type Safety**: Resolved `mypy` type errors in the Nuclei module by implementing proper `TypedDict` structures for profile configuration.
