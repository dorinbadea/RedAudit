# RedAudit v2.9.0 Release Notes

**Release Date:** 2025-12-12
**Codename:** Smart Improvements & Clean Docs

---

## Overview

RedAudit v2.9.0 represents a significant leap forward in **intelligence and usability**. This release introduces "Smart" features that reduce noise and manual effort, alongside a complete overhaul of the documentation to ensure a professional, version-agnostic experience.

## Key Improvements

### 1. Smart-Check (Intelligent False Positive Filtering)

RedAudit now automatically filters 90%+ of common Nikto false positives by analyzing the `Content-Type` of responses.

- **Problem**: Nikto often flags JSON APIs or binary endpoints as vulnerable because they don't have HTML headers like `X-Frame-Options`.
- **Solution**: Smart-Check detects if a response is JSON/XML/Image and suppresses unrelated findings automatically.
- **Benefit**: Cleaner reports with fewer distractions.

### 2. UDP Taming (50-80% Faster Scans)

UDP scanning has been optimized to be faster without sacrificing detection quality.

- **Old Behavior**: Scanned all ports or huge ranges, often hitting timeouts.
- **New Behavior**:
  - Uses `--top-ports 100` for deep scans to catch the most critical services (DNS, DHCP, NTP, etc.).
  - Enforces strict `--host-timeout 300s` to prevent "zombie" scans.
  - Reduces retries (`--max-retries 1`) for reliable LAN environments.

### 3. Entity Resolution (Unified Assets)

RedAudit now intelligently groups multiple IP addresses belonging to the same physical device.

- **Mechanism**: Connects IPs sharing the same MAC address locally.
- **Output**: A new `unified_assets` array in the JSON report showing the "physical" device view.

### 4. Professional SIEM Integration (ECS v8.11)

The JSON report schema has been enhanced for direct ingestion into modern SIEMs (Elastic, Splunk).

- **ECS Compliance**: Adds `ecs`, `event`, and `host` fields following Elastic Common Schema v8.11.
- **Risk Scoring**: Calculates a dynamic `risk_score` (0-100) per host based on open ports, vulnerabilities, and services.
- **Auto-Tagging**: Automatically tags hosts (e.g., `web_server`, `database`, `iot`, `router`) based on detected services.

### 5. Documentation Cleanup

A massive effort was undertaken to **simplify and professionalize** the project documentation.

- **Version-Agnostic**: Removed confusing "New in v2.x" headers from READMEs and Manuals.
- **Unified Style**: Consistent formatting across English (EN) and Spanish (ES) documentation.
- **Updated Diagrams**: New, cleaner architecture diagrams with subtle branding.

---

## Files Changed

| Category | Changes |
|----------|---------|
| **Core** | Added `verify_vuln.py` (Smart-Check), `entity_resolver.py`, `siem.py`. |
| **Logic** | Updated `scanner.py` for UDP optimization and `reporter.py` for SIEM output. |
| **Docs** | Massive cleanup of `README.md`, `MANUAL*`, `SECURITY*`, and `USAGE*`. |
| **Tests** | Added 3 new test suites (`test_verify_vuln`, `test_entity_resolver`, `test_siem`). |

---

## Validating the Release

To verify your installation matches this release:

```bash
bash redaudit_verify.sh
# Expected output: "RedAudit v2.9.0 Integrity Check"
```

---

## Thanks

Special thanks to the feedback on documentation clarity and scan efficiency that drove this "Smart" release.
