# Release Notes v3.10.1

**Release Date:** 2026-01-02
**Codename:** Identity Consistency & Vendor Hints

## Summary

This patch release addresses audit recommendations for identity enrichment consistency. It ensures that MAC addresses discovered via passive neighbor cache trigger online OUI lookups, consolidates DNS reverse hostnames into the canonical record, and introduces hostname-based vendor inference as a fallback when OUI lookup fails (e.g., for randomized MACs).

## New Features

### Vendor Hints Module

New utility (`redaudit/utils/vendor_hints.py`) that infers device manufacturer from hostname patterns when OUI lookup is unavailable:

- Recognizes patterns like `iPhone`, `Galaxy`, `Pixel`, `MacBook`, `iPad`, `FRITZ`, `Xbox`, etc.
- Returns vendor with `(guess)` suffix to indicate inference method
- Priority: OUI lookup > hostname pattern matching

## Fixes

### Neighbor Cache MAC Enrichment

MAC addresses discovered via `ip neigh` (passive neighbor cache) now trigger an online OUI vendor lookup via `macvendors.com`, ensuring consistent vendor identification across all discovery methods.

### DNS Reverse Consolidation

Phase 0 (low-impact) DNS reverse lookups stored in `phase0_enrichment.dns_reverse` are now consolidated into the canonical `host.dns.reverse` field if empty. This ensures:

- Consistent hostname display in HTML and TXT reports
- Proper entity resolution using all available hostname sources
- Better identity scoring for SmartScan decisions

### Data Flow Consistency

Fixed gaps where low-impact enrichment data was not propagating to downstream consumers:

- `entity_resolver.py`: Now uses `phase0_enrichment.dns_reverse` as fallback
- `reporter.py`: TXT report uses new `_get_hostname_fallback()` helper
- `html_reporter.py`: Uses `get_best_vendor()` for vendor display with hostname fallback

## Testing

- Added `tests/test_audit_fixes.py` with integration tests for DNS consolidation
- Added `tests/test_mac_enrichment.py` for vendor hints and neighbor cache enrichment
- All 2354+ tests passing

## Upgrade Notes

This is a backward-compatible patch release. No configuration changes required.

---

[Full Changelog](../../CHANGELOG.md) | [Documentation Index](../INDEX.md)
