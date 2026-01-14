# Release Notes v4.6.20

**Release Date**: 2026-01-14

## Summary

This release fixes critical bug detection issues and improves code quality through consolidation of duplicated functions.

## New Features

### Nuclei Timeout Configuration

New `--nuclei-timeout` CLI flag allows configuring the batch timeout (default 300 seconds):

```bash
redaudit --target 192.168.1.0/24 --nuclei --nuclei-timeout 600
```

Useful for Docker networks or slow environments where the default timeout causes partial scans.

## Bug Fixes

### vsftpd 2.3.4 Backdoor Detection

Fixed detection of the infamous CVE-2011-2523 backdoor. The detection now combines `service`, `product`, `version`, and `banner` fields from Nmap output, ensuring the vulnerability is correctly identified and assigned risk score 100.

### Title Consistency Between Reports

JSONL export now uses `descriptive_title` for both `title` and `descriptive_title` fields, matching HTML report behavior. This ensures consistent finding titles across all output formats.

## Improvements

### Unified Title Generation

Consolidated the duplicated `_extract_title` functions from `jsonl_exporter.py` and `html_reporter.py` into a single `extract_finding_title` function in `siem.py`. This removes approximately 170 lines of duplicated code and ensures consistent title generation with the following fallback chain:

1. Use existing `descriptive_title` if set
2. Use Nuclei `template_id`
3. Use CVE IDs
4. Generate from `parsed_observations`
5. Use first valid `nikto_findings` entry
6. Fall back to port-based title (e.g., "HTTP Service Finding on Port 80")

## Commits

- `a02e2be` - fix(siem): detect vsftpd 2.3.4 backdoor from port version field
- `1ee7860` - refactor(siem): unify extract_finding_title across exporters
- `cd3fd36` - feat(cli): add --nuclei-timeout flag for configurable batch timeout
- `b036021` - fix(siem): handle None observations and add nikto_findings fallback

## Upgrade Notes

No breaking changes. Upgrade by pulling the latest version and reinstalling:

```bash
git pull origin main
pip install -e .
```
