# RedAudit v4.8.0 Release Notes

**Launch Date:** January 16, 2026
**Theme:** Speed & Precision (RustScan Integration + Nuclei Opt-in)

##  HyperScan-First Architecture (RustScan)

This release introduces **RustScan** as the primary engine for high-speed TCP connectivity checks, replacing the legacy Masscan backend.

- **Significant Speedup**: Full port discovery (1-65535) now completes in ~3 seconds on local networks (vs ~140s with masscan).
- **Graceful Fallback**: If RustScan is not available, RedAudit seamlessly falls back to standard nmap techniques.
- **Reporting**: New `rustscan` object in report schema (backwards compatible `masscan` key alias retained).

##  Reduced Noise (Nuclei Opt-in)

To streamline network audits and respect "quiet" environments, Nuclei (vulnerability template scanning) is now **OFF by default**.

- **Opt-in Required**: Use the new `--nuclei` flag to enable it.
- **Wizard Update**: The interactive wizard now defaults to "No" when asking about extensive web vulnerability scanning.
- **Why**: Nuclei is excellent for web app security but often overkill for general network infrastructure audits, causing excessive traffic and timeouts on dense segments.

## ️ Internal Improvements

- **Refactored `net_discovery`**: Cleaner logic separating discovery phase from enumeration.
- **Enhanced Timeout Handling**: Improved batch processing logic for web scanners to prevent premature timeouts.
- **Documentation**: Updated Manuals (EN/ES) and Schemas to reflect toolchain changes.
