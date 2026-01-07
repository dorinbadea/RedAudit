# RedAudit v4.3.0 Release Notes

## Enterprise Risk Scoring & Deep Scan Optimizations

RedAudit v4.3.0 represents a major milestone in "Smart-Check" auditing, introducing a rewritten Risk Scoring engine (V2) and significantly deeper scanning capabilities for containerized environments.

### 🌟 Headline Features

#### 1. Enterprise Risk Scoring V2

The risk calculation engine has been overhauled to treat **Configuration Findings** (from Nikto, Nuclei, Zap) as first-class citizens alongside CVEs.

* **Previous behavior**: Risk score was heavily weighted by CVSS/CVEs. A host with zero CVEs but an exposed admin panel (Critical finding) might receive a low risk score.
* **New behavior**: Findings with `high` or `critical` severity directly impact the Density Bonus and Exposure Multiplier. A host with critical misconfigurations now correctly scores in the 80-100 (High/Critical) range, ensuring accurate prioritization.

#### 2. Docker & Deep Scan Optimization (H2)

We've optimized the "Deep Scan" phase to better handle Docker containers and ephemeral services often found in modern stacks:

* **Nikto Unchained**: Removed default tuning constraints (`-Tuning x`) and increased timeout to 5 minutes (`300s`). This ensures Nikto completes full checks against complex web apps.
* **Nuclei Expanded**: The scanner now processes findings with `severity="low"`, capturing critical information leaks (e.g., exposed logs, status pages, .git config) that were previously filtered out.

#### 3. HyperScan SYN Mode

New optional SYN-based port scanning mode for privileged users:

* **Speed**: ~10x faster than connect scans.
* **Usage**: Automatically selected when running as root with scapy installed, or force with `--hyperscan-mode syn`.

### 🛡️ Improvements

* **Warning Suppression**: Cleaned up `arp-scan` and `scapy` error output (redundant "Mac address not found" warnings) for a professional, noise-free terminal experience.
* **Identity Visualization**: HTML reports now color-code the `identity_score` to clearly show which hosts are fully identified vs. those needing manual review.
* **PCAP Management**: Automated cleanup and organization of packet capture artifacts.

### 🐛 Fixes

* **Smart-Check Validation**: Enhanced false positive filtering using CPE cross-validation.
* **Broken Risk Logic**: Fixed regression where non-CVE findings resulted in 0 risk score.

---

**Upgrade:**

```bash
git pull
sudo bash redaudit_install.sh
```
