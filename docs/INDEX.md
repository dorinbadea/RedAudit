# RedAudit Documentation

**RedAudit** is an automated network auditing framework for Linux that orchestrates industry-standard tools (`nmap`, `whatweb`, `nikto`, `testssl.sh`, `nuclei`, `searchsploit`) into a concurrent pipeline. It supports **defensive hardening** and **authorized offensive assessments**, with deterministic, structured output. The wizard prints normalized targets with estimated host counts, Nuclei runs report partial timeouts, and web app scanners are gated when infrastructure identities are detected.

## Main Documentation

| Document | Purpose | Audience | When to read |
|:---|:---|:---|:---|
| **[Manual](MANUAL.en.md)**<br>([Español](MANUAL.es.md)) | Architecture, capabilities, and workflow reference. | Security Analysts, Architects | **Start here.** Understand *how* it works before running scans. |
| **[Usage Guide](USAGE.en.md)**<br>([Español](USAGE.es.md)) | CLI examples, scenarios, and flag reference. | Pentesters, Operators | When running scans or automating workflows. |
| **[Didactic Guide](DIDACTIC_GUIDE.en.md)**<br>([Español](DIDACTIC_GUIDE.es.md)) | Educational walkthrough of network auditing concepts with RedAudit. | Students, Juniors | For learning network auditing concepts. |
| **[Report Schema](REPORT_SCHEMA.en.md)**<br>([Español](REPORT_SCHEMA.es.md)) | JSON/JSONL schema reference, evidence fields, and pipeline transparency. | Developers, SIEM Engineers | When integrating RedAudit outputs. |
| **[Security Model](SECURITY.en.md)**<br>([Español](SECURITY.es.md)) | Privileges, encryption, and operational safety model. | Compliance, SecOps | Before deploying in sensitive environments. |
| **[Troubleshooting](TROUBLESHOOTING.en.md)**<br>([Español](TROUBLESHOOTING.es.md)) | Common errors and fixes (permissions, missing tools). | All Users | If something goes wrong. |
| **[Roadmap](ROADMAP.en.md)**<br>([Español](ROADMAP.es.md)) | Planned features, verified capabilities, and direction. | Contributors, Users | To see what's coming next. |
| **[SIEM Integration](SIEM_INTEGRATION.en.md)**<br>([Español](SIEM_INTEGRATION.es.md)) | Filebeat/Logstash pipelines and Sigma rules for ingest. | SIEM Engineers, SOC | When integrating scan results into a SIEM. |

## Assets

- **Images**: [images/](images/)
- **Changelog**: [../CHANGELOG.md](../CHANGELOG.md)
- **Contributing**: [../CONTRIBUTING.md](../CONTRIBUTING.md)

---

> **Note**: This index is the primary entry point for documentation navigation.
