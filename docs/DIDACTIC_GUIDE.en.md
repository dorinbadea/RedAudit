# RedAudit Instructor Guide

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](DIDACTIC_GUIDE.es.md)

**Audience:** Instructors, Professors, Mentors
**Purpose:** Teach network auditing concepts using RedAudit as a practical tool
**Prerequisite Knowledge:** TCP/IP fundamentals, Linux CLI basics
**Source of Truth:** `redaudit/core/auditor.py`

> **This is NOT a software manual.** For CLI reference, see [USAGE.en.md](USAGE.en.md). For architecture details, see [MANUAL.en.md](MANUAL.en.md).

---

## 1. Executive Summary for Instructors

### Session Planning Guide

| Duration | Scope | Topics | Lab |
|:---|:---|:---|:---|
| **30 min** | Demo Only | What is orchestration? Live scan of 1 host. JSON output. | None |
| **60 min** | Intro | Orchestration + Heuristics. Scan a /28 subnet. | Lab 1 (Basic) |
| **90 min** | Standard | Above + Deep Scan logic + Reporting structure. | Lab 1 + Lab 2 |
| **120 min** | Advanced | Above + SIEM integration + Code walkthrough. | All three labs |

### Materials Checklist

- [ ] VM with Kali/Parrot (RedAudit pre-installed)
- [ ] Isolated lab network (10.0.0.0/24 or similar)
- [ ] At least 3 target hosts with varied services (1 web, 1 SSH-only, 1 "empty")
- [ ] Projector/screen for live demo
- [ ] Printed rubric (Section 5)

---

## 2. Core Teaching Concepts

### Concept 1: Orchestration vs. Manual Scanning

**What to explain:**
Running `nmap`, `nikto`, `testssl` manually produces scattered outputs. Correlating "what vulnerabilities exist on port 443 of host X?" requires manual grep/analysis.

**Orchestration** means:

1. A central program calls multiple tools in sequence.
2. Results are unified into a single structured document (JSON).
3. Decisions (e.g., "should we scan UDP?") are made automatically via heuristics.

**Where in code:** [`run_complete_scan()`](../redaudit/core/auditor.py) orchestrates all phases.

---

### Concept 2: Evidence-Driven Auditing

**What to explain:**
Professional audits require **verifiable evidence**. A report stating "port 22 is open" is worthless without:

- Timestamp of the scan
- Tool and version used
- Raw output (or hash thereof)

**RedAudit provides:**

- JSON with `timestamp`, `version`, `scan_duration`
- Optional PCAP captures
- File permissions (0600) to prevent tampering

**Practical question:** "If a client disputes your findings, how do you prove you ran the scan correctly?"

---

### Concept 3: Heuristic Decision-Making (Deep Scan)

**What to explain:**
Scanning every host with full UDP (-p- -sU) would take hours. RedAudit uses **heuristics** to decide when extra effort is warranted.

**Trigger conditions (verified against code):**

| Condition | Reasoning |
|:---|:---|
| ≤3 open ports | Possible firewall, need deeper probing |
| Services = `unknown` or `tcpwrapped` | Evasion detected, identity unclear |
| No MAC/vendor extracted | Host identity unknown |
| >8 open ports | Complex host, worth full enumeration |

**Where in code:** Conditions in [`scan_host_ports()`](../redaudit/core/auditor.py)

---

### Concept 4: Structured Reporting (ECS Schema)

**What to explain:**
Raw text output is human-readable but machine-hostile. Structured JSON enables:

- SIEM ingestion (Elasticsearch, Splunk)
- Automated alerting
- Trend analysis over time

**RedAudit uses ECS v8.11** (Elastic Common Schema):

- `host.ip`, `host.mac`, `host.os.name`
- `vulnerability.severity`, `vulnerability.category`
- `event.type: redaudit.scan.complete`

**Where in code:** [`siem.py`](../redaudit/core/siem.py) defines ECS mappings.

---

## 3. Operational Flow (Simplified)

Use this diagram in lectures. It accurately reflects the actual code flow.

```mermaid
flowchart TD
    A[Start] --> B{Dependencies OK?}
    B -->|No| X[Exit with Error]
    B -->|Yes| C[Discovery: nmap -sn]
    C --> D[List of UP hosts]
    D --> E[Parallel Port Scan]
    E --> F{Trigger Deep Scan?}
    F -->|No| V[Agentless verification (optional)]
    F -->|Yes| H[Deep Scan: 3 Phases]
    H --> V
    V --> G[Web/SSL/CVE Enrichment]
    G --> I[Generate Artifacts]
    I --> J{Encryption?}
    J -->|Yes| K[AES-128 Encrypt]
    J -->|No| L[Save Plain]
    K --> L
    L --> M[End]
```

**Teaching tip:** Walk through the diagram before the first demo. After the demo, have students identify which phase they observed.

---

## 4. Guided Labs

### Lab 1: Basic Discovery (30 min)

**Objective:** Execute a scan, locate the output, interpret the JSON.

**Setup:**

- Target: Single host with SSH + HTTP (e.g., Metasploitable)
- Mode: `normal`

**Steps:**

1. Run: `sudo redaudit -t 10.0.0.5 -m normal --yes`
2. Locate the output folder: `ls ~/Documents/RedAuditReports/`
3. Open the JSON: `cat redaudit_*.json | jq '.hosts[0].ports'`
4. Answer: How many ports are open? What services were detected?

**Expected Outcome:** Students can navigate the file structure and extract data from JSON.

---

### Lab 2: Deep Scan Trigger Analysis (45 min)

**Objective:** Observe heuristic decision-making and understand adaptive behavior.

**Setup:**

- Target A: Host with 10+ open ports (complex)
- Target B: Host with 1 open port (minimal)
- Mode: `full`

**Steps:**

1. Run: `sudo redaudit -t 10.0.0.0/28 -m full --yes`
2. During scan, observe console output for `[deep]` markers.
3. After scan, examine JSON for `deep_scan` objects.
4. Compare Target A vs Target B: Which triggered Deep Scan? Why?

**Discussion Prompt:** "What would happen if RedAudit always ran Deep Scan?"

---

### Lab 3: Report Integration Challenge (60 min)

**Objective:** Ingest RedAudit output into a SIEM-like system.

**Setup:**

- Previous scan results (JSON)
- Elasticsearch instance (or Kibana sandbox)
- Optional: jq, curl

**Steps:**

1. Extract high-risk hosts: `cat redaudit_*.json | jq '.hosts[] | select(.risk_score > 70)'`
2. Convert to JSONL: Use the `findings.jsonl` file directly.
3. Ingest into Elasticsearch (example in [MANUAL.en.md](MANUAL.en.md#integration)).
4. Create a simple Kibana visualization.

**Expected Outcome:** Students understand the bridge between scanning and operations.

---

## 5. Assessment & Rubric

### Short-Answer Questions

1. What is the difference between `--mode fast` and `--mode full`?
2. Under what conditions does RedAudit trigger a Deep Scan?
3. Why are JSONL files not generated when `--encrypt` is enabled?
4. What is the purpose of the `.salt` file?

### Grading Rubric (Lab 2)

| Criterion | Excellent (4) | Good (3) | Developing (2) | Incomplete (1) |
|:---|:---|:---|:---|:---|
| Identifies Deep Scan triggers | All 4 conditions | 3 conditions | 2 conditions | 0-1 conditions |
| Explains reasoning | Clear, accurate | Minor errors | Vague | Missing |
| Locates JSON evidence | Correct path + key | Correct path | Incorrect path | Not attempted |

---

## 6. Common Student Errors

Based on real classroom observations:

| Error | Symptom | Correction |
|:---|:---|:---|
| Running without `sudo` | `Permission denied` on sockets | Explain raw socket requirements |
| Scanning public IPs | Scan takes forever or fails | Use only lab networks. Discuss legality. |
| Expecting playbooks with `--encrypt` | `playbooks/` folder empty | Encryption disables plaintext artifacts |
| Comparing old/new reports fails | `--diff` returns "No scan performed" | Explain `--diff` is comparison-only, not a scan |
| Editing constants.py without restarting | Changes don't apply | Python caches imports; restart is required |
| Confusing scan mode with UDP mode | Wrong ports scanned | `--mode` ≠ `--udp-mode`. One is intensity, other is protocol scope. |
| Treating ETA as exact | ETA feels “stuck” or overly large | Explain `ETA≤` is timeout-based upper bound; `ETA≈` is a dynamic estimate |

---

## 7. Code References for Teaching

These are the most pedagogically useful code locations. Use them for advanced students or live code walkthroughs.

| Concept | File | Function/Area |
|:---|:---|:---|
| Main orchestration | `core/auditor.py` | `run_complete_scan()` |
| Deep Scan triggers | `core/auditor.py` | `scan_host_ports()` (look for `trigger_deep`) |
| Parallel execution | `core/auditor.py` | `scan_hosts_concurrent()` with `ThreadPoolExecutor` |
| Progress UI + ETA | `core/auditor.py` | `_progress_columns()` and `scan_hosts_concurrent()` |
| Timeout-safe host scans | `core/auditor.py` | `_run_nmap_xml_scan()` |
| Async port probing | `core/prescan.py` | `check_port()` using `asyncio` |
| ECS schema mapping | `core/siem.py` | `build_ecs_event()` |
| Encryption | `core/crypto.py` | `encrypt_file()`, `derive_key_from_password()` |
| Playbook generation | `core/playbook_generator.py` | `generate_playbook()`, `save_playbooks()` |
| Session logging (v3.7) | `utils/session_log.py` | `SessionLogger`, `start_session_log()` (`session_logs/session_*.log/.txt`) |

> **Note:** Avoid referencing specific line numbers as they change between versions. Reference function names instead.

---

## 8. Further Reading

- [MANUAL.en.md](MANUAL.en.md) – Full architecture and CLI reference
- [USAGE.en.md](USAGE.en.md) – Practical examples by scenario
- [REPORT_SCHEMA.en.md](REPORT_SCHEMA.en.md) – JSON field definitions
- [TROUBLESHOOTING.en.md](TROUBLESHOOTING.en.md) – Error resolution

---

[Back to Documentation Index](INDEX.md)
