# Roadmap & Architecture Proposals

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](ROADMAP.es.md)

**Audience:** Contributors, stakeholders
**Scope:** Planned features, verified capabilities, discarded concepts.
**Source of Truth:** Repository code and Git history

---

This document outlines the technical roadmap, verifies implemented capabilities, and records discarded approaches for RedAudit.

## 1. Active Roadmap (Planned / In Progress / Deferred)

This section contains only pending roadmap work. Implemented baseline items are tracked in **Completed Milestones**.

### Status Legend

| Status | Meaning |
| --- | --- |
| **Planned** | Scoped and approved for a future milestone, not started. |
| **In Progress** | Actively being implemented or validated. |
| **Deferred** | Explicitly postponed until constraints are resolved. |
| **Done** | Implemented and tracked only in Completed Milestones. |
| **Replaced** | Superseded by a newer implementation path. |

### v5.x Expansion Backlog (Pending)

| Workstream | Status | Description | Guardrails |
| --- | --- | --- | --- |
| **Streaming JSON Report (Large-Network Tuning)** | Planned (v5.x) | Extend current streaming/report memory protections for extreme dataset sizes and long-running exports. | Keep deterministic output and avoid behavior changes in normal-size runs. |

### v5.x Execution Program (Expansion Work)

| Block | Status | Goal | Main Deliverables | Guardrails |
| --- | --- | --- | --- | --- |
| **C1 - Policy Layer for Leak Following** | Done | Add policy-level controls on top of safe baseline behavior. | Policy schema, allowlist profiles, deterministic precedence rules. | No scope expansion outside explicit policy boundaries. |
| **C2 - IoT Probe Pack Expansion** | Done | Broaden protocol/vendor coverage without weakening defaults. | New probe packs, bounded execution planner, confidence thresholds. | `off` remains no-op; safe controls remain mandatory. |
| **C3 - Runtime Budget Governance** | Done | Keep expansion features predictable under constrained runtimes. | Unified budget accounting for follow-up/probe operations, skip reason taxonomy extensions. | Budget exhaustion must degrade to hints, not confirmed findings. |
| **C4 - Reporting and Schema Extensions** | Done | Expose expansion outcomes with full auditability. | JSON/HTML/TXT fields for policy decisions, evidence payloads, and skip reasons. | Preserve backward compatibility for existing report consumers. |
| **C5 - UX and Documentation Alignment (EN/ES)** | Done | Keep operator intent explicit across CLI/wizard/docs. | Help/prompt/documentation synchronization for all new controls. | No ambiguous wording about defaults, safety, or scope boundaries. |
| **C6 - Regression and Release Gate** | Done | Validate reliability before release promotion. | Branch-complete tests for touched logic and docs/schema consistency sweep. | 100% coverage on touched code paths; no drift in `off` behavior. |

#### Detailed Work Plan and Acceptance Gates

1. **Deliver C1 first (policy semantics before orchestration).**
   - Define policy model and evaluation precedence.
   - Keep skip reason taxonomy deterministic and user-auditable.
   - Exit gate: unit tests for precedence and deny paths.

2. **Deliver C2 runtime wiring with bounded execution.**
   - Integrate expanded probe packs only under safe/explicit modes.
   - Keep baseline behavior unchanged when expansion controls are `off`.
   - Exit gate: integration tests for parity in off mode and bounded expansion mode.

3. **Deliver C3 + C4 for runtime governance and reporting.**
   - Persist budget and policy decisions in runtime/report payloads.
   - Keep report outputs coherent across JSON/HTML/TXT.
   - Exit gate: snapshot/assertion coverage for all new report fields.

4. **Deliver C5 docs and UX synchronization.**
   - Align CLI help, wizard prompts, roadmap/schema/usage docs in EN/ES.
   - Validate wording consistency against implemented options.
   - Exit gate: docs consistency review with no EN/ES semantic drift.

5. **Close with C6 release gate.**
   - Run local quality gate after final changes.
   - Verify no regressions in resume flow, progress rendering, and reporting coherence.
   - Exit gate: all quality checks green and changelog/release notes aligned.

#### C-Program Tracking Checklist

- [x] C1 policy layer implemented and tested.
- [x] C2 probe-pack expansion implemented and tested.
- [x] C3 budget governance implemented and tested.
- [x] C4 reporting/schema extensions implemented and tested.
- [x] C5 EN/ES UX and documentation synchronized.
- [x] C6 release gate passed with regression checks.

### Deferred Technical Backlog

| Feature | Status | Description |
| --- | --- | --- |
| **Auditor Runtime De-mixin (Phase 2)** | Deferred | Wizard-first de-mixin is completed; remaining runtime decomposition is deferred until it unlocks testing or fixes defects. |
| **PyPI Distribution** | Deferred | Publishing `pip install redaudit`. Blocked by need for extensive cross-platform testing. |
| **Plugin Engine** | Deferred | "Plugin-first" architecture to decouple core scanner from tools. |
| **AsyncIO Migration** | Deferred | Full migration to AsyncIO deferred to v5.0. |
| **Centralized Timeout Registry** | Deferred | Consolidate scanner timeouts in one place for easier tuning and testing. |

### Future Features (v5.0.0)

| Feature | Description |
| --- | --- |
| **Streaming JSON Report (Large-Network Tuning)** | Additional streaming/report memory safeguards for very large datasets and long-running exports. |
| **Scope Expansion Telemetry Visualization** | Visual aggregation of policy decisions, IoT probe runtime counters, and evidence classes in dashboard views. |
| **Pipeline Audit** | Interactive visualization of the discovery flow. |

---

## 2. Completed Milestones (History)

These items are ordered chronologically (most recent first).

### v4.20.2 Scope Expansion Wizard UX Polish (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Guided Advanced Scope Expansion** | Done (v4.20.2) | Advanced wizard options now use explicit guided paths with readable policy-pack labels and clear `Automatic (Recommended)`/manual choices. |
| **Automatic Safe Fallback for Empty Manual Inputs** | Done (v4.20.2) | Empty manual CSV entries in advanced scope-expansion prompts now resolve deterministically to automatic safe defaults instead of ambiguous state. |
| **Explicit Advanced-Skip Outcome** | Done (v4.20.2) | Selecting `No (default)` on advanced scope-expansion setup now explicitly confirms that automatic recommended defaults are in effect. |

### v4.20.x Wizard Composition Hardening (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Wizard-first de-mixin** | Done (v4.20.x) | Interactive flow was extracted into composed services (`wizard_service.py`, `scan_wizard_flow.py`) and `AuditorRuntime` no longer inherits `Wizard`. |
| **Compatibility-preserving migration** | Done (v4.20.x) | `wizard.py` is kept as a compatibility facade so existing imports/tests continue to work while ownership boundaries are clearer. |
| **Interrupt status clarity** | Done (v4.20.x) | Active-scan interruption now shows an explicit "saving partial progress and cleanup" operator message before shutdown. |

### v4.20.0 Scope Expansion Hardening (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Advanced Leak Following Policies** | Done (v4.20.0) | Added policy packs (`safe-default`, `safe-strict`, `safe-extended`), allowlist profiles, and deterministic precedence (`denylist` > explicit allowlist > profile allowlist > in-scope > reject). |
| **Expanded Protocol-Specific IoT Probes** | Done (v4.20.0) | Added protocol/vendor probe packs (`ssdp`, `coap`, `wiz`, `yeelight`, `tuya`) with runtime candidate gating, per-host budget, and per-probe timeout enforcement. |
| **Evidence Model Hardening for Expansion Signals** | Done (v4.20.0) | Added structured scope-expansion evidence (`feature`, `classification`, `source`, `signal`, `decision`, `reason`, `host`, `timestamp`, `raw_ref`) and promotion guardrails for corroborated signals. |

### v4.19.52 HTML Language and Chart Clarity (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Language-Coherent HTML Report** | Done (v4.19.52) | `report.html` now follows the active run language instead of producing mixed-language defaults. |
| **Single HTML Output per Run** | Done (v4.19.52) | Spanish runs no longer create an additional `report_es.html`; output is unified in the selected language. |
| **No-Data Chart States** | Done (v4.19.52) | HTML dashboards now render explicit no-data states when severity or port datasets are empty. |

### v4.19.51 Installer Config Policy Alignment (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Manual Reinstall Reseed** | Done (v4.19.51) | Manual installer runs now reset stale `~/.redaudit/config.json` so selected language is applied cleanly. |
| **Auto-Update Preference Preserve** | Done (v4.19.51) | Auto-update path keeps existing user preferences instead of resetting stored config. |
| **NVD Config Merge Safety** | Done (v4.19.51) | Saving NVD API key during install now merges into config and preserves existing defaults. |

### v4.19.50 Startup UX and Language Persistence (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Startup Update Notice Visibility** | Done (v4.19.50) | Auto-update notices are now displayed after banner/menu rendering so users can see them reliably. |
| **Installer Language Persistence** | Done (v4.19.50) | Installer persists selected language (`en`/`es`) to user config; auto-update preserves config while manual reinstall can reseed preferences. |
| **Wizard Prompt Cleanup** | Done (v4.19.50) | Interactive prompts no longer prepend the decorative `?` marker. |

### v4.19.49 Python 3.10+ Baseline and Lock Hardening (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Python Runtime Baseline** | Done (v4.19.49) | RedAudit runtime/CI support now targets Python 3.10-3.12. |
| **Lock Security Alignment** | Done (v4.19.49) | Dependency lockfiles no longer include the Python 3.9-only `filelock` branch. |

### v4.19.48 Nuclei Resume Entry Management (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Resume Entry Management** | Done (v4.19.48) | The resume menu can delete one or all stale entries without manual file cleanup. |
| **Resume Cleanup Documentation** | Done (v4.19.48) | README/USAGE/MANUAL and didactic guidance now document in-menu cleanup. |

### v4.19.47 Updater Timeout and Async Cleanup (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Non-Blocking Git Clone Output** | Done (v4.19.47) | Updater clone output handling is non-blocking, so the 120-second safety timeout remains effective. |
| **HyperScan Async Cleanup** | Done (v4.19.47) | Full-port fallback now closes pending coroutines safely when event-loop execution fails. |
| **Updater Missing-Git Diagnostics** | Done (v4.19.47) | Missing `git` is reported separately from generic missing-file failures for clearer troubleshooting. |

### v4.19.46 Coverage Expansion and Leak-Follow Guard (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Strategic Coverage Expansion** | Done (v4.19.46) | Coverage was raised in `updater.py`, `jsonl_exporter.py`, `config.py`, `auditor_scan.py`, and `auditor_vuln.py` with added edge-case paths. |
| **Leak-Follow Port Parsing Guard** | Done (v4.19.46) | `build_leak_follow_targets` now safely handles malformed or non-numeric candidate port values. |

### v4.19.45 Startup Update Freshness (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Launch-Time Update Check** | Done (v4.19.45) | RedAudit now checks for updates at startup with a short non-blocking timeout. |
| **Offline Fallback Notice Continuity** | Done (v4.19.45) | When GitHub cannot be reached, cached release metadata still drives update notices when applicable. |

### v4.19.44 Rich Runtime and Lock Alignment (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Rich Runtime Upgrade** | Done (v4.19.44) | Rich was upgraded from 14.2.0 to 14.3.2 to improve CLI rendering stability. |
| **Lockfile Consistency for Rich** | Done (v4.19.44) | `requirements.lock`, `requirements-dev.lock`, and `poetry.lock` now pin Rich coherently for Python >= 3.10. |

### v4.19.43 Startup Update UX Baseline (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Cache-First Startup Update Notice** | Done (v4.19.43) | Startup now runs an automatic non-blocking cache-first update check and only shows notices when a newer version exists. |

### v4.19.42 Resume Manifest and Risk Accounting Integrity (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Resume Manifest Metadata Block** | Done (v4.19.42) | `run_manifest.json` includes a `nuclei_resume` block with pending-target and resume counters when artifacts exist. |
| **Nuclei Target Accounting Fields** | Done (v4.19.42) | Pipeline summary now exposes both `targets_total` and `targets_pre_optimization` for clearer accounting. |
| **Final Resume Artifact Capture** | Done (v4.19.42) | Session logs are closed before persistence so final `session_resume_*` artifacts are captured reliably. |
| **Risk Finding Count Coherence** | Done (v4.19.42) | SIEM risk breakdown now counts `finding_total` correctly and avoids invalid `risk findings 1/0` output. |
| **JSONL Hostname Reverse-DNS Fallback** | Done (v4.19.42) | `assets.jsonl` and `findings.jsonl` now use reverse-DNS fallback when `hostname` is empty. |

### v4.19.41 Canonical Vendor and Risk Evidence Fields (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Canonical Vendor Metadata** | Done (v4.19.41) | SIEM enrichment now resolves a single canonical vendor with `vendor_source` and `vendor_confidence`. |
| **Risk Evidence Detail Counters** | Done (v4.19.41) | Risk breakdown now includes counters for service CVEs, exploits, backdoor signatures, and findings totals. |
| **Cross-Output Vendor Consistency** | Done (v4.19.41) | HTML/TXT/JSONL exports now prefer the same canonical vendor field to reduce cross-report drift. |
| **Vendor Guessing Guardrails** | Done (v4.19.41) | Generic `*.fritz.box` labels are no longer forced to AVM, NAS hints map to `server`, and ECS vendor follows canonical resolution. |

### v4.19.40 Resume Risk Stability Hardening (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Idempotent Severity Enrichment** | Done (v4.19.40) | `enrich_vulnerability_severity()` is now idempotent for already-normalized findings to prevent resume risk drift. |
| **Experimental TLS Ambiguity Downgrade** | Done (v4.19.40) | Experimental TestSSL signals are downgraded when cross-signaled with "no web server found". |
| **Summary Risk Evidence Counters** | Done (v4.19.40) | `summary.json` now includes host/port evidence severity counters plus combined totals with scanner findings. |

### v4.19.39 Config Self-Healing (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Malformed Config Auto-Recovery** | Done (v4.19.39) | `load_config()` now backs up invalid config files and rebuilds a valid default config safely. |

### v4.19.38 Partial Output and SIEM Risk Coherence (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Nuclei Partial Output Coherence** | Done (v4.19.38) | Partial Nuclei runs are now persisted with coherent partial naming and TXT status metadata. |
| **SIEM Risk Recompute Stability** | Done (v4.19.38) | Host risk is computed after vulnerability normalization/consolidation and mapped back consistently on resume. |
| **Credential Audit Events** | Done (v4.19.38) | Credential providers now emit `credential_audit` events for access/store outcomes without exposing secrets. |
| **Installer JSON Serialization Safety** | Done (v4.19.38) | Installer NVD config generation now uses `jq` when available with `python3` fallback instead of raw shell JSON echoing. |

### v4.19.37 Scope-Expansion Runtime Consistency (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Nuclei Targets Total Coherence** | Done (v4.19.37) | `targets_total` now remains coherent when leak-follow appends additional targets. |
| **Coverage Messaging Alignment** | Done (v4.19.37) | Full-coverage status text now matches runtime behavior and selected-profile handling. |
| **Spanish Scope Label Localization** | Done (v4.19.37) | Scope-expansion labels are now fully localized in Spanish HTML reports. |
| **Runtime Counter Parse Guards** | Done (v4.19.37) | Scope-expansion runtime counters are parsed safely even when persisted values are malformed. |

### v4.19.36 Core Coverage Expansion Campaign (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Core Coverage Boost (>98%)** | Done (v4.19.36) | Coverage was significantly expanded across core modules, including near-complete coverage in `nuclei.py` and `auditor.py`. |
| **100% Coverage Targets** | Done (v4.19.36) | `webhook.py`, `osquery.py`, and `nvd.py` reached 100% coverage with additional defensive-path validation. |

### v4.19.35 Nuclei Resume & Profile Transparency (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Resume Count Label** | Done (v4.19.35) | Nuclei resume entries show how many times a run has been resumed. |
| **Profile Selected vs Effective** | Done (v4.19.35) | Reports record the selected profile, effective profile, and auto-switch status. |
| **Auto-Switch Documentation** | Done (v4.19.35) | README/USAGE and report schema document the auto-switch behavior. |

### v4.19.34 Risk Breakdown Traceability (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Risk Breakdown** | Done (v4.19.34) | Risk tooltips now separate evidence-backed and heuristic signals with a max-CVSS source. |
| **Auth Failures** | Done (v4.19.34) | Authenticated scan failures surface in HTML and summary exports. |
| **Asset Open Ports** | Done (v4.19.34) | `assets.jsonl` now includes open ports for inventory pipelines. |

### v4.19.27 Nuclei Warning + Resume Cancel (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Nuclei Runtime Warning** | Done (v4.19.27) | Warning is Nuclei-specific and shown before the scan starts. |
| **Resume Cancel** | Done (v4.19.27) | Ctrl+C during resume cancels cleanly without a stack trace. |

### v4.19.29 Playbook Remediation Persistence (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Playbook Persistence** | Done (v4.19.29) | Playbooks are stored in JSON reports and regenerated for HTML when missing. |

### v4.19.33 Release Workflow Reliability (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Release Workflow** | Done (v4.19.33) | Release job now updates existing releases and uses versioned release notes. |

### v4.19.32 Installer ShellCheck Fix (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Installer ShellCheck** | Done (v4.19.32) | OUI seeding helper is defined before use to satisfy ShellCheck. |

### v4.19.31 OUI Seeded Installer + Trust Signals (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Installer OUI Seed** | Done (v4.19.31) | Installer provisions a local Wireshark OUI database under `~/.redaudit/manuf`. |
| **Experimental TestSSL Handling** | Done (v4.19.31) | Experimental signals are no longer treated as confirmed exploitable. |
| **HTML False Positive Notes** | Done (v4.19.31) | Reports surface possible false positives alongside observations. |

### v4.19.30 Nuclei Full Coverage Targets (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Full Coverage Targets** | Done (v4.19.30) | Full coverage now includes all detected HTTP ports for strong-identity hosts. |

### v4.19.28 HTML Charts + Docs Hygiene (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **HTML Charts** | Done (v4.19.28) | Chart.js is bundled locally so CSP does not block report charts. |
| **Docs Cleanup** | Done (v4.19.28) | README and release notes align with current style and toolchain. |

### v4.19.26 Seed Keyring Script Bash Compatibility (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Seed Keyring Script** | Done (v4.19.26) | `scripts/seed_keyring.py` now re-routes to Python when invoked via `bash`. |

### v4.19.25 BetterCAP Cleanup (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **BetterCAP Cleanup** | Done (v4.19.25) | L2 recon now performs a best-effort BetterCAP termination after use. |

### v4.19.24 Report Hardening + Resume Docs (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Report CSP** | Done (v4.19.24) | HTML reports include a Content-Security-Policy meta header. |
| **Chown Debug Logs** | Done (v4.19.24) | Best-effort chown now logs debug details when it fails. |
| **Nuclei Timeout Constant** | Done (v4.19.24) | Default Nuclei timeout override is centralized. |
| **Resume Cleanup Docs** | Done (v4.19.24) | Documents that resumes refresh in place and how to clean stale files. |

### v4.19.23 Security Hardening (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Webhook HTTPS Enforcement** | Done (v4.19.23) | Webhooks reject non-HTTPS URLs and avoid redirects. |
| **Verify-First HTTP Probes** | Done (v4.19.23) | TLS verification is attempted first, with insecure fallback only on failure. |
| **Safer Terminal Clear** | Done (v4.19.23) | Terminal clear avoids shell execution and uses safe fallbacks. |
| **Proxy Temp Permissions** | Done (v4.19.23) | Proxychains temp config is written with restrictive permissions. |

### v4.19.22 Wizard Back + Long Scan Warning (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Wizard Back Navigation** | Done (v4.19.22) | Added back/cancel support in Standard and Exhaustive profile prompts. |
| **Long Scan Warning** | Done (v4.19.22) | Warns when full or Nuclei-enabled modes can exceed 4 hours. |

### v4.19.21 Resume Sleep Inhibition (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Resume Sleep Prevention** | Done (v4.19.21) | Resume runs now activate sleep prevention when configured. |

### v4.19.20 Resume HTML Refresh (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Resume HTML Detection** | Done (v4.19.20) | Resume runs regenerate HTML when `report.html` artifacts exist. |

### v4.19.19 Nuclei Progress Rendering Fixes (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Progress Status Colors** | Done (v4.19.19) | Warning/error status lines render with the correct colors during Rich progress. |
| **Running Batch Clamp** | Done (v4.19.19) | Progress no longer reaches 100% while Nuclei batches are still running (ES detail handling). |
| **Timeout Resume Targets** | Done (v4.19.19) | Partial runs caused by timeouts now save pending targets for resume. |

### v4.19.18 Nuclei Control and Timeout Clarity (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Nuclei Exclude List** | Done (v4.19.18) | CLI/wizard support for excluding targets by host, host:port, or URL. |
| **Retry/Split Progress Detail** | Done (v4.19.18) | Progress detail now exposes retry attempts and split depth. |
| **Timeout Target Summary** | Done (v4.19.18) | Timeout warnings summarize common hosts/ports in stalled batches. |

### v4.19.17 Installer Snap Bootstrap (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Snapd Bootstrap** | Done (v4.19.17) | Installer provisions snapd on Ubuntu-like systems when snap packages are required. |
| **Snap Tool Availability** | Done (v4.19.17) | Searchsploit and ZAP snap installs now work when apt packages are missing. |

### v4.19.16 Nuclei Output Coherence (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Nuclei Summary Coherence** | Done (v4.19.16) | Partial/timeouts now clear success and avoid misleading no-findings messaging. |
| **Resume Status Tracking** | Done (v4.19.16) | Resume summaries retain timeout/failed batch info and recompute success. |
| **Batch Activity Wording** | Done (v4.19.16) | Progress detail now reflects active batches to reduce parallelism confusion. |
| **Wizard Color Guardrail** | Done (v4.19.16) | Yes/No label matching no longer mis-colors "Normal" timing option. |

### v4.19.15 Installer ShellCheck Cleanup (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Unused Distro Vars** | Done (v4.19.15) | Removed unused distro variables to keep ShellCheck clean without behavior changes. |

### v4.19.14 Searchsploit Fallback (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Snap Fallback** | Done (v4.19.14) | Installer falls back to `snap install searchsploit` when GitHub-based installs fail. |

### v4.19.13 Installer Python Stability (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Pip Missing-Only Install** | Done (v4.19.13) | Installer only pip-installs missing Python modules to avoid conflicts on managed environments. |
| **ExploitDB Archive Fallback** | Done (v4.19.13) | Installer can download exploitdb via archive when git clone fails. |
| **Apt Python Helpers** | Done (v4.19.13) | Optional apt installs include python3-paramiko and python3-keyrings-alt. |

### v4.19.12 Installer Python Dependencies (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Pip Bootstrap** | Done (v4.19.12) | Installer includes `python3-pip` to ensure Python dependency installs succeed on fresh systems. |
| **Impacket Apt Fallback** | Done (v4.19.12) | Installer attempts `python3-impacket` via apt when available. |

### v4.19.11 Installer Toolchain Resilience (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Ubuntu Repo Enablement** | Done (v4.19.11) | Installer enables Universe/Multiverse when required for toolchain availability. |
| **GitHub Fallback Installs** | Done (v4.19.11) | Missing tools (Nuclei, exploitdb/searchsploit, enum4linux) are installed from GitHub when apt lacks them. |

### v4.19.9 Nuclei Resume UI Consistency (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Pending-Only Resume Totals** | Done (v4.19.9) | Resume progress bars now reflect only pending Nuclei targets. |
| **Sequential Detail Accuracy** | Done (v4.19.9) | Progress detail no longer reports parallel batches when budgets force sequential. |
| **Localized Scan Messages** | Done (v4.19.9) | Nuclei batch/start and scan heartbeat strings align with the active language. |

### v4.19.8 Resume Artifact Integrity (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Resume Summary Integrity** | Done (v4.19.8) | Resume runs keep host/target counts aligned with existing results. |
| **Nuclei Targets Preservation** | Done (v4.19.8) | Resume runs no longer overwrite `nuclei_targets.txt`; pending targets stay separate. |
| **JSONL Asset Backfill** | Done (v4.19.8) | Findings ensure matching asset entries for vulnerability-only hosts. |
| **Session Log TTY Colors** | Done (v4.19.8) | Session logs retain INFO color by honoring terminal TTY status. |
| **Deep Identity Label Cleanup** | Done (v4.19.8) | Deep identity warnings omit legacy strategy version suffixes. |

### v4.19.7 Red Team Self-Target Exclusion (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Red Team Self-IP Exclusion** | Done (v4.19.7) | Red Team target selection now excludes auditor IPs to prevent self-enumeration. |

### v4.19.6 Nuclei Progress Detail and INFO Contrast (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Parallel Batch Detail** | Done (v4.19.6) | Progress detail now reports parallel batch completion accurately. |
| **INFO Color Contrast** | Done (v4.19.6) | INFO status output uses the standard blue color for readability. |

### v4.19.5 Nuclei Resume Metadata Alignment (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Resume Targets Restore** | Done (v4.19.5) | Resume runs now preserve target networks in report summaries/manifests. |
| **Resume Duration Preservation** | Done (v4.19.5) | Resume summaries retain total scan duration instead of resetting to zero. |

### v4.19.4 Nuclei Resume Budget Control (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Resume Budget Override** | Done (v4.19.4) | Resume prompts let operators change or disable the saved runtime budget. |
| **CLI Resume Override** | Done (v4.19.4) | `--nuclei-max-runtime` applies when resuming from CLI. |
| **Budget-Aware Batching** | Done (v4.19.4) | Budget runs skip starting a new batch if remaining time cannot cover the estimated batch runtime. |

### v4.19.3 Audit Follow-ups (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **SNMP v3 Protocol Mapping** | Done (v4.19.3) | Auth/priv protocol names map to PySNMP objects and respect explicit auth/priv keys. |
| **SNMP Topology CVE Safety** | Done (v4.19.3) | SNMP topology processing no longer assumes an initialized NVD API key. |
| **WhatWeb Diff Alignment** | Done (v4.19.3) | Diff reports count WhatWeb findings using the correct key. |
| **Offline OUI /28 and /36** | Done (v4.19.3) | Offline manuf lookups resolve 28- and 36-bit prefixes. |
| **Nuclei Timeout Default** | Done (v4.19.3) | Configuration default matches the CLI 300s timeout. |
| **Docs Alignment Cleanup** | Done (v4.19.3) | ES timing presets, thread fallback, and Docker/Security docs align with policy. |

### v4.19.2 Nuclei Resume Progress (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Resume Progress UI** | Done (v4.19.2) | Resume runs use the standard progress UI even when a runtime budget is set. |
| **Resume Sorting** | Done (v4.19.2) | Resume candidates are ordered by the latest update timestamp. |
| **Resume Warnings** | Done (v4.19.2) | Budget/timeout warnings are shown after resume runs with pending targets. |

### v4.19.1 Nuclei Budget Enforcement (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Nuclei Budget Cap** | Done (v4.19.1) | Runtime budget caps batches to remaining time and saves pending targets mid-batch. |
| **Nuclei Budget UX** | Done (v4.19.1) | Progress detail uses status color and budget-only stops avoid timeout warnings. |

### v4.19.0 Nuclei Runtime Resume (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Nuclei Runtime Budget** | Done (v4.19.0) | Optional runtime budget writes resume artifacts and keeps the scan moving. |
| **Nuclei Resume Flow** | Done (v4.19.0) | Resume from main menu or CLI, updating reports in the same scan folder. |

### v4.18.22 Nuclei Coverage Timeout Floor (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Nuclei Timeout Floor** | Done (v4.18.22) | Split retries keep the configured batch timeout as a floor to preserve coverage on slow targets. |

### v4.18.21 Updater Home Refresh Safety (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Home Copy Backup** | Done (v4.18.21) | System updates back up dirty `~/RedAudit` copies and refresh documentation. |

### v4.18.20 Nuclei Resilience and UI Sync Refinement (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Nuclei Parallel Clamp** | Done (v4.18.20) | Long Nuclei timeouts now clamp parallel batches to reduce full-scan timeouts. |
| **UI Language Resync** | Done (v4.18.20) | UI manager now updates when CLI language changes after initialization. |
| **ANSI Status Contrast** | Done (v4.18.20) | ANSI status lines now apply the status color to the full message text. |

### v4.18.19 UI Consistency and Snapshot Coverage (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **UI Language Sync** | Done (v4.18.19) | UI manager language now follows CLI language to prevent mixed EN/ES output. |
| **Progress Line Styling** | Done (v4.18.19) | Rich progress output applies status color to all message lines. |
| **Config Snapshot Fields** | Done (v4.18.19) | Report snapshots now include `deep_id_scan`, `trust_hyperscan`, and `nuclei_timeout`. |

### v4.18.18 Wizard Contrast and Low-Impact Enrichment (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Vendor-Only HTTP Probe** | Done (v4.18.18) | Phase 0 enrichment optionally probes HTTP/HTTPS when a host has vendor/MAC only and zero open ports. |
| **Wizard Default Contrast** | Done (v4.18.18) | Non-selected options render in blue and default values are highlighted in prompts. |
| **Nuclei Split Timeout Clamp** | Done (v4.18.18) | Split batches reduce timeout budgets to avoid long retries on slow targets. |

### v4.18.17 HyperScan Reporting Clarity (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **HyperScan Summary Alignment** | Done (v4.18.17) | HyperScan-First comparisons now track TCP-only discovery for CLI consistency. |
| **HyperScan UDP Count in Pipeline** | Done (v4.18.17) | Pipeline net discovery counts include total HyperScan UDP ports for report visibility. |

### v4.13 Resilience & Observability (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Dead Host Retries** | Done (v4.13.0) | New `--dead-host-retries` CLI flag to abandon hosts after N consecutive timeouts. |
| **Honeypot Detection** | Done (v4.9.1) | Heuristic tagging (`honeypot`) for hosts with excessive open ports (>100). |
| **No-Response Tagging** | Done (v4.9.1) | Distinct `no_response` tag for hosts that fail Nmap scanning. |
| **i18n Nuclei Time Estimates** | Done (v4.13.0) | Corrected wizard profile time estimates for fast/balanced profiles. |

### v4.12 Performance & Data Quality (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Nuclei 'Fast' Profile Optimization** | Done (v4.12.1) | Boosted speed (300 req/s) and batch size (15) for fast profile. |
| **OUI Vendor Enrichment** | Done (v4.12.1) | Fallback to online API for unknown vendors in network topology. |
| **Clarified 'Express' Wizard** | Done (v4.12.1) | Updated i18n to explicitly state "Discovery Only". |
| **Flexible Nuclei Config** | Done (v4.12.1) | Configurable `rate_limit` and `batch_size` per profile with override support. |
| **Escalation Reason Counters** | Done (v4.12.1) | Aggregated metrics on why deep scans were triggered (score, ambiguity). |

### v4.11 Performance & IoT Visibility (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Nuclei Scan Profiles** | Done (v4.11.0) | `--profile` flag (full/balanced/fast) to control scan intensity and speed. |
| **IoT WiZ Detection** | Done (v4.11.0) | Specialized UDP probe (38899) for WiZ smart bulbs. |
| **OUI Database Expansion** | Done (v4.11.0) | Updated Macs to ~39k vendors (Wireshark ingest). |
| **Nuclei Batch Optimization** | Done (v4.11.0) | Reduced batch size (10) and increased timeouts (600s) for dense nets. |

### v4.10 Advanced Discovery (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **SNMP Router Query** | Done (v4.10.0) | Query router interfaces and remote ARP tables via `snmpwalk`. |
| **LLDP Discovery** | Done (v4.10.0) | Discover switch topology on managed networks via `lldpctl`. |
| **CDP Discovery** | Done (v4.10.0) | Cisco Discovery Protocol parsing for Cisco-based topologies. |
| **VLAN Tagging Detection** | Done (v4.10.0) | Detect 802.1Q tagged VLANs on the audit host interfaces via `ifconfig`/`ip link`. |

### v4.9 Hidden Network Detection (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Routed Network Discovery** | Done (v4.9.0) | Detect hidden networks via `ip route` and `ip neigh` parsing. |
| **Interactive Discovery Prompt** | Done (v4.9.0) | Wizard asks to include discovered routed networks in scope. |
| **CLI --scan-routed** | Done (v4.9.0) | Automated inclusion of routed networks for CI/CD pipelines. |
| **IoT UDP Port Visibility** | Done (v4.9.1) | Ensure specialized UDP ports (e.g., WiZ 38899) found by HyperScan are included in final reports. |
| **Honeypot Detection** | Done (v4.9.1) | Heuristic tagging (`honeypot`) for hosts with excessive open ports (>100). |
| **No-Response Tagging** | Done (v4.9.1) | Distinct `no_response` tag for hosts that fail Nmap scanning. |

### v4.8 RustScan and Installer Fixes (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **RustScan Full Port Range** | Done (v4.8.2) | Force `-r 1-65535` to scan all ports instead of RustScan's default top 1000. |
| **ARM64 Installer Support** | Done (v4.8.3) | Added ARM64/aarch64 detection for Raspberry Pi and Apple Silicon VMs. |
| **Nuclei Wizard Toggle** | Done (v4.8.1) | Restore interactive Nuclei enable prompt in Exhaustive profile. |

### v4.7 HyperScan Masscan Integration (Done)

| Feature | Status | Description |
| :--- | :--- | :--- |
| **Masscan Backend** | Replaced (v4.8.0) | `masscan_scanner.py` replaced by `RustScan` for higher speed and accuracy. |
| **RustScan Integration** | Done (v4.8.0) | New primary module for HyperScan. Scans all ports in ~3s. |
| **Docker Network Fallback** | Done (v4.7.1) | Automatic Scapy fallback when Masscan returns 0 ports (Docker bridge networks). |
| **Nuclei Timeout Fix** | Done (v4.7.2) | Increased command_runner timeout to 600s for Nuclei (was 60s, causing batch timeouts). |
| **NVD API 404 Skip** | Done (v4.7.2) | Skip retries on 404 responses (CPE not found). Reduces log spam. |

### v4.6 Scan Fidelity & Time Control (Done)

| Feature | Status | Description |
| :--- | :--- | :--- |
| **Infra-Aware Web App Gating** | Done | Skip sqlmap/ZAP on infrastructure UIs when identity evidence indicates router/switch/AP devices. |
| **Deep Scan Identity Evidence** | Done | HTTP title/server and device-type hints suppress deep scan when identity is already strong. |
| **Quick HTTP Identity Probe** | Done | Short HTTP/HTTPS probe on quiet hosts to resolve identity early. |
| **Nuclei Partial Reporting** | Done | Mark partial runs and record timeout/failed batch indexes in reports. |
| **Nuclei Batch Heartbeat** | Done (v4.6.11) | Keep progress updates during long batches to show activity and elapsed time. |
| **Nuclei Target Progress** | Done (v4.6.13) | Show target-based progress within batches to avoid frozen bars. |
| **Nuclei Progress Stability** | Done (v4.6.15) | Keep target progress monotonic across batch retries/timeouts. |
| **Nuclei Timeout Hardening** | Done (v4.6.16) | Adaptive batch timeouts and recursive splits to reduce partial runs. |
| **Sudo Keyring Context** | Done (v4.6.17) | Preserve DBus context when loading saved credentials under sudo. |
| **Host Report Alignment** | Done (v4.6.15) | Backfill host entries with unified asset names/interfaces for consistency. |
| **HTTP Identity Source Guard** | Done (v4.6.11) | Treat UPnP-only titles as hints and avoid forcing web scans or identity scoring. |
| **Wizard Target Normalization Summary** | Done (v4.6.13) | Show normalized targets with estimated host counts before execution. |
| **SSH Credential Spray** | Done (v4.6.18) | Try all credentials in spray list until success. Enables unified credential lists. |
| **Finding Prioritization** | Done (v4.6.19) | New `priority_score` (0-100) and `confirmed_exploitable` fields for better vulnerability ranking. |
| **Classic Backdoor Detection** | Done (v4.6.19) | Automatic banner detection for `vsftpd 2.3.4`, `UnrealIRCd 3.2.8.1`, and other known backdoors. |
| **Report Confidence Score** | Done (v4.6.19) | `confidence_score` (0.0-1.0) based on cross-validation (Nuclei+CVE) to reduce false positives. |
| **Improved Finding Titles** | Done (v4.6.19) | Descriptive titles ("SSL Hostname Mismatch", "Missing HSTS") with better fallback logic. |
| **Wizard Spray Counter** | Done (v4.6.19) | Display `(+N spray)` in credential summary for better visibility. |

### v4.4 Code Coverage & Stability (Done)

| Feature | Status | Description |
| :--- | :--- | :--- |
| **100% Topology Coverage** | Done (v4.4.5) | Achieved complete test coverage for `topology.py` (route parsing, loop detection, graphing). |
| **>94% Updater Coverage** | Done (v4.4.5) | Hardened `updater.py` with robust tests for Git operations, rollback scenarios, edge-case failures. |
| **Project Coverage ~89%** | Done (v4.4.5) | Overall project coverage at 88.75% (1619 tests passing). |
| **Memory Leak Fix** | Done (v4.4.5) | Fixed infinite loop in test mocks that caused 95GB RAM spike. |
| **Generator-based Targeting** | Done (v4.4.0) | Switch from list-based targeting to generator-based streaming. Prevents memory spikes when loading large subnets (/16). |
| **Streaming JSON Report** | Done | Optimized `auditor_scan.py` host collection to avoid list materialization on large networks. |
| **Smart-Throttle (Adaptive Congestion)** | Done (v4.4.0) | AIMD-based dynamic batch size adjustment (Smart-Throttle). Detects network stress/packet loss and auto-throttles scans. |

### v4.3 Risk Score & Performance Improvements (Done)

| Feature | Status | Description |
| :--- | :--- | :--- |
| **Weighted Maximum Gravity Algorithm** | Done | Refactored `calculate_risk_score()` to use CVSS scores from NVD data as primary factor. |
| **Risk Score Breakdown Tooltip** | Done | HTML reports show detailed risk score components on hover. |
| **Identity Score Visualization** | Done | HTML reports display color-coded identity_score with tooltip showing identity signals. |
| **Smart-Check CPE Validation** | Done | Enhanced Nuclei false positive detection using host CPE data before HTTP header checks. |
| **HyperScan SYN Mode** | Done | Optional scapy-based SYN scanning (`--hyperscan-mode syn`) for ~10x faster discovery. |
| **PCAP Management Utilities** | Done | `merge_pcap_files()`, `organize_pcap_files()`, `finalize_pcap_artifacts()` for post-scan cleanup. |

### v4.2 Pipeline Optimizations (Released in v4.2.0)

See [Release Notes](../releases/RELEASE_NOTES_v4.2.0.md) for details.

### v4.1 Performance Optimizations (Done)

| Feature | Status | Description |
| :--- | :--- | :--- |
| **HyperScan-First Sequential** | Done | Pre-scan all 65,535 ports per host sequentially before nmap. Avoids FD exhaustion. |
| **Parallel Vuln Scanning** | Done | Run nikto/testssl/whatweb concurrently per host. |
| **Pre-filter Nikto CDN** | Done | Skip Nikto on Cloudflare/Akamai/AWS CloudFront. |
| **Masscan Port Reuse** | Done | Pre-scan uses masscan ports if already discovered. |
| **CVE Lookup Reordering** | Done | CVE correlation moved after Vuln Scan + Nuclei. |

### v4.0 Architecture Refactoring (Done)

Internal refactoring using Strangler Fig pattern. Completed in v4.0.0.

### Infrastructure (Priority: High)

| Feature | Status | Description |
| :--- | :--- | :--- |
| **Test Suite Consolidation** | Done | Refactored 199 test files → 123 files. Created `conftest.py`. Removed 76 coverage-gaming artifacts. 1130 tests at 85% coverage. |

### Baseline Milestones Moved from Active Roadmap (Done)

These baseline entries were moved from section 1 during roadmap logic refactoring so
`Active Roadmap` keeps pending work only. Existing milestone order above remains unchanged.

### v4.19.x Scope Controls and Evidence Contract Baseline (Done)

| Feature | Status | Default | Guardrails |
| --- | --- | --- | --- |
| **Leak Following (Safe Scope)** | Done (v4.19.x baseline) | `off` (report hints only) | Follow only in-scope candidates in `safe` mode; never expand to public/third-party targets by default. |
| **Protocol-Specific IoT Probes (Minimal Set)** | Done (v4.19.x baseline) | `off` | Trigger only on ambiguity + strong signals; per-host budget and strict per-probe timeout. |
| **Evidence vs Heuristic Marking** | Done (v4.19.x baseline) | Enabled when feature is used | Store probe/headers as evidence, keep heuristic deductions explicitly labeled. |

Implemented operator controls (safe defaults):

- `--leak-follow off|safe`
- `--leak-follow-allowlist <csv>`
- `--iot-probes off|safe`
- `--iot-probe-budget-seconds <n>`
- `--iot-probe-timeout-seconds <n>`

#### Phase A Implementation Contract (Implemented in v4.19.x)

| Area | Contract |
| --- | --- |
| **Goal** | Add safe, opt-in primitives for leak-follow hints and minimal IoT protocol checks without changing default scan scope. |
| **Non-goal** | No automatic scope expansion to Internet/public ranges; no unaudited "always-on" deep protocol probing. |
| **CLI Controls** | `--leak-follow off|safe` and `--iot-probes off|safe`, both defaulting to `off`. |
| **Wizard UX** | Prompts must state that `off` is default and `safe` is in-scope only; wording must be explicit and operator-friendly. |
| **Activation Rule (Leak Following)** | In `safe` mode, follow only RFC1918/ULA candidates already in scan scope or explicitly allowlisted by operator. |
| **Activation Rule (IoT Probes)** | Run only for ambiguous assets with strong corroborating signals (for example vendor OUI + matching service hints). |
| **Budgets/Timeouts** | Per-host probe budget and per-probe timeout are mandatory guardrails; timeout exhaustion must degrade to report-only hints. |
| **Evidence Marking** | Every promoted signal must store raw evidence (header/probe/response metadata) and heuristic labels separately. |
| **Reporting Contract** | Add explicit sections/fields for: mode used, candidates detected, actions taken, skipped reasons, and guardrail hits. |
| **Failure Mode** | On parser/probe uncertainty, fall back to "hint" classification rather than confirmed finding. |

Acceptance criteria for Phase A:

- New controls are visible in CLI help and wizard prompts with safe defaults.
- JSON/HTML output shows whether leak following and IoT probes were off, safe-applied, or skipped by guardrails.
- No behavior change when both features remain `off`.
- Tests cover all new decision branches (including timeout and deny paths) in touched modules.

#### Phase B Execution Plan (Completed Baseline)

| Block | Goal | Main Deliverables | Guardrails |
| --- | --- | --- | --- |
| **B1 - Leak candidate extraction** | Detect internal scope-expansion hints at runtime. | Parse candidate hosts/IPs from trusted HTTP evidence (headers and redirect targets), normalize and deduplicate candidates. | No finding promotion from parsing alone; malformed/ambiguous values stay as hints. |
| **B2 - Safe scope gate** | Apply strict in-scope filtering for any candidate follow-up. | RFC1918/ULA checks, target-scope matching, explicit allowlist matching, skip reason codes. | Reject public/third-party ranges by default; never auto-follow out-of-scope targets. |
| **B3 - Controlled follow execution** | Follow accepted candidates without changing default behavior. | Runtime integration into Nuclei target planning, bounded follow-up queue, deterministic ordering. | `off` remains no-op; `safe` is bounded by per-run limits and existing timeout budgets. |
| **B4 - Evidence and reporting** | Make every decision auditable. | Report fields for detected/followed/skipped candidates, skip reasons, and guardrail hits in JSON/HTML/summary. | Keep evidence and heuristic interpretation explicitly separated. |
| **B5 - UX and docs alignment** | Keep operator intent clear and predictable. | Prompt/help text clarifying selected profile vs effective behavior (including auto-switch), updated EN/ES docs and schema notes. | No ambiguous wording about port coverage or follow behavior. |
| **B6 - Test and regression hardening** | Guarantee reliability before release. | Branch-complete tests for parser/gating/runtime/report paths, fixture updates, negative-path coverage. | 100% coverage on touched paths; no silent behavior drift in `off` mode. |

Phase B tracking checklist:

- [x] B1 candidate extraction implemented and tested.
- [x] B2 safe scope gate implemented and tested.
- [x] B3 runtime follow integration implemented and tested.
- [x] B4 reporting fields and templates updated and tested.
- [x] B5 EN/ES documentation updated and synchronized.
- [x] B6 full regression pass completed and release-ready.

### v4.18.8 Dependency and Module Baseline (Done)

| Feature | Status | Description |
| --- | --- | --- |
| **Dependency Pinning Mode** | Done (v4.18.8) | Optional toolchain pinning for GitHub-downloaded tools via `REDAUDIT_TOOLCHAIN_MODE` and version overrides. |
| **Poetry Lockfile Evaluation** | Done (v4.18.8) | Added `poetry.lock` alongside pip-tools for evaluation and workflow parity. |
| **Red Team Module Split** | Done (v4.18.8) | Split Red Team discovery logic into a dedicated module to reduce `net_discovery.py` size. |

---

## 3. Verified Capabilities Reference

Reference verification of key capabilities against the codebase.

| Capability | Version | Code Path / Verification |
| --- | --- | --- |
| **Passive LLDP Discovery** | v4.10.0 | `core/topology.py` (via `tcpdump` & `lldpctl`) |
| **Passive CDP Discovery** | v4.10.0 | `core/topology.py` (via `tcpdump`/CISCO-CDP) |
| **VLAN Tagging (802.1Q)** | v4.10.0 | `core/topology.py` (via `ip link`/`ifconfig`) |
| **WiZ IoT Probe (UDP)** | v4.11.0 | `core/udp_probe.py`, `core/auditor.py` |
| **Nuclei Profiles** | v4.11.0 | `core/nuclei.py`, `core/auditor.py` |
| **OUI Database** | v4.11.0 | `data/manuf` (38k+ vendors) |
| **Routed Network Discovery** | v4.9.0 | `core/net_discovery.py` (`ip route`/`ip neigh`) |
| **RustScan Integration** | v4.8.0 | `core/rustscan.py` |
| **Smart-Check** | v4.3.0 | `core/scanner/enrichment.py` (CPE/False Positive logic) |

---

## 4. Discarded Concepts

Ideas considered but rejected to maintain project focus.

| Proposal | Reason for Rejection |
| :--- | :--- |
| **Web GUI (Controller)** | Increases attack surface and dependency weight. RedAudit is designed as a headless CLI tool for automation. |
| **Active Exploitation Framework** | Out of scope. RedAudit is for *auditing* and *discovery*, not weaponized exploitation (like Metasploit). |
| **Native Windows Support** | Too complex due to raw socket requirements. Use WSL2 or Docker on Windows. |
| **PDF Report Generation** | Adds heavy dependencies (LaTeX/ReportLab). JSON/HTML output is preferred for modern workflows. |
| **Distributed Scanning** | Too complex (FastAPI/Redis). RedAudit is a tactical CLI tool, not a SaaS platform. Architecture rejected. |

---

## 5. Contributing

1. Check [Issues](https://github.com/dorinbadea/RedAudit/issues).
2. Read [CONTRIBUTING.md](../CONTRIBUTING.md).
3. Open a Discussion before starting major features.

[Back to Documentation Index](INDEX.md)
