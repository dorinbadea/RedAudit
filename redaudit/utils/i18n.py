#!/usr/bin/env python3
"""
RedAudit - Internationalization (i18n)
Copyright (C) 2026  Dorin Badea
GPLv3 License

Translation strings for English and Spanish.
"""

import locale
import os
from typing import Optional

TRANSLATIONS = {
    "en": {
        "interrupted": "\n⚠  Interruption received. Saving current state...",
        "terminating_scans": "Terminating active scans...",
        "heartbeat_info": "⏱  Activity Monitor: {} ({}s elapsed)",
        "heartbeat_warn": "⏱  Activity Monitor: {} - No output for {}s (tool may be busy)",
        "heartbeat_fail": (
            "⏱  Activity Monitor: {} - Long silence (>{}s). "
            "The active tool is still running; this is normal for slow or filtered hosts."
        ),
        "deep_scan_skip": "✔ Info sufficient (MAC/OS found), skipping phase 2.",
        "verifying_env": "Verifying environment integrity...",
        "config_module_missing": "Config module not available",
        "detected": "✓ {} detected",
        "nmap_avail": "✓ python-nmap available",
        "impacket_available": "Impacket available (SMB/WMI)",
        "impacket_missing": "Impacket missing (pip install impacket) - SMB/WMI auth disabled",
        "pysnmp_available": "PySNMP available (SNMP v3)",
        "pysnmp_missing": "PySNMP missing (pip install pysnmp) - SNMP v3 auth disabled",
        "nmap_missing": "python-nmap library not found. Please install the system package 'python3-nmap' via apt.",
        "nmap_binary_missing": "Error: nmap binary not found.",
        "missing_crit": "Error: missing critical dependencies: {}",
        "missing_opt": "Warning: missing optional tools: {} (reduced web/traffic features)",
        "tool_version_warn": (
            "Tool version warning: {} {} (expected {}); parser compatibility may be affected."
        ),
        "tool_version_unknown": (
            "Tool version warning: {} version not detected (expected {}); "
            "parser compatibility may be affected."
        ),
        "crypto_missing": "cryptography library not available. Report encryption disabled.",
        "avail_at": "✓ {} available at {}",
        "not_found": "{} not found (automatic usage skipped)",
        "ask_yes_no_opts": " (Y/n)",
        "ask_yes_no_opts_neg": " (y/N)",
        "ask_num_limit": "Host limit (ENTER = all discovered, or enter a max number):",
        "val_out_of_range": "Value out of range ({}-{})",
        "select_opt": "Select an option",
        "invalid_cidr": "Invalid CIDR",
        "analyzing_nets": "Analyzing local interfaces and networks...",
        "netifaces_missing": "netifaces not available, using fallback method",
        "no_nets_auto": "No networks detected automatically",
        "select_net": "Select network:",
        "manual_entry": "Enter manual",
        "scan_all": "Scan ALL",
        "scan_config": "SCAN CONFIGURATION",
        "scan_mode": "Scan Mode:",
        "mode_fast": "FAST (Discovery only; lowest noise)",
        "mode_normal": "NORMAL (Top ports; balanced coverage)",
        "mode_full": "FULL (All ports + scripts + vulns + deep identity; slowest)",
        "wizard_profile_q": "What type of audit do you want to perform?",
        "wizard_profile_express": "Express — Discovery only, no vuln scanning (~10 min)",
        "wizard_profile_standard": "Standard — Discovery + vulnerability scanning (~30 min)",
        "wizard_profile_exhaustive": "Exhaustive — Maximum depth + Nuclei CVE detection (~2h)",
        "wizard_profile_custom": "Custom — Full control (9 steps)",
        "nvd_not_configured_reminder": "⚠  NVD API key not configured. CVE correlation will be skipped.",
        "nvd_get_key_hint": "   Get a free key at: https://nvd.nist.gov/developers/request-an-api-key",
        "exhaustive_mode_applying": "🚀 Applying Exhaustive profile for maximum discovery...",
        "timing_q": "Scan timing (adjust based on network sensitivity):",
        "timing_stealth": "Stealth — Slow, low noise (2s delay)",
        "timing_normal": "Normal — Balanced speed/coverage (no delay)",
        "timing_aggressive": "Aggressive — Max speed, more noise (parallel bursts)",
        "go_back": "Cancel",
        "threads": "Concurrent threads (higher = faster/noisier):",
        "threads_suggested": "Concurrent threads (higher = faster/noisier) [suggested: {} based on {} cores]:",
        "vuln_scan_q": "Run web vulnerability analysis?",
        "cve_lookup_q": "Enable CVE correlation via NVD? (slower, enriches with CVE data)",
        "gen_txt": "Generate additional TXT report?",
        "gen_html": "Generate interactive HTML report?",
        "output_dir": "Output directory:",
        "start_audit": "Start audit?",
        "scan_start": "Scanning {} hosts...",
        "deep_scan_new_hosts": "Discovered {0} new hosts. Starting DeepScan...",
        "cve_enrich_new_hosts": "Enriching {0} new hosts with CVE data...",
        "scanning_host": "Scanning host {}... (Mode: {})",
        "scanned_host": "Scanned {}",
        "hosts_active": "Active hosts in {}: {}",
        "scan_error": "Scan failed: {}",
        "scan_error_host": "⚠  Scan error {0}: {1}",
        "progress": "Progress: {}/{} hosts",
        "worker_error": "[worker error] {}",
        "vuln_analysis": "Analyzing vulnerabilities on {} web hosts...",
        "windows_verify_label": "Agentless verification",
        "windows_verify_start": "Running agentless verification on {} target(s)...",
        "windows_verify_none": "No compatible targets detected for agentless verification.",
        "windows_verify_done": "Agentless verification completed for {} host(s)",
        "windows_verify_limit": "Agentless verification capped at {} targets",
        "vulns_found": "⚠  Vulnerabilities found on {}",
        "no_hosts": "No hosts found.",
        "exec_params": "EXECUTION PARAMETERS",
        "web_vulns": "Web vulns",
        "cve_lookup": "CVE correlation (NVD)",
        "windows_verify": "Agentless verify",
        "targets": "Targets",
        "mode": "Mode",
        "output": "Output",
        "final_summary": "FINAL SUMMARY",
        "nets": "  Networks:    {}",
        "hosts_up": "  Hosts up:    {}",
        "hosts_full": "  Hosts full:  {}",
        "vulns_web": "  Web vulns:   {}",
        "vulns_web_detail": "  Web vulns:   {} (raw: {})",
        "duration": "  Duration:    {}",
        "pcaps": "  PCAPs:       {}",
        "reports_gen": "\n✓ Reports generated in {}",
        "legal_warn": "\nLEGAL WARNING: Only for use on authorized networks.",
        "legal_ask": "Do you confirm you have authorization to scan these networks?",
        "json_report": "JSON Report: {}",
        "txt_report": "TXT Report: {}",
        "html_report": "HTML Report: {}",
        "html_report_es": "HTML Report (ES): {}",
        "playbooks_generated": "Remediation playbooks generated: {}",
        "summary": "SUMMARY",
        "save_err": "Error saving report: {}",
        "root_req": "Error: root privileges (sudo) required.",
        "config_cancel": "Configuration cancelled.",
        "banner_subtitle": "   INTERACTIVE NETWORK AUDIT     ::  {}",
        "selection_target": "TARGET SELECTION",
        "interface_detected": "✓ Interfaces detected:",
        "encrypt_reports": "Encrypt reports with password?",
        "encryption_password": "Report encryption password",
        "encryption_enabled": "✓ Encryption enabled",
        "cryptography_required": "Error: Encryption requires python3-cryptography. Install with: sudo apt install python3-cryptography",
        "rate_limiting": "Enable rate limiting (slower but stealthier)?",
        "rate_delay": "Delay between hosts (seconds; 0 = none):",
        "low_impact_enrichment_q": "Enable Phase 0 low-impact enrichment (DNS/mDNS/SNMP)?",
        "ports_truncated": "⚠  {}: {} ports found, showing top 50",
        # v3.1+: Persisted defaults
        "save_defaults_q": "Save these settings as defaults for future runs?",
        "save_defaults_info_yes": "This overwrites your previous defaults and will be used as initial values in future runs.",
        "save_defaults_info_no": "If you don't save, you will need to configure again next time (existing defaults remain unchanged).",
        "save_defaults_confirm_yes": "Are you sure you want to save these settings as defaults?",
        "save_defaults_confirm_no": "Do you want to save them as defaults anyway?",
        "defaults_saved": "✓ Defaults saved to ~/.redaudit/config.json",
        "defaults_save_error": "Could not save defaults to ~/.redaudit/config.json",
        "defaults_not_saved": "Defaults not saved.",
        "defaults_not_saved_run_only": (
            "OK. Defaults will not be updated. The scan will run with these parameters for this run only."
        ),
        "save_defaults_effect": "From now on, these values will be used as defaults (you can override them with CLI flags).",
        # v3.2.1+: Defaults control at startup
        "defaults_detected": "Saved defaults detected for future runs.",
        "defaults_action_q": "How would you like to proceed?",
        "defaults_action_use": "Use defaults and continue",
        "defaults_action_review": "Review/modify parameters before continuing",
        "defaults_action_ignore": "Ignore defaults (base values for this run)",
        "defaults_use_immediately_q": "Start scan immediately with these defaults?",
        "defaults_show_summary_q": "Show current defaults summary?",
        "defaults_targets_applied": "Using saved targets ({} network(s))",
        "defaults_summary_title": "Current saved defaults:",
        "defaults_summary_targets": "Targets",
        "targets_normalized": "Targets normalized (est. hosts): {}",
        "targets_total": "Estimated total hosts: {}",
        "defaults_summary_threads": "Threads",
        "defaults_summary_output": "Output dir",
        "defaults_summary_rate_limit": "Rate limit (s)",
        "defaults_summary_udp_mode": "UDP mode",
        "defaults_summary_udp_ports": "UDP ports (full mode)",
        "defaults_summary_topology": "Topology discovery",
        # v3.2.3: Additional defaults display
        "defaults_summary_scan_mode": "Scan mode",
        "defaults_summary_web_vulns": "Web vulns scan",
        "defaults_summary_nuclei": "Nuclei templates",
        "defaults_summary_nuclei_runtime": "Nuclei max runtime",
        "defaults_summary_net_discovery": "Net Discovery",
        "defaults_summary_redteam": "Red Team modules",
        "defaults_summary_active_l2": "Active L2 probing",
        "defaults_summary_kerbrute": "Kerberos user enum (kerbrute)",
        "defaults_summary_cve_lookup": "CVE correlation",
        "defaults_summary_txt_report": "TXT report",
        "defaults_summary_html_report": "HTML report",
        "defaults_summary_windows_verify": "Agentless verify",
        "defaults_ignore_confirm": "OK. Saved defaults will be ignored for this run.",
        "jsonl_exports": "JSONL exports: {} findings, {} assets",
        # v3.1+: UDP configuration
        "udp_mode_q": "UDP scan mode (deep scan):",
        "udp_mode_quick": "QUICK (priority UDP ports only)",
        "udp_mode_full": "FULL (top UDP ports for identity discovery)",
        "udp_ports_profile_q": "Full UDP coverage (FULL mode):",
        "udp_ports_profile_fast": "50 (Fast) — quickest, lowest coverage",
        "udp_ports_profile_balanced": "100 (Balanced) — recommended default",
        "udp_ports_profile_thorough": "200 (Thorough) — more coverage, slower",
        "udp_ports_profile_aggressive": "500 (Aggressive) — max coverage, slowest",
        "udp_ports_profile_custom": "Custom… (enter a number)",
        "udp_ports_q": "Custom: top UDP ports to scan in FULL mode (50-500):",
        # v3.1+: Topology discovery
        "topology_q": "Enable topology discovery (ARP/VLAN/LLDP + gateway/routes) in addition to the host scan?",
        "topology_only_help": (
            "Topology-only mode skips host scanning. Choose NO to run a normal scan + topology."
        ),
        "topology_only_q": "Topology-only (skip host/port scanning)?",
        "topology_start": "Discovering topology (best-effort)...",
        "deep_identity_start": "Deep identity scan for {} (strategy: {})",
        "deep_identity_cmd": "[deep] {} → {} (~{}s estimated)",
        "deep_identity_done": "Deep identity scan finished for {} in {:.1f}s",
        "deep_scan_budget_exhausted": "Deep scan budget exhausted ({}/{}), skipping aggressive scan for {}",
        "dead_host_budget_exhausted": "Dead host budget exhausted ({}/{}), abandoning host {}",
        "deep_strategy_adaptive": "Adaptive (3-Phase v2.8)",
        "deep_udp_priority_cmd": "[deep] {} → {} (~1-5s, priority UDP)",
        "deep_udp_full_cmd": "[deep] {} → {} (~120-180s, top {} UDP)",
        "banner_grab": "[banner] {} → Grabbing banners for {} unidentified ports",
        "nmap_cmd": "[nmap] {} → {}",
        "exploits_found": "⚠  Found {} known exploits for {}",
        "testssl_analysis": "Running deep SSL/TLS analysis on {}:{} (may take 60s)...",
        "scanning_hosts": "Scanning hosts...",
        # Update system (v2.8.0)
        "update_check_prompt": "Check for updates before starting?",
        "update_checking": "Checking for updates...",
        "update_check_failed": "Could not check for updates (network issue or GitHub unavailable)",
        "update_current": "You are running the latest version ({})",
        "update_available": "RedAudit v{} available (current: v{})",
        "update_release_date": "Release date: {}",
        "update_release_type": "Type: {}",
        "update_highlights": "Highlights:",
        "update_breaking_changes": "Breaking changes:",
        "update_notes_fallback_en": "Notes available in English only.",
        "update_notes_fallback_es": "Notes available in Spanish only.",
        "update_release_url": "Full release notes: {}",
        "update_prompt": "Would you like to update now?",
        "update_starting": "Downloading update...",
        "update_skipped": "Update skipped. Continuing with current version.",
        "update_restarting": "Update installed! Restarting RedAudit...",
        "update_restart_failed": "Update installed, but restart failed. Please exit and re-run: {}",
        "update_refresh_hint": (
            "Note: If the banner/version does not refresh after an update, restart your terminal "
            "or run `hash -r` (zsh/bash)."
        ),
        "update_restart_terminal_title": "RESTART REQUIRED",
        "update_restart_terminal_body": "Please restart the terminal to apply the changes.",
        "update_restart_terminal_hint": "Recommended: close and reopen this terminal. Alternative: run `{}`.",
        "update_restart_terminal_prompt": "RedAudit will exit now to prevent running mixed versions.",
        "update_restart_terminal_press_enter": "Press Enter to exit...",
        "update_home_changes_detected_skip": "Local changes detected in {}. Skipping home folder update.",
        "update_home_changes_detected_backup": (
            "Local changes detected in {}. Backing up and refreshing the home folder copy."
        ),
        "update_home_changes_detected_abort": (
            "Local changes detected in {}. Commit/stash or remove the folder before updating."
        ),
        "update_home_changes_verify_failed_skip": (
            "Could not verify local changes in {}. Skipping home folder update for safety."
        ),
        "update_home_changes_verify_failed_backup": (
            "Could not verify local changes in {}. Backing up and refreshing the home folder copy."
        ),
        "update_home_changes_verify_failed_abort": (
            "Could not verify local changes in {}. Update aborted for safety."
        ),
        "update_repo_sync_skip_dirty": ("Local changes detected in {}. Skipping repo sync."),
        "update_repo_sync_fetch_failed": "Could not refresh tags in {}. Skipping repo sync.",
        "update_repo_sync_ok": "Updated local repo {} to {}.",
        "update_repo_sync_pull_failed": "Could not fast-forward {} to main. Skipping repo sync.",
        "update_repo_sync_branch_skip": ("Repo {} is on '{}' (not main). Tags refreshed only."),
        "update_requires_root": "Update check requires sudo/root (or run with --skip-update-check).",
        "update_requires_root_install": (
            "System install update requires sudo/root. Re-run with sudo to update "
            "/usr/local/bin/redaudit."
        ),
        # NVD API Key configuration (v3.0.1)
        "nvd_key_set_cli": "✓ NVD API key set from command line",
        "nvd_key_invalid": "⚠  Invalid NVD API key format",
        "nvd_key_not_configured": "⚠  CVE lookup enabled but no NVD API key configured (slower rate limit)",
        "nvd_setup_header": "NVD API KEY SETUP (Optional)",
        "nvd_setup_info": "CVE Correlation requires an NVD API key for faster lookups.\nWithout key: 5 requests/30s | With key: 50 requests/30s\n\nRegister for FREE at:",
        "nvd_option_config": "Save in config file (~/.redaudit/config.json)",
        "nvd_option_env": "I'll set NVD_API_KEY environment variable myself",
        "nvd_option_skip": "Continue without API key (slower)",
        "nvd_ask_storage": "How would you like to configure the API key?",
        "nvd_key_skipped": "API key skipped",
        "nvd_key_saved": "✓ NVD API key saved to config file",
        "nvd_key_save_error": "⚠  Error saving API key to config",
        "nvd_key_invalid_format": "Invalid API key format. Expected UUID format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)",
        "nvd_env_instructions": "Add this to your ~/.bashrc or ~/.zshrc:",
        "nvd_env_set_later": "You can set the environment variable later",
        "nvd_slow_mode": "⚠  Continuing with slow mode (5 requests/30 seconds)",
        # v3.2+: Network discovery
        "net_discovery_start": "Running enhanced network discovery (DHCP/NetBIOS/mDNS)...",
        "net_discovery_dhcp_found": "✓ Found {} DHCP server(s)",
        "net_discovery_routed_found": "ℹ️  Found {} hidden routed network(s) via local gateway(s):",
        "net_discovery_routed_add_q": "Add these hidden networks to the scan scope?",
        "net_discovery_vlans_found": "⚠  Detected {} potential guest network(s)/VLAN(s)",
        "net_discovery_seed_hosts": "Net Discovery identified {} host(s) to include in the scan",
        "net_discovery_seed_added": "Added {} host(s) missed by ICMP discovery",
        "net_discovery_q": "Enable enhanced network discovery (DHCP/NetBIOS/mDNS/UPNP)?",
        "net_discovery_redteam_q": "Include Red Team techniques (SNMP/SMB enum, slower/noisier)?",
        "redteam_mode_q": "Red Team options:",
        "redteam_mode_a": "A) Discovery only (recommended)",
        "redteam_mode_b": "B) Enable Red Team modules (requires root; slower/noisier)",
        "redteam_requires_root": (
            "Red Team modules require root privileges. Re-run with sudo or disable Red Team."
        ),
        "redteam_active_l2_q": (
            "Enable active Layer 2 (L2) probing? (Requires root; most intrusive)"
        ),
        "redteam_kerberos_userenum_q": (
            "Enable Kerberos user enumeration via Kerbrute when Kerberos/AD is detected? "
            "(Authorized testing only)"
        ),
        "kerberos_realm_q": "Kerberos realm (optional; ENTER to auto-detect, e.g., corp.local)",
        "kerberos_userlist_q": (
            "Username wordlist path for Kerbrute (optional; e.g., /usr/share/wordlists/usernames.txt)"
        ),
        # v3.2.2+: Main menu
        "menu_option_scan": "Start scan (wizard)",
        "menu_option_update": "Check for updates",
        "menu_option_diff": "Diff reports (JSON)",
        "menu_option_resume_nuclei": "Resume Nuclei (pending)",
        "menu_option_exit": "Exit",
        "menu_prompt": "Select option [0-4]:",
        "menu_nav_hint": "Use ↑/↓/←/→ and Enter to select.",
        "wizard_go_back": "Cancel",
        "menu_invalid_option": "Invalid option. Please select 0-4.",
        "auto_continue_countdown": "Auto-continue in {}s",
        "yes_option": "Yes",
        "yes_default": "Yes (default)",
        "no_option": "No",
        "no_default": "No (default)",
        "vuln_scan_opt": "Web vulnerability scan",
        "diff_enter_old_path": "Path to OLD report (JSON):",
        "diff_enter_new_path": "Path to NEW report (JSON):",
        # v3.2.2+: Simplified topology prompt
        "topology_discovery_q": "Topology discovery:",
        "topology_disabled": "Disabled",
        "topology_enabled_scan": "Enable (scan + topology)",
        "topology_only_mode": "Topology only (skip host/port scan)",
        # v3.2.2+: Hardcoded strings → i18n
        "target_prompt": "Target (CIDR/IP/range). Example: 192.168.1.0/24:",
        "manual_cidr_prompt": (
            "Targets (CIDR/IP/range, comma-separated). Example: 192.168.1.0/24, "
            "192.168.1.10-192.168.1.20:"
        ),
        "confirm_prompt": "Confirm:",
        "legal_warning_skipped": "⚠  Legal warning skipped (--yes flag)",
        "invalid_target_too_long": "Invalid target (too long): {}",
        "invalid_cidr_target": "Invalid target: {}",
        "no_valid_targets": "No valid targets provided",
        "target_required_non_interactive": "Error: --target is required in non-interactive mode",
        "invalid_proxy_url": "Invalid proxy URL: {}",
        "proxy_configured": "Proxy configured: {}",
        "proxy_test_failed": "Proxy test failed: {}",
        "proxychains_missing": "proxychains not installed. Install proxychains4 to enable proxy routing.",
        "proxy_in_use": "Proxy routing enabled via proxychains ({})",
        "random_password_generated": "Generated random encryption password (save this!): {}",
        # v3.2.2+: Non-TTY update one-liner
        "update_oneliner": "UPDATE: RedAudit v{} available (current v{}) — {}",
        # v3.2.2+: Boolean formatting
        "enabled": "Enabled",
        "disabled": "Disabled",
        # v3.2.3+: Stealth mode
        "stealth_mode_info": "Stealth mode: {} timing, {} thread(s), {}s+ delay",
        # v3.6: Nuclei integration
        "nuclei_scan_start": "Running Nuclei template scan on HTTP targets...",
        "nuclei_findings": "✓ Nuclei found {} vulnerabilities",
        "nuclei_no_findings": "Nuclei scan completed (no findings)",
        "nuclei_suspected": "Nuclei flagged {} suspected false positive(s)",
        "nuclei_partial": "Nuclei scan partial: {} timeout batch(es), {} failed",
        "nuclei_q": "Run Nuclei (specialized for HTTP/Web services)?",
        # v4.11.0: Nuclei profile selector
        "nuclei_profile_q": "Nuclei scan profile:",
        "nuclei_full": "Full - All templates (~2h)",
        "nuclei_balanced": "Balanced - Core templates (~1h, recommended)",
        "nuclei_fast": "Fast - Critical CVEs (~30-60min)",
        # v4.17: Full coverage option (v4.18: shortened to prevent truncation)
        "nuclei_full_coverage_q": (
            "Scan ALL detected HTTP ports? (beyond 80/443; increases targets)"
        ),
        "nuclei_budget_q": "Max Nuclei runtime in minutes (0 = unlimited)",
        "nuclei_resume_saved": "Nuclei resume saved: {}",
        "nuclei_resume_prompt": "Resume pending Nuclei targets now?",
        "nuclei_resume_none": "No pending Nuclei resumes found.",
        "nuclei_resume_select": "Select a pending Nuclei resume:",
        "nuclei_resume_cancel": "Resume canceled.",
        "nuclei_resume_running": "Resuming Nuclei on pending targets...",
        "nuclei_resume_done": "Nuclei resume completed: {} findings added",
        "nuclei_resume_failed": "Nuclei resume failed: {}",
        "nuclei_resume_skipped": (
            "Nuclei resume postponed. You can resume later from the main menu or with --nuclei-resume."
        ),
        "windows_verify_q": "Enable agentless verification (SMB/RDP/LDAP/SSH/HTTP)?",
        "windows_verify_max_q": "Max targets for agentless verification (1-200; higher = slower):",
        # v3.7: Interactive webhooks
        "webhook_q": "Configure real-time alert webhook (Slack/Teams/PagerDuty)?",
        "webhook_url_prompt": "Webhook URL (https://..., e.g., https://hooks.slack.com/...):",
        "webhook_invalid_url": "Invalid webhook URL. Must start with https://",
        "webhook_configured": "✓ Webhook configured: {}",
        "webhook_test_q": "Send a test alert to verify the webhook?",
        "webhook_test_success": "✓ Test webhook sent successfully",
        "webhook_test_failed": "⚠  Test webhook failed: {}",
        "auditor_name_q": "Auditor name (optional; e.g., Jane Doe)",
        # v3.7: Advanced Net Discovery wizard
        "net_discovery_advanced_q": "Configure advanced Net Discovery options?",
        "net_discovery_snmp_prompt": "SNMP community string (ENTER = public)",
        "net_discovery_dns_zone_prompt": (
            "DNS zone for transfer attempts (optional; ENTER to skip, e.g., corp.local):"
        ),
        "net_discovery_max_targets_prompt": (
            "Max targets for Red Team modules (default: 50; higher = slower):"
        ),
        "net_discovery_options_saved": "Net Discovery options saved",
        # v4.2: SQLMap integration
        "sqlmap_config_q": "Web Application Scan Intensity (sqlmap):",
        "sqlmap_l1": "Standard (Level 1, Risk 1) — Safe, basic checks",
        "sqlmap_l3": "Deep (Level 3, Risk 1) — More payloads, header checks",
        "sqlmap_risk": "Risky (Level 3, Risk 2) — Heavy, time-based SQLi (slower)",
        "sqlmap_extreme": "Extreme (Level 5, Risk 3) — Max payloads, potentially destructive",
        "zap_q": "Enable OWASP ZAP? (Requires zap.sh in PATH, slower execution)",
        "redteam_masscan_q": "Use masscan for initial discovery? (High speed, requires root)",
        # v4.2: HyperScan/DeepScan i18n
        "hyperscan_start": "HyperScan-First: Running discovery for {} hosts in parallel...",
        "hyperscan_start_sequential": "HyperScan-First: Running discovery for {} hosts (SYN mode, sequential)...",
        "hyperscan_complete": "HyperScan-First complete: {} total ports in {:.1f}s",
        "hyperscan_ports_found": "[{}/{}] {}: found {} open ports",
        "hyperscan_no_ports": "[{}/{}] {}: no ports detected",
        "hyperscan_masscan_reuse": "[{}/{}] {}: reusing {} discovered ports",
        "udp_probes_progress": "UDP probes ({})",
        "deep_scan_running": "Running DeepScan on {} hosts...",
        "deep_scan_heartbeat": "DeepScan... {0}/{1} ({2}:{3:02d})",
        "deep_scan_progress": "DeepScan: {0}/{1}",
        "auditor_ip_excluded": "ℹ️  Auto-excluded {} auditor IP(s) from target list to prevent self-scanning.",
        # v4.3: HyperScan mode wizard
        "hyperscan_mode_q": "HyperScan discovery method:",
        "hyperscan_auto": "Auto — Detect best method (SYN if root, else connect)",
        "hyperscan_connect": "Connect — Standard TCP (no root required, stealthier)",
        "hyperscan_syn": "SYN — Raw packets (requires root + scapy, faster)",
        "trust_hyperscan_q": "Skip deep scan on identified hosts? (faster)",
        # v4.0: Authenticated Scanning
        "auth_scan_q": "Enable authenticated scanning?",
        "auth_ssh_configure_q": "Configure SSH credentials?",
        "auth_ssh_user_prompt": "SSH User",
        "auth_method_key": "Private Key",
        "auth_method_pass": "Password",
        "auth_method_q": "Authentication Method",
        "auth_ssh_key_prompt": "Private Key Path",
        "auth_ssh_pass_hint": "Input SSH password (hidden)",
        "auth_scan_start": "Starting authenticated scan on {0} as user {1}...",
        "auth_scan_connected": "Authentication successful ({0})! Gathering host info...",
        "auth_scan_failed": "Authenticated scan failed: {0}",
        "ssh_auth_failed_all": "{0}: SSH auth failed (all creds)",
        "smb_auth_failed_all": "{0}: SMB auth failed (all creds)",
        # v4.2: SMB
        "auth_smb_configure_q": "Configure Windows/SMB credentials?",
        "auth_smb_user_prompt": "Windows User (e.g. Administrator)",
        "auth_smb_domain_prompt": "Windows Domain (optional, ENTER for none)",
        "auth_smb_pass_hint": "Input Windows/SMB password (hidden)",
        "auth_save_keyring_q": "Save credentials to system keyring for future scans?",
        "auth_saved_creds_found": "Saved credentials found in keyring:",
        "auth_saved_creds_found_invoking": "Saved credentials found in keyring for user {0}:",
        "auth_load_saved_q": "Load saved credentials?",
        "auth_configure_manual_q": "Configure credentials manually?",
        "auth_loaded_creds": "Loaded {0} credential(s) from keyring.",
        "auth_add_more_q": "Add more credentials?",
        # v4.3: SNMP v3
        "auth_snmp_configure_q": "Configure SNMP v3 credentials (network devices)?",
        "auth_snmp_user_prompt": "SNMP v3 Username",
        "auth_snmp_auth_proto_q": "Auth Protocol:",
        "auth_snmp_priv_proto_q": "Privacy Protocol:",
        # v4.5.0: Authenticated scanning orchestration
        "auth_scan_no_hosts": "No SSH-enabled hosts found for authenticated scanning.",
        "auth_scan_starting": "Authenticated scan: {} SSH hosts with stored credentials...",
        "auth_scan_complete": "Authenticated scan complete: {} SSH, {} Lynis audits",
        "auth_ssh_configure_q": "Configure SSH credentials?",
        # v4.5.1: Multi-credential support
        "auth_universal_q": "Configure credentials (universal - auto-detects protocol)?",
        "auth_cred_number": "Credential %d",
        "auth_add_another": "Add another credential?",
        "auth_cred_user_prompt": "Username",
        "auth_cancel_hint": "Type 'cancel' to abort and return to the wizard.",
        "auth_cred_pass_prompt": "Password (hidden)",
        "auth_creds_summary": "Configured %d credentials for automatic protocol detection.",
        "auth_trying_creds": "Trying credentials on %s:%d (%s)...",
        "auth_cred_success": "Credential matched: %s@%s",
        "auth_mode_q": "Credential configuration mode:",
        "auth_mode_universal": "Universal (simple): auto-detect protocol",
        "auth_mode_universal": "Universal (simple): auto-detect protocol",
        "auth_mode_advanced": "Advanced: configure SSH/SMB/SNMP separately",
        "auth_protocol_hint": "Credentials will be tried on: SSH (22), SMB (445), SNMP (161), RDP (3389)",
        "auth_scan_opt": "Authenticated (SSH/SMB/SNMP)",
        "snmp_topology_q": "Enable SNMP Topology Discovery (Routes/ARP/Interfaces)?",
        "follow_routes_q": "Automatically follow discovered routes (scan new subnets)?",
        "wizard_custom_intro": "Custom wizard: 9 steps. Use Cancel to go back.",
    },
    "es": {
        "interrupted": "\n⚠  Interrupción recibida. Guardando estado actual...",
        "terminating_scans": "Terminando escaneos activos...",
        "heartbeat_info": "⏱  Monitor de Actividad: {} ({}s transcurridos)",
        "heartbeat_warn": "⏱  Monitor de Actividad: {} - Sin salida hace {}s (herramienta ocupada)",
        "heartbeat_fail": (
            "⏱  Monitor de Actividad: {} - Silencio prolongado (>{}s). "
            "La herramienta activa sigue ejecutándose; esto es normal en hosts lentos o filtrados."
        ),
        "deep_scan_skip": "✔ Info suficiente (MAC/OS detectado), saltando fase 2.",
        "verifying_env": "Verificando integridad del entorno...",
        "config_module_missing": "Módulo de configuración no disponible",
        "detected": "✓ {} detectado",
        "nmap_avail": "✓ python-nmap disponible",
        "impacket_available": "Impacket disponible (SMB/WMI)",
        "impacket_missing": "Impacket no disponible (pip install impacket) - SMB/WMI desactivado",
        "pysnmp_available": "PySNMP disponible (SNMP v3)",
        "pysnmp_missing": "PySNMP no disponible (pip install pysnmp) - SNMP v3 desactivado",
        "nmap_missing": "Librería python-nmap no encontrada. Instala el paquete de sistema 'python3-nmap' vía apt.",
        "nmap_binary_missing": "Error: binario nmap no encontrado.",
        "missing_crit": "Error: faltan dependencias críticas: {}",
        "missing_opt": "Aviso: faltan herramientas opcionales: {} (menos funciones web/tráfico)",
        "tool_version_warn": (
            "Aviso de versión: {} {} (se espera {}); la compatibilidad de parseo puede verse afectada."
        ),
        "tool_version_unknown": (
            "Aviso de versión: no se pudo detectar la versión de {} (se espera {}); "
            "la compatibilidad de parseo puede verse afectada."
        ),
        "crypto_missing": "Librería cryptography no disponible. El cifrado de informes queda deshabilitado.",
        "avail_at": "✓ {} disponible en {}",
        "not_found": "{} no encontrado (se omitirá su uso automático)",
        "ask_yes_no_opts": " (S/n)",
        "ask_yes_no_opts_neg": " (s/N)",
        "ask_num_limit": "Límite de hosts (ENTER = todos los descubiertos, o escribe un número máximo):",
        "val_out_of_range": "Valor fuera de rango ({}-{})",
        "select_opt": "Selecciona una opción",
        "invalid_cidr": "CIDR inválido",
        "analyzing_nets": "Analizando interfaces y redes locales...",
        "netifaces_missing": "netifaces no disponible, usando método alternativo",
        "no_nets_auto": "No se detectaron redes automáticamente",
        "select_net": "Selecciona red:",
        "manual_entry": "Introducir manual",
        "scan_all": "Escanear TODAS",
        "scan_config": "CONFIGURACIÓN DE ESCANEO",
        "scan_mode": "Modo de escaneo:",
        "mode_fast": "RÁPIDO (solo discovery; mínimo ruido)",
        "mode_normal": "NORMAL (Puertos principales; equilibrio)",
        "mode_full": "COMPLETO (Todos los puertos + scripts + vulns + identidad profunda; más lento)",
        "wizard_profile_q": "Que tipo de auditoria deseas realizar?",
        "wizard_profile_express": "Express — Solo discovery (~10 min)",
        "wizard_profile_standard": "Estandar — Discovery + vulns (~30 min)",
        "wizard_profile_exhaustive": "Exhaustivo — Profundidad maxima + Nuclei (~2h)",
        "wizard_profile_custom": "Personalizado — Control total (9 pasos)",
        "nvd_not_configured_reminder": "⚠  API key de NVD no configurada. Se omitirá correlación CVE.",
        "nvd_get_key_hint": "   Obtén una key gratis en: https://nvd.nist.gov/developers/request-an-api-key",
        "exhaustive_mode_applying": "Aplicando perfil Exhaustivo para máximo descubrimiento...",
        "timing_q": "Velocidad de escaneo (ajustar según sensibilidad de la red):",
        "timing_stealth": "Sigiloso — Lento, bajo ruido (2s de retardo)",
        "timing_normal": "Normal — Equilibrio velocidad/cobertura (sin retardo)",
        "timing_aggressive": "Agresivo — Velocidad máxima, más ruido (ráfagas paralelas)",
        "go_back": "Cancelar",
        "threads": "Hilos concurrentes (más alto = más rápido/ruidoso):",
        "threads_suggested": "Hilos concurrentes (más alto = más rápido/ruidoso) [sugerido: {} según {} cores]:",
        "vuln_scan_q": "¿Ejecutar análisis de vulnerabilidades web?",
        "cve_lookup_q": "¿Activar correlación CVE vía NVD? (más lento, enriquece con datos CVE)",
        "gen_txt": "¿Generar informe TXT adicional?",
        "gen_html": "¿Generar informe HTML interactivo?",
        "output_dir": "Directorio de salida:",
        "start_audit": "¿Iniciar auditoría?",
        "scan_start": "Escaneando {} hosts...",
        "deep_scan_new_hosts": "Descubiertos {0} hosts nuevos. Iniciando DeepScan...",
        "cve_enrich_new_hosts": "Enriqueciendo {0} hosts nuevos con datos CVE...",
        "scanning_host": "Escaneando host {}... (Modo: {})",
        "scanned_host": "Escaneado {}",
        "hosts_active": "Hosts activos en {}: {}",
        "scan_error": "Fallo en escaneo: {}",
        "scan_error_host": "⚠  Error de escaneo {0}: {1}",
        "progress": "Progreso: {}/{} hosts",
        "worker_error": "[error de trabajador] {}",
        "vuln_analysis": "Analizando vulnerabilidades en {} hosts web...",
        "windows_verify_label": "Verificación sin agente",
        "windows_verify_start": "Ejecutando verificación sin agente en {} objetivo(s)...",
        "windows_verify_none": "No se detectaron objetivos compatibles para verificación sin agente.",
        "windows_verify_done": "Verificación sin agente completada en {} host(s)",
        "windows_verify_limit": "Verificación sin agente limitada a {} objetivos",
        "vulns_found": "⚠  Vulnerabilidades registradas en {}",
        "no_hosts": "No se encontraron hosts.",
        "exec_params": "PARÁMETROS DE EJECUCIÓN",
        "web_vulns": "Vulnerabilidades web",
        "cve_lookup": "Correlación CVE (NVD)",
        "windows_verify": "Verificación sin agente",
        "targets": "Objetivos",
        "mode": "Modo",
        "output": "Salida",
        "final_summary": "RESUMEN FINAL",
        "nets": "  Redes:       {}",
        "hosts_up": "  Hosts vivos: {}",
        "hosts_full": "  Completos:   {}",
        "vulns_web": "  Vulns web:   {}",
        "vulns_web_detail": "  Vulns web:   {} (raw: {})",
        "duration": "  Duración:    {}",
        "pcaps": "  PCAPs:       {}",
        "reports_gen": "\n✓ Informes generados en {}",
        "legal_warn": "\nADVERTENCIA LEGAL: Solo para uso en redes autorizadas.",
        "legal_ask": "¿Confirmas que tienes autorización para escanear estas redes?",
        "json_report": "Informe JSON: {}",
        "txt_report": "Informe TXT: {}",
        "html_report": "Informe HTML: {}",
        "html_report_es": "Informe HTML (ES): {}",
        "playbooks_generated": "Playbooks de remediación generados: {}",
        "summary": "RESUMEN",
        "save_err": "Error guardando informe: {}",
        "root_req": "Error: se requieren privilegios de root (sudo).",
        "config_cancel": "Configuración cancelada.",
        "banner_subtitle": "   AUDITORÍA DE RED INTERACTIVA  ::  {}",
        "selection_target": "SELECCIÓN DE OBJETIVO",
        "interface_detected": "✓ Interfaces detectadas:",
        "encrypt_reports": "¿Cifrar informes con contraseña?",
        "encryption_password": "Contraseña para cifrar informes",
        "encryption_enabled": "✓ Cifrado activado",
        "cryptography_required": "Error: El cifrado requiere python3-cryptography. Instala con: sudo apt install python3-cryptography",
        "rate_limiting": "¿Activar limitación de velocidad (más lento pero más sigiloso)?",
        "rate_delay": "Retardo entre hosts (segundos; 0 = ninguno):",
        "low_impact_enrichment_q": "¿Activar enriquecimiento de bajo impacto (Fase 0: DNS/mDNS/SNMP)?",
        "ports_truncated": "⚠  {}: {} puertos encontrados, mostrando los 50 principales",
        # v3.1+: Defaults persistentes
        "save_defaults_q": "¿Guardar estos ajustes como valores por defecto para futuras ejecuciones?",
        "save_defaults_info_yes": "Esto sobrescribe tus valores por defecto anteriores y se aplicará como valores iniciales en futuras ejecuciones.",
        "save_defaults_info_no": "Si no guardas, la próxima vez tendrás que configurar de nuevo (los valores por defecto actuales, si existen, no cambian).",
        "save_defaults_confirm_yes": "¿Estás seguro de que quieres guardar estos ajustes como valores por defecto?",
        "save_defaults_confirm_no": "¿Quieres guardarlos como valores por defecto igualmente?",
        "defaults_saved": "✓ Valores por defecto guardados en ~/.redaudit/config.json",
        "defaults_save_error": "No se pudieron guardar los valores por defecto en ~/.redaudit/config.json",
        "defaults_not_saved": "Valores por defecto no guardados.",
        "defaults_not_saved_run_only": (
            "OK. No se actualizarán los defaults. El escaneo se ejecutará con estos parámetros solo en esta ejecución."
        ),
        "save_defaults_effect": "A partir de ahora, estos valores se usarán como valores por defecto (puedes sobrescribirlos con flags CLI).",
        # v3.2.1+: Control de defaults al inicio
        "defaults_detected": "Se han detectado valores por defecto guardados para futuras ejecuciones.",
        "defaults_action_q": "¿Qué quieres hacer?",
        "defaults_action_use": "Usar defaults y continuar",
        "defaults_action_review": "Revisar/modificar parámetros antes de continuar",
        "defaults_action_ignore": "Ignorar defaults (valores base en esta ejecución)",
        "defaults_use_immediately_q": "¿Iniciar escaneo inmediatamente con estos defaults?",
        "defaults_show_summary_q": "¿Mostrar resumen de defaults actuales?",
        "defaults_targets_applied": "Usando objetivos guardados ({} red(es))",
        "defaults_summary_title": "Defaults guardados actuales:",
        "defaults_summary_targets": "Objetivos",
        "targets_normalized": "Objetivos normalizados (hosts estimados): {}",
        "targets_total": "Total de hosts estimados: {}",
        "defaults_summary_threads": "Hilos",
        "defaults_summary_output": "Salida",
        "defaults_summary_rate_limit": "Limitación (s)",
        "defaults_summary_udp_mode": "Modo UDP",
        "defaults_summary_udp_ports": "Puertos UDP (modo completo)",
        "defaults_summary_topology": "Descubrimiento de topología",
        # v3.2.3: Nuevos campos de defaults
        "defaults_summary_scan_mode": "Modo de escaneo",
        "defaults_summary_web_vulns": "Escaneo vulns web",
        "defaults_summary_nuclei": "Templates Nuclei",
        "defaults_summary_nuclei_runtime": "Tiempo maximo Nuclei",
        "defaults_summary_net_discovery": "Net Discovery",
        "defaults_summary_redteam": "Módulos Red Team",
        "defaults_summary_active_l2": "L2 activo",
        "defaults_summary_kerbrute": "Enum usuarios Kerberos (kerbrute)",
        "defaults_summary_cve_lookup": "Correlación CVE",
        "defaults_summary_txt_report": "Informe TXT",
        "defaults_summary_html_report": "Informe HTML",
        "defaults_summary_windows_verify": "Verificación sin agente",
        "defaults_ignore_confirm": "OK. Los defaults guardados se ignorarán en esta ejecución.",
        "jsonl_exports": "Exportaciones JSONL: {} hallazgos, {} activos",
        # v3.1+: Configuración UDP
        "udp_mode_q": "Modo UDP (deep scan):",
        "udp_mode_quick": "RÁPIDO (solo puertos UDP prioritarios)",
        "udp_mode_full": "COMPLETO (top puertos UDP para identidad)",
        "udp_ports_profile_q": "Cobertura UDP (modo COMPLETO):",
        "udp_ports_profile_fast": "50 (Rápido) — más rápido, menos cobertura",
        "udp_ports_profile_balanced": "100 (Equilibrado) — recomendado",
        "udp_ports_profile_thorough": "200 (Exhaustivo) — más cobertura, más lento",
        "udp_ports_profile_aggressive": "500 (Agresivo) — máxima cobertura, el más lento",
        "udp_ports_profile_custom": "Personalizado… (introducir un número)",
        "udp_ports_q": "Personalizado: top puertos UDP a escanear en modo COMPLETO (50-500):",
        # v3.1+: Descubrimiento de topología
        "topology_q": "¿Activar descubrimiento de topología (ARP/VLAN/LLDP + gateway/rutas) además del escaneo de hosts?",
        "topology_only_help": "El modo solo topología omite el escaneo de hosts. Elige NO para un escaneo normal + topología.",
        "topology_only_q": "¿Solo topología (omitir escaneo de hosts/puertos)?",
        "topology_start": "Descubriendo topología (en la medida de lo posible)...",
        "deep_identity_start": "Escaneo de identidad profundo para {} (estrategia: {})",
        "deep_identity_cmd": "[deep] {} → {} (~{}s estimados)",
        "deep_identity_done": "Escaneo de identidad profundo finalizado para {} en {:.1f}s",
        "deep_scan_budget_exhausted": "Presupuesto de deep scan agotado ({}/{}), se omite el escaneo agresivo para {}",
        "dead_host_budget_exhausted": "Presupuesto de host muerto agotado ({}/{}), se abandona el host {}",
        "deep_strategy_adaptive": "Adaptativo (3 fases v2.8)",
        "deep_udp_priority_cmd": "[deep] {} → {} (~1-5s, UDP prioritario)",
        "deep_udp_full_cmd": "[deep] {} → {} (~120-180s, top {} UDP)",
        "banner_grab": "[banner] {} → Capturando banners para {} puertos no identificados",
        "nmap_cmd": "[nmap] {} → {}",
        "exploits_found": "⚠  Encontrados {} exploits conocidos para {}",
        "testssl_analysis": "Ejecutando análisis SSL/TLS profundo en {}:{} (puede tomar 60s)...",
        "scanning_hosts": "Escaneando hosts...",
        # Sistema de actualizaciones (v2.8.0)
        "update_check_prompt": "¿Buscar actualizaciones antes de iniciar?",
        "update_checking": "Buscando actualizaciones...",
        "update_check_failed": "No se pudo verificar actualizaciones (problema de red o GitHub no disponible)",
        "update_current": "Estás ejecutando la última versión ({})",
        "update_available": "RedAudit v{} disponible (actual: v{})",
        "update_release_date": "Fecha: {}",
        "update_release_type": "Tipo: {}",
        "update_highlights": "Novedades:",
        "update_breaking_changes": "Cambios incompatibles:",
        "update_notes_fallback_en": "Notas solo disponibles en inglés.",
        "update_notes_fallback_es": "Notas solo disponibles en español.",
        "update_release_url": "Notas completas: {}",
        "update_prompt": "¿Deseas actualizar ahora?",
        "update_starting": "Descargando actualización...",
        "update_skipped": "Actualización omitida. Continuando con la versión actual.",
        "update_restarting": "¡Actualización instalada! Reiniciando RedAudit...",
        "update_restart_failed": "Actualización instalada, pero el reinicio falló. Sal y vuelve a ejecutar: {}",
        "update_refresh_hint": (
            "Nota: Si el banner/versión no se refresca tras actualizar, reinicia el terminal "
            "o ejecuta `hash -r` (zsh/bash)."
        ),
        "update_restart_terminal_title": "REINICIO REQUERIDO",
        "update_restart_terminal_body": "Por favor, reinicie la terminal para aplicar los cambios.",
        "update_restart_terminal_hint": (
            "Recomendado: cierra y vuelve a abrir esta terminal. Alternativa: ejecuta `{}`."
        ),
        "update_restart_terminal_prompt": (
            "RedAudit se cerrará ahora para evitar ejecutar versiones mezcladas."
        ),
        "update_restart_terminal_press_enter": "Pulsa Enter para salir...",
        "update_home_changes_detected_skip": (
            "Detectados cambios locales en {}. Omitiendo la actualización de la carpeta en home."
        ),
        "update_home_changes_detected_backup": (
            "Detectados cambios locales en {}. Se creara una copia de seguridad y se actualizara la carpeta en home."
        ),
        "update_home_changes_detected_abort": (
            "Detectados cambios locales en {}. Haz commit/stash o elimina la carpeta antes de actualizar."
        ),
        "update_home_changes_verify_failed_skip": (
            "No se pudieron verificar cambios locales en {}. Omitiendo la actualización de la carpeta en home por seguridad."
        ),
        "update_home_changes_verify_failed_backup": (
            "No se pudieron verificar cambios locales en {}. Se creara una copia de seguridad y se actualizara la carpeta en home."
        ),
        "update_home_changes_verify_failed_abort": (
            "No se pudieron verificar cambios locales en {}. Actualización abortada por seguridad."
        ),
        "update_repo_sync_skip_dirty": (
            "Se detectaron cambios locales en {}. Se omite la sincronización del repo."
        ),
        "update_repo_sync_fetch_failed": (
            "No se pudieron actualizar los tags en {}. Se omite la sincronización."
        ),
        "update_repo_sync_ok": "Repositorio local {} actualizado a {}.",
        "update_repo_sync_pull_failed": (
            "No se pudo avanzar {} a main. Se omite la sincronización."
        ),
        "update_repo_sync_branch_skip": (
            "El repo {} está en '{}' (no main). Solo se actualizaron los tags."
        ),
        "update_requires_root": "La comprobación de actualizaciones requiere sudo/root (o usa --skip-update-check).",
        "update_requires_root_install": (
            "La actualización del sistema requiere sudo/root. Vuelve a ejecutar con sudo para "
            "actualizar /usr/local/bin/redaudit."
        ),
        # Configuración de API Key de NVD (v3.0.1)
        "nvd_key_set_cli": "✓ API key de NVD establecida desde línea de comandos",
        "nvd_key_invalid": "⚠  Formato de API key de NVD inválido",
        "nvd_key_not_configured": "⚠  CVE lookup activado pero sin API key de NVD configurada (límite de velocidad más lento)",
        "nvd_setup_header": "CONFIGURACIÓN DE API KEY DE NVD (Opcional)",
        "nvd_setup_info": "La correlación CVE requiere una API key de NVD para consultas más rápidas.\nSin key: 5 peticiones/30s | Con key: 50 peticiones/30s\n\nRegístrate GRATIS en:",
        "nvd_option_config": "Guardar en fichero de configuración (~/.redaudit/config.json)",
        "nvd_option_env": "Configuraré la variable de entorno NVD_API_KEY manualmente",
        "nvd_option_skip": "Continuar sin API key (más lento)",
        "nvd_ask_storage": "¿Cómo quieres configurar la API key?",
        "nvd_key_skipped": "API key omitida",
        "nvd_key_saved": "✓ API key de NVD guardada en fichero de configuración",
        "nvd_key_save_error": "⚠  Error guardando API key en configuración",
        "nvd_key_invalid_format": "Formato de API key inválido. Esperado formato UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)",
        "nvd_env_instructions": "Añade esto a tu ~/.bashrc o ~/.zshrc:",
        "nvd_env_set_later": "Puedes configurar la variable de entorno más tarde",
        "nvd_slow_mode": "⚠  Continuando en modo lento (5 peticiones/30 segundos)",
        # v3.2+: Descubrimiento de red
        "net_discovery_start": "Ejecutando Net Discovery mejorado (DHCP/NetBIOS/mDNS)...",
        "net_discovery_dhcp_found": "✓ Encontrado(s) {} servidor(es) DHCP",
        "net_discovery_routed_found": "ℹ️  Encontrada(s) {} red(es) enrutada(s) oculta(s) vía gateway(s) local(es):",
        "net_discovery_routed_add_q": "¿Añadir estas redes ocultas al alcance del escaneo?",
        "net_discovery_vlans_found": "⚠  Detectada(s) {} red(es) de invitados/VLAN(s) potencial(es)",
        "net_discovery_seed_hosts": "Net Discovery identificó {} hosts para incluir en el escaneo",
        "net_discovery_seed_added": "Añadidos {} hosts que no respondieron al ICMP",
        "net_discovery_q": "¿Activar Net Discovery mejorado (DHCP/NetBIOS/mDNS/UPNP)?",
        "net_discovery_redteam_q": "¿Incluir técnicas Red Team (enum SNMP/SMB, más lento/ruidoso)?",
        "redteam_mode_q": "Opciones de Red Team:",
        "redteam_mode_a": "A) Solo descubrimiento (recomendado)",
        "redteam_mode_b": "B) Activar módulos Red Team (requiere root; más lento/ruidoso)",
        "redteam_requires_root": (
            "Los módulos de Red Team requieren privilegios de root. Ejecuta con sudo o desactiva Red Team."
        ),
        "redteam_active_l2_q": "¿Activar L2 activo (sondeo en capa 2)? (Requiere root; más intrusivo)",
        "redteam_kerberos_userenum_q": (
            "¿Habilitar enumeración de usuarios Kerberos con Kerbrute cuando se detecte Kerberos/AD? "
            "(Solo con autorización)"
        ),
        "kerberos_realm_q": "Realm de Kerberos (opcional; ENTER para autodetectar, ej. corp.local)",
        "kerberos_userlist_q": (
            "Ruta al wordlist de usuarios para Kerbrute (opcional; ej. /usr/share/wordlists/usernames.txt)"
        ),
        # v3.2.2+: Menú principal
        "menu_option_scan": "Iniciar escaneo (wizard)",
        "menu_option_update": "Buscar actualizaciones",
        "menu_option_diff": "Comparar informes (JSON)",
        "menu_option_resume_nuclei": "Reanudar Nuclei (pendiente)",
        "menu_option_exit": "Salir",
        "menu_prompt": "Selecciona una opción [0-4]:",
        "menu_nav_hint": "Usa ↑/↓/←/→ y Enter para seleccionar.",
        "wizard_go_back": "Cancelar",
        "menu_invalid_option": "Opción inválida. Selecciona 0-4.",
        "auto_continue_countdown": "Continuar automáticamente en {}s",
        "yes_option": "Sí",
        "yes_default": "Sí (por defecto)",
        "no_option": "No",
        "no_default": "No (por defecto)",
        "vuln_scan_opt": "Escaneo de vulnerabilidades web",
        "diff_enter_old_path": "Ruta al informe ANTERIOR (JSON):",
        "diff_enter_new_path": "Ruta al informe NUEVO (JSON):",
        # v3.2.2+: Prompt de topología simplificado
        "topology_discovery_q": "Descubrimiento de topología:",
        "topology_disabled": "Desactivado",
        "topology_enabled_scan": "Activar (escaneo + topología)",
        "topology_only_mode": "Solo topología (omitir hosts/puertos)",
        # v3.2.2+: Strings hardcoded → i18n
        "target_prompt": "Objetivo (CIDR/IP/rango). Ejemplo: 192.168.1.0/24:",
        "manual_cidr_prompt": (
            "Objetivos (CIDR/IP/rango, separados por comas). Ejemplo: 192.168.1.0/24, "
            "192.168.1.10-192.168.1.20:"
        ),
        "confirm_prompt": "Confirmar:",
        "legal_warning_skipped": "⚠  Advertencia legal omitida (flag --yes)",
        "invalid_target_too_long": "Objetivo inválido (demasiado largo): {}",
        "invalid_cidr_target": "Objetivo inválido: {}",
        "no_valid_targets": "No se proporcionaron objetivos válidos",
        "target_required_non_interactive": "Error: --target es requerido en modo no interactivo",
        "invalid_proxy_url": "URL de proxy inválida: {}",
        "proxy_configured": "Proxy configurado: {}",
        "proxy_test_failed": "Prueba de proxy fallida: {}",
        "proxychains_missing": "proxychains no está instalado. Instala proxychains4 para habilitar el proxy.",
        "proxy_in_use": "Proxy en uso vía proxychains ({})",
        "random_password_generated": "Contraseña aleatoria generada para cifrado (¡guárdala!): {}",
        # v3.2.2+: Update one-liner no-TTY
        "update_oneliner": "UPDATE: RedAudit v{} disponible (actual v{}) — {}",
        # v3.2.2+: Formato de booleanos
        "enabled": "Activado",
        "disabled": "Desactivado",
        # v3.2.3+: Modo sigiloso
        "stealth_mode_info": "Modo sigiloso: timing {}, {} hilo(s), {}s+ retardo",
        # v3.6: Integración Nuclei
        "nuclei_scan_start": "Ejecutando escaneo de templates Nuclei en objetivos HTTP...",
        "nuclei_findings": "✓ Nuclei encontró {} vulnerabilidades",
        "nuclei_no_findings": "Escaneo Nuclei completado (sin hallazgos)",
        "nuclei_suspected": "Nuclei marcó {} falso(s) positivo(s) sospechado(s)",
        "nuclei_partial": "Escaneo Nuclei parcial: {} lote(s) con timeout, {} fallidos",
        "nuclei_q": "¿Ejecutar Nuclei (especializado para servicios HTTP/Web)?",
        # v4.11.0: Selector de perfil Nuclei
        "nuclei_profile_q": "Perfil de escaneo Nuclei:",
        "nuclei_full": "Completo - Todos los templates (~2h)",
        "nuclei_balanced": "Equilibrado - Templates esenciales (~1h, recomendado)",
        "nuclei_fast": "Rapido - CVEs criticos (~30-60min)",
        # v4.17: Opcion de cobertura completa (v4.18: abreviado)
        "nuclei_full_coverage_q": (
            "Escanear TODOS los puertos HTTP detectados? (además de 80/443; más objetivos)"
        ),
        "nuclei_budget_q": "Tiempo maximo de Nuclei en minutos (0 = ilimitado)",
        "nuclei_resume_saved": "Reanudacion Nuclei guardada: {}",
        "nuclei_resume_prompt": "¿Reanudar ahora los objetivos pendientes de Nuclei?",
        "nuclei_resume_none": "No hay reanudaciones de Nuclei pendientes.",
        "nuclei_resume_select": "Selecciona una reanudacion de Nuclei pendiente:",
        "nuclei_resume_cancel": "Reanudacion cancelada.",
        "nuclei_resume_running": "Reanudando Nuclei en objetivos pendientes...",
        "nuclei_resume_done": "Reanudacion de Nuclei completada: {} hallazgos añadidos",
        "nuclei_resume_failed": "Reanudacion de Nuclei fallida: {}",
        "nuclei_resume_skipped": (
            "Reanudacion de Nuclei pospuesta. Puedes reanudar luego desde el menu o con "
            "--nuclei-resume."
        ),
        "windows_verify_q": "¿Activar verificación sin agente (SMB/RDP/LDAP/SSH/HTTP)?",
        "windows_verify_max_q": "Máximo de objetivos para verificación sin agente (1-200; más alto = más lento):",
        # v3.7: Webhooks interactivos
        "webhook_q": "¿Configurar webhook de alertas en tiempo real (Slack/Teams/PagerDuty)?",
        "webhook_url_prompt": "URL del webhook (https://..., ej. https://hooks.slack.com/...):",
        "webhook_invalid_url": "URL de webhook inválida. Debe empezar con https://",
        "webhook_configured": "✓ Webhook configurado: {}",
        "webhook_test_q": "¿Enviar alerta de prueba para verificar el webhook?",
        "webhook_test_success": "✓ Webhook de prueba enviado correctamente",
        "webhook_test_failed": "⚠  Webhook de prueba fallido: {}",
        "auditor_name_q": "Nombre del auditor (opcional; ej. Juan Pérez)",
        # v3.7: Opciones avanzadas Net Discovery
        "net_discovery_advanced_q": "¿Configurar opciones avanzadas de Net Discovery?",
        "net_discovery_snmp_prompt": "Cadena de comunidad SNMP (ENTER = public)",
        "net_discovery_dns_zone_prompt": (
            "Zona DNS para intentos de transferencia (opcional; ENTER para omitir, ej. corp.local):"
        ),
        "net_discovery_max_targets_prompt": (
            "Máx. objetivos para módulos Red Team (por defecto: 50; más alto = más lento):"
        ),
        "net_discovery_options_saved": "✓ Opciones de Net Discovery guardadas",
        # v4.2: Integración SQLMap
        "sqlmap_config_q": "Intensidad de escaneo Web (sqlmap):",
        "sqlmap_l1": "Estándar (Nivel 1, Riesgo 1) — Seguro, comprobaciones básicas",
        "sqlmap_l3": "Profundo (Nivel 3, Riesgo 1) — Más payloads, headers",
        "sqlmap_risk": "Arriesgado (Nivel 3, Riesgo 2) — Pesado, SQLi basado en tiempo",
        "sqlmap_extreme": "Extremo (Nivel 5, Riesgo 3) — Máximos payloads, potencial destrucción",
        "zap_q": "¿Activar OWASP ZAP? (Requiere zap.sh en PATH, ejecución más lenta)",
        "redteam_masscan_q": "¿Usar masscan para descubrimiento inicial? (Alta velocidad, requiere root)",
        # v4.2: HyperScan/DeepScan i18n
        "hyperscan_start": "HyperScan-First: Ejecutando descubrimiento en {} hosts en paralelo...",
        "hyperscan_start_sequential": "HyperScan-First: Ejecutando descubrimiento en {} hosts (modo SYN, secuencial)...",
        "hyperscan_complete": "HyperScan-First completo: {} puertos totales en {:.1f}s",
        "hyperscan_ports_found": "[{}/{}] {}: {} puertos abiertos encontrados",
        "hyperscan_no_ports": "[{}/{}] {}: ningún puerto detectado",
        "hyperscan_masscan_reuse": "[{}/{}] {}: reutilizando {} puertos descubiertos",
        "udp_probes_progress": "Sondas UDP ({})",
        "deep_scan_running": "Ejecutando DeepScan en {} hosts...",
        "deep_scan_heartbeat": "DeepScan... {0}/{1} ({2}:{3:02d})",
        "deep_scan_progress": "DeepScan: {0}/{1}",
        "auditor_ip_excluded": "ℹ️  Auto-excluidas {} IP(s) del auditor para evitar auto-escaneo.",
        # v4.3: HyperScan mode wizard
        "hyperscan_mode_q": "Método de descubrimiento HyperScan:",
        "hyperscan_auto": "Auto — Detectar mejor método (SYN si root, sino connect)",
        "hyperscan_connect": "Connect — TCP estándar (no requiere root, más sigiloso)",
        "hyperscan_syn": "SYN — Paquetes raw (requiere root + scapy, más rápido)",
        "trust_hyperscan_q": "Omitir deep scan en hosts identificados? (mas rapido)",
        # v4.0: Authenticated Scanning
        "auth_scan_q": "¿Activar escaneo autenticado?",
        "auth_ssh_user_prompt": "Usuario SSH",
        "auth_method_key": "Clave Privada",
        "auth_method_pass": "Contraseña",
        "auth_method_q": "Método de autenticación",
        "auth_ssh_key_prompt": "Ruta a la Clave Privada",
        "auth_ssh_pass_hint": "Introduce contraseña SSH (oculta)",
        "auth_scan_start": "Iniciando escaneo autenticado en {0} como usuario {1}...",
        "auth_scan_connected": "¡Autenticación exitosa ({0})! Recopilando información del host...",
        "auth_scan_failed": "Fallo en escaneo autenticado: {0}",
        "ssh_auth_failed_all": "{0}: Autenticación SSH fallida (todas las credenciales)",
        "smb_auth_failed_all": "{0}: Autenticación SMB fallida (todas las credenciales)",
        # v4.2: SMB
        "auth_smb_configure_q": "¿Configurar credenciales Windows/SMB?",
        "auth_smb_user_prompt": "Usuario Windows (ej. Administrador)",
        "auth_smb_domain_prompt": "Dominio Windows (opcional, ENTER para ninguno)",
        "auth_smb_pass_hint": "Introduce contraseña Windows/SMB (oculta)",
        "auth_save_keyring_q": "¿Guardar credenciales en el keyring del sistema para futuros escaneos?",
        "auth_saved_creds_found": "Credenciales guardadas encontradas en keyring:",
        "auth_saved_creds_found_invoking": "Credenciales guardadas encontradas en keyring para el usuario {0}:",
        "auth_load_saved_q": "¿Cargar credenciales guardadas?",
        "auth_configure_manual_q": "¿Configurar credenciales manualmente?",
        "auth_loaded_creds": "Cargadas {0} credencial(es) desde keyring.",
        "auth_add_more_q": "¿Añadir más credenciales?",
        # v4.3: SNMP v3
        "auth_snmp_configure_q": "¿Configurar credenciales SNMP v3 (dispositivos de red)?",
        "auth_snmp_user_prompt": "Nombre de usuario SNMP v3",
        "auth_snmp_auth_proto_q": "Protocolo de Autenticación:",
        "auth_snmp_priv_proto_q": "Protocolo de Privacidad:",
        # v4.5.0: Authenticated scanning orchestration
        "auth_scan_no_hosts": "No se encontraron hosts con SSH para escaneo autenticado.",
        "auth_scan_starting": "Escaneo autenticado: {} hosts SSH con credenciales guardadas...",
        "auth_scan_complete": "Escaneo autenticado completo: {} SSH, {} auditorías Lynis",
        "auth_ssh_configure_q": "¿Configurar credenciales SSH?",
        # v4.5.1: Multi-credential support
        "auth_universal_q": "¿Configurar credenciales (universal - detecta protocolo automáticamente)?",
        "auth_cred_number": "Credencial %d",
        "auth_add_another": "¿Añadir otra credencial?",
        "auth_cred_user_prompt": "Usuario",
        "auth_cancel_hint": "Escribe 'cancelar' para cancelar y volver al asistente.",
        "auth_cred_pass_prompt": "Contraseña (oculta)",
        "auth_creds_summary": "Configuradas %d credenciales para detección automática de protocolo.",
        "auth_trying_creds": "Probando credenciales en %s:%d (%s)...",
        "auth_cred_success": "Credencial válida: %s@%s",
        "auth_mode_q": "Modo de configuración de credenciales:",
        "auth_mode_universal": "Universal (simple): detectar protocolo automáticamente",
        "auth_mode_advanced": "Avanzado: configurar SSH/SMB/SNMP por separado",
        "auth_protocol_hint": "Las credenciales se probarán en: SSH (22), SMB (445), SNMP (161), RDP (3389)",
        "auth_scan_opt": "Autenticado (SSH/SMB/SNMP)",
        "snmp_topology_q": "¿Activar descubrimiento de topología SNMP (Rutas/ARP/Interfaces)?",
        "follow_routes_q": "¿Seguir rutas descubiertas automáticamente (escanear nuevas subredes)?",
        "wizard_custom_intro": "Wizard personalizado: 9 pasos. Usa Cancelar para volver.",
    },
}


def get_text(key: str, lang: str = "en", *args) -> str:
    """
    Get translated text for a given key.

    Args:
        key: Translation key
        lang: Language code ('en' or 'es')
        *args: Format arguments

    Returns:
        Translated and formatted string
    """
    lang_dict = TRANSLATIONS.get(lang, TRANSLATIONS["en"])
    val = lang_dict.get(key, key)
    return val.format(*args) if args else val


def detect_preferred_language(preferred: Optional[str] = None) -> str:
    """
    Detect preferred language for the CLI (en/es).

    Priority:
    1) Explicit preference (if valid)
    2) Environment (LC_ALL, LC_MESSAGES, LANG)
    3) System locale
    4) Fallback: en
    """

    if preferred in TRANSLATIONS:
        return preferred

    def _map(val: str) -> Optional[str]:
        if not val:
            return None
        raw = val.strip()
        if not raw:
            return None
        # Examples: es_ES.UTF-8, en_US, es-ES, C.UTF-8
        raw = raw.split(".", 1)[0].split("@", 1)[0]
        raw = raw.replace("-", "_")
        code = raw.split("_", 1)[0].lower()
        return code if code in TRANSLATIONS else None

    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        detected = _map(os.environ.get(var, ""))
        if detected:
            return detected

    try:
        detected = _map(locale.getlocale()[0] or "")
        if detected:
            return detected
    except Exception:  # nosec
        pass

    try:
        detected = _map((locale.getdefaultlocale() or (None, None))[0] or "")
        if detected:
            return detected
    except Exception:  # nosec
        pass

    return "en"
