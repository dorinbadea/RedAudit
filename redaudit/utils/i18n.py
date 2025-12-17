#!/usr/bin/env python3
"""
RedAudit - Internationalization (i18n)
Copyright (C) 2025  Dorin Badea
GPLv3 License

Translation strings for English and Spanish.
"""

import locale
import os
from typing import Optional

TRANSLATIONS = {
    "en": {
        "interrupted": "\n⚠️  Interruption received. Saving current state...",
        "terminating_scans": "Terminating active scans...",
        "heartbeat_info": "⏱  Activity Monitor: {} ({}s elapsed)",
        "heartbeat_warn": "⏱  Activity Monitor: {} - No output for {}s (tool may be busy)",
        "heartbeat_fail": (
            "⏱  Activity Monitor: {} - Long silence (>{}s). "
            "The active tool is still running; this is normal for slow or filtered hosts."
        ),
        "deep_scan_skip": "✅ Info sufficient (MAC/OS found), skipping phase 2.",
        "verifying_env": "Verifying environment integrity...",
        "config_module_missing": "Config module not available",
        "detected": "✓ {} detected",
        "nmap_avail": "✓ python-nmap available",
        "nmap_missing": "python-nmap library not found. Please install the system package 'python3-nmap' via apt.",
        "nmap_binary_missing": "Error: nmap binary not found.",
        "missing_crit": "Error: missing critical dependencies: {}",
        "missing_opt": "Warning: missing optional tools: {} (reduced web/traffic features)",
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
        "mode_fast": "FAST (Discovery only)",
        "mode_normal": "NORMAL (Discovery + Top Ports)",
        "mode_full": "FULL (Full Ports + Scripts + Vulns + Deep Identity Scan)",
        "threads": "Concurrent threads:",
        "vuln_scan_q": "Run web vulnerability analysis?",
        "cve_lookup_q": "Enable CVE correlation via NVD? (slower, enriches with CVE data)",
        "gen_txt": "Generate additional TXT report?",
        "gen_html": "Generate interactive HTML report?",
        "output_dir": "Output directory:",
        "start_audit": "Start audit?",
        "scan_start": "Scanning {} hosts...",
        "scanning_host": "Scanning host {}... (Mode: {})",
        "scanned_host": "Scanned {}",
        "hosts_active": "Active hosts in {}: {}",
        "scan_error": "Scan failed: {}",
        "progress": "Progress: {}/{} hosts",
        "worker_error": "[worker error] {}",
        "vuln_analysis": "Analyzing vulnerabilities on {} web hosts...",
        "vulns_found": "⚠️  Vulnerabilities found on {}",
        "no_hosts": "No hosts found.",
        "exec_params": "EXECUTION PARAMETERS",
        "web_vulns": "Web vulns",
        "cve_lookup": "CVE correlation (NVD)",
        "targets": "Targets",
        "mode": "Mode",
        "output": "Output",
        "final_summary": "FINAL SUMMARY",
        "nets": "  Networks:    {}",
        "hosts_up": "  Hosts up:    {}",
        "hosts_full": "  Hosts full:  {}",
        "vulns_web": "  Web vulns:   {}",
        "duration": "  Duration:    {}",
        "pcaps": "  PCAPs:       {}",
        "reports_gen": "\n✓ Reports generated in {}",
        "legal_warn": "\nLEGAL WARNING: Only for use on authorized networks.",
        "legal_ask": "Do you confirm you have authorization to scan these networks?",
        "json_report": "JSON Report: {}",
        "txt_report": "TXT Report: {}",
        "html_report": "HTML Report: {}",
        "playbooks_generated": "Remediation playbooks generated: {}",
        "summary": "SUMMARY",
        "save_err": "Error saving report: {}",
        "root_req": "Error: root privileges (sudo) required.",
        "config_cancel": "Configuration cancelled.",
        "banner_subtitle": "   INTERACTIVE NETWORK AUDIT     ::  KALI LINUX",
        "selection_target": "TARGET SELECTION",
        "interface_detected": "✓ Interfaces detected:",
        "encrypt_reports": "Encrypt reports with password?",
        "encryption_password": "Report encryption password",
        "encryption_enabled": "✓ Encryption enabled",
        "cryptography_required": "Error: Encryption requires python3-cryptography. Install with: sudo apt install python3-cryptography",
        "rate_limiting": "Enable rate limiting (slower but stealthier)?",
        "rate_delay": "Delay between hosts (seconds):",
        "ports_truncated": "⚠️  {}: {} ports found, showing top 50",
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
        "defaults_summary_threads": "Threads",
        "defaults_summary_output": "Output dir",
        "defaults_summary_rate_limit": "Rate limit (s)",
        "defaults_summary_udp_mode": "UDP mode",
        "defaults_summary_udp_ports": "UDP ports (full mode)",
        "defaults_summary_topology": "Topology discovery",
        # v3.2.3: Additional defaults display
        "defaults_summary_scan_mode": "Scan mode",
        "defaults_summary_web_vulns": "Web vulns scan",
        "defaults_summary_cve_lookup": "CVE correlation",
        "defaults_summary_txt_report": "TXT report",
        "defaults_summary_html_report": "HTML report",
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
        "deep_strategy_adaptive": "Adaptive (3-Phase v2.8)",
        "deep_udp_priority_cmd": "[deep] {} → {} (~1-5s, priority UDP)",
        "deep_udp_full_cmd": "[deep] {} → {} (~120-180s, top {} UDP)",
        "banner_grab": "[banner] {} → Grabbing banners for {} unidentified ports",
        "nmap_cmd": "[nmap] {} → {}",
        "exploits_found": "⚠️  Found {} known exploits for {}",
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
        "update_requires_root": "Update check requires sudo/root (or run with --skip-update-check).",
        # NVD API Key configuration (v3.0.1)
        "nvd_key_set_cli": "✓ NVD API key set from command line",
        "nvd_key_invalid": "⚠️  Invalid NVD API key format",
        "nvd_key_not_configured": "⚠️  CVE lookup enabled but no NVD API key configured (slower rate limit)",
        "nvd_setup_header": "NVD API KEY SETUP (Optional)",
        "nvd_setup_info": "CVE Correlation requires an NVD API key for faster lookups.\nWithout key: 5 requests/30s | With key: 50 requests/30s\n\nRegister for FREE at:",
        "nvd_option_config": "Save in config file (~/.redaudit/config.json)",
        "nvd_option_env": "I'll set NVD_API_KEY environment variable myself",
        "nvd_option_skip": "Continue without API key (slower)",
        "nvd_ask_storage": "How would you like to configure the API key?",
        "nvd_key_skipped": "API key skipped",
        "nvd_key_saved": "✓ NVD API key saved to config file",
        "nvd_key_save_error": "⚠️  Error saving API key to config",
        "nvd_key_invalid_format": "Invalid API key format. Expected UUID format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)",
        "nvd_env_instructions": "Add this to your ~/.bashrc or ~/.zshrc:",
        "nvd_env_set_later": "You can set the environment variable later",
        "nvd_slow_mode": "⚠️  Continuing with slow mode (5 requests/30 seconds)",
        # v3.2+: Network discovery
        "net_discovery_start": "Running enhanced network discovery (DHCP/NetBIOS/mDNS)...",
        "net_discovery_dhcp_found": "✓ Found {} DHCP server(s)",
        "net_discovery_vlans_found": "⚠️  Detected {} potential guest network(s)/VLAN(s)",
        "net_discovery_q": "Enable enhanced network discovery (DHCP/NetBIOS/mDNS/UPNP)?",
        "net_discovery_redteam_q": "Include Red Team techniques (SNMP/SMB enum, slower/noisier)?",
        # v3.2.2+: Main menu
        "menu_option_scan": "Start scan (wizard)",
        "menu_option_update": "Check for updates",
        "menu_option_diff": "Diff reports (JSON)",
        "menu_option_exit": "Exit",
        "menu_prompt": "Select option [0-3]:",
        "menu_invalid_option": "Invalid option. Please select 0-3.",
        "diff_enter_old_path": "Path to OLD report (JSON):",
        "diff_enter_new_path": "Path to NEW report (JSON):",
        # v3.2.2+: Simplified topology prompt
        "topology_discovery_q": "Topology discovery:",
        "topology_disabled": "Disabled",
        "topology_enabled_scan": "Enable (scan + topology)",
        "topology_only_mode": "Topology only (skip host/port scan)",
        # v3.2.2+: Hardcoded strings → i18n
        "target_prompt": "Target (CIDR/IP/range). Example: 192.168.1.0/24:",
        "confirm_prompt": "Confirm:",
        "legal_warning_skipped": "⚠️  Legal warning skipped (--yes flag)",
        "invalid_target_too_long": "Invalid target (too long): {}",
        "invalid_cidr_target": "Invalid CIDR: {}",
        "no_valid_targets": "No valid targets provided",
        "target_required_non_interactive": "Error: --target is required in non-interactive mode",
        "invalid_proxy_url": "Invalid proxy URL: {}",
        "proxy_configured": "Proxy configured: {}",
        "proxy_test_failed": "Proxy test failed: {}",
        "random_password_generated": "Generated random encryption password (save this!): {}",
        # v3.2.2+: Non-TTY update one-liner
        "update_oneliner": "UPDATE: RedAudit v{} available (current v{}) — {}",
        # v3.2.2+: Boolean formatting
        "enabled": "Enabled",
        "disabled": "Disabled",
        # v3.2.3+: Stealth mode
        "stealth_mode_info": "Stealth mode: {} timing, {} thread(s), {}s+ delay",
    },
    "es": {
        "interrupted": "\n⚠️  Interrupción recibida. Guardando estado actual...",
        "terminating_scans": "Terminando escaneos activos...",
        "heartbeat_info": "⏱  Monitor de Actividad: {} ({}s transcurridos)",
        "heartbeat_warn": "⏱  Monitor de Actividad: {} - Sin salida hace {}s (herramienta ocupada)",
        "heartbeat_fail": (
            "⏱  Monitor de Actividad: {} - Silencio prolongado (>{}s). "
            "La herramienta activa sigue ejecutándose; esto es normal en hosts lentos o filtrados."
        ),
        "deep_scan_skip": "✅ Info suficiente (MAC/OS detectado), saltando fase 2.",
        "verifying_env": "Verificando integridad del entorno...",
        "config_module_missing": "Módulo de configuración no disponible",
        "detected": "✓ {} detectado",
        "nmap_avail": "✓ python-nmap disponible",
        "nmap_missing": "Librería python-nmap no encontrada. Instala el paquete de sistema 'python3-nmap' vía apt.",
        "nmap_binary_missing": "Error: binario nmap no encontrado.",
        "missing_crit": "Error: faltan dependencias críticas: {}",
        "missing_opt": "Aviso: faltan herramientas opcionales: {} (menos funciones web/tráfico)",
        "crypto_missing": "Librería cryptography no disponible. El cifrado de reportes queda deshabilitado.",
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
        "mode_fast": "RÁPIDO (solo discovery)",
        "mode_normal": "NORMAL (Discovery + Puertos principales)",
        "mode_full": "COMPLETO (Puertos + Scripts + Vulns + Escaneo de identidad profundo)",
        "threads": "Hilos concurrentes:",
        "vuln_scan_q": "¿Ejecutar análisis de vulnerabilidades web?",
        "cve_lookup_q": "¿Activar correlación CVE vía NVD? (más lento, enriquece con datos CVE)",
        "gen_txt": "¿Generar reporte TXT adicional?",
        "gen_html": "¿Generar reporte HTML interactivo?",
        "output_dir": "Directorio de salida:",
        "start_audit": "¿Iniciar auditoría?",
        "scan_start": "Escaneando {} hosts...",
        "scanning_host": "Escaneando host {}... (Modo: {})",
        "scanned_host": "Escaneado {}",
        "hosts_active": "Hosts activos en {}: {}",
        "scan_error": "Fallo en escaneo: {}",
        "progress": "Progreso: {}/{} hosts",
        "worker_error": "[error de trabajador] {}",
        "vuln_analysis": "Analizando vulnerabilidades en {} hosts web...",
        "vulns_found": "⚠️  Vulnerabilidades registradas en {}",
        "no_hosts": "No se encontraron hosts.",
        "exec_params": "PARÁMETROS DE EJECUCIÓN",
        "web_vulns": "Vulnerabilidades web",
        "cve_lookup": "Correlación CVE (NVD)",
        "targets": "Objetivos",
        "mode": "Modo",
        "output": "Salida",
        "final_summary": "RESUMEN FINAL",
        "nets": "  Redes:       {}",
        "hosts_up": "  Hosts vivos: {}",
        "hosts_full": "  Completos:   {}",
        "vulns_web": "  Vulns web:   {}",
        "duration": "  Duración:    {}",
        "pcaps": "  PCAPs:       {}",
        "reports_gen": "\n✓ Reportes generados en {}",
        "legal_warn": "\nADVERTENCIA LEGAL: Solo para uso en redes autorizadas.",
        "legal_ask": "¿Confirmas que tienes autorización para escanear estas redes?",
        "json_report": "Reporte JSON: {}",
        "txt_report": "Reporte TXT: {}",
        "html_report": "Reporte HTML: {}",
        "playbooks_generated": "Playbooks de remediación generados: {}",
        "summary": "RESUMEN",
        "save_err": "Error guardando reporte: {}",
        "root_req": "Error: se requieren privilegios de root (sudo).",
        "config_cancel": "Configuración cancelada.",
        "banner_subtitle": "   AUDITORÍA DE RED INTERACTIVA  ::  KALI LINUX",
        "selection_target": "SELECCIÓN DE OBJETIVO",
        "interface_detected": "✓ Interfaces detectadas:",
        "encrypt_reports": "¿Cifrar reportes con contraseña?",
        "encryption_password": "Contraseña para cifrar reportes",
        "encryption_enabled": "✓ Cifrado activado",
        "cryptography_required": "Error: El cifrado requiere python3-cryptography. Instala con: sudo apt install python3-cryptography",
        "rate_limiting": "¿Activar limitación de velocidad (más lento pero más sigiloso)?",
        "rate_delay": "Retardo entre hosts (segundos):",
        "ports_truncated": "⚠️  {}: {} puertos encontrados, mostrando los 50 principales",
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
        "defaults_summary_threads": "Hilos",
        "defaults_summary_output": "Salida",
        "defaults_summary_rate_limit": "Limitación (s)",
        "defaults_summary_udp_mode": "Modo UDP",
        "defaults_summary_udp_ports": "Puertos UDP (modo completo)",
        "defaults_summary_topology": "Descubrimiento de topología",
        # v3.2.3: Nuevos campos de defaults
        "defaults_summary_scan_mode": "Modo de escaneo",
        "defaults_summary_web_vulns": "Escaneo vulns web",
        "defaults_summary_cve_lookup": "Correlación CVE",
        "defaults_summary_txt_report": "Reporte TXT",
        "defaults_summary_html_report": "Reporte HTML",
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
        "deep_strategy_adaptive": "Adaptativo (3 fases v2.8)",
        "deep_udp_priority_cmd": "[deep] {} → {} (~1-5s, UDP prioritario)",
        "deep_udp_full_cmd": "[deep] {} → {} (~120-180s, top {} UDP)",
        "banner_grab": "[banner] {} → Capturando banners para {} puertos no identificados",
        "nmap_cmd": "[nmap] {} → {}",
        "exploits_found": "⚠️  Encontrados {} exploits conocidos para {}",
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
        "update_requires_root": "La comprobación de actualizaciones requiere sudo/root (o usa --skip-update-check).",
        # Configuración de API Key de NVD (v3.0.1)
        "nvd_key_set_cli": "✓ API key de NVD establecida desde línea de comandos",
        "nvd_key_invalid": "⚠️  Formato de API key de NVD inválido",
        "nvd_key_not_configured": "⚠️  CVE lookup activado pero sin API key de NVD configurada (límite de velocidad más lento)",
        "nvd_setup_header": "CONFIGURACIÓN DE API KEY DE NVD (Opcional)",
        "nvd_setup_info": "La correlación CVE requiere una API key de NVD para consultas más rápidas.\nSin key: 5 peticiones/30s | Con key: 50 peticiones/30s\n\nRegístrate GRATIS en:",
        "nvd_option_config": "Guardar en archivo de configuración (~/.redaudit/config.json)",
        "nvd_option_env": "Configuraré la variable de entorno NVD_API_KEY manualmente",
        "nvd_option_skip": "Continuar sin API key (más lento)",
        "nvd_ask_storage": "¿Cómo quieres configurar la API key?",
        "nvd_key_skipped": "API key omitida",
        "nvd_key_saved": "✓ API key de NVD guardada en archivo de configuración",
        "nvd_key_save_error": "⚠️  Error guardando API key en configuración",
        "nvd_key_invalid_format": "Formato de API key inválido. Esperado formato UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)",
        "nvd_env_instructions": "Añade esto a tu ~/.bashrc o ~/.zshrc:",
        "nvd_env_set_later": "Puedes configurar la variable de entorno más tarde",
        "nvd_slow_mode": "⚠️  Continuando en modo lento (5 peticiones/30 segundos)",
        # v3.2+: Descubrimiento de red
        "net_discovery_start": "Ejecutando descubrimiento de red mejorado (DHCP/NetBIOS/mDNS)...",
        "net_discovery_dhcp_found": "✓ Encontrado(s) {} servidor(es) DHCP",
        "net_discovery_vlans_found": "⚠️  Detectada(s) {} red(es) de invitados/VLAN(s) potencial(es)",
        "net_discovery_q": "¿Activar descubrimiento de red mejorado (DHCP/NetBIOS/mDNS/UPNP)?",
        "net_discovery_redteam_q": "¿Incluir técnicas Red Team (enum SNMP/SMB, más lento/ruidoso)?",
        # v3.2.2+: Menú principal
        "menu_option_scan": "Iniciar escaneo (wizard)",
        "menu_option_update": "Buscar actualizaciones",
        "menu_option_diff": "Comparar reportes (JSON)",
        "menu_option_exit": "Salir",
        "menu_prompt": "Selecciona una opción [0-3]:",
        "menu_invalid_option": "Opción inválida. Selecciona 0-3.",
        "diff_enter_old_path": "Ruta al reporte ANTERIOR (JSON):",
        "diff_enter_new_path": "Ruta al reporte NUEVO (JSON):",
        # v3.2.2+: Prompt de topología simplificado
        "topology_discovery_q": "Descubrimiento de topología:",
        "topology_disabled": "Desactivado",
        "topology_enabled_scan": "Activar (escaneo + topología)",
        "topology_only_mode": "Solo topología (omitir hosts/puertos)",
        # v3.2.2+: Strings hardcoded → i18n
        "target_prompt": "Objetivo (CIDR/IP/rango). Ejemplo: 192.168.1.0/24:",
        "confirm_prompt": "Confirmar:",
        "legal_warning_skipped": "⚠️  Advertencia legal omitida (flag --yes)",
        "invalid_target_too_long": "Objetivo inválido (demasiado largo): {}",
        "invalid_cidr_target": "CIDR inválido: {}",
        "no_valid_targets": "No se proporcionaron objetivos válidos",
        "target_required_non_interactive": "Error: --target es requerido en modo no interactivo",
        "invalid_proxy_url": "URL de proxy inválida: {}",
        "proxy_configured": "Proxy configurado: {}",
        "proxy_test_failed": "Prueba de proxy fallida: {}",
        "random_password_generated": "Contraseña aleatoria generada para cifrado (¡guárdala!): {}",
        # v3.2.2+: Update one-liner no-TTY
        "update_oneliner": "UPDATE: RedAudit v{} disponible (actual v{}) — {}",
        # v3.2.2+: Formato de booleanos
        "enabled": "Activado",
        "disabled": "Desactivado",
        # v3.2.3+: Modo sigiloso
        "stealth_mode_info": "Modo sigiloso: timing {}, {} hilo(s), {}s+ retardo",
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
