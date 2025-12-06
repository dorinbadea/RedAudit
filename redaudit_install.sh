#!/bin/bash
# RedAudit installer / updater v2.3 (Full core + hardening)

# 0) Environment checks
if ! command -v apt >/dev/null 2>&1; then
    echo "Error: This installer is designed for Debian/Kali systems with 'apt'."
    exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "Error: This script must be run as root (sudo)."
    exit 1
fi

AUTO_YES=false
if [[ "$1" == "-y" ]]; then AUTO_YES=true; fi

# 1) Language selection
echo "----------------------------------------------------------------"
echo " Select Language / Selecciona Idioma"
echo "----------------------------------------------------------------"
echo " 1. English"
echo " 2. Español"
echo "----------------------------------------------------------------"
if [[ -n "$2" ]]; then
    LANG_OPT="$2"
else
    read -r -p "Choice/Opción [1/2]: " LANG_OPT
fi

if [[ "$LANG_OPT" == "2" || "$LANG_OPT" == "es" ]]; then
    SELECTED_LANG="es"
    MSG_INSTALL="🔧 Instalando / actualizando RedAudit v2.3..."
    MSG_OPTIONAL="📦 Opcional: instalar pack de utilidades de red recomendadas:"
    MSG_ASK_INSTALL="¿Quieres instalarlas ahora? [S/n]: "
    MSG_SKIP="↩ Saltando instalación de utilidades extra."
    MSG_EXEC="➡ Ejecutando:"
    MSG_DONE="✅ Instalación completada."
    MSG_USAGE="👉 Ejecuta 'redaudit' para iniciar."
    MSG_APT_ERROR="❌ Error con apt. Revisa tu conexión."
    MSG_ALIAS_ADDED="ℹ️ Alias 'redaudit' añadido a"
    MSG_ALIAS_EXISTS="ℹ️ Alias 'redaudit' ya existe en"
else
    SELECTED_LANG="en"
    MSG_INSTALL="🔧 Installing / updating RedAudit v2.3..."
    MSG_OPTIONAL="📦 Optional: install recommended network utilities pack:"
    MSG_ASK_INSTALL="Do you want to install them now? [Y/n]: "
    MSG_SKIP="↩ Skipping extra utilities installation."
    MSG_EXEC="➡ Executing:"
    MSG_DONE="✅ Installation completed."
    MSG_USAGE="👉 Run 'redaudit' to start."
    MSG_APT_ERROR="❌ Error with apt. Check your connection."
    MSG_ALIAS_ADDED="ℹ️ Alias 'redaudit' added to"
    MSG_ALIAS_EXISTS="ℹ️ Alias 'redaudit' already exists in"
fi

echo "$MSG_INSTALL"

# 2) Dependencies (sistema, no pip)
EXTRA_PKGS="curl wget openssl nmap tcpdump tshark whois bind9-dnsutils python3-nmap python3-cryptography"

echo
echo "$MSG_OPTIONAL"
echo "   $EXTRA_PKGS"

if $AUTO_YES; then
    RESP="y"
else
    read -r -p "$MSG_ASK_INSTALL" RESP
fi
RESP=${RESP,,}

INSTALL_YES=false
if [[ "$SELECTED_LANG" == "es" ]]; then
    if [[ -z "$RESP" || "$RESP" =~ ^(s|si|sí|y|yes)$ ]]; then INSTALL_YES=true; fi
else
    if [[ -z "$RESP" || "$RESP" =~ ^(y|yes)$ ]]; then INSTALL_YES=true; fi
fi

if $INSTALL_YES; then
    echo "$MSG_EXEC apt update && apt install -y $EXTRA_PKGS"
    if ! apt update || ! apt install -y $EXTRA_PKGS; then
        echo "$MSG_APT_ERROR"
        exit 1
    fi
else
    echo "$MSG_SKIP"
fi

# 3) Generate Python Script (core completo con hardening)
TEMP_SCRIPT=$(mktemp)
cat << 'EOF' > "$TEMP_SCRIPT"
#!/usr/bin/env python3
"""RedAudit - Interactive Network Audit
Version 2.3 (Full Toolchain + Heartbeat)
"""

import subprocess
import sys
import os
import signal
import json
import socket
import ipaddress
import importlib
import shutil
import threading
import time
import re
import getpass
import base64
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import RotatingFileHandler

# Optional cryptography; the installer ensures it's present.
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:  # pragma: no cover - handled by installer
    Fernet = None
    PBKDF2HMAC = None
    hashes = None

VERSION = "2.3"
DEFAULT_LANG = "__LANG__"  # Replaced by installer via sed

TRANSLATIONS = {
    "en": {
        "interrupted": "\n⚠️  Interruption received. Saving current state...",
        "heartbeat_info": "⏱  Activity Monitor: {} ({}s elapsed)",
        "heartbeat_warn": "⏱  Activity Monitor: {} - No output for {}s (nmap might be busy)",
        "heartbeat_fail": "⏱  Activity Monitor: {} - Possible freeze (> {}s silent). Check or Ctrl+C.",
        "verifying_env": "Verifying environment integrity...",
        "detected": "✓ {} detected",
        "nmap_avail": "✓ python-nmap available",
        "nmap_missing": "python-nmap library not found. Please install the system package 'python3-nmap' via apt.",
        "missing_crit": "Error: missing critical dependencies: {}",
        "missing_opt": "Warning: missing optional tools: {} (reduced web/traffic features)",
        "avail_at": "✓ {} available at {}",
        "not_found": "{} not found (automatic usage skipped)",
        "ask_yes_no_opts": " (Y/n)",
        "ask_yes_no_opts_neg": " (y/N)",
        "ask_num_limit": "Host limit for deep scan (or 'all'):",
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
        "mode_full": "FULL (Full Ports + Scripts + Vulns)",
        "threads": "Concurrent threads:",
        "vuln_scan_q": "Run web vulnerability analysis?",
        "gen_txt": "Generate additional TXT report?",
        "output_dir": "Output directory:",
        "start_audit": "Start audit?",
        "scan_start": "Scanning {} hosts...",
        "scanning_host": "Scanning host {}... (Mode: {})",
        "hosts_active": "Active hosts in {}: {}",
        "scan_error": "Scan failed: {}",
        "progress": "Progress: {}/{} hosts",
        "vuln_analysis": "Analyzing vulnerabilities on {} web hosts...",
        "vulns_found": "⚠️  Vulnerabilities found on {}",
        "no_hosts": "No hosts found.",
        "exec_params": "EXECUTION PARAMETERS",
        "targets": "Targets",
        "mode": "Mode",
        "output": "Output",
        "final_summary": "FINAL SUMMARY",
        "nets": "  Networks:    {}",
        "hosts_up": "  Hosts up:    {}",
        "hosts_full": "  Hosts full:  {}",
        "vulns_web": "  Web vulns:   {}",
        "duration": "  Duration:    {}",
        "reports_gen": "\n✓ Reports generated in {}",
        "legal_warn": "\nLEGAL WARNING: Only for use on authorized networks.",
        "legal_ask": "Do you confirm you have authorization to scan these networks?",
        "json_report": "JSON Report: {}",
        "txt_report": "TXT Report: {}",
        "save_err": "Error saving report: {}",
        "root_req": "Error: root privileges (sudo) required.",
        "config_cancel": "Configuration cancelled.",
        "banner_subtitle": "   INTERACTIVE NETWORK AUDIT     ::  KALI LINUX",
        "selection_target": "TARGET SELECTION",
        "interface_detected": "✓ Interfaces detected:",
        "encrypt_reports": "Encrypt reports with password?",
        "encryption_password": "Report encryption password",
        "encryption_enabled": "✓ Encryption enabled",
        "rate_limiting": "Enable rate limiting (slower but stealthier)?",
        "rate_delay": "Delay between hosts (seconds):",
        "ports_truncated": "⚠️  {}: {} ports found, showing top 50",
    },
    "es": {
        "interrupted": "\n⚠️  Interrupción recibida. Guardando estado actual...",
        "heartbeat_info": "⏱  Monitor de Actividad: {} ({}s transcurridos)",
        "heartbeat_warn": "⏱  Monitor de Actividad: {} - Sin salida hace {}s (nmap puede estar ocupado)",
        "heartbeat_fail": "⏱  Monitor de Actividad: {} - Posible bloqueo (> {}s silencio). Revisa o Ctrl+C.",
        "verifying_env": "Verificando integridad del entorno...",
        "detected": "✓ {} detectado",
        "nmap_avail": "✓ python-nmap disponible",
        "nmap_missing": "Librería python-nmap no encontrada. Instala el paquete de sistema 'python3-nmap' vía apt.",
        "missing_crit": "Error: faltan dependencias críticas: {}",
        "missing_opt": "Aviso: faltan herramientas opcionales: {} (menos funciones web/tráfico)",
        "avail_at": "✓ {} disponible en {}",
        "not_found": "{} no encontrado (se omitirá su uso automático)",
        "ask_yes_no_opts": " (S/n)",
        "ask_yes_no_opts_neg": " (s/N)",
        "ask_num_limit": "Límite de hosts a escanear en profundidad (o 'todos'):",
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
        "mode_normal": "NORMAL (Discovery + Top Ports)",
        "mode_full": "COMPLETO (Full Ports + Vulns)",
        "threads": "Hilos concurrentes:",
        "vuln_scan_q": "¿Ejecutar análisis de vulnerabilidades web?",
        "gen_txt": "¿Generar reporte TXT adicional?",
        "output_dir": "Directorio de salida:",
        "start_audit": "¿Iniciar auditoría?",
        "scan_start": "Escaneando {} hosts...",
        "scanning_host": "Escaneando host {}... (Modo: {})",
        "hosts_active": "Hosts activos en {}: {}",
        "scan_error": "Fallo en escaneo: {}",
        "progress": "Progreso: {}/{} hosts",
        "vuln_analysis": "Analizando vulnerabilidades en {} hosts web...",
        "vulns_found": "⚠️  Vulnerabilidades registradas en {}",
        "no_hosts": "No se encontraron hosts.",
        "exec_params": "PARÁMETROS DE EJECUCIÓN",
        "targets": "Objetivos",
        "mode": "Modo",
        "output": "Salida",
        "final_summary": "RESUMEN FINAL",
        "nets": "  Redes:       {}",
        "hosts_up": "  Hosts vivos: {}",
        "hosts_full": "  Hosts full:  {}",
        "vulns_web": "  Vulns web:   {}",
        "duration": "  Duración:    {}",
        "reports_gen": "\n✓ Reportes generados en {}",
        "legal_warn": "\nADVERTENCIA LEGAL: Solo para uso en redes autorizadas.",
        "legal_ask": "¿Confirmas que tienes autorización para escanear estas redes?",
        "json_report": "Reporte JSON: {}",
        "txt_report": "Reporte TXT: {}",
        "save_err": "Error guardando reporte: {}",
        "root_req": "Error: se requieren privilegios de root (sudo).",
        "config_cancel": "Configuración cancelada.",
        "banner_subtitle": "   AUDITORÍA DE RED INTERACTIVA  ::  KALI LINUX",
        "selection_target": "SELECCIÓN DE OBJETIVO",
        "interface_detected": "✓ Interfaces detectadas:",
        "encrypt_reports": "¿Cifrar reportes con contraseña?",
        "encryption_password": "Contraseña para cifrar reportes",
        "encryption_enabled": "✓ Cifrado activado",
        "rate_limiting": "¿Activar limitación de velocidad (más lento pero más sigiloso)?",
        "rate_delay": "Retardo entre hosts (segundos):",
        "ports_truncated": "⚠️  {}: {} puertos encontrados, mostrando los 50 principales",
    },
}


class InteractiveNetworkAuditor:
    """Main orchestrator for RedAudit scans."""

    WEB_SERVICES_KEYWORDS = ["http", "https", "ssl", "www", "web", "admin", "proxy", "alt", "connect"]
    WEB_SERVICES_EXACT = [
        "http", "https", "www", "http-proxy", "ssl/http",
        "ssl/https", "http-alt", "http-admin", "http-connect"
    ]

    def __init__(self):
        self.lang = DEFAULT_LANG if DEFAULT_LANG in TRANSLATIONS else "en"
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "version": VERSION,
            "network_info": [],
            "hosts": [],
            "vulnerabilities": [],
            "summary": {},
        }
        self.config = {
            "target_networks": [],
            "max_hosts": "all",
            "max_hosts_value": "all",
            "scan_mode": "normal",
            "threads": 6,
            "output_dir": os.path.expanduser("~/RedAuditReports"),
            "scan_vulnerabilities": True,
            "save_txt_report": True,
            "encryption_salt": None,
        }

        self.encryption_enabled = False
        self.encryption_key = None
        self.rate_limit_delay = 0.0
        self.extra_tools = {}

        self.last_activity = datetime.now()
        self.activity_lock = threading.Lock()
        self.heartbeat_stop = False
        self.heartbeat_thread = None
        self.current_phase = "init"
        self.interrupted = False
        self.scan_start_time = None

        self.COLORS = {
            "HEADER": "\033[95m",
            "OKBLUE": "\033[94m",
            "OKGREEN": "\033[92m",
            "WARNING": "\033[93m",
            "FAIL": "\033[91m",
            "ENDC": "\033[0m",
            "BOLD": "\033[1m",
            "CYAN": "\033[96m",
        }

        self.logger = None
        self._setup_logging()
        signal.signal(signal.SIGINT, self.signal_handler)

    # ---------- Helpers & i18n ----------

    def t(self, key, *args):
        lang_dict = TRANSLATIONS.get(self.lang, TRANSLATIONS["en"])
        val = lang_dict.get(key, key)
        return val.format(*args) if args else val

    def print_status(self, message, status="INFO", update_activity=True):
        if update_activity:
            with self.activity_lock:
                self.last_activity = datetime.now()

        ts = datetime.now().strftime("%H:%M:%S")
        color = self.COLORS.get(status, self.COLORS["OKBLUE"])

        # Wrap long messages a bit to avoid ugly lines
        if len(message) > 100:
            lines = [message[i : i + 100] for i in range(0, len(message), 100)]
        else:
            lines = [message]

        print(f"{color}[{ts}] [{status}]{self.COLORS['ENDC']} {lines[0]}")
        for line in lines[1:]:
            print(f"  {line}")
        sys.stdout.flush()

    @staticmethod
    def sanitize_ip(ip_str):
        try:
            ipaddress.ip_address(ip_str)
            return ip_str
        except ValueError:
            return None

    @staticmethod
    def sanitize_hostname(hostname):
        if hostname and re.match(r"^[a-zA-Z0-9\.\-]+$", hostname):
            return hostname
        return None

    # ---------- Logging & heartbeat ----------

    def _setup_logging(self):
        log_dir = os.path.expanduser("~/.redaudit/logs")
        try:
            os.makedirs(log_dir, exist_ok=True)
        except OSError:
            return

        log_file = os.path.join(log_dir, f"redaudit_{datetime.now().strftime('%Y%m%d')}.log")
        logger = logging.getLogger("RedAudit")
        logger.setLevel(logging.DEBUG)

        fmt = logging.Formatter(
            "%(asctime)s - [%(levelname)s] - %(funcName)s:%(lineno)d - %(message)s"
        )
        fh = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
        fh.setFormatter(fmt)
        fh.setLevel(logging.DEBUG)

        ch = logging.StreamHandler()
        ch.setLevel(logging.ERROR)
        ch.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

        if not logger.handlers:
            logger.addHandler(fh)
            logger.addHandler(ch)

        self.logger = logger
        logger.info("=" * 60)
        logger.info("RedAudit session start")
        logger.info("User: %s", os.getenv("SUDO_USER", os.getenv("USER", "unknown")))
        logger.info("PID: %s", os.getpid())

    def start_heartbeat(self):
        if self.heartbeat_thread:
            return
        self.heartbeat_stop = False
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()

    def stop_heartbeat(self):
        self.heartbeat_stop = True
        if self.heartbeat_thread:
            try:
                self.heartbeat_thread.join(timeout=1.0)
            except RuntimeError:
                pass
            self.heartbeat_thread = None

    def _heartbeat_loop(self):
        while not self.heartbeat_stop:
            with self.activity_lock:
                delta = (datetime.now() - self.last_activity).total_seconds()

            phase = self.current_phase
            if phase not in ("init", "saving", "interrupted"):
                if 60 <= delta < 300:
                    self.print_status(self.t("heartbeat_warn", phase, int(delta)), "WARNING", False)
                elif delta >= 300:
                    self.print_status(self.t("heartbeat_fail", phase, int(delta)), "FAIL", False)
                    if self.logger:
                        self.logger.warning("Heartbeat silence > %ss in %s", delta, phase)
            time.sleep(30)

    # ---------- Crypto ----------

    def ask_password_twice(self, prompt="Password"):
        while True:
            p1 = getpass.getpass(
                f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {prompt}: "
            )
            if len(p1) < 8:
                msg = "Password must be at least 8 characters"
                if self.lang == "es":
                    msg = "La contraseña debe tener al menos 8 caracteres"
                self.print_status(msg, "WARNING")
                continue
            p2 = getpass.getpass(
                f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} Confirm: "
            )
            if p1 == p2:
                return p1
            msg = "Passwords don't match"
            if self.lang == "es":
                msg = "Las contraseñas no coinciden"
            self.print_status(msg, "WARNING")

    def derive_key_from_password(self, password, salt=None):
        if PBKDF2HMAC is None:
            raise RuntimeError("cryptography not available")
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def encrypt_data(self, data):
        if not self.encryption_key or Fernet is None:
            return data
        try:
            f = Fernet(self.encryption_key)
            if isinstance(data, str):
                data = data.encode()
            return f.encrypt(data)
        except Exception as exc:  # pragma: no cover
            if self.logger:
                self.logger.error("Encryption error: %s", exc)
            return data

    def setup_encryption(self):
        if self.ask_yes_no(self.t("encrypt_reports"), default="no"):
            pwd = self.ask_password_twice(self.t("encryption_password"))
            key, salt = self.derive_key_from_password(pwd)
            self.encryption_key = key
            self.config["encryption_salt"] = base64.b64encode(salt).decode()
            self.encryption_enabled = True
            self.print_status(self.t("encryption_enabled"), "OKGREEN")

    # ---------- Dependencies ----------

    def check_dependencies(self):
        self.print_status(self.t("verifying_env"), "HEADER")

        # nmap binary
        if shutil.which("nmap") is None:
            self.print_status("Error: nmap binary not found.", "FAIL")
            return False

        # python-nmap
        global nmap
        try:
            nmap = importlib.import_module("nmap")
            self.print_status(self.t("nmap_avail"), "OKGREEN")
        except ImportError:
            self.print_status(self.t("nmap_missing"), "FAIL")
            return False

        tools = [
            "whatweb",
            "nikto",
            "curl",
            "wget",
            "openssl",
            "tcpdump",
            "tshark",
            "whois",
            "dig",
        ]
        missing = []
        for tname in tools:
            path = shutil.which(tname)
            if path:
                self.extra_tools[tname] = path
                self.print_status(self.t("avail_at", tname, path), "OKGREEN")
            else:
                self.extra_tools[tname] = None
                missing.append(tname)

        if missing:
            self.print_status(self.t("missing_opt", ", ".join(missing)), "WARNING")
        return True

    # ---------- Input utilities ----------

    def ask_yes_no(self, question, default="yes"):
        default = default.lower()
        opts = (
            self.t("ask_yes_no_opts")
            if default in ("yes", "y", "s", "si", "sí")
            else self.t("ask_yes_no_opts_neg")
        )
        valid = {
            "yes": True,
            "y": True,
            "s": True,
            "si": True,
            "sí": True,
            "no": False,
            "n": False,
        }
        while True:
            ans = input(
                f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {question}{opts}: "
            ).strip().lower()
            if ans == "":
                return valid.get(default, True)
            if ans in valid:
                return valid[ans]

    def ask_number(self, question, default=10, min_val=1, max_val=1000):
        while True:
            ans = input(
                f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {question} [{default}]: "
            ).strip()
            if ans == "":
                return default
            if ans.lower() in ("todos", "all"):
                return "all"
            try:
                num = int(ans)
                if min_val <= num <= max_val:
                    return num
                self.print_status(
                    self.t("val_out_of_range", min_val, max_val), "WARNING"
                )
            except ValueError:
                continue

    def ask_choice(self, question, options, default=0):
        print(f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {question}")
        for i, opt in enumerate(options):
            marker = f"{self.COLORS['BOLD']}▶{self.COLORS['ENDC']}" if i == default else " "
            print(f"  {marker} {i+1}. {opt}")
        while True:
            ans = input(
                f"\n{self.t('select_opt')} [1-{len(options)}] ({default+1}): "
            ).strip()
            if ans == "":
                return default
            try:
                idx = int(ans) - 1
                if 0 <= idx < len(options):
                    return idx
            except ValueError:
                continue

    def ask_manual_network(self):
        while True:
            net = input(
                f"\n{self.COLORS['CYAN']}?{self.COLORS['ENDC']} CIDR (e.g. 192.168.1.0/24): "
            ).strip()
            try:
                ipaddress.ip_network(net, strict=False)
                return net
            except ValueError:
                self.print_status(self.t("invalid_cidr"), "WARNING")

    # ---------- Network detection ----------

    def detect_interface_type(self, iface):
        if iface.startswith("e"):
            return "Ethernet"
        if iface.startswith("w"):
            return "Wi-Fi"
        if iface.startswith(("tun", "tap")):
            return "VPN"
        return "Other"

    def _detect_networks_netifaces(self):
        nets = []
        try:
            import netifaces

            for iface in netifaces.interfaces():
                if iface.startswith(("lo", "docker", "br-", "veth")):
                    continue
                try:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        for info in addrs[netifaces.AF_INET]:
                            ip_addr = info.get("addr")
                            mask = info.get("netmask")
                            if ip_addr and mask and ip_addr != "127.0.0.1":
                                net = ipaddress.ip_network(
                                    f"{ip_addr}/{mask}", strict=False
                                )
                                nets.append(
                                    {
                                        "interface": iface,
                                        "ip": ip_addr,
                                        "network": f"{net.network_address}/{net.prefixlen}",
                                        "hosts_estimated": max(
                                            net.num_addresses - 2, 0
                                        ),
                                        "type": self.detect_interface_type(iface),
                                    }
                                )
                except Exception:
                    continue
        except ImportError:
            self.print_status(self.t("netifaces_missing"), "WARNING")
        return nets

    def _detect_networks_fallback(self):
        nets = []
        try:
            res = subprocess.run(
                ["ip", "-4", "-o", "addr", "show"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in res.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) < 4:
                    continue
                iface = parts[1]
                if iface.startswith(("lo", "docker", "br-", "veth")):
                    continue
                try:
                    ipi = ipaddress.ip_interface(parts[3])
                    nets.append(
                        {
                            "interface": iface,
                            "ip": str(ipi.ip),
                            "network": str(ipi.network),
                            "hosts_estimated": max(ipi.network.num_addresses - 2, 0),
                            "type": self.detect_interface_type(iface),
                        }
                    )
                except ValueError:
                    continue
        except Exception:
            pass
        return nets

    def detect_all_networks(self):
        self.print_status(self.t("analyzing_nets"), "INFO")
        nets = self._detect_networks_netifaces()
        if not nets:
            nets = self._detect_networks_fallback()

        # dedupe by (network, interface)
        unique = {(n["network"], n["interface"]): n for n in nets}
        nets_list = list(unique.values())
        self.results["network_info"] = nets_list
        return nets_list

    def ask_network_range(self):
        print(f"\n{self.COLORS['HEADER']}{self.t('selection_target')}{self.COLORS['ENDC']}")
        print("-" * 60)
        nets = self.detect_all_networks()
        if nets:
            print(
                f"{self.COLORS['OKGREEN']}{self.t('interface_detected')}{self.COLORS['ENDC']}"
            )
            opts = []
            for n in nets:
                info = f" ({n['interface']})" if n["interface"] else ""
                opts.append(
                    f"{n['network']}{info} - ~{n['hosts_estimated']} hosts"
                )
            opts.append(self.t("manual_entry"))
            opts.append(self.t("scan_all"))
            choice = self.ask_choice(self.t("select_net"), opts)
            if choice == len(opts) - 2:
                return [self.ask_manual_network()]
            if choice == len(opts) - 1:
                return [n["network"] for n in nets]
            return [nets[choice]["network"]]
        else:
            self.print_status(self.t("no_nets_auto"), "WARNING")
            return [self.ask_manual_network()]

    # ---------- Scanning ----------

    def get_nmap_arguments(self, mode):
        args = {
            "rapido": "-sn -T4 --max-retries 1 --host-timeout 10s",
            "normal": "-T4 -F -sV --version-intensity 5 --host-timeout 60s --open",
            "completo": "-T4 -p- -sV -sC -A --version-intensity 9 --host-timeout 300s --max-retries 2 --open",
        }
        return args.get(mode, args["normal"])

    def scan_network_discovery(self, network):
        self.current_phase = f"discovery:{network}"
        self.logger.info("Discovery on %s", network)
        nm = nmap.PortScanner()
        args = self.get_nmap_arguments("rapido")
        try:
            nm.scan(hosts=network, arguments=args)
        except Exception as exc:
            self.logger.error("Discovery failed on %s: %s", network, exc)
            self.print_status(self.t("scan_error", exc), "FAIL")
            return []
        hosts = [h for h in nm.all_hosts() if nm[h].state() == "up"]
        self.print_status(self.t("hosts_active", network, len(hosts)), "OKGREEN")
        return hosts

    def is_web_service(self, name):
        if not name:
            return False
        n = name.lower()
        if n in self.WEB_SERVICES_EXACT:
            return True
        return any(k in n for k in self.WEB_SERVICES_KEYWORDS)

    def deep_scan_host(self, host_ip):
        """Aggressive follow-up scan plus optional traffic capture."""
        safe_ip = self.sanitize_ip(host_ip)
        if not safe_ip:
            return None

        self.current_phase = f"deep:{safe_ip}"
        self.print_status(f"Deep scanning {safe_ip}...", "WARNING")
        cmds = [
            ["nmap", "-A", "-sV", "-Pn", "-p-", "--open", safe_ip],
            ["nmap", "-O", "-sSU", "-Pn", safe_ip],
        ]
        deep = {"commands": []}
        for cmd in cmds:
            try:
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
                deep["commands"].append(
                    {
                        "command": " ".join(cmd),
                        "returncode": res.returncode,
                        "stdout": (res.stdout or "")[:8000],
                        "stderr": (res.stderr or "")[:2000],
                    }
                )
            except subprocess.TimeoutExpired as exc:
                deep["commands"].append(
                    {
                        "command": " ".join(cmd),
                        "error": f"Timeout after {exc.timeout}s",
                    }
                )
            except Exception as exc:
                deep["commands"].append(
                    {
                        "command": " ".join(cmd),
                        "error": str(exc),
                    }
                )

        pcap_info = self.capture_traffic_snippet(safe_ip)
        if pcap_info:
            deep["pcap_capture"] = pcap_info
        return deep

    def capture_traffic_snippet(self, host_ip, duration=15):
        """Small PCAP capture with tcpdump + optional tshark summary."""
        if not self.extra_tools.get("tcpdump"):
            return None

        safe_ip = self.sanitize_ip(host_ip)
        if not safe_ip:
            return None

        # pick interface heuristically: first interface whose network contains the host
        iface = None
        try:
            ip_obj = ipaddress.ip_address(safe_ip)
            for net in self.results.get("network_info", []):
                try:
                    net_obj = ipaddress.ip_network(net["network"], strict=False)
                    if ip_obj in net_obj:
                        iface = net.get("interface")
                        break
                except Exception:
                    continue
        except ValueError:
            return None

        if not iface:
            iface = "eth0"

        if not re.match(r"^[a-zA-Z0-9\-_]+$", iface):
            return None

        ts = datetime.now().strftime("%H%M%S")
        base_dir = self.config.get("output_dir", os.path.expanduser("~/RedAuditReports"))
        os.makedirs(base_dir, exist_ok=True)
        pcap_file = os.path.join(
            base_dir, f"traffic_{safe_ip.replace('.','_')}_{ts}.pcap"
        )

        cmd = [
            self.extra_tools["tcpdump"],
            "-i",
            iface,
            "host",
            safe_ip,
            "-c",
            "50",
            "-G",
            str(duration),
            "-W",
            "1",
            "-w",
            pcap_file,
        ]
        info = {"pcap_file": pcap_file, "iface": iface}
        try:
            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=duration + 5,
            )
        except subprocess.TimeoutExpired as exc:
            info["tcpdump_error"] = f"Timeout after {exc.timeout}s"
        except Exception as exc:
            info["tcpdump_error"] = str(exc)

        # tshark summary if available
        if self.extra_tools.get("tshark"):
            try:
                res = subprocess.run(
                    [
                        self.extra_tools["tshark"],
                        "-r",
                        pcap_file,
                        "-q",
                        "-z",
                        "io,phs",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                info["tshark_summary"] = (res.stdout or res.stderr or "")[:2000]
            except Exception as exc:
                info["tshark_error"] = str(exc)

        return info

    def enrich_host_with_dns_and_whois(self, host_record):
        ip_str = host_record["ip"]
        host_record["dns"] = {}
        if self.extra_tools.get("dig"):
            try:
                res = subprocess.run(
                    [
                        self.extra_tools["dig"],
                        "+short",
                        "-x",
                        ip_str,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if res.stdout.strip():
                    host_record["dns"]["reverse"] = res.stdout.strip().splitlines()
            except Exception:
                pass

        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if not ip_obj.is_private and self.extra_tools.get("whois"):
                res = subprocess.run(
                    [
                        self.extra_tools["whois"],
                        ip_str,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                text = res.stdout or res.stderr
                if text:
                    lines = [l for l in text.splitlines() if l.strip()][:25]
                    host_record["dns"]["whois_summary"] = "\n".join(lines)
        except Exception:
            pass

    def http_enrichment(self, url, scheme, host_ip, port):
        data = {}
        if self.extra_tools.get("curl"):
            try:
                res = subprocess.run(
                    [
                        self.extra_tools["curl"],
                        "-I",
                        "--max-time",
                        "10",
                        url,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                if res.stdout:
                    data["curl_headers"] = res.stdout.strip()[:2000]
            except Exception:
                pass
        if self.extra_tools.get("wget"):
            try:
                res = subprocess.run(
                    [
                        self.extra_tools["wget"],
                        "--spider",
                        "-S",
                        "-T",
                        "10",
                        url,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                hdrs = res.stderr or res.stdout
                if hdrs:
                    data["wget_spider"] = hdrs.strip()[:2000]
            except Exception:
                pass
        if scheme == "https" and self.extra_tools.get("openssl"):
            try:
                res = subprocess.run(
                    [
                        self.extra_tools["openssl"],
                        "s_client",
                        "-connect",
                        f"{host_ip}:{port}",
                        "-servername",
                        host_ip,
                        "-brief",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                if res.stdout:
                    data["tls_info"] = res.stdout.strip()[:2000]
            except Exception:
                pass
        return data

    def scan_host_ports(self, host):
        safe_ip = self.sanitize_ip(host)
        if not safe_ip:
            self.logger.warning("Invalid IP: %s", host)
            return {"ip": host, "error": "Invalid IP"}

        self.current_phase = f"ports:{safe_ip}"
        nm = nmap.PortScanner()
        args = self.get_nmap_arguments(self.config["scan_mode"])
        self.logger.debug("Nmap scan %s %s", safe_ip, args)
        try:
            nm.scan(safe_ip, arguments=args)
            if safe_ip not in nm.all_hosts():
                # fallback to deep scan only
                deep = self.deep_scan_host(safe_ip)
                return {"ip": safe_ip, "status": "down", "deep_scan": deep} if deep else {"ip": safe_ip, "status": "down"}
            data = nm[safe_ip]
            hostname = ""
            try:
                hostnames = data.hostnames()
                if hostnames:
                    hostname = hostnames[0].get("name") or ""
            except Exception:
                hostname = ""

            ports = []
            web_count = 0
            for proto in data.all_protocols():
                for p in data[proto]:
                    svc = data[proto][p]
                    name = svc.get("name", "")
                    product = svc.get("product", "")
                    version = svc.get("version", "")
                    is_web = self.is_web_service(name)
                    if is_web:
                        web_count += 1
                    ports.append(
                        {
                            "port": p,
                            "protocol": proto,
                            "service": name,
                            "product": product,
                            "version": version,
                            "is_web_service": is_web,
                        }
                    )

            total_ports = len(ports)
            if total_ports > 50:
                self.print_status(
                    self.t("ports_truncated", safe_ip, total_ports), "WARNING"
                )
                ports = ports[:50]

            host_record = {
                "ip": safe_ip,
                "hostname": self.sanitize_hostname(hostname) or "",
                "ports": ports,
                "web_ports_count": web_count,
                "status": data.state(),
                "total_ports_found": total_ports,
            }

            # Deep scan for "quiet" hosts
            if total_ports <= 3:
                deep = self.deep_scan_host(safe_ip)
                if deep:
                    host_record["deep_scan"] = deep

            self.enrich_host_with_dns_and_whois(host_record)
            return host_record

        except Exception as exc:
            self.logger.error("Scan error %s: %s", safe_ip, exc, exc_info=True)
            result = {"ip": safe_ip, "error": str(exc)}
            try:
                deep = self.deep_scan_host(safe_ip)
                if deep:
                    result["deep_scan"] = deep
            except Exception:
                pass
            return result

    def scan_hosts_concurrent(self, hosts):
        self.print_status(self.t("scan_start", len(hosts)), "HEADER")
        unique_hosts = sorted(set(hosts))
        results = []

        with ThreadPoolExecutor(max_workers=self.config["threads"]) as executor:
            futures = {}
            for h in unique_hosts:
                if self.interrupted:
                    break
                fut = executor.submit(self.scan_host_ports, h)
                futures[fut] = h
                if self.rate_limit_delay > 0:
                    time.sleep(self.rate_limit_delay)

            total = len(futures)
            done = 0
            for fut in as_completed(futures):
                if self.interrupted:
                    break
                host_ip = futures[fut]
                try:
                    res = fut.result()
                    results.append(res)
                except Exception as exc:
                    self.logger.error("Worker error for %s: %s", host_ip, exc)
                done += 1
                if total and done % max(1, total // 10) == 0:
                    self.print_status(
                        self.t("progress", done, total), "INFO", update_activity=False
                    )

        self.results["hosts"] = results
        return results

    def scan_vulnerabilities_web(self, host_info):
        web_ports = [
            p for p in host_info.get("ports", []) if p.get("is_web_service")
        ]
        if not web_ports:
            return None

        ip = host_info["ip"]
        vulns = []

        for p in web_ports[:3]:
            svc_name = (p.get("service") or "").lower()
            scheme = "https" if p["port"] == 443 or "ssl" in svc_name else "http"
            url = f"{scheme}://{ip}:{p['port']}"
            entry = {
                "url": url,
                "port": p["port"],
                "service": p.get("service"),
                "findings": [],
            }

            # whatweb
            if self.extra_tools.get("whatweb"):
                try:
                    res = subprocess.run(
                        [self.extra_tools["whatweb"], "--color=never", "-a", "1", url],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    if res.stdout:
                        entry["whatweb"] = res.stdout.strip()[:300]
                except Exception:
                    pass

            # nikto only on full mode
            if (
                self.config.get("scan_mode") == "completo"
                and self.extra_tools.get("nikto")
            ):
                try:
                    res = subprocess.run(
                        [
                            self.extra_tools["nikto"],
                            "-h",
                            url,
                            "-Tuning",
                            "123b",
                            "-t",
                            "30",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=180,
                    )
                    if res.stdout and "+" in res.stdout:
                        lines = [
                            l.strip()
                            for l in res.stdout.splitlines()
                            if "+" in l and "Server:" not in l
                        ]
                        if lines:
                            entry["nikto_findings"] = lines[:5]
                            entry["findings"].extend(lines[:3])
                except Exception:
                    pass

            http_extra = self.http_enrichment(
                url, scheme, ip, p["port"]
            )
            if http_extra:
                entry.update(http_extra)

            if any(
                key in entry
                for key in ("whatweb", "nikto_findings", "curl_headers", "tls_info")
            ):
                vulns.append(entry)

        return {"host": ip, "vulnerabilities": vulns} if vulns else None

    def scan_vulnerabilities_concurrent(self, host_results):
        web_hosts = [h for h in host_results if h.get("web_ports_count", 0) > 0]
        if not web_hosts:
            return
        self.current_phase = "vulns"
        self.print_status(self.t("vuln_analysis", len(web_hosts)), "HEADER")
        workers = min(3, self.config["threads"])
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self.scan_vulnerabilities_web, h): h["ip"]
                for h in web_hosts
            }
            for fut in as_completed(futures):
                if self.interrupted:
                    break
                try:
                    res = fut.result()
                    if res:
                        self.results["vulnerabilities"].append(res)
                        self.print_status(
                            self.t("vulns_found", res["host"]), "WARNING"
                        )
                except Exception as exc:
                    self.print_status(f"[worker error] {exc}", "WARNING")

    # ---------- Reporting ----------

    def generate_summary(self, all_hosts, results):
        duration = (
            datetime.now() - self.scan_start_time
            if self.scan_start_time is not None
            else None
        )
        total_vulns = sum(
            len(v.get("vulnerabilities", []))
            for v in self.results.get("vulnerabilities", [])
        )
        self.results["summary"] = {
            "networks": len(self.config.get("target_networks", [])),
            "hosts_found": len(all_hosts),
            "hosts_scanned": len(results),
            "vulns_found": total_vulns,
            "duration": str(duration).split(".")[0] if duration else None,
        }

    def _generate_text_report_string(self, partial=False):
        lines = []
        status_txt = "PARTIAL/INTERRUPTED" if partial else "COMPLETED"
        lines.append(f"NETWORK AUDIT REPORT v{VERSION}\n")
        lines.append(f"Date: {datetime.now()}\n")
        lines.append(f"Status: {status_txt}\n\n")

        summ = self.results.get("summary", {})
        lines.append(f"Networks:      {summ.get('networks', 0)}\n")
        lines.append(f"Hosts Found:   {summ.get('hosts_found', 0)}\n")
        lines.append(f"Hosts Scanned: {summ.get('hosts_scanned', 0)}\n")
        lines.append(f"Web Vulns:     {summ.get('vulns_found', 0)}\n\n")

        for h in self.results.get("hosts", []):
            lines.append(f"Host: {h.get('ip')} ({h.get('hostname')})\n")
            lines.append(f"  Status: {h.get('status')}\n")
            lines.append(f"  Total Ports: {h.get('total_ports_found')}\n")
            for p in h.get("ports", []):
                lines.append(
                    f"    - {p['port']}/{p['protocol']}  {p['service']}  {p['version']}\n"
                )
            if h.get("dns", {}).get("reverse"):
                lines.append("  Reverse DNS:\n")
                for r in h["dns"]["reverse"]:
                    lines.append(f"    {r}\n")
            if h.get("dns", {}).get("whois_summary"):
                lines.append("  Whois summary:\n")
                lines.append("    " + h["dns"]["whois_summary"].replace("\n", "\n    ") + "\n")
            if h.get("deep_scan"):
                lines.append("  Deep scan data present.\n")
            lines.append("\n")

        if self.results.get("vulnerabilities"):
            lines.append("WEB VULNERABILITIES SUMMARY:\n")
            for v in self.results["vulnerabilities"]:
                lines.append(f"\nHost: {v['host']}\n")
                for item in v.get("vulnerabilities", []):
                    lines.append(f"  URL: {item.get('url','')}\n")
                    if item.get("whatweb"):
                        lines.append(f"    WhatWeb: {item['whatweb'][:80]}...\n")
                    if item.get("nikto_findings"):
                        lines.append(
                            f"    Nikto: {len(item['nikto_findings'])} findings.\n"
                        )
        return "".join(lines)

    def show_config_summary(self):
        print(f"\n{self.COLORS['HEADER']}{self.t('exec_params')}{self.COLORS['ENDC']}")
        conf = {
            self.t("targets"): self.config["target_networks"],
            self.t("mode"): self.config["scan_mode"],
            self.t("threads"): self.config["threads"],
            "Vulns": self.config.get("scan_vulnerabilities"),
            self.t("output"): self.config["output_dir"],
        }
        for k, v in conf.items():
            print(f"  {k}: {v}")

    def show_results(self):
        s = self.results.get("summary", {})
        print(f"\n{self.COLORS['HEADER']}{self.t('final_summary')}{self.COLORS['ENDC']}")
        print(self.t("nets", s.get("networks")))
        print(self.t("hosts_up", s.get("hosts_found")))
        print(self.t("hosts_full", s.get("hosts_scanned")))
        print(self.t("vulns_web", s.get("vulns_found")))
        print(self.t("duration", s.get("duration")))
        print(
            f"{self.COLORS['OKGREEN']}{self.t('reports_gen', self.config['output_dir'])}{self.COLORS['ENDC']}"
        )

    def show_legal_warning(self):
        print(f"{self.COLORS['FAIL']}{self.t('legal_warn')}{self.COLORS['ENDC']}")
        return self.ask_yes_no(self.t("legal_ask"), default="no")

    def save_results(self, partial=False):
        self.current_phase = "saving"
        prefix = "PARTIAL_" if partial else ""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(
            self.config.get("output_dir", os.path.expanduser("~/RedAuditReports")),
            f"{prefix}redaudit_{ts}",
        )

        try:
            os.makedirs(os.path.dirname(base), exist_ok=True)

            # JSON
            json_data = json.dumps(self.results, indent=2, default=str)
            if self.encryption_enabled:
                json_enc = self.encrypt_data(json_data)
                json_path = f"{base}.json.enc"
                with open(json_path, "wb") as f:
                    f.write(json_enc)
            else:
                json_path = f"{base}.json"
                with open(json_path, "w", encoding="utf-8") as f:
                    f.write(json_data)
            self.print_status(self.t("json_report", json_path), "OKGREEN")

            # TXT
            if self.config.get("save_txt_report"):
                txt_data = self._generate_text_report_string(partial=partial)
                if self.encryption_enabled:
                    txt_enc = self.encrypt_data(txt_data)
                    txt_path = f"{base}.txt.enc"
                    with open(txt_path, "wb") as f:
                        f.write(txt_enc)
                else:
                    txt_path = f"{base}.txt"
                    with open(txt_path, "w", encoding="utf-8") as f:
                        f.write(txt_data)
                self.print_status(self.t("txt_report", txt_path), "OKGREEN")

            # Salt
            if self.encryption_enabled and self.config.get("encryption_salt"):
                salt_bytes = base64.b64decode(self.config["encryption_salt"])
                with open(f"{base}.salt", "wb") as f:
                    f.write(salt_bytes)

        except Exception as exc:
            if self.logger:
                self.logger.error("Save error: %s", exc, exc_info=True)
            self.print_status(self.t("save_err", exc), "FAIL")

    # ---------- Interactive flow ----------

    def clear_screen(self):
        os.system("clear" if os.name == "posix" else "cls")

    def print_banner(self):
        subtitle = self.t("banner_subtitle")
        banner = f"""
{self.COLORS['FAIL']}
    ____          _    {self.COLORS['BOLD']}{self.COLORS['HEADER']}_   _           _ _ _{self.COLORS['ENDC']}{self.COLORS['FAIL']}
   / __ \\___  ___| |  {self.COLORS['BOLD']}{self.COLORS['HEADER']}/ \\  _   _  __| (_) |_{self.COLORS['ENDC']}{self.COLORS['FAIL']}
  / /_/ / _ \\/ __| | {self.COLORS['BOLD']}{self.COLORS['HEADER']}/ _ \\| | | |/ _` | | __|{self.COLORS['ENDC']}{self.COLORS['FAIL']}
 / _, _/  __/ (__| |{self.COLORS['BOLD']}{self.COLORS['HEADER']}/ ___ \\ |_| | (_| | | |_{self.COLORS['ENDC']}{self.COLORS['FAIL']}
/_/ |_|\\___|\\___|_|{self.COLORS['BOLD']}{self.COLORS['HEADER']}/_/   \\_\\__,_|\\__,_|_|\\__|{self.COLORS['ENDC']}
                                      {self.COLORS['CYAN']}v{VERSION}{self.COLORS['ENDC']}
{self.COLORS['OKBLUE']}══════════════════════════════════════════════════════{self.COLORS['ENDC']}
{self.COLORS['BOLD']}{subtitle}{self.COLORS['ENDC']}
{self.COLORS['OKBLUE']}══════════════════════════════════════════════════════{self.COLORS['ENDC']}
"""
        print(banner)

    def interactive_setup(self):
        self.clear_screen()
        self.print_banner()

        if not self.check_dependencies():
            return False
        if not self.show_legal_warning():
            return False

        print(f"\n{self.COLORS['HEADER']}{self.t('scan_config')}{self.COLORS['ENDC']}")
        print("=" * 60)

        # targets
        self.config["target_networks"] = self.ask_network_range()

        # mode
        scan_modes = [
            self.t("mode_fast"),
            self.t("mode_normal"),
            self.t("mode_full"),
        ]
        modes_map = {0: "rapido", 1: "normal", 2: "completo"}
        self.config["scan_mode"] = modes_map[self.ask_choice(self.t("scan_mode"), scan_modes, 1)]

        # host limit
        if self.config["scan_mode"] != "rapido":
            limit = self.ask_number(self.t("ask_num_limit"), default=25)
            self.config["max_hosts_value"] = limit
        else:
            self.config["max_hosts_value"] = "all"

        # threads
        self.config["threads"] = self.ask_number(self.t("threads"), default=6, min_val=1, max_val=16)

        # rate limiting
        if self.ask_yes_no(self.t("rate_limiting"), default="no"):
            delay = self.ask_number(self.t("rate_delay"), default=1, min_val=0, max_val=60)
            self.rate_limit_delay = float(delay)

        # vuln scan
        self.config["scan_vulnerabilities"] = self.ask_yes_no(self.t("vuln_scan_q"), default="yes")

        # output dir
        default_reports = os.path.expanduser("~/RedAuditReports")
        out_dir = input(
            f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {self.t('output_dir')} [{default_reports}]: "
        ).strip()
        if not out_dir:
            out_dir = default_reports
        self.config["output_dir"] = out_dir

        # txt report
        self.config["save_txt_report"] = self.ask_yes_no(self.t("gen_txt"), default="yes")

        # encryption
        self.setup_encryption()

        self.show_config_summary()
        return self.ask_yes_no(self.t("start_audit"), default="yes")

    def run_complete_scan(self):
        self.scan_start_time = datetime.now()
        self.start_heartbeat()

        all_hosts = []
        for net in self.config.get("target_networks", []):
            if self.interrupted:
                break
            all_hosts.extend(self.scan_network_discovery(net))

        all_hosts = sorted(set(all_hosts))

        if not all_hosts:
            self.print_status(self.t("no_hosts"), "WARNING")
            self.generate_summary(all_hosts, [])
            self.save_results(partial=False)
            self.stop_heartbeat()
            return False

        if self.config["scan_mode"] == "rapido":
            self.results["hosts"] = [{"ip": h, "status": "up"} for h in all_hosts]
            self.generate_summary(all_hosts, self.results["hosts"])
            self.show_results()
            self.save_results(partial=False)
            self.stop_heartbeat()
            return True

        limit = self.config.get("max_hosts_value", "all")
        if isinstance(limit, int):
            targets = all_hosts[:limit]
        else:
            targets = all_hosts
        host_results = self.scan_hosts_concurrent(targets)

        if self.config.get("scan_vulnerabilities"):
            self.scan_vulnerabilities_concurrent(host_results)

        self.results["hosts"] = host_results
        self.generate_summary(all_hosts, host_results)
        self.show_results()
        self.save_results(partial=False)
        self.stop_heartbeat()
        return True

    # ---------- Signals ----------

    def signal_handler(self, sig, frame):
        if not self.interrupted:
            self.interrupted = True
            self.print_status(self.t("interrupted"), "FAIL")
            try:
                self.save_results(partial=True)
            finally:
                self.stop_heartbeat()
            sys.exit(1)


def main():
    if os.geteuid() != 0:
        print("Error: root privileges (sudo) required.")
        sys.exit(1)
    app = InteractiveNetworkAuditor()
    if app.interactive_setup():
        ok = app.run_complete_scan()
        sys.exit(0 if ok else 1)
    else:
        print(app.t("config_cancel"))
        sys.exit(0)


if __name__ == "__main__":
    main()
EOF

# Inject selected language
sed -i "s/__LANG__/$SELECTED_LANG/g" "$TEMP_SCRIPT"

# Install to /usr/local/bin
mv "$TEMP_SCRIPT" /usr/local/bin/redaudit
chown root:root /usr/local/bin/redaudit
chmod 755 /usr/local/bin/redaudit

# 4) Alias setup
REAL_USER=${SUDO_USER:-$USER}
if [ -n "$REAL_USER" ]; then
    REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
    USER_SHELL=$(getent passwd "$REAL_USER" | cut -d: -f7)
    RC_FILE="$REAL_HOME/.bashrc"
    [[ "$USER_SHELL" == *"zsh"* ]] && RC_FILE="$REAL_HOME/.zshrc"

    if ! grep -q "alias redaudit=" "$RC_FILE" 2>/dev/null; then
        echo "alias redaudit='sudo /usr/local/bin/redaudit'" >> "$RC_FILE"
        chown "$REAL_USER" "$RC_FILE"
        echo "$MSG_ALIAS_ADDED $RC_FILE"
    else
        echo "$MSG_ALIAS_EXISTS $RC_FILE"
    fi
fi

echo
echo "$MSG_DONE"
echo "$MSG_USAGE"