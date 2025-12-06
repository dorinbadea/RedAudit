#!/bin/bash
# RedAudit installer / updater v2.3 (Full Toolchain + Heartbeat)

# 0) Comprobaciones de entorno: apt + root
if ! command -v apt >/dev/null 2>&1; then
    echo "Este instalador está pensado para sistemas con apt (Debian/Kali)."
    exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "Este instalador debe ejecutarse como root (por ejemplo: sudo bash redaudit_install.sh)."
    exit 1
fi

AUTO_YES=false
if [[ "$1" == "-y" ]]; then AUTO_YES=true; fi

# 1) Language selection / Selección de idioma
echo "----------------------------------------------------------------"
echo " Select Language / Selecciona Idioma"
echo "----------------------------------------------------------------"
echo " 1. English"
echo " 2. Español"
echo "----------------------------------------------------------------"
read -r -p "Choice/Opción [1/2]: " LANG_OPT

if [[ "$LANG_OPT" == "2" || "$LANG_OPT" == "es" ]]; then
    SELECTED_LANG="es"
    MSG_INSTALL="🔧 Instalando / actualizando RedAudit v2.3..."
    MSG_OPTIONAL="📦 Opcional: instalar pack de utilidades de red recomendadas:"
    MSG_ASK_INSTALL="¿Quieres instalarlas ahora? [S/n]: "
    MSG_SKIP="↩ Saltando instalación de utilidades extra."
    MSG_EXEC="➡ Ejecutando:"
    MSG_DONE="✅ Instalación / actualización completada."
    MSG_USAGE="👉 En tu usuario normal, ejecuta:"
    MSG_ALIAS_ADDED="ℹ️ Alias 'redaudit' añadido a"
    MSG_ALIAS_EXISTS="ℹ️ Alias 'redaudit' ya existe en"
    MSG_APT_ERROR="❌ Error instalando dependencias con apt. Revisa la configuración de red o vuelve a intentarlo más tarde."
else
    SELECTED_LANG="en"
    MSG_INSTALL="🔧 Installing / updating RedAudit v2.3..."
    MSG_OPTIONAL="📦 Optional: install recommended network utilities pack:"
    MSG_ASK_INSTALL="Do you want to install them now? [Y/n]: "
    MSG_SKIP="↩ Skipping extra utilities installation."
    MSG_EXEC="➡ Executing:"
    MSG_DONE="✅ Installation / update completed."
    MSG_USAGE="👉 In your normal user, run:"
    MSG_ALIAS_ADDED="ℹ️ Alias 'redaudit' added to"
    MSG_ALIAS_EXISTS="ℹ️ Alias 'redaudit' already exists in"
    MSG_APT_ERROR="❌ Error installing dependencies with apt. Check your network or try again later."
fi

echo "$MSG_INSTALL"

# 2) Opcional: pack de utilidades de red recomendadas
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
    if [[ -z "$RESP" || "$RESP" == "s" || "$RESP" == "si" || "$RESP" == "sí" || "$RESP" == "y" ]]; then INSTALL_YES=true; fi
else
    if [[ -z "$RESP" || "$RESP" == "y" || "$RESP" == "yes" ]]; then INSTALL_YES=true; fi
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

# 3) Crear /usr/local/bin/redaudit con el código Python v2.3
# We use sed to inject the selected language into the python script
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
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
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
from logging.handlers import RotatingFileHandler

# Cryptography (optional modules logic handled in check_dependencies if needed,
# but we are enforcing it via apt, so we import normally)
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
except ImportError:
    # Fallback/Exit if not present (should be installed by script)
    pass

VERSION = "2.3"
DEFAULT_LANG = "__LANG__"  # Will be replaced by installer
nmap = None

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
        "nmap_installed": "✓ python-nmap installed successfully",
        "missing_crit": "Error: missing critical dependencies: {}",
        "missing_opt": "Warning: missing optional tools: {} (reduced web scan)",
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
        "scanning_host": "Scanning host {}... (Mode: {})",
        "encrypt_reports": "Encrypt reports with password?",
        "encryption_password": "Report encryption password",
        "encryption_enabled": "✓ Encryption enabled",
        "rate_limiting": "Enable rate limiting (slower but stealthier)?",
        "rate_delay": "Delay between hosts (seconds):",
        "ports_truncated": "⚠️  {}: {} ports found, showing top 50",
        "scan_all": "Scan ALL",
        "scan_config": "SCAN CONFIGURATION",
        "scan_mode": "Scan Mode:",
        "mode_fast": "FAST (Discovery only)",
        "mode_normal": "NORMAL (Discovery + Top Ports)",
        "mode_full": "FULL (Full Ports + Scripts + Vulns)",
        "threads": "Concurrent threads:",
        "vuln_scan": "Run web vulnerability analysis?",
        "gen_txt": "Generate additional TXT report?",
        "custom_dir": "Use custom output directory?",
        "dir_prompt": "Directory:",
        "dir_err": "Error creating directory: {}",
        "start_audit": "Start audit?",
        "discovery_on": "Discovery on {}...",
        "hosts_active": "Active hosts in {}: {}",
        "discovery_fail": "Discovery failed {}: {}",
        "deep_scan_launch": "Launching deep scan on {}...",
        "scanning_concurrent": "Scanning {} hosts with {} threads...",
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
        "vulns_web": "  Vulns web:   {}",
        "duration": "  Duration:    {}",
        "reports_gen": "\n✓ Reports generated in {}",
        "legal_warn": "\nLEGAL WARNING: Only for use on authorized networks.",
        "legal_ask": "Do you confirm you have authorization to scan these networks?",
        "json_report": "JSON Report: {}.json",
        "txt_report": "TXT Report: {}.txt",
        "save_err": "Error saving report: {}",
        "root_req": "Error: root privileges (sudo) required.",
        "config_cancel": "Configuration cancelled.",
        "banner_subtitle": "   INTERACTIVE NETWORK AUDIT     ::  KALI LINUX",
        "selection_target": "TARGET SELECTION",
        "interface_detected": "✓ Interfaces detected:",
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
        "nmap_installed": "✓ python-nmap instalado correctamente",
        "missing_crit": "Error: faltan dependencias críticas: {}",
        "missing_opt": "Aviso: faltan herramientas opcionales: {} (escaneo web reducido)",
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
        "mode_full": "COMPLETO (Full Ports + Scripts + Vulns)",
        "threads": "Hilos concurrentes:",
        "vuln_scan": "¿Ejecutar análisis de vulnerabilidades web?",
        "gen_txt": "¿Generar reporte TXT adicional?",
        "custom_dir": "¿Usar directorio de salida personalizado?",
        "dir_prompt": "Directorio:",
        "dir_err": "Error creando directorio: {}",
        "start_audit": "¿Iniciar auditoría?",
        "discovery_on": "Discovery en {}...",
        "hosts_active": "Hosts activos en {}: {}",
        "discovery_fail": "Fallo en discovery {}: {}",
        "deep_scan_launch": "Lanzando deep scan sobre {}...",
        "scanning_concurrent": "Escaneando {} hosts con {} hilos...",
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
        "json_report": "Reporte JSON: {}.json",
        "txt_report": "Reporte TXT: {}.txt",
        "save_err": "Error guardando reporte: {}",
        "root_req": "Error: se requieren privilegios de root (sudo).",
        "config_cancel": "Configuración cancelada.",
        "banner_subtitle": "   AUDITORÍA DE RED INTERACTIVA  ::  KALI LINUX",
        "selection_target": "SELECCIÓN DE OBJETIVO",
        "interface_detected": "✓ Interfaces detectadas:",
    }
}

class InteractiveNetworkAuditor:
    # Heurística de servicios web
    WEB_SERVICES_KEYWORDS = ["http", "https", "ssl", "www", "web", "admin", "proxy", "alt", "connect"]
    WEB_SERVICES_EXACT = [
        "http", "https", "www", "http-proxy", "ssl/http",
        "ssl/https", "http-alt", "http-admin", "http-connect"
    ]

    def __init__(self):
        self.lang = DEFAULT_LANG
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "version": VERSION,
            "network_info": [],
            "hosts": [],
            "vulnerabilities": [],
            "summary": {}
        }

        self.config = {
            'target_networks': [],
            'max_hosts': 'todos',
            'max_hosts_value': 'todos',
            'scan_mode': 'normal',
            'threads': 6,
            'output_dir': os.path.expanduser("~/RedAuditReports"),
            'scan_vulnerabilities': True,
            'save_txt_report': True
        }

        # Crear directorio de salida por defecto si es posible
        try:
            os.makedirs(self.config['output_dir'], exist_ok=True)
        except Exception:
            pass

        self.COLORS = {
            "HEADER": "\033[95m", "OKBLUE": "\033[94m", "OKGREEN": "\033[92m",
            "WARNING": "\033[93m", "FAIL": "\033[91m", "ENDC": "\033[0m",
            "BOLD": "\033[1m", "CYAN": "\033[96m", "MAGENTA": "\033[95m",
            "GREEN": "\033[92m"
        }

        self.interrupted = False
        self.scan_start_time = None
        self.extra_tools = {}

        self.heartbeat_stop = False
        self.last_activity = datetime.now()
        self.activity_lock = threading.Lock()
        
        # New configurable fields
        self.encryption_enabled = False
        self.encryption_key = None
        self.config['encryption_salt'] = None
        self.rate_limit_delay = 0

        self.setup_logging()

        # Monitor de vida
        self.current_phase = "init"
        self.heartbeat_thread = None

        signal.signal(signal.SIGINT, self.signal_handler)

    def setup_logging(self):
        """Configura logging profesional para auditoría."""
        log_dir = os.path.expanduser("~/.redaudit/logs")
        try:
            os.makedirs(log_dir, exist_ok=True)
        except:
            return

        log_file = os.path.join(log_dir, f"redaudit_{datetime.now().strftime('%Y%m%d')}.log")

        self.logger = logging.getLogger('RedAudit')
        self.logger.setLevel(logging.DEBUG)

        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - [%(levelname)s] - %(funcName)s:%(lineno)d - %(message)s'
        )

        file_handler = RotatingFileHandler(
            log_file, maxBytes=10*1024*1024, backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.ERROR) 
        console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))

        if not self.logger.handlers:
            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)

        self.logger.info("="*60)
        self.logger.info(f"RedAudit v{VERSION} initialized")
        self.logger.info(f"User: {os.getenv('SUDO_USER', os.getenv('USER'))}")
        self.logger.info(f"PID: {os.getpid()}")

    @staticmethod
    def sanitize_ip(ip_str):
        """Valida que sea una IP válida, devuelve None si no lo es."""
        try:
            import ipaddress
            ipaddress.ip_address(ip_str)
            return ip_str
        except ValueError:
            return None

    @staticmethod
    def sanitize_hostname(hostname):
        """Sanitiza hostname para prevenir inyección."""
        if re.match(r'^[a-zA-Z0-9\.\-]+$', hostname):
            return hostname
        return None

    def ask_password_twice(self, prompt="Password"):
        """Pide contraseña dos veces para confirmar."""
        while True:
            pwd1 = getpass.getpass(f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {prompt}: ")
            if len(pwd1) < 8:
                msg = "Password must be at least 8 characters" if self.lang == "en" else "La contraseña debe tener al menos 8 caracteres"
                self.print_status(msg, "WARNING")
                continue
            pwd2 = getpass.getpass(f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} Confirm password: ")
            if pwd1 == pwd2:
                return pwd1
            msg = "Passwords don't match" if self.lang == "en" else "Las contraseñas no coinciden"
            self.print_status(msg, "WARNING")

    def derive_key_from_password(self, password, salt=None):
        """Deriva una clave Fernet desde una contraseña usando PBKDF2."""
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def encrypt_data(self, data):
        """Cifra datos con Fernet."""
        if not self.encryption_key:
            return data
        try:
            f = Fernet(self.encryption_key)
            if isinstance(data, str):
                data = data.encode()
            return f.encrypt(data)
        except Exception as e:
            self.print_status(f"Encryption error: {e}", "FAIL")
            return data

    def setup_encryption(self):
        """Configura el cifrado si el usuario lo solicita."""
        msg = self.t("encrypt_reports")
        if self.ask_yes_no(msg, "no"):
            pwd_prompt = self.t("encryption_password")
            password = self.ask_password_twice(pwd_prompt)
            key, salt = self.derive_key_from_password(password)
            self.encryption_key = key
            self.encryption_enabled = True
            self.config['encryption_salt'] = base64.b64encode(salt).decode()
            self.print_status(self.t("encryption_enabled"), "OKGREEN")
        signal.signal(signal.SIGTERM, self.signal_handler)

    def t(self, key, *args):
        """Translate helper"""
        text = TRANSLATIONS.get(self.lang, TRANSLATIONS["en"]).get(key, key)
        if args:
            return text.format(*args)
        return text

    # ========= Señales =========

    def signal_handler(self, sig, frame):
        if not self.interrupted:
            self.interrupted = True
            self.print_status(self.t("interrupted"), "FAIL")
            self.stop_heartbeat()
            self.save_results(partial=True)
            sys.exit(1)

    # ========= Heartbeat =========

    def start_heartbeat(self):
        if self.heartbeat_thread is not None:
            return
        self.heartbeat_stop = False
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()

    def stop_heartbeat(self):
        self.heartbeat_stop = True
        if self.heartbeat_thread is not None:
            try:
                self.heartbeat_thread.join(timeout=1.0)
            except RuntimeError:
                pass
        self.heartbeat_thread = None

    def _heartbeat_loop(self):
        while not self.heartbeat_stop:
            now = datetime.now()
            delta = (now - self.last_activity).total_seconds()
            try:
                # Format phase for better readability
            with self.activity_lock:
                now = datetime.now()
                delta = (now - self.last_activity).total_seconds()
            
            try:
                # Si estamos en espera o hay actividad reciente, decidimos qué imprimir
                phase_desc = self.current_phase
                # Si hay silencio > 300s, puede ser un bloqueo
                
                # Solo informar periódicamente si la fase no es init/saving
                if phase_desc not in ["init", "saving", "interrupted"]:
                    if delta < 60:
                        # Actividad normal, no spamear
                        # msg = self.t("heartbeat_info", phase_desc, int(delta))
                        # self.print_status(msg, "INFO", update_activity=False)
                        pass
                    elif delta < 300:
                        msg = self.t("heartbeat_warn", phase_desc, int(delta))
                        self.print_status(msg, "WARNING", update_activity=False)
                    else:
                        msg = self.t("heartbeat_fail", phase_desc, int(delta))
                        self.print_status(msg, "FAIL", update_activity=False)
                        self.logger.warning(f"Heartbeat silence detected: {delta}s in phase {phase_desc}")
            except Exception as e:
                self.logger.error(f"Heartbeat loop error: {e}")
            time.sleep(30)

    # ========= Utilidades básicas =========

    def print_status(self, message, status="INFO", update_activity=True):
        if update_activity:
            with self.activity_lock:
                self.last_activity = datetime.now()
        
        ts = datetime.now().strftime("%H:%M:%S")
        color = self.COLORS.get(status, self.COLORS["OKBLUE"])
        if len(message) > 80:
            lines = [message[i:i+80] for i in range(0, len(message), 80)]
            print(f"{color}[{ts}] [{status}]{self.COLORS['ENDC']} {lines[0]}")
            for line in lines[1:]:
                print(f"  {line}")
        else:
            print(f"{color}[{ts}] [{status}]{self.COLORS['ENDC']} {message}")
        sys.stdout.flush()
        if update_activity:
            self.last_activity = datetime.now()

    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')

    def print_banner(self):
        subtitle = self.t("banner_subtitle")
        banner = f"""
{self.COLORS['FAIL']}
    ____          _    {self.COLORS['BOLD']}{self.COLORS['HEADER']}_   _           _ _ _{self.COLORS['ENDC']}{self.COLORS['FAIL']}
   / __ \___  ___| |  {self.COLORS['BOLD']}{self.COLORS['HEADER']}/ \  _   _  __| (_) |_{self.COLORS['ENDC']}{self.COLORS['FAIL']}
  / /_/ / _ \/ __| | {self.COLORS['BOLD']}{self.COLORS['HEADER']}/ _ \| | | |/ _` | | __|{self.COLORS['ENDC']}{self.COLORS['FAIL']}
 / _, _/  __/ (__| |{self.COLORS['BOLD']}{self.COLORS['HEADER']}/ ___ \ |_| | (_| | | |_{self.COLORS['ENDC']}{self.COLORS['FAIL']}
/_/ |_|\___|\___|_|{self.COLORS['BOLD']}{self.COLORS['HEADER']}/_/   \_\__,_|\__,_|_|\__|{self.COLORS['ENDC']}
                                      {self.COLORS['CYAN']}v{VERSION}{self.COLORS['ENDC']}
{self.COLORS['OKBLUE']}══════════════════════════════════════════════════════{self.COLORS['ENDC']}
{self.COLORS['BOLD']}{subtitle}{self.COLORS['ENDC']}
{self.COLORS['OKBLUE']}══════════════════════════════════════════════════════{self.COLORS['ENDC']}
"""
        print(banner)

    # ========= Dependencias =========

    def check_dependencies(self):
        self.print_status(self.t("verifying_env"), "HEADER")

        required_tools = [
            ("nmap", ["nmap", "--version"]),
        ]
        recommended_tools = [
            ("whatweb", ["whatweb", "--version"]),
            ("nikto", ["nikto", "-Version"]),
        ]

        missing_required = []
        missing_recommended = []

        # Binarios requeridos
        for name, cmd in required_tools:
            try:
                if subprocess.run(cmd, capture_output=True).returncode != 0:
                    raise FileNotFoundError
                self.print_status(self.t("detected", name), "OKGREEN")
            except (FileNotFoundError, subprocess.SubprocessError):
                missing_required.append(name)

        # Binarios recomendados
        for name, cmd in recommended_tools:
            try:
                if subprocess.run(cmd, capture_output=True).returncode != 0:
                    raise FileNotFoundError
                self.print_status(self.t("detected", name), "OKGREEN")
            except (FileNotFoundError, subprocess.SubprocessError):
                missing_recommended.append(name)

        # python-nmap
        global nmap
        try:
            nmap = importlib.import_module("nmap")
            self.print_status(self.t("nmap_avail"), "OKGREEN")
        except ImportError:
            self.print_status(self.t("nmap_missing"), "FAIL")
            missing_required.append("python-nmap (apt install python3-nmap)")

        # Extra tools
        extra = ["curl", "wget", "openssl", "tcpdump", "tshark", "whois", "dig"]
        for tool in extra:
            path = shutil.which(tool)
            if path:
                self.extra_tools[tool] = path
                self.print_status(self.t("avail_at", tool, path), "OKGREEN")
            else:
                self.extra_tools[tool] = None
                self.print_status(self.t("not_found", tool), "INFO")

        if missing_required:
            self.print_status(self.t("missing_crit", ', '.join(missing_required)), "FAIL")
            return False

        if missing_recommended:
            self.print_status(
                self.t("missing_opt", ', '.join(missing_recommended)),
                "WARNING"
            )

        return True

    # ========= Entrada interactiva =========

    def ask_yes_no(self, question, default="yes"):
        opts = self.t("ask_yes_no_opts") if default.lower() in ("sí", "si", "s", "y", "yes") else self.t("ask_yes_no_opts_neg")
        while True:
            ans = input(f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {question}{opts}: ").strip().lower()
            if ans == "":
                return default.lower() in ("sí", "si", "s", "y", "yes")
            if ans in ("sí", "si", "s", "y", "yes"):
                return True
            if ans in ("no", "n"):
                return False

    def ask_number(self, question, default=10, min_val=1, max_val=1000):
        while True:
            ans = input(f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {question} [{default}]: ").strip()
            if ans == "":
                return default
            if ans.lower() == "todos" or ans.lower() == "all":
                return "todos"
            try:
                num = int(ans)
                if min_val <= num <= max_val:
                    return num
                self.print_status(self.t("val_out_of_range", min_val, max_val), "WARNING")
            except ValueError:
                pass

    def ask_choice(self, question, options, default=0):
        print(f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {question}")
        for i, opt in enumerate(options):
            marker = f"{self.COLORS['GREEN']}▶{self.COLORS['ENDC']}" if i == default else " "
            print(f"  {marker} {i+1}. {opt}")
        while True:
            try:
                ans = input(f"\n{self.t('select_opt')} [1-{len(options)}] ({default+1}): ").strip()
                if ans == "":
                    return default
                n = int(ans) - 1
                if 0 <= n < len(options):
                    return n
            except ValueError:
                pass

    def ask_manual_network(self):
        while True:
            net = input(
                f"\n{self.COLORS['CYAN']}?{self.COLORS['ENDC']} CIDR (ej: 192.168.1.0/24): "
            ).strip()
            try:
                ipaddress.ip_network(net, strict=False)
                return net
            except ValueError:
                self.print_status(self.t("invalid_cidr"), "WARNING")

    def detect_interface_type(self, iface):
        if iface.startswith('e'):
            return "Ethernet"
        if iface.startswith('w'):
            return "Wi-Fi"
        if iface.startswith(('tun', 'tap')):
            return "VPN"
        return "Other"

    def detect_networks_fallback(self):
        nets = []
        try:
            res = subprocess.run(
                ['ip', '-4', '-o', 'addr', 'show'],
                capture_output=True, text=True, timeout=5
            )
            for line in res.stdout.strip().split('\n'):
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 4:
                    continue
                iface = parts[1]
                if iface.startswith(('lo', 'docker')):
                    continue
                try:
                    ipi = ipaddress.ip_interface(parts[3])
                    nets.append({
                        'interface': iface,
                        'ip': str(ipi.ip),
                        'network': str(ipi.network),
                        'hosts_estimated': max(ipi.network.num_addresses - 2, 0),
                        'type': self.detect_interface_type(iface)
                    })
                except ValueError:
                    continue
        except Exception:
            pass
        return nets

    def detect_all_networks(self):
        self.print_status(self.t("analyzing_nets"), "INFO")
        nets = []
        try:
            import netifaces
            for iface in netifaces.interfaces():
                if iface.startswith(('lo', 'docker', 'br-', 'veth')):
                    continue
                try:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        for info in addrs[netifaces.AF_INET]:
                            ip_addr = info.get('addr')
                            mask = info.get('netmask')
                            if ip_addr and mask and ip_addr != '127.0.0.1':
                                net = ipaddress.ip_network(f"{ip_addr}/{mask}", strict=False)
                                nets.append({
                                    'interface': iface,
                                    'ip': ip_addr,
                                    'network': f"{net.network_address}/{net.prefixlen}",
                                    'hosts_estimated': max(net.num_addresses - 2, 0),
                                    'type': self.detect_interface_type(iface)
                                })
                except Exception:
                    continue
        except ImportError:
            self.print_status(self.t("netifaces_missing"), "WARNING")

        if not nets:
            nets = self.detect_networks_fallback()

        unique = {(n['network'], n['interface']): n for n in nets}
        nets_list = list(unique.values())
        self.results["network_info"] = nets_list
        return nets_list

    def ask_network_range(self):
        print(f"\n{self.COLORS['HEADER']}📡 {self.t('selection_target')}{self.COLORS['ENDC']}")
        print("-" * 50)
        nets = self.detect_all_networks()
        if nets:
            print(f"{self.COLORS['OKGREEN']}{self.t('interface_detected')}{self.COLORS['ENDC']}")
            opts = []
            for n in nets:
                info = f" ({n['interface']})" if n['interface'] else ""
                opts.append(f"{n['network']}{info} - ~{n['hosts_estimated']} hosts")
            opts.append(self.t("manual_entry"))
            opts.append(self.t("scan_all"))
            choice = self.ask_choice(self.t("select_net"), opts)
            if choice == len(opts) - 2:
                return [self.ask_manual_network()]
            if choice == len(opts) - 1:
                return [n['network'] for n in nets]
            return [nets[choice]['network']]
        else:
            self.print_status(self.t("no_nets_auto"), "WARNING")
            return [self.ask_manual_network()]

    def ask_host_limit(self):
        resp = self.ask_number(
            self.t("ask_num_limit"),
            default=25
        )
        self.config['max_hosts_value'] = resp if (resp == "todos" or resp == "all") else int(resp)
        return resp

    def interactive_setup(self):
        self.clear_screen()
        self.print_banner()

        if not self.check_dependencies() or not self.show_legal_warning():
            return False

        print(f"\n{self.COLORS['HEADER']}{self.COLORS['BOLD']}{self.t('scan_config')}{self.COLORS['ENDC']}")
        print("=" * 60)

        self.config['target_networks'] = self.ask_network_range()

        scan_modes = [
            self.t("mode_fast"),
            self.t("mode_normal"),
            self.t("mode_full")
        ]
        modes_map = {0: 'rapido', 1: 'normal', 2: 'completo'}
        self.config['scan_mode'] = modes_map[self.ask_choice(self.t("scan_mode"), scan_modes, 1)]

        if self.config['scan_mode'] != 'rapido':
            self.config['max_hosts'] = self.ask_host_limit()
        else:
            self.config['max_hosts_value'] = "todos"

        self.config['threads'] = self.ask_number(self.t("threads"), default=6, max_val=16)

        # NUEVO: rate limiting
        msg_rate = self.t("rate_limiting")
        if self.ask_yes_no(msg_rate, "no"):
            delay = self.ask_number(self.t("rate_delay"), default=1, min_val=0, max_val=60)
            self.rate_limit_delay = float(delay)

        self.config['scan_vulnerabilities'] = self.ask_yes_no(self.t("vuln_scan_q"), "yes")
        
        default_reports = os.path.expanduser("~/RedAuditReports")
        out_dir = self.input_wrapper(f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {self.t('output_dir')} [{default_reports}]: ")
        if not out_dir:
            out_dir = default_reports
        self.config['output_dir'] = out_dir
        
        self.config['save_txt_report'] = self.ask_yes_no(self.t("gen_txt"), "yes")

        # NUEVO: configurar cifrado opcional
        self.setup_encryption()

        # The original 'custom_dir' block is now replaced by the 'output_dir' logic above.
        # If the user wants to specify a custom directory, they can do so in the 'output_dir' prompt.
        # The 'custom_dir' prompt is removed to avoid redundancy.

        self.show_config_summary()
        return self.ask_yes_no(self.t("start_audit"), "yes")

    # ========= Motor de escaneo =========

    def get_nmap_arguments(self, scan_type):
        args = {
            'rapido': '-sn -T4 --max-retries 1 --host-timeout 10s',
            'normal': '-T4 -F -sV --version-intensity 5 --host-timeout 60s',
            'completo': '-T4 -p- -sV -sC -A --version-intensity 9 --host-timeout 300s --max-retries 2'
        }
        base = args.get(scan_type, args['normal'])
        if '--open' not in base:
            base = base + " --open"
        return base

    def is_web_service(self, service_name):
        if not service_name:
            return False
        s = service_name.lower()
        if s in self.WEB_SERVICES_EXACT:
            return True
        return any(k in s for k in self.WEB_SERVICES_KEYWORDS)

    def scan_network_discovery(self, network):
        """Fase 1: Descubrimiento de hosts (-sn)."""
        self.current_phase = f"discovery:{network}"
        self.logger.info(f"Starting discovery on {network}")
        
        nm = nmap.PortScanner()
        args = self.get_nmap_arguments('rapido')
        self.logger.debug(f"Nmap command: nmap {args} {network}")
        
        try:
            nm.scan(hosts=network, arguments=args)
        except Exception as e:
            self.print_status(self.t("scan_error", str(e)), "FAIL")
            self.logger.error(f"Discovery failed on {network}: {e}", exc_info=True)
            return []
            
        hosts = [h for h in nm.all_hosts() if nm[h].state() == "up"]
        self.logger.info(f"Discovery on {network} found {len(hosts)} active hosts")
        self.print_status(self.t("hosts_active", network, len(hosts)), "OKGREEN")
        return hosts

    def get_interface_for_host(self, host_ip):
        try:
            ip_obj = ipaddress.ip_address(host_ip)
        except ValueError:
            return None
        for net in self.results.get("network_info", []):
            try:
                net_obj = ipaddress.ip_network(net['network'], strict=False)
                if ip_obj in net_obj:
                    return net.get('interface')
            except Exception:
                continue
        if self.results.get("network_info"):
            return self.results["network_info"][0].get("interface")
        return None

    def capture_traffic_snippet(self, host_ip, iface="eth0", duration=15):
        """Captura un fragmento de tráfico con tcpdump para análisis."""
        # Hardening: Validate Inputs
        safe_ip = self.sanitize_ip(host_ip)
        if not safe_ip:
            return {"error": "Invalid IP address"}
        
        # Simple interface validation (alphanumeric + dash/underscore)
        if not re.match(r'^[a-zA-Z0-9\-_]+$', iface):
             return {"error": "Invalid interface name"}

        ts = datetime.now().strftime("%H%M%S")
        pcap_file = os.path.join(
            self.config['output_dir'], 
            f"traffic_{safe_ip.replace('.','_')}_{ts}.pcap"
        )
        
        # tcpdump command
        cmd = [
            "tcpdump", "-i", iface, 
            "host", safe_ip, 
            "-c", "50",     # max 50 paquets
            "-G", str(duration), "-W", "1", # Rotación por tiempo (limitado a duration)
            "-w", pcap_file
        ]
        
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=duration+5)
        except subprocess.TimeoutExpired:
                info["tshark_error"] = str(e)
        return info

    def deep_scan_host(self, host_ip):
        """Deep scan automatizado para hosts “raros” (pocos puertos o errores)."""
        self.current_phase = f"deep:{host_ip}"
        self.print_status(self.t("deep_scan_launch", host_ip), "WARNING")
        cmds = [
            ["nmap", "-A", "-sV", "-Pn", "-p-", "--open", host_ip],
            ["nmap", "-O", "-sSU", "-Pn", host_ip],
        ]
        deep = {"commands": []}
        for cmd in cmds:
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                deep["commands"].append({
                    "command": " ".join(cmd),
                    "returncode": res.returncode,
                    "stdout": (res.stdout or "")[:8000],
                    "stderr": (res.stderr or "")[:2000],
                })
            except subprocess.TimeoutExpired as e:
                deep["commands"].append({
                    "command": " ".join(cmd),
                    "error": f"Timeout tras {e.timeout}s"
                })
            except Exception as e:
                deep["commands"].append({
                    "command": " ".join(cmd),
                    "error": str(e)
                })

        pcap_info = self.capture_traffic_snippet(host_ip)
        if pcap_info:
            deep["pcap_capture"] = pcap_info
        return deep

    def enrich_host_with_dns_and_whois(self, host_record):
        """dig -x + whois (solo IPs públicas) si están disponibles."""
        ip_str = host_record["ip"]
        host_record["dns"] = {}
        if self.extra_tools.get("dig"):
            try:
                res = subprocess.run(
                    [self.extra_tools["dig"], "+short", "-x", ip_str],
                    capture_output=True, text=True, timeout=5
                )
                if res.stdout.strip():
                    host_record["dns"]["reverse"] = res.stdout.strip().splitlines()
            except Exception:
                pass
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if not ip_obj.is_private and self.extra_tools.get("whois"):
                res = subprocess.run(
                    [self.extra_tools["whois"], ip_str],
                    capture_output=True, text=True, timeout=15
                )
                text = res.stdout or res.stderr
                if text:
                    lines = [l for l in text.splitlines() if l.strip()][:25]
                    host_record["dns"]["whois_summary"] = "\n".join(lines)
        except Exception:
            pass

    def http_enrichment(self, url, scheme, host_ip, port):
        """curl -I, wget --spider y openssl s_client para servicios web."""
        data = {}
        if self.extra_tools.get("curl"):
            try:
                res = subprocess.run(
                    [self.extra_tools["curl"], "-I", "--max-time", "10", url],
                    capture_output=True, text=True, timeout=15
                )
                if res.stdout:
                    data["curl_headers"] = res.stdout.strip()[:2000]
            except Exception:
                pass
        if self.extra_tools.get("wget"):
            try:
                res = subprocess.run(
                    [self.extra_tools["wget"], "--spider", "-S", "-T", "10", url],
                    capture_output=True, text=True, timeout=20
                )
                hdrs = res.stderr or res.stdout
                if hdrs:
                    data["wget_spider"] = hdrs.strip()[:2000]
            except Exception:
                pass
        if scheme == "https" and self.extra_tools.get("openssl"):
            try:
                res = subprocess.run(
                    [self.extra_tools["openssl"], "s_client",
                     "-connect", f"{host_ip}:{port}", "-servername", host_ip, "-brief"],
                    capture_output=True, text=True, timeout=15
                )
                if res.stdout:
                    data["tls_info"] = res.stdout.strip()[:2000]
            except Exception:
                pass
        return data

    def scan_host_ports(self, host):
                ports = ports[:50]

            host_record = {
                "ip": host,
                "hostname": data.hostname() if data.hostname() else socket.getfqdn(host),
                "ports": ports,
                "web_ports_count": web_count,
                "status": data.state()
            }

            # Deep scan si el host es "callado": pocos puertos
            if len(ports) <= 3:
                deep = self.deep_scan_host(host)
                if deep:
                    host_record["deep_scan"] = deep

            self.enrich_host_with_dns_and_whois(host_record)
            return host_record

        except Exception as e:
            result = {"ip": host, "error": str(e)}
            try:
                deep = self.deep_scan_host(host)
                if deep:
                    result["deep_scan"] = deep
            except Exception:
                pass
            return result

    def scan_vulnerabilities_web(self, host_info):
        self.current_phase = f"vulns:{host_info.get('ip')}"
        web_ports = [p for p in host_info.get("ports", []) if p.get("is_web_service")]
        if not web_ports:
            return None

        vulns = []
        for port in web_ports[:3]:
            svc = port['service'].lower()
            scheme = "https" if port['port'] == 443 or "ssl" in svc else "http"
            url = f"{scheme}://{host_info['ip']}:{port['port']}"
            entry = {"url": url, "port": port['port'], "service": port['service'], "findings": []}

            # WhatWeb
            try:
                res = subprocess.run(
                    ["whatweb", "--color=never", "-a", "1", url],
                    capture_output=True, text=True, timeout=30
                )
                if res.stdout:
                    entry["whatweb"] = res.stdout.strip()[:300]
            except Exception:
                pass

            # Nikto solo en modo completo
            if self.config['scan_mode'] == 'completo':
                try:
                    res = subprocess.run(
                        ["nikto", "-h", url, "-Tuning", "123b", "-t", "30"],
                        capture_output=True, text=True, timeout=120
                    )
                    if res.stdout and "+" in res.stdout:
                        lines = [
                            l.strip() for l in res.stdout.split('\n')
                            if "+" in l and "Server:" not in l
                        ]
                        entry["nikto_findings"] = lines[:5]
                        entry["findings"].extend(lines[:3])
                except Exception:
                    pass

            # curl / wget / openssl
            extra_http = self.http_enrichment(url, scheme, host_info['ip'], port['port'])
            if extra_http:
                entry.update(extra_http)

            if entry.get("whatweb") or entry.get("nikto_findings") or entry.get("curl_headers"):
            vulns.append(entry)

        return {"host": host_info['ip'], "vulnerabilities": vulns} if vulns else None

    def scan_hosts_concurrent(self, hosts):
        """Fase 2: Escaneo de puertos concurrente."""
        self.print_status(self.t("scan_start", len(hosts)), "HEADER")
        
        results = []
                    self.print_status(f"{res['ip']}: {res['error']}", "WARNING")
                if total > 0 and done % max(1, total // 10) == 0:
        max_workers = self.config['threads']
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for h in hosts:
                if self.interrupted:
                    break
                future = executor.submit(self.scan_host_ports, h)
                futures[future] = h
                
                # Rate limiting delay if configured
                if self.rate_limit_delay > 0:
                    time.sleep(self.rate_limit_delay)

            try:
                for future in as_completed(futures):
                    if self.interrupted:
                        break
                    host = futures[future]
                    try:
                        res = future.result()
                        results.append(res)
                    except Exception as e:
                        # Log error but don't crash
                        self.logger.error(f"Error scanning host {host}: {e}", exc_info=True)
            except KeyboardInterrupt:
                self.signal_handler(signal.SIGINT, None)
                
        self.results["hosts"] = results
        return results

    def scan_vulnerabilities_concurrent(self, host_results):
        web_hosts = [h for h in host_results if h.get("web_ports_count", 0) > 0]
        if not web_hosts:
            return
        self.current_phase = "vulns:concurrent"
        self.print_status(self.t("vuln_analysis", len(web_hosts)), "HEADER")
        with ThreadPoolExecutor(max_workers=min(3, self.config['threads'])) as executor:
            futures = {executor.submit(self.scan_vulnerabilities_web, h): h['ip'] for h in web_hosts}
            for f in as_completed(futures):
                if self.interrupted:
                    break
                try:
                    res = f.result()
                except Exception as e:
                    self.print_status(f"[worker error] {e}", "WARNING")
                    continue
                if res:
                    self.results["vulnerabilities"].append(res)
                    self.print_status(
                        self.t("vulns_found", res['host']),
                        "WARNING"
                    )

    def run_complete_scan(self):
        self.scan_start_time = datetime.now()
        self.clear_screen()
        self.print_banner()

        # Arrancar monitor de vida
        self.start_heartbeat()

        # 1) Discovery
        self.current_phase = "discovery"
        all_hosts = []
        for net in self.config['target_networks']:
            if self.interrupted:
                break
            all_hosts.extend(self.scan_network_discovery(net))
        all_hosts = list(sorted(set(all_hosts)))

        if not all_hosts:
            self.print_status(self.t("no_hosts"), "WARNING")
            self.generate_summary(all_hosts, [])
            self.save_results()
            self.stop_heartbeat()
            return False

        if self.config['scan_mode'] == 'rapido':
            self.results['hosts'] = [{"ip": h, "status": "up"} for h in all_hosts]
            self.generate_summary(all_hosts, [])
            self.show_results()
            self.save_results()
            self.stop_heartbeat()
            return True

        # 2) Escaneo detallado
        limit = self.config.get('max_hosts_value', 'todos')
        targets = all_hosts if limit == 'todos' else all_hosts[:int(limit)]
        host_results = self.scan_hosts_concurrent(targets)

        # 3) Vulnerabilidades web
        if self.config.get('scan_vulnerabilities'):
            self.scan_vulnerabilities_concurrent(host_results)

        self.results['hosts'] = host_results
        self.generate_summary(all_hosts, host_results)
        self.show_results()
        self.save_results()
        self.stop_heartbeat()
        return True

    # ========= Reporting =========

    def generate_summary(self, all_hosts, results):
        duration = datetime.now() - self.scan_start_time if self.scan_start_time else None
        total_vulns = sum(
            len(v.get("vulnerabilities", [])) for v in self.results.get("vulnerabilities", [])
        )
        self.results["summary"] = {
            "networks": len(self.config['target_networks']),
            "hosts_found": len(all_hosts),
            "hosts_scanned": len(results),
            "vulns_found": total_vulns,
            "duration": str(duration).split('.')[0] if duration else None
        }

    def show_config_summary(self):
        print(f"\n{self.COLORS['HEADER']}{self.t('exec_params')}{self.COLORS['ENDC']}")
        conf = {
            self.t("targets"): self.config['target_networks'],
            self.t("mode"): self.config['scan_mode'],
            self.t("threads"): self.config['threads'],
            "Vulns": self.config.get('scan_vulnerabilities'),
            self.t("output"): self.config['output_dir']
        }
        for k, v in conf.items():
            print(f"  {k}: {v}")

    def show_results(self):
        s = self.results.get("summary", {})
        print(f"\n{self.COLORS['HEADER']}{self.t('final_summary')}{self.COLORS['ENDC']}")
        print(self.t("nets", s.get('networks')))
        print(self.t("hosts_up", s.get('hosts_found')))
        print(self.t("hosts_full", s.get('hosts_scanned')))
        print(self.t("vulns_web", s.get('vulns_found')))
        print(self.t("duration", s.get('duration')))
        print(f"{self.COLORS['OKGREEN']}{self.t('reports_gen', self.config['output_dir'])}{self.COLORS['ENDC']}")

    def show_legal_warning(self):
        print(f"{self.COLORS['FAIL']}{self.t('legal_warn')}{self.COLORS['ENDC']}")
        return self.ask_yes_no(self.t("legal_ask"), "no")

    def _generate_text_report_string(self, partial):
        """Genera el reporte de texto como string."""
        lines = []
        status_txt = "PARTIAL/INTERRUPTED" if partial else "COMPLETED"
        lines.append(f"NETWORK AUDIT REPORT v{VERSION}\n")
        lines.append(f"Date: {datetime.now()}\n")
        lines.append(f"Status: {status_txt}\n\n")
        
        summ = self.results.get("summary", {})
        lines.append(f"Hosts Found: {summ.get('hosts_found', 0)}\n")
        lines.append(f"Hosts Scanned: {summ.get('hosts_scanned', 0)}\n")
        lines.append(f"Vulns Found: {summ.get('vulns_found', 0)}\n\n")

        if self.results.get("vulnerabilities"):
            lines.append("VULNERABILITIES:\n")
            for v in self.results['vulnerabilities']:
                lines.append(f"\nHost: {v['host']}\n")
                if 'vulnerabilities' in v:
                    for item in v['vulnerabilities']:
                        lines.append(f"  - {item.get('url','')}\n")
                        if item.get("whatweb"):
                            lines.append(f"    WhatWeb: {item['whatweb'][:80]}...\n")
                        if item.get("nikto_findings"):
                            lines.append(f"    Nikto: {len(item['nikto_findings'])} hallazgos.\n")
        lines.append("\n")
        return "".join(lines)

    def save_results(self, partial=False):
        self.current_phase = "saving"
        prefix = "PARTIAL_" if partial else ""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(self.config['output_dir'], f"{prefix}redaudit_{ts}")

        try:
            os.makedirs(self.config['output_dir'], exist_ok=True)

            # JSON
            json_data = json.dumps(self.results, indent=2, default=str)
            if self.encryption_enabled:
                json_data_enc = self.encrypt_data(json_data)
                json_path = f"{base}.json.enc"
                with open(json_path, 'wb') as f:
                    f.write(json_data_enc)
                self.print_status(self.t("json_report", json_path), "OKGREEN")
            else:
                json_path = f"{base}.json"
                with open(json_path, 'w') as f:
                    f.write(json_data)
                self.print_status(self.t("json_report", json_path), "OKGREEN")

            # TXT
            if self.config.get('save_txt_report'):
        f.write(f"NETWORK AUDIT REPORT v{VERSION}\n")
        f.write(f"Date: {datetime.now()}\n")
        f.write(f"Status: {'PARTIAL/INTERRUPTED' if partial else 'COMPLETED'}\n\n")
        summ = self.results.get("summary", {})
        f.write(f"Hosts Found: {summ.get('hosts_found')}\n")
        f.write(f"Hosts Scanned: {summ.get('hosts_scanned')}\n")
        f.write(f"Vulns Found: {summ.get('vulns_found')}\n\n")
        if self.results.get("vulnerabilities"):
            f.write("VULNERABILITIES:\n")
            for v in self.results['vulnerabilities']:
                f.write(f"\nHost: {v['host']}\n")
                for item in v['vulnerabilities']:
                    f.write(f"  - {item['url']}\n")
                    if item.get("whatweb"):
                        f.write(f"    WhatWeb: {item['whatweb'][:80]}...\n")
                    if item.get("nikto_findings"):
                        f.write(f"    Nikto: {len(item['nikto_findings'])} hallazgos.\n")
        f.write("\n")


def main():
    if os.geteuid() != 0:
        print("Error: root privileges (sudo) required.")
        sys.exit(1)
    auditor = InteractiveNetworkAuditor()
    if auditor.interactive_setup():
        ok = auditor.run_complete_scan()
        sys.exit(0 if ok else 1)
    else:
        print(auditor.t("config_cancel"))
        sys.exit(0)


if __name__ == "__main__":
    main()
EOF

# Inject selected language
sed -i "s/__LANG__/$SELECTED_LANG/g" "$TEMP_SCRIPT"

# Move to final location
mv "$TEMP_SCRIPT" /usr/local/bin/redaudit
chown root:root /usr/local/bin/redaudit
chmod 755 /usr/local/bin/redaudit

# 4) Alias persistente en ~/.bashrc o ~/.zshrc (del usuario real)
REAL_USER=${SUDO_USER:-$USER}
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
USER_SHELL=$(getent passwd "$REAL_USER" | cut -d: -f7)
RC_FILE="$REAL_HOME/.bashrc" # Default

if [[ "$USER_SHELL" == *"zsh"* ]]; then
    RC_FILE="$REAL_HOME/.zshrc"
elif [[ "$USER_SHELL" == *"bash"* ]]; then
    RC_FILE="$REAL_HOME/.bashrc"
fi

if ! grep -q "alias redaudit=" "$RC_FILE" 2>/dev/null; then
  echo "alias redaudit='sudo /usr/local/bin/redaudit'" >> "$RC_FILE"
  chown "$REAL_USER" "$RC_FILE"
  echo "$MSG_ALIAS_ADDED $RC_FILE"
else
  echo "$MSG_ALIAS_EXISTS $RC_FILE"
fi

echo
echo "$MSG_DONE"
echo "$MSG_USAGE"
echo "     source $RC_FILE"
echo "   redaudit"