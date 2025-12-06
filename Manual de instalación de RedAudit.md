Manual de instalación de RedAudit v2.3

Rol: pentester / programador senior

1. Requisitos previos

Sistema objetivo:
	•	Kali Linux (o distro similar basada en Debian)
	•	Usuario con sudo configurado
	•	Conexión a Internet para instalar paquetes

Paquetes que usaremos (se pueden instalar al vuelo desde el propio instalador, pero los dejo explícitos):

sudo apt update
sudo apt install -y \
  python3 python3-pip python3-nmap \
  curl wget openssl nmap tcpdump tshark whois bind9-dnsutils \
  whatweb nikto

Nota: whatweb, nikto y nmap son los que RedAudit necesita realmente. El resto son utilidades que el script deja listas para módulos futuros (tcpdump/tshark/WHOIS/DNS/etc).

⸻

2. Preparar carpeta de trabajo

Usamos una carpeta estándar para herramientas:

mkdir -p ~/herramientas_seguridad
cd ~/herramientas_seguridad


⸻

3. Crear el instalador de RedAudit

En esa carpeta creamos el instalador (un script bash que genera / actualiza /usr/local/bin/redaudit):

nano redaudit_install.sh

Pega todo el script del final de este mensaje (desde #!/bin/bash hasta el último echo). Guarda y cierra.

Después:

chmod +x redaudit_install.sh


⸻

4. Ejecutar instalación / actualización

Lanzas el instalador como root (vía sudo):

sudo ./redaudit_install.sh

El instalador:
	1.	Ofrece instalar el pack de utilidades de red:
	•	curl wget openssl nmap tcpdump tshark whois bind9-dnsutils
	2.	Crea o reemplaza /usr/local/bin/redaudit con la versión Python 2.3.
	3.	Ajusta permisos:
	•	755 (root propietario, ejecutable por todos).
	4.	Añade (si no existe) el alias en tu ~/.bashrc:
	•	alias redaudit='sudo /usr/local/bin/redaudit'

⸻

5. Activar el alias en tu shell

Tras la instalación:

source ~/.bashrc

A partir de aquí, en cualquier terminal de tu usuario normal:

redaudit


⸻

6. Verificación rápida

Comandos útiles para comprobar que todo está en su sitio:

# Dónde está el binario
which redaudit
# → debe apuntar a /usr/local/bin/redaudit (vía alias)

# Ver permisos del binario
ls -l /usr/local/bin/redaudit

# Confirmar alias
grep "alias redaudit" ~/.bashrc


⸻

7. Actualizar RedAudit a una nueva versión

Cuando quieras actualizar el código (por ejemplo, pasar de 2.3 a 2.4):
	1.	Editas el instalador:

cd ~/herramientas_seguridad
nano redaudit_install.sh
# → pegas la nueva versión del instalador
chmod +x redaudit_install.sh


	2.	Lo ejecutas de nuevo:

sudo ./redaudit_install.sh
source ~/.bashrc



El binario /usr/local/bin/redaudit se sobrescribe con la nueva versión.

⸻

8. Desinstalación (por si hace falta)

Eliminar binario y alias:

sudo rm -f /usr/local/bin/redaudit
sed -i '/alias redaudit=/d' ~/.bashrc
source ~/.bashrc


⸻

SCRIPT COMPLETO PARA COPIAR Y PEGAR

Guárdalo como redaudit_install.sh

#!/bin/bash
# RedAudit installer / updater v2.3 (Full Toolchain + Heartbeat)

echo "🔧 Instalando / actualizando RedAudit v2.3..."

# 1) Opcional: pack de utilidades de red recomendadas
EXTRA_PKGS="curl wget openssl nmap tcpdump tshark whois bind9-dnsutils python3-nmap"

echo
echo "📦 Opcional: instalar pack de utilidades de red recomendadas:"
echo "   $EXTRA_PKGS"
read -r -p "¿Quieres instalarlas ahora? [S/n]: " RESP
RESP=${RESP,,}
if [[ -z "$RESP" || "$RESP" == "s" || "$RESP" == "si" || "$RESP" == "sí" || "$RESP" == "y" ]]; then
    echo "➡ Ejecutando: apt update && apt install -y $EXTRA_PKGS"
    sudo apt update && sudo apt install -y $EXTRA_PKGS
else
    echo "↩ Saltando instalación de utilidades extra."
fi

# 2) Crear /usr/local/bin/redaudit con el código Python v2.3
sudo tee /usr/local/bin/redaudit > /dev/null << 'EOF'
#!/usr/bin/env python3
"""RedAudit - Auditoría de red interactiva
Versión 2.3 (Full Toolchain + Heartbeat)
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

VERSION = "2.3"
nmap = None


class InteractiveNetworkAuditor:
    # Heurística de servicios web
    WEB_SERVICES_KEYWORDS = ["http", "https", "ssl", "www", "web", "admin", "proxy", "alt", "connect"]
    WEB_SERVICES_EXACT = [
        "http", "https", "www", "http-proxy", "ssl/http",
        "ssl/https", "http-alt", "http-admin", "http-connect"
    ]

    def __init__(self):
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
            'output_dir': '.',
            'scan_vulnerabilities': True,
            'save_txt_report': True
        }

        self.COLORS = {
            "HEADER": "\033[95m", "OKBLUE": "\033[94m", "OKGREEN": "\033[92m",
            "WARNING": "\033[93m", "FAIL": "\033[91m", "ENDC": "\033[0m",
            "BOLD": "\033[1m", "CYAN": "\033[96m", "MAGENTA": "\033[95m",
            "GREEN": "\033[92m"
        }

        self.interrupted = False
        self.scan_start_time = None
        self.extra_tools = {}  # curl, wget, openssl, tcpdump, tshark, whois, dig

        # Monitor de vida
        self.last_activity = datetime.now()
        self.current_phase = "init"
        self.heartbeat_stop = False
        self.heartbeat_thread = None

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    # ========= Señales =========

    def signal_handler(self, sig, frame):
        if not self.interrupted:
            self.interrupted = True
            self.print_status("\n⚠️  Interrupción recibida. Guardando estado actual...", "FAIL")
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
                if delta < 60:
                    msg = f"⏱ Heartbeat: fase={self.current_phase} · última actividad hace {int(delta)}s"
                    self.print_status(msg, "INFO", update_activity=False)
                elif delta < 300:
                    msg = (
                        f"⏱ Heartbeat: fase={self.current_phase} · "
                        f"sin actividad aparente desde hace {int(delta)}s (nmap puede seguir trabajando)"
                    )
                    self.print_status(msg, "WARNING", update_activity=False)
                else:
                    msg = (
                        f"⏱ Heartbeat: fase={self.current_phase} · posible bloqueo "
                        f"(> {int(delta)}s sin actividad real). Considera revisar o interrumpir con Ctrl+C."
                    )
                    self.print_status(msg, "FAIL", update_activity=False)
            except Exception:
                # No queremos que un fallo en el heartbeat tumbe el escaneo
                pass
            time.sleep(30)

    # ========= Utilidades básicas =========

    def print_status(self, message, status="INFO", update_activity=True):
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
        # Banner ASCII "RedAudit" estilizado
        banner = f"""
{self.COLORS['FAIL']}
    ____          _    {self.COLORS['BOLD']}{self.COLORS['HEADER']}_   _           _ _ _{self.COLORS['ENDC']}{self.COLORS['FAIL']}
   / __ \___  ___| |  {self.COLORS['BOLD']}{self.COLORS['HEADER']}/ \  _   _  __| (_) |_{self.COLORS['ENDC']}{self.COLORS['FAIL']}
  / /_/ / _ \/ __| | {self.COLORS['BOLD']}{self.COLORS['HEADER']}/ _ \| | | |/ _` | | __|{self.COLORS['ENDC']}{self.COLORS['FAIL']}
 / _, _/  __/ (__| |{self.COLORS['BOLD']}{self.COLORS['HEADER']}/ ___ \ |_| | (_| | | |_{self.COLORS['ENDC']}{self.COLORS['FAIL']}
/_/ |_|\___|\___|_|{self.COLORS['BOLD']}{self.COLORS['HEADER']}/_/   \_\__,_|\__,_|_|\__|{self.COLORS['ENDC']}
                                      {self.COLORS['CYAN']}v{VERSION}{self.COLORS['ENDC']}
{self.COLORS['OKBLUE']}══════════════════════════════════════════════════════{self.COLORS['ENDC']}
{self.COLORS['BOLD']}   AUDITORÍA DE RED INTERACTIVA  ::  KALI LINUX{self.COLORS['ENDC']}
{self.COLORS['OKBLUE']}══════════════════════════════════════════════════════{self.COLORS['ENDC']}
"""
        print(banner)

    # ========= Dependencias =========

    def check_dependencies(self):
        self.print_status("Verificando integridad del entorno...", "HEADER")

        required_tools = [
            ("nmap", ["nmap", "--version"]),
            ("whatweb", ["whatweb", "--version"]),
        ]
        recommended_tools = [
            ("nikto", ["nikto", "-Version"]),
        ]

        missing_required = []
        missing_recommended = []

        # Binarios requeridos
        for name, cmd in required_tools:
            try:
                if subprocess.run(cmd, capture_output=True).returncode != 0:
                    raise FileNotFoundError
                self.print_status(f"✓ {name} detectado", "OKGREEN")
            except (FileNotFoundError, subprocess.SubprocessError):
                missing_required.append(name)

        # Binarios recomendados
        for name, cmd in recommended_tools:
            try:
                if subprocess.run(cmd, capture_output=True).returncode != 0:
                    raise FileNotFoundError
                self.print_status(f"✓ {name} detectado", "OKGREEN")
            except (FileNotFoundError, subprocess.SubprocessError):
                missing_recommended.append(name)

        # python-nmap
        global nmap
        try:
            nmap = importlib.import_module("nmap")
            self.print_status("✓ python-nmap disponible", "OKGREEN")
        except ImportError:
            self.print_status("Librería python-nmap no encontrada. Intentando instalar vía apt...", "WARNING")
            try:
                subprocess.check_call(
                    ["apt", "install", "-y", "python3-nmap"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                nmap = importlib.import_module("nmap")
                self.print_status("✓ python-nmap instalado correctamente", "OKGREEN")
            except Exception:
                missing_required.append("python-nmap (apt install python3-nmap)")

        # Extra tools: se usan si están, no son críticas
        extra = ["curl", "wget", "openssl", "tcpdump", "tshark", "whois", "dig"]
        for tool in extra:
            path = shutil.which(tool)
            if path:
                self.extra_tools[tool] = path
                self.print_status(f"✓ {tool} disponible en {path}", "OKGREEN")
            else:
                self.extra_tools[tool] = None
                self.print_status(f"{tool} no encontrado (se omitirá su uso automático)", "INFO")

        if missing_required:
            self.print_status(f"Error: faltan dependencias críticas: {', '.join(missing_required)}", "FAIL")
            return False

        if missing_recommended:
            self.print_status(
                f"Aviso: faltan herramientas opcionales: {', '.join(missing_recommended)} (escaneo web reducido)",
                "WARNING"
            )

        return True

    # ========= Entrada interactiva =========

    def ask_yes_no(self, question, default="sí"):
        opts = " (S/n)" if default.lower() in ("sí", "si", "s", "y", "yes") else " (s/N)"
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
            if ans.lower() == "todos":
                return "todos"
            try:
                num = int(ans)
                if min_val <= num <= max_val:
                    return num
                self.print_status(f"Valor fuera de rango ({min_val}-{max_val})", "WARNING")
            except ValueError:
                pass

    def ask_choice(self, question, options, default=0):
        print(f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {question}")
        for i, opt in enumerate(options):
            marker = f"{self.COLORS['GREEN']}▶{self.COLORS['ENDC']}" if i == default else " "
            print(f"  {marker} {i+1}. {opt}")
        while True:
            try:
                ans = input(f"\nSelecciona una opción [1-{len(options)}] ({default+1}): ").strip()
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
                self.print_status("CIDR inválido", "WARNING")

    def detect_interface_type(self, iface):
        if iface.startswith('e'):
            return "Ethernet"
        if iface.startswith('w'):
            return "Wi-Fi"
        if iface.startswith(('tun', 'tap')):
            return "VPN"
        return "Otro"

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
        self.print_status("Analizando interfaces y redes locales...", "INFO")
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
            self.print_status("netifaces no disponible, usando método alternativo", "WARNING")

        if not nets:
            nets = self.detect_networks_fallback()

        unique = {(n['network'], n['interface']): n for n in nets}
        nets_list = list(unique.values())
        self.results["network_info"] = nets_list
        return nets_list

    def ask_network_range(self):
        print(f"\n{self.COLORS['HEADER']}📡 SELECCIÓN DE OBJETIVO{self.COLORS['ENDC']}")
        print("-" * 50)
        nets = self.detect_all_networks()
        if nets:
            print(f"{self.COLORS['OKGREEN']}✓{self.COLORS['ENDC']} Interfaces detectadas:")
            opts = []
            for n in nets:
                info = f" ({n['interface']})" if n['interface'] else ""
                opts.append(f"{n['network']}{info} - ~{n['hosts_estimated']} hosts")
            opts.append("Introducir manual")
            opts.append("Escanear TODAS")
            choice = self.ask_choice("Selecciona red:", opts)
            if choice == len(opts) - 2:
                return [self.ask_manual_network()]
            if choice == len(opts) - 1:
                return [n['network'] for n in nets]
            return [nets[choice]['network']]
        else:
            self.print_status("No se detectaron redes automáticamente", "WARNING")
            return [self.ask_manual_network()]

    def ask_host_limit(self):
        resp = self.ask_number(
            "Límite de hosts a escanear en profundidad (o 'todos'):",
            default=25
        )
        self.config['max_hosts_value'] = resp if resp == "todos" else int(resp)
        return resp

    def interactive_setup(self):
        self.clear_screen()
        self.print_banner()

        if not self.check_dependencies() or not self.show_legal_warning():
            return False

        print(f"\n{self.COLORS['HEADER']}{self.COLORS['BOLD']}CONFIGURACIÓN DE ESCANEO{self.COLORS['ENDC']}")
        print("=" * 60)

        self.config['target_networks'] = self.ask_network_range()

        scan_modes = [
            "RÁPIDO (solo discovery)",
            "NORMAL (Discovery + Top Ports)",
            "COMPLETO (Full Ports + Scripts + Vulns)"
        ]
        modes_map = {0: 'rapido', 1: 'normal', 2: 'completo'}
        self.config['scan_mode'] = modes_map[self.ask_choice("Modo de escaneo:", scan_modes, 1)]

        if self.config['scan_mode'] != 'rapido':
            self.config['max_hosts'] = self.ask_host_limit()
        else:
            self.config['max_hosts_value'] = "todos"

        self.config['threads'] = self.ask_number("Hilos concurrentes:", default=6, max_val=16)

        if self.config['scan_mode'] != 'rapido':
            self.config['scan_vulnerabilities'] = self.ask_yes_no(
                "¿Ejecutar análisis de vulnerabilidades web?", "sí"
            )

        self.config['save_txt_report'] = self.ask_yes_no("¿Generar reporte TXT adicional?", "sí")

        if self.ask_yes_no("¿Usar directorio de salida personalizado?", "no"):
            while True:
                d = input(f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} Directorio: ").strip()
                if not d:
                    d = '.'
                try:
                    os.makedirs(d, exist_ok=True)
                    self.config['output_dir'] = d
                    break
                except Exception as e:
                    self.print_status(f"Error creando directorio: {e}", "FAIL")

        self.show_config_summary()
        return self.ask_yes_no("¿Iniciar auditoría?", "sí")

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
        self.current_phase = f"discovery:{network}"
        self.print_status(f"Discovery en {network}...", "INFO")
        try:
            scanner = nmap.PortScanner()
            scanner.scan(hosts=network, arguments=self.get_nmap_arguments('rapido'))
            hosts = [h for h in scanner.all_hosts() if scanner[h].state() == "up"]
            self.print_status(f"Hosts activos en {network}: {len(hosts)}", "OKGREEN")
            return hosts
        except Exception as e:
            self.print_status(f"Fallo en discovery {network}: {e}", "FAIL")
            return []

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

    def capture_traffic_snippet(self, host_ip):
        """Captura corta de tráfico con tcpdump + resumen con tshark (si existen)."""
        if not self.extra_tools.get("tcpdump"):
            return None
        iface = self.get_interface_for_host(host_ip)
        if not iface:
            return None
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_name = f"redaudit_{host_ip.replace('.', '_')}_{ts}.pcap"
        pcap_path = os.path.join(self.config['output_dir'], pcap_name)
        cmd = [self.extra_tools["tcpdump"], "-i", iface, "host", host_ip, "-c", "50", "-w", pcap_path]
        info = {"interface": iface, "pcap_file": pcap_name}
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            info["tcpdump_returncode"] = res.returncode
        except subprocess.TimeoutExpired:
            info["tcpdump_timeout"] = True
            return info
        except Exception as e:
            info["tcpdump_error"] = str(e)
            return info

        if self.extra_tools.get("tshark"):
            try:
                res = subprocess.run(
                    [self.extra_tools["tshark"], "-r", pcap_path, "-c", "10",
                     "-T", "fields", "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst",
                     "-e", "tcp.port", "-e", "udp.port"],
                    capture_output=True, text=True, timeout=15
                )
                if res.stdout:
                    info["tshark_summary"] = res.stdout.strip()[:2000]
            except Exception as e:
                info["tshark_error"] = str(e)
        return info

    def deep_scan_host(self, host_ip):
        """Deep scan automatizado para hosts “raros” (pocos puertos o errores)."""
        self.current_phase = f"deep:{host_ip}"
        self.print_status(f"Lanzando deep scan sobre {host_ip}...", "WARNING")
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
        """Escaneo de puertos por host + deep scan automático si es “sospechoso”."""
        self.current_phase = f"ports:{host}"
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=host, arguments=self.get_nmap_arguments(self.config['scan_mode']))
            if host not in nm.all_hosts():
                result = {"ip": host, "error": "Sin respuesta"}
                deep = self.deep_scan_host(host)
                if deep:
                    result["deep_scan"] = deep
                return result

            data = nm[host]
            ports = []
            web_count = 0

            for proto in data.all_protocols():
                for p, info in data[proto].items():
                    if info['state'] == 'open':
                        svc = info.get('name', 'unknown')
                        is_web = self.is_web_service(svc)
                        if is_web:
                            web_count += 1
                        ports.append({
                            "port": p,
                            "protocol": proto,
                            "service": svc,
                            "version": info.get('version', ''),
                            "is_web_service": is_web
                        })

            if len(ports) > 50:
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
        if not hosts:
            return []
        self.current_phase = "ports:concurrent"
        self.print_status(f"Escaneando {len(hosts)} hosts con {self.config['threads']} hilos...", "HEADER")
        results = []
        with ThreadPoolExecutor(max_workers=self.config['threads']) as executor:
            futures = {executor.submit(self.scan_host_ports, h): h for h in hosts}
            done = 0
            total = len(hosts)
            for f in as_completed(futures):
                if self.interrupted:
                    break
                done += 1
                res = f.result()
                if "ports" in res:
                    results.append(res)
                    self.print_status(
                        f"✓ {res['ip']}: {len(res.get('ports', []))} puertos (web: {res.get('web_ports_count', 0)})",
                        "OKGREEN"
                    )
                elif "error" in res:
                    self.print_status(f"{res['ip']}: {res['error']}", "WARNING")
                if total > 0 and done % max(1, total // 10) == 0:
                    self.print_status(f"Progreso: {done}/{total} hosts", "INFO")
        return results

    def scan_vulnerabilities_concurrent(self, host_results):
        web_hosts = [h for h in host_results if h.get("web_ports_count", 0) > 0]
        if not web_hosts:
            return
        self.current_phase = "vulns:concurrent"
        self.print_status(f"Analizando vulnerabilidades en {len(web_hosts)} hosts web...", "HEADER")
        with ThreadPoolExecutor(max_workers=min(3, self.config['threads'])) as executor:
            futures = {executor.submit(self.scan_vulnerabilities_web, h): h['ip'] for h in web_hosts}
            for f in as_completed(futures):
                if self.interrupted:
                    break
                res = f.result()
                if res:
                    self.results["vulnerabilities"].append(res)
                    self.print_status(
                        f"⚠️  Vulnerabilidades registradas en {res['host']}",
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
            self.print_status("No se encontraron hosts.", "WARNING")
            self.generate_summary(all_hosts, [])
            self.save_results()
            self.stop_heartbeat()
            return False

        if self.config['scan_mode'] == 'rapido':
            self.results['hosts'] = [{"ip": h, "status": "up"} for h in all_hosts]
            self.generate_summary(all_hosts, [])
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
        print(f"\n{self.COLORS['HEADER']}PARÁMETROS DE EJECUCIÓN{self.COLORS['ENDC']}")
        conf = {
            "Objetivos": self.config['target_networks'],
            "Modo": self.config['scan_mode'],
            "Hilos": self.config['threads'],
            "Vulns": self.config.get('scan_vulnerabilities'),
            "Salida": self.config['output_dir']
        }
        for k, v in conf.items():
            print(f"  {k}: {v}")

    def show_results(self):
        s = self.results.get("summary", {})
        print(f"\n{self.COLORS['HEADER']}RESUMEN FINAL{self.COLORS['ENDC']}")
        print(f"  Redes:       {s.get('networks')}")
        print(f"  Hosts vivos: {s.get('hosts_found')}")
        print(f"  Hosts full:  {s.get('hosts_scanned')}")
        print(f"  Vulns web:   {s.get('vulns_found')}")
        print(f"  Duración:    {s.get('duration')}")
        print(f"\n{self.COLORS['OKGREEN']}✓ Reportes generados en {self.config['output_dir']}{self.COLORS['ENDC']}")

    def show_legal_warning(self):
        print(f"\n{self.COLORS['FAIL']}ADVERTENCIA LEGAL: Solo para uso en redes autorizadas.{self.COLORS['ENDC']}")
        return self.ask_yes_no("¿Confirmas que tienes autorización para escanear estas redes?", "no")

    def save_results(self, partial=False):
        self.current_phase = "saving"
        prefix = "PARTIAL_" if partial else ""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(self.config['output_dir'], f"{prefix}redaudit_{ts}")
        try:
            with open(f"{base}.json", 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            self.print_status(f"Reporte JSON: {base}.json", "OKGREEN")
            if self.config.get('save_txt_report'):
                with open(f"{base}.txt", 'w') as f:
                    self._generate_text_report(f, partial)
                self.print_status(f"Reporte TXT: {base}.txt", "OKGREEN")
        except Exception as e:
            self.print_status(f"Error guardando reporte: {e}", "FAIL")

    def _generate_text_report(self, f, partial):
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
        print("Error: se requieren privilegios de root (sudo).")
        sys.exit(1)
    auditor = InteractiveNetworkAuditor()
    if auditor.interactive_setup():
        ok = auditor.run_complete_scan()
        sys.exit(0 if ok else 1)
    else:
        print("Configuración cancelada.")
        sys.exit(0)


if __name__ == "__main__":
    main()
EOF

# 3) Permisos del binario
sudo chmod 755 /usr/local/bin/redaudit

# 4) Alias persistente en ~/.bashrc (del usuario real)
REAL_USER=${SUDO_USER:-$USER}
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

if ! grep -q "alias redaudit=" "$REAL_HOME/.bashrc" 2>/dev/null; then
  echo "alias redaudit='sudo /usr/local/bin/redaudit'" >> "$REAL_HOME/.bashrc"
  chown "$REAL_USER" "$REAL_HOME/.bashrc"
  echo "ℹ️ Alias 'redaudit' añadido a $REAL_HOME/.bashrc"
else
  echo "ℹ️ Alias 'redaudit' ya existe en $REAL_HOME/.bashrc (no se duplica)."
fi

echo
echo "✅ Instalación / actualización completada."
echo "👉 En tu usuario normal, ejecuta:"
echo "     source ~/.bashrc"
echo "   y luego:"
echo "     redaudit"