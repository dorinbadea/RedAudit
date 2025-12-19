# Guía de Uso de RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](USAGE.en.md)

**Audiencia:** Pentesters, Operadores de Seguridad, Blue Teamers
**Alcance:** Opciones CLI, ejemplos de uso, configuración, opciones de ejecución
**Qué NO cubre este documento:** Teoría de redes, desarrollo de exploits
**Fuente de verdad:** `redaudit --help`

---

## 1. Inicio Rápido

Ejecuta estos comandos para comenzar de inmediato.

**Asistente Interactivo (Recomendado para primera vez)**

Nuevo en v3.7: Configura Webhooks, SIEM y Descubrimiento Avanzado interactivamente.

```bash
sudo redaudit
```

**Inventario Rápido (LAN)**

```bash
sudo redaudit -t 192.168.1.0/24 -m fast --yes
```

**Auditoría Estándar (Host Único)**

```bash
sudo redaudit -t 10.10.10.5 -m normal --html-report
```

---

## 2. Ejemplos por Escenario

### Lab / CTF (Agresivo)

Enfoque en velocidad y máxima recolección de información.

```bash
sudo redaudit -t 192.168.56.101 \
  --mode full \
  --udp-mode full \
  --threads 16 \
  --no-prevent-sleep
```

**Artefactos:** JSON, HTML, PCAP (si deep scan se activa), Playbooks.

### Pentest Autorizado (Sigiloso/Corporativo)

Enfoque en bajo ruido, artefactos fiables y cifrado para cadena de custodia.

```bash
sudo redaudit -t 10.20.0.0/24 \
  --stealth \
  --encrypt \
  --encrypt-password "ProyectoCliente2025!" \
  --html-report
```

**Notas:** `stealth` fuerza timing T1 y retardo de 5s. El cifrado deshabilita HTML/JSONL.

### Blue Team / NetOps (Descubrimiento)

Enfoque en identificar dispositivos no autorizados y fugas de red.

```bash
sudo redaudit -t 172.16.0.0/16 \
  --mode fast \
  --net-discovery arp,mdns,upnp \
  --topology \
  --allow-non-root
```

**Notas:** `allow-non-root` salta fingerprinting de SO y captura PCAP.

### Red Team (Reconocimiento Interno)

Enfoque en Active Directory, enumeración Kerberos y SNMP desde punto de pivote.

```bash
sudo redaudit -t 10.0.0.0/8 \
  --proxy socks5://127.0.0.1:1080 \
  --redteam \
  --redteam-active-l2 \
  --kerberos-realm CORP.LOCAL
```

**Riesgos:** `redteam-active-l2` usa sondeo activo (bettercap/scapy) que puede disparar IDS.

### Pipeline CI/CD (Verificación de Cambios)

Análisis diferencial entre dos escaneos previos.

```bash
redaudit --diff reports/report_v1.json reports/report_v2.json
```

**Salida:** Análisis delta mostrando puertos Nuevos/Abiertos/Cerrados/Cambiados. No se realiza escaneo.

---

## 3. Referencia de Flags CLI

Agrupadas por función operativa. Verificadas contra el estado actual del código.

### Alcance e Intensidad

| Flag | Descripción |
|:---|:---|
| `-t, --target CIDR` | IP, rango o CIDR (soporta lista separada por comas) |
| `-m, --mode` | `fast` (ping), `normal` (top 1000), `full` (65k + scripts) |
| `-j, --threads N` | Hosts paralelos 1-16 (Defecto: 6) |
| `--rate-limit S` | Retardo entre hosts en segundos (aplica jitter) |
| `--stealth` | Fuerza timing T1, 1 hilo, 5s retardo |
| `--dry-run` | Muestra comandos sin ejecutarlos |

### Conectividad y Proxy

| Flag | Descripción |
|:---|:---|
| `--proxy URL` | Proxy SOCKS5 (socks5://host:port) |
| `--ipv6` | Activa modo escaneo solo IPv6 |
| `--no-prevent-sleep`| No inhibir suspensión del sistema |

### Descubrimiento Avanzado

| Flag | Descripción |
|:---|:---|
| `--net-discovery` | Protocolos broadcast (dhcp,netbios,mdns,upnp,arp,fping) |
| `--topology` | Mapeo de topología L2/L3 (rutas/gateways) |
| `--udp-mode` | `quick` (puertos prioritarios) o `full` (top ports) |
| `--redteam` | Añade técnicas de recon AD/Kerberos/SNMP |
| `--redteam-active-l2` | Habilita sondeo activo L2 más ruidoso |

### Reportes e Integración

| Flag | Descripción |
|:---|:---|
| `-o, --output DIR` | Directorio de salida personalizado |
| `--html-report` | Generar dashboard interactivo (HTML) |
| `--webhook URL` | Enviar hallazgos a Slack/Teams/Discord |
| `--nuclei` | Habilitar escaneo de templates con Nuclei (requiere `nuclei`; solo en modo full) |
| `--no-nuclei` | Deshabilitar Nuclei (sobrescribe defaults persistentes) |
| `--no-vuln-scan` | Omitir escaneo de vulnerabilidades Web/Nikto |
| `--cve-lookup` | Correlar servicios con datos CVE NVD |

### Seguridad y Privacidad

| Flag | Descripción |
|:---|:---|
| `-e, --encrypt` | Cifrar todos los artefactos sensibles (AES-128) |
| `--allow-non-root` | Ejecutar sin sudo (capacidad limitada) |
| `--searchsploit` | (Habilitado por defecto en normal/full) |

### Configuración

| Flag | Descripción |
|:---|:---|
| `--save-defaults` | Guardar argumentos CLI actuales en `~/.redaudit/config.json` |
| `--use-defaults` | Cargar argumentos desde config.json automáticamente |
| `--ignore-defaults` | Forzar valores de fábrica |
| `--no-color` | Deshabilitar salida a color |
| `--skip-update-check` | Saltar chequeo de actualizaciones al inicio |

---

## 4. Salida y Rutas

**Ruta por Defecto:**
`~/Documents/RedAuditReports/RedAudit_<TIMESTAMP>/`

Para cambiar la ruta por defecto permanentemente:

```bash
sudo redaudit --output /opt/redaudit/reports --save-defaults --yes
```

**Manifiesto de Artefactos:**

- **.json**: Modelo de datos completo (siempre creado).
- **.txt**: Resumen legible por humanos.
- **.html**: Dashboard (requiere `--html-report`, deshabilitado por `--encrypt`).
- **.jsonl**: Eventos streaming para SIEM (deshabilitado por `--encrypt`).
- **.pcap**: Capturas de paquetes (solo si Deep Scan + tcpdump + Root).
- **session.log**: Salida de terminal raw con códigos de color (en `session_logs/`).
- **session.txt**: Salida de terminal en texto plano limpio (en `session_logs/`).

---

## 5. Errores Comunes

**`Permission denied` (socket error)**
RedAudit necesita root para:

- Procesamiento de salida SYN Scan (`-sS`)
- Fingerprinting de SO (`-O`)
- Generación de PCAP
**Solución:** Ejecutar con `sudo` o usar `--allow-non-root`.

**`nmap: command not found`**
Dependencias faltantes en el PATH.
**Solución:** Ejecutar `sudo bash redaudit_install.sh` o revisar `/usr/local/lib/redaudit`.

**`Decryption failed`**
Falta el archivo `.salt` o contraseña incorrecta.
**Solución:** Asegurar que el archivo `.salt` está en el mismo directorio que el `.enc`.

---

[Volver al README](../README_ES.md) | [Índice de Documentación](INDEX.md)
