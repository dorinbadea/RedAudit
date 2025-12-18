# Manual de Usuario de RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](MANUAL.en.md)

**Audiencia:** Analistas de Seguridad, Arquitectos
**Alcance:** Arquitectura, capacidades, lógica de flujo, referencia de herramientas.
**Fuente de verdad:** `redaudit/core/orchestrator.py`

---

## 1. Introducción

RedAudit es un framework de auditoría de red automatizado diseñado para **hardening defensivo** y **evaluaciones ofensivas autorizadas**. A diferencia de los escáneres de puertos simples, orquesta un pipeline concurrente de herramientas estándar de la industria (`nmap`, `nikto`, `nuclei`, `testssl.sh`) para proporcionar inteligencia procesable.

Está diseñado para ser **seguro por defecto**, **determinista** y **guiado por el operador**—automatizando la fase repetitiva de descubrimiento para que los analistas puedan centrarse en la explotación o remediación.

---

## 2. Capacidades Principales

RedAudit agrega capacidades en cuatro dominios operativos:

### Escaneo y Descubrimiento

| Capacidad | Descripción |
|:---|:---|
| **Deep Scan Adaptativo** | Escalación de 3 fases (TCP → UDP Prioritario → UDP Completo) basada en ambigüedad del host |
| **HyperScan** | Batch TCP async + broadcast UDP IoT + ARP agresivo para triage ultrarrápido |
| **Descubrimiento de Topología** | Mapeo L2/L3 (ARP/VLAN/LLDP + gateway/rutas) para detección de redes ocultas |
| **Descubrimiento de Red** | Protocolos broadcast (DHCP/NetBIOS/mDNS/UPNP) para detección de redes de invitados |
| **Modo Sigiloso** | Timing paranoid T1, mono-hilo, retardos 5s+ para evasión IDS empresarial |

### Inteligencia y Correlación

| Capacidad | Descripción |
|:---|:---|
| **Correlación CVE** | NVD API 2.0 con matching CPE 2.3 y caché de 7 días |
| **Búsqueda de Exploits** | Consultas automáticas a ExploitDB (`searchsploit`) para servicios detectados |
| **Escaneo de Templates** | Templates community de Nuclei para detección de vulnerabilidades HTTP/HTTPS |
| **Filtro Smart-Check** | Reducción de falsos positivos en 3 capas (Content-Type, tamaño, magic bytes) |
| **Detección de Fugas de Subred** | Identifica redes ocultas via análisis de redirects/headers HTTP |

### Reportes e Integración

| Capacidad | Descripción |
|:---|:---|
| **Salida Multi-Formato** | JSON, TXT, dashboard HTML, JSONL (compatible ECS v8.11) |
| **Playbooks de Remediación** | Guías Markdown auto-generadas por host/categoría |
| **Análisis Diferencial** | Compara reportes JSON para rastrear cambios en la red |
| **Exportaciones SIEM-Ready** | JSONL con scoring de riesgo y hash de observables para deduplicación |
| **Cifrado de Reportes** | AES-128-CBC (Fernet) con derivación PBKDF2-HMAC-SHA256 |

### Operaciones

| Capacidad | Descripción |
|:---|:---|
| **Defaults Persistentes** | Preferencias de usuario guardadas en `~/.redaudit/config.json` |
| **Soporte IPv6 + Proxy** | Escaneo dual-stack completo con pivoting SOCKS5 |
| **Rate Limiting** | Retardo inter-host configurable con jitter ±30% para evasión IDS |
| **Interfaz Bilingüe** | Localización completa Inglés/Español |
| **Auto-Actualización** | Actualizaciones atómicas staged con rollback automático en caso de fallo |

---

## 3. Instalación y Configuración

### Requisitos

- **SO**: Kali Linux, Debian 11+, Ubuntu 20.04+, Parrot OS
- **Privilegios**: `sudo` / root recomendado (para sockets raw, detección SO, PCAP)
- **Python**: 3.9+

### Instalación Rápida

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit && sudo bash redaudit_install.sh
source ~/.zshrc  # o ~/.bashrc
```

El instalador gestiona todas las dependencias, configura el entorno python y crea el alias `redaudit`.

---

## 4. Arquitectura y Flujo

### Flujo Lógico

RedAudit opera como una capa de orquestación. No ejecuta ciegamente todas las herramientas en todos los hosts. En su lugar, utiliza un motor de **Lógica Adaptativa**:

```
┌─────────────────────────────────────────────────────────────┐
│                    FASE 1: TCP Agresivo                     │
│              Todos los hosts: -A -p- -sV -Pn                │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Evaluación Identidad │
              │  • ¿MAC extraída?     │
              │  • ¿Fingerprint SO?   │
              │  • ¿Versiones servs?  │
              └───────────┬───────────┘
                          │
            ┌─────────────┴─────────────┐
            │                           │
            ▼                           ▼
    ┌───────────────┐          ┌────────────────┐
    │ SUFICIENTE    │          │ HOST AMBIGUO   │
    │ Detener scan  │          │ Continuar...   │
    └───────────────┘          └───────┬────────┘
                                       │
                                       ▼
                    ┌──────────────────────────────────────┐
                    │     FASE 2a: UDP Prioritario         │
                    │  17 puertos comunes (DNS, DHCP, SNMP)│
                    └──────────────────┬───────────────────┘
                                       │
                          ┌────────────┴────────────┐
                          │                         │
                          ▼                         ▼
                  ┌───────────────┐        ┌────────────────┐
                  │ Identidad OK  │        │ Aún ambiguo    │
                  │ Detener       │        │ (modo full)    │
                  └───────────────┘        └───────┬────────┘
                                                   │
                                                   ▼
                              ┌─────────────────────────────────┐
                              │     FASE 2b: UDP Extendido      │
                              │  --top-ports N (configurable)   │
                              └─────────────────────────────────┘
```

**Heurísticas de Disparo** (Escalación Automática):
RedAudit escala a escaneo profundo si:

1. Se encuentran menos de 3 puertos abiertos.
2. Los servicios se identifican como `unknown` o `tcpwrapped`.
3. Faltan datos MAC/Vendor.
4. El host parece vivo pero no responde a las sondas estándar.

### Modos de Escaneo

| Modo | Flag CLI | Comportamiento | Caso de Uso |
|:---|:---|:---|:---|
| **Rápido** | `--mode fast` | Solo Descubrimiento de Host (`-sn`). | Inventario rápido, verificación de accesibilidad. |
| **Normal** | `--mode normal` | Puertos Top, Versiones, Scripts de Servicio. | Auditoría de seguridad estándar. |
| **Completo** | `--mode full` | Todos los Puertos, Recon Web, SSL, Nuclei, UDP. | Análisis integral pre-pentest. |

---

## 5. Guía de Uso

### Modo Interactivo (Wizard)

Simplemente ejecuta `sudo redaudit` para entrar en la interfaz de texto.

1. **Objetivo**: Selección de IP/CIDR.
2. **Modo**: Selección del perfil de escaneo.
3. **Opciones**: Cifrado, hilos, etc.
4. **Ejecución**: Lanzar el escaneo.

### No-Interactivo (Automatización)

Para scripts y CI/CD, usa las flags CLI con `--yes`.

#### Ejemplos

```bash
# Inventario rápido de LAN
sudo redaudit --target 192.168.1.0/24 --mode fast --yes

# Auditoría Estándar con Cifrado
sudo redaudit --target 10.0.0.0/24 --mode normal --encrypt --yes

# Escaneo Sigiloso (Bajo ruido)
sudo redaudit --target 192.168.1.50 --threads 2 --rate-limit 5 --yes

# Análisis Diferencial (Comparar dos reportes)
redaudit --diff reporte_lunes.json reporte_viernes.json
```

### Flags CLI Clave

| Flag | Propósito |
|:---|:---|
| `-t, --target` | Rango(s) CIDR a escanear. |
| `-m, --mode` | `fast`, `normal`, `full`. |
| `-j, --threads` | Workers paralelos (1-16, Defecto: 6). |
| `--rate-limit` | Segundos de retardo entre hosts (jitter ±30%). |
| `--encrypt` | Cifrar salidas con AES-128. |
| `--net-discovery` | Activar descubrimiento activo L2/Broadcast. |
| `--topology` | Activar mapeo de topología L2/L3. |
| `--html-report` | Generar dashboard interactivo. |
| `--webhook URL` | Enviar hallazgos en tiempo real a Slack/Teams. |
| `--save-defaults` | Persistir ajustes actuales en config. |

---

## 6. Reportes y Herramientas

### Estructura de Directorios

Los reportes se guardan en `~/Documents/RedAuditReports/` por defecto.

```text
RedAudit_2025-01-15_21-30-45/
├── redaudit_20250115.json      # Datos completos legibles por máquina
├── redaudit_20250115.txt       # Resumen ejecutivo en texto
├── report.html                 # Dashboard HTML Interactivo
├── findings.jsonl              # Eventos para ingesta SIEM (v8.11 ECS)
├── assets.jsonl                # Inventario de activos SIEM
└── playbooks/                  # Guías de remediación Markdown
```

### Referencia de Herramientas

RedAudit orquesta estas herramientas subyacentes:

| Categoría | Herramientas | Sección del Reporte |
|:---|:---|:---|
| **Escáner Core** | `nmap`, `python3-nmap` | `hosts[].ports` |
| **Recon Web** | `whatweb`, `curl`, `wget`, `nikto` | `vulnerabilities` |
| **Escáner Templates**| `nuclei` | `vulnerabilities` |
| **SSL/TLS** | `testssl.sh`, `openssl` | `vulnerabilities.tls` |
| **Exploits** | `searchsploit` | `ports[].known_exploits` |
| **CVEs** | NVD API | `ports[].cve` |
| **Red** | `arp-scan`, `tshark`, `tcpdump` | `network_discovery` |

### Integración SIEM

Cuando el cifrado está desactivado, `findings.jsonl` proporciona un flujo plano de eventos compatible con Elastic Common Schema (ECS) v8.11, ideal para ingesta en ELK, Splunk o Graylog.

---

## 7. Seguridad y Solución de Problemas

### Modelo de Seguridad

- **Privilegios**: Usa `sudo` solo para operaciones necesarias (sockets nmap).
- **Cifrado**: Usa AES-128-CBC (Fernet) + PBKDF2-HMAC-SHA256 (clave de 32 bytes).
- **Validación de Entrada**: Chequeo estricto de tipos en todos los argumentos CLI; sin `shell=True`.

### Solución de Problemas

Consulta [TROUBLESHOOTING.md](TROUBLESHOOTING.es.md) para códigos de error detallados.

**Problemas Comunes:**

- **Permiso Denegado**: Ejecutar con `sudo`.
- **Herramientas Faltantes**: Re-ejecutar `bash redaudit_install.sh`.
- **Fallo de Descifrado**: Asegurar que existe el archivo `.salt` junto al archivo `.enc`.

---

[Volver al README](../README_ES.md)
