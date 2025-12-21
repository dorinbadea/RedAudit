# RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](README.md)

![Versión](https://img.shields.io/github/v/tag/dorinbadea/RedAudit?sort=semver&style=flat-square)
![Python](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square)
![Licencia](https://img.shields.io/badge/licencia-GPLv3-green?style=flat-square)
![Plataforma](https://img.shields.io/badge/plataforma-linux-lightgrey?style=flat-square)
![CI/CD](https://github.com/dorinbadea/RedAudit/actions/workflows/tests.yml/badge.svg?style=flat-square)

<div align="center">

```
 ____          _    _             _ _ _
|  _ \ ___  __| |  / \  _   _  __| (_) |_
| |_) / _ \/ _` | / _ \| | | |/ _` | | __|
|  _ <  __/ (_| |/ ___ \ |_| | (_| | | |_
|_| \_\___|__,_/_/   \_\__,_|\__,_|_|\__|
```

**AUDITORÍA DE RED INTERACTIVA**

</div>

## ¿Qué es RedAudit?

RedAudit es un framework de auditoría de red que orquesta herramientas de seguridad estándar de la industria (nmap, nikto, testssl, nuclei) en un pipeline concurrente. Automatiza flujos de trabajo desde el descubrimiento hasta el reporte, produciendo artefactos estructurados JSON/HTML/JSONL aptos para ingesta SIEM o informes de cumplimiento.

**Casos de uso**: Hardening defensivo, scoping para pentesting, seguimiento de cambios entre evaluaciones.

**Diferenciador clave**: Escaneo adaptativo multifase con escalación automática—no solo ejecución paralela de herramientas.

---

## Inicio Rápido

```bash
# Instalar
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit && sudo bash redaudit_install.sh

# Ejecutar tu primer escaneo
sudo redaudit --target 192.168.1.0/24 --mode normal --yes
```

Para modo interactivo (wizard guiado), simplemente ejecuta:

```bash
sudo redaudit
```

---

## Capacidades Principales

### Escaneo y Descubrimiento

| Capacidad | Descripción |
|:---|:---|
| **Deep Scan Adaptativo** | Escalación en 3 fases (TCP → UDP Prioritario → UDP Extendido) solo cuando la identidad es débil o el host no responde |
| **HyperScan** | Batch TCP async + broadcast UDP IoT + ARP agresivo para triage ultrarrápido |
| **Descubrimiento de Topología** | Mapeo L2/L3 (ARP/VLAN/LLDP + gateway/rutas) para detección de redes ocultas |
| **Descubrimiento de Red** | Protocolos broadcast (DHCP/NetBIOS/mDNS/UPNP) para detección de redes de invitados |
| **Verificación sin agente** | Probing SMB/RDP/LDAP/SSH/HTTP opcional para fingerprinting sin credenciales |
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
| **Webhooks Interactivos** | Alertas tiempo real via Slack, Teams o PagerDuty (configurables en wizard) |
| **Logging de Sesión** | Captura de salida terminal en doble formato (`.log` raw + `.txt` limpio) |
| **Escaneo con Timeout** | Escaneos de host con timeout duro; progreso con ETA límite |
| **Soporte IPv6 + Proxy** | Escaneo dual-stack completo con pivoting SOCKS5 |
| **Rate Limiting** | Retardo inter-host configurable con jitter ±30% para evasión IDS |
| **Interfaz Bilingüe** | Localización completa Inglés/Español |
| **Auto-Actualización** | Actualizaciones atómicas staged con rollback automático en caso de fallo |

---

## Cómo Funciona

### Vista General de Arquitectura

RedAudit opera como una capa de orquestación, gestionando hilos de ejecución concurrentes para la interacción de red y el procesamiento de datos. Implementa una arquitectura de dos fases: descubrimiento genérico seguido de escaneos profundos dirigidos.

![Vista General del Sistema](docs/images/system_overview_v3.7.3.png)

### Lógica de Escaneo Adaptativo

RedAudit no aplica un perfil de escaneo fijo a todos los hosts. En su lugar, usa heurísticas en tiempo de ejecución para decidir la escalación:

```text
┌─────────────────────────────────────────────────────────────┐
│          FASE 1: Perfil Nmap según el modo de escaneo        │
│        rápido/normal/completo definen el scan base           │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Evaluación Identidad │
              │  • ¿MAC/vendor?       │
              │  • ¿Hostname/DNS?     │
              │  • ¿Versión servicio? │
              │  • ¿CPE/banner?       │
              │  • ¿Hints sin agente? │
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
                    │  FASE 2a: UDP Prioritario            │
                    │  17 puertos comunes (DNS/DHCP/SNMP)  │
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

En modo **full/completo**, el deep scan normalmente se omite porque el perfil base ya es agresivo. Solo se usa como
fallback cuando un host no responde.

**Heurísticas de Disparo** (qué hace un host "ambiguo", sobre todo en rápido/normal):

- Pocos puertos abiertos (≤3)
- Servicios sospechosos (`unknown`, `tcpwrapped`)
- Falta de MAC/vendor/hostname
- Sin versión de servicio (score de identidad bajo)
- Puertos filtrados o sin respuesta (fallback)

**Resultado**: Escaneos más rápidos que UDP siempre activo, manteniendo calidad de detección para IoT, servicios filtrados
y equipos legacy.

### Modelo de Concurrencia

RedAudit usa `ThreadPoolExecutor` de Python para escanear múltiples hosts simultáneamente.

| Parámetro | Defecto | Rango | Notas |
|:---|:---|:---|:---|
| `--threads` | 6 | 1-16 | Hilos comparten memoria, ejecutan nmap independientemente |
| `--rate-limit` | 0 | 0-∞ | Segundos entre hosts (jitter ±30% aplicado) |

**Guía**:

- **Hilos altos (10-16)**: Más rápido, pero más ruido de red. Riesgo de congestión.
- **Hilos bajos (1-4)**: Más lento, más sigiloso, más amable con redes legacy.
- **Rate limit >0**: Recomendado para entornos de producción para evitar triggers IDS.

---

## Instalación

RedAudit requiere un entorno basado en Debian (se recomienda Kali Linux). Se recomiendan privilegios `sudo` para funcionalidad completa (sockets raw, detección SO, tcpdump). Existe modo limitado sin root via `--allow-non-root`.

```bash
# 1. Clonar el repositorio
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit

# 2. Ejecutar el instalador (gestiona dependencias y aliases)
sudo bash redaudit_install.sh
```

### Activar el Alias

Después de instalar, recarga la configuración de tu shell:

| Distribución | Shell por Defecto | Comando |
|:---|:---|:---|
| **Kali Linux** (2020.3+) | Zsh | `source ~/.zshrc` |
| **Debian / Ubuntu / Parrot** | Bash | `source ~/.bashrc` |

**O simplemente abre una nueva ventana de terminal.**

### Verificación Post-Instalación

```bash
which redaudit            # Debería devolver: /usr/local/bin/redaudit
redaudit --version        # Debería mostrar la versión actual
bash redaudit_verify.sh   # Verificación completa de integridad
```

---

## Uso

### Modo Interactivo (Wizard)

Lanza sin argumentos para setup guiado:

```bash
sudo redaudit
```

El wizard te guiará:

1. **Selección de Objetivo**: Elige una subred local o introduce CIDR manual
2. **Modo de Escaneo**: Selecciona RÁPIDO, NORMAL o COMPLETO
3. **Opciones**: Configura hilos, rate limiting, cifrado
4. **Autorización**: Confirma que tienes permiso para escanear

### Modo No Interactivo / Automatización

```bash
# Descubrimiento rápido de hosts
sudo redaudit --target 192.168.1.0/24 --mode fast --yes

# Auditoría de seguridad estándar
sudo redaudit --target 192.168.1.0/24 --mode normal --yes

# Auditoría completa con cifrado
sudo redaudit --target 192.168.1.0/24 --mode full --encrypt --yes

# Escaneo sigiloso con rate limiting
sudo redaudit --target 10.0.0.0/24 --mode normal --rate-limit 2 --threads 4 --yes

# Descubrimiento de red con mapeo de topología
sudo redaudit --target 192.168.1.0/24 --net-discovery --topology --yes

# Análisis diferencial (comparar escaneos)
redaudit --diff ~/reports/lunes.json ~/reports/viernes.json
```

### Opciones CLI Principales

| Opción | Descripción |
|:---|:---|
| `-t, --target` | Red(es) objetivo en notación CIDR |
| `-m, --mode` | Modo de escaneo: `fast` / `normal` / `full` (defecto: normal) |
| `-j, --threads` | Hilos concurrentes (1-16, defecto: 6) |
| `--rate-limit` | Retardo entre hosts en segundos (jitter ±30%) |
| `-e, --encrypt` | Cifrar reportes con AES-128 |
| `-o, --output` | Directorio de salida |
| `--topology` | Activar descubrimiento de topología |
| `--net-discovery` | Descubrimiento L2/broadcast mejorado |
| `--cve-lookup` | Correlación CVE via NVD API |
| `--diff OLD NEW` | Análisis diferencial entre escaneos |
| `--html-report` | Generar dashboard HTML interactivo |
| `--stealth` | Activar timing paranoid para evasión IDS |
| `-y, --yes` | Omitir confirmaciones (modo automatización) |

Consulta `redaudit --help` o [USAGE.md](docs/USAGE.es.md) para la lista completa de más de 40 opciones.

---

## Configuración

### Comportamiento de Escaneo

| Parámetro | Propósito | Recomendación |
|:---|:---|:---|
| `--threads N` | Escaneo paralelo de hosts | 6 para equilibrado, 2-4 para sigilo |
| `--rate-limit N` | Retardo inter-host (segundos) | 1-5s para entornos de producción |
| `--udp-ports N` | Puertos UDP en modo full | 100 (defecto), hasta 500 para exhaustivo |
| `--stealth` | Modo paranoid | Usar cuando evasión IDS es crítica |

### Salida y Cifrado

Los reportes se guardan en `~/Documents/RedAuditReports` (defecto) con timestamps.

**Cifrado** (cuando se usa `-e, --encrypt`):

1. Se genera un salt aleatorio de 16 bytes
2. Tu contraseña deriva una clave de 32 bytes via PBKDF2-HMAC-SHA256 (480k iteraciones)
3. Los archivos se cifran usando Fernet (AES-128-CBC)
4. Un archivo `.salt` se guarda junto a los reportes cifrados

**Descifrado**:

```bash
python3 redaudit_decrypt.py /ruta/a/report.json.enc
```

### Persistencia

Guarda defaults para evitar repetir flags:

```bash
redaudit --target 192.168.1.0/24 --threads 8 --rate-limit 1 --save-defaults --yes
# Las ejecuciones futuras usarán estos ajustes automáticamente
```

Los defaults se almacenan en `~/.redaudit/config.json`.

---

## Referencia de Herramientas

RedAudit orquesta estas herramientas:

| Categoría | Herramientas | Propósito |
|:---|:---|:---|
| **Escáner Core** | `nmap`, `python3-nmap` | Escaneo TCP/UDP, detección de servicios/versión, fingerprinting SO |
| **Reconocimiento Web** | `whatweb`, `curl`, `wget`, `nikto` | Cabeceras HTTP, tecnologías, vulnerabilidades |
| **Escáner Templates** | `nuclei` | Escáner de templates opcional (habilitar en wizard o con `--nuclei`) |
| **Inteligencia Exploits** | `searchsploit` | Búsqueda ExploitDB para servicios detectados |
| **Inteligencia CVE** | NVD API | Correlación CVE para versiones de servicios |
| **Análisis SSL/TLS** | `testssl.sh` | Escaneo profundo de vulnerabilidades SSL/TLS |
| **Captura de Tráfico** | `tcpdump`, `tshark` | Captura de paquetes para análisis de protocolos |
| **DNS/Whois** | `dig`, `whois` | DNS inverso y consulta de propiedad |
| **Topología** | `arp-scan`, `ip route` | Descubrimiento L2, detección VLAN, mapeo gateway |
| **Descubrimiento Red** | `nbtscan`, `netdiscover`, `fping`, `avahi` | Descubrimiento broadcast/L2 |
| **Red Team Recon** | `snmpwalk`, `enum4linux`, `masscan`, `kerbrute` | Enumeración activa opcional (opt-in) |
| **Cifrado** | `python3-cryptography` | Cifrado AES-128 para reportes |

### Estructura del Proyecto

```text
redaudit/
├── core/                   # Funcionalidad principal
│   ├── auditor.py          # Orquestador principal
│   ├── wizard.py           # UI interactiva (WizardMixin)
│   ├── scanner.py          # Lógica de escaneo Nmap + IPv6
│   ├── network.py          # Detección de interfaces/red
│   ├── prescan.py          # Descubrimiento rápido asyncio
│   ├── hyperscan.py        # Descubrimiento paralelo ultrarrápido
│   ├── net_discovery.py    # Descubrimiento L2/broadcast mejorado
│   ├── topology.py         # Descubrimiento de topología de red
│   ├── udp_probe.py        # Helpers de sondeo UDP
│   ├── agentless_verify.py # Verificación sin agente SMB/RDP/LDAP/SSH/HTTP
│   ├── nuclei.py           # Integración escáner templates Nuclei
│   ├── playbook_generator.py # Generador de playbooks remediación
│   ├── nvd.py              # Correlación CVE via NVD API
│   ├── osquery.py          # Helpers de verificación Osquery (opcional)
│   ├── entity_resolver.py  # Consolidación de activos / resolución de entidades
│   ├── evidence_parser.py  # Helpers de parsing de evidencias
│   ├── reporter.py         # Salida JSON/TXT/HTML/JSONL
│   ├── html_reporter.py    # Renderizado de reportes HTML
│   ├── jsonl_exporter.py   # Exportación JSONL para SIEM
│   ├── siem.py             # Integración SIEM (ECS v8.11)
│   ├── diff.py             # Análisis diferencial
│   ├── crypto.py           # Cifrado/descifrado AES-128
│   ├── command_runner.py   # Ejecución segura comandos externos
│   ├── power.py            # Inhibición de reposo
│   ├── proxy.py            # Manejo de proxy
│   ├── scanner_versions.py # Detección de versiones de herramientas
│   ├── verify_vuln.py      # Filtro Smart-Check falsos positivos
│   └── updater.py          # Sistema de auto-actualización
├── templates/              # Templates reportes HTML
└── utils/                  # Utilidades (i18n, config, constantes)
```

---

## Referencia

### Terminología

| Término | Definición |
|:---|:---|
| **Deep Scan** | Escalación selectiva (fingerprinting TCP + UDP) cuando la identidad es débil o el host no responde |
| **HyperScan** | Módulo de descubrimiento async ultrarrápido (batch TCP, UDP IoT, ARP agresivo) |
| **Smart-Check** | Filtro de falsos positivos en 3 capas (Content-Type, tamaño, magic bytes) |
| **Entity Resolution** | Consolidación de dispositivos multi-interfaz en activos unificados |
| **ECS** | Elastic Common Schema v8.11 para compatibilidad SIEM |
| **Finding ID** | Hash SHA256 determinístico para correlación entre escaneos |
| **CPE** | Common Platform Enumeration v2.3 para matching NVD |
| **JSONL** | Formato JSON Lines para ingesta streaming SIEM |
| **Fernet** | Cifrado simétrico (AES-128-CBC + HMAC-SHA256) |
| **PBKDF2** | Derivación de clave basada en contraseña (480k iteraciones) |
| **Thread Pool** | Workers concurrentes para escaneo paralelo de hosts |
| **Rate Limiting** | Retardo inter-host con jitter ±30% para evasión IDS |
| **Heartbeat** | Hilo de fondo que advierte si el escaneo está silencioso >300s |

### Solución de Problemas

Para solución de problemas completa, consulta: 📖 **[Guía Completa de Solución de Problemas](docs/TROUBLESHOOTING.es.md)**

**Enlaces Rápidos**:

- [Problemas de Instalación](docs/TROUBLESHOOTING.es.md#1-permission-denied--root-privileges-required)
- [Problemas de Escaneo](docs/TROUBLESHOOTING.es.md#5-scan-appears-frozen--long-pauses)
- [Problemas de Network Discovery](docs/TROUBLESHOOTING.es.md#12-net-discovery-missing-tools--tool_missing-v32)
- [Cifrado/Descifrado](docs/TROUBLESHOOTING.es.md#8-decryption-failed-invalid-token)

### Logging

Los logs de depuración se almacenan en `~/.redaudit/logs/` (rotación: 5 archivos, 10MB cada uno).

---

## Changelog

Consulta [CHANGELOG_ES.md](CHANGELOG_ES.md) para el historial completo de versiones.

## Contribución

¡Agradecemos las contribuciones! Consulta [CONTRIBUTING_ES.md](.github/CONTRIBUTING_ES.md) para más detalles.

## Licencia

RedAudit se distribuye bajo la **GNU General Public License v3.0 (GPLv3)**. Consulta [LICENSE](LICENSE).

---

## Aviso Legal

**RedAudit** es una herramienta de seguridad únicamente para **auditorías autorizadas**. Escanear redes sin permiso es ilegal. Al usar esta herramienta, aceptas total responsabilidad por tus acciones y acuerdas usarla solo en sistemas de tu propiedad o para los que tengas autorización explícita.

---

[Documentación Completa](docs/INDEX.md) | [Esquema de Reporte](docs/REPORT_SCHEMA.es.md) | [Especificaciones de Seguridad](docs/SECURITY.es.md)
