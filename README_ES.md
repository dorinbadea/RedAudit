# RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](README.md)

RedAudit es una herramienta CLI para auditoría de red estructurada y hardening en sistemas Kali/Debian.

![Versión](https://img.shields.io/github/v/tag/dorinbadea/RedAudit?sort=semver&style=flat-square)
![Python](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square)
![Licencia](https://img.shields.io/badge/licencia-GPLv3-green?style=flat-square)

![CI/CD](https://github.com/dorinbadea/RedAudit/actions/workflows/tests.yml/badge.svg?style=flat-square)

```text
 ____          _    _             _ _ _
|  _ \ ___  __| |  / \  _   _  __| (_) |_
| |_) / _ \/ _` | / _ \| | | |/ _` | | __|
|  _ <  __/ (_| |/ ___ \ |_| | (_| | | |_
|_| \_\___|\__,_/_/   \_\__,_|\__,_|_|\__|
                                      v3.5.1
      Herramienta Interactiva de Auditoría de Red
```

## Visión General

RedAudit automatiza las fases de descubrimiento, enumeración y reporte en evaluaciones de seguridad de red. Está diseñado para su uso en entornos de laboratorio controlados, flujos de trabajo de hardening defensivo y ejercicios de seguridad ofensiva autorizados. Al orquestar herramientas estándar de la industria en un pipeline concurrente coherente, reduce la carga manual y garantiza una generación de resultados consistente.

La herramienta cubre la brecha entre el escaneo ad-hoc y la auditoría formal, proporcionando artefactos estructurados (JSON/TXT/HTML/JSONL + playbooks de remediación) listos para workflows de reporte o análisis SIEM.

## Características

- **Deep Scan Adaptativo de 3 Fases**: Escalado inteligente (TCP agresivo → UDP prioritario → UDP identidad completa) disparado por ambigüedad del host
- **Sondeo UDP Prioritario Async (v3.1.3)**: Sondeo asyncio concurrente rápido de puertos UDP prioritarios durante deep scan para triage de servicios
- **Descubrimiento de Topología Async (v3.1.3)**: Recolección L2/L3 paralelizada (ARP/VLAN/LLDP + gateway/rutas) para mapeo de red más rápido
- **Filtrado Smart-Check de Falsos Positivos**: Verificación de 3 capas (Content-Type, checks de tamaño, validación magic bytes) reduce ruido Nikto en 90%
- **Cross-Validation (v3.1.4)**: Detecta falsos positivos de Nikto comparando hallazgos con cabeceras curl/wget
- **Títulos Descriptivos (v3.1.4)**: Los títulos de hallazgos ahora describen el tipo de problema, no solo la URL
- **Descubrimiento de Red Mejorado (v3.2)**: Descubrimiento broadcast/L2 (DHCP/NetBIOS/mDNS/UPNP/ARP/fping) — auto-habilitado en modo `full` (v3.2.1) y cuando la topología está activada (v3.2.3); el wizard interactivo pregunta y lo habilita por defecto. Recon Red Team opt-in con `--redteam`.
- **Detección de Fugas de Subred (v3.2.1)**: Identifica redes ocultas/invitados analizando fugas HTTP (via redirects y headers) para pivoting.
- **Instalación Atómica con Rollback (v3.2.2)**: Las actualizaciones usan staging atómico con rollback automático en caso de fallo.
- **Descubrimiento de Topología de Red**: Mapeo best-effort L2/L3 (ARP/VLAN/LLDP + gateway/rutas) para detección de redes ocultas
- **Inteligencia CVE**: Integración NVD API 2.0 con matching CPE 2.3, caché de 7 días, y finding IDs determinísticos
- **Exportaciones SIEM**: Auto-generación de archivos planos JSONL (findings, assets, summary) con cumplimiento ECS v8.11
- **Entity Resolution**: Consolidación de dispositivos multi-interfaz vía fingerprinting hostname/NetBIOS/mDNS
- **Defaults Persistentes**: Preferencias de usuario guardadas en `~/.redaudit/config.json` para automatización de workflows
- **Análisis Diferencial**: Motor de comparación de reportes JSON para rastrear cambios de red en el tiempo
- **Soporte IPv6 + Proxy**: Escaneo dual-stack completo con capacidades de pivoting SOCKS5
- **Cifrado de Reportes**: AES-128-CBC (Fernet) con derivación de claves PBKDF2-HMAC-SHA256 (480k iteraciones)
- **Rate Limiting con Jitter**: Retardo inter-host configurable (randomización ±30%) para evasión IDS
- **Menú Principal Interactivo (v3.2)**: Punto de entrada amigable para escaneo, actualizaciones y análisis diff (sin argumentos).
- **Módulo HyperScan (v3.2.3)**: Descubrimiento paralelo ultrarrápido (TCP batch asyncio, 45+ puertos UDP, ARP agresivo, broadcast IoT) con detección de backdoors.
- **Modo Sigiloso (v3.2.3)**: Flag `--stealth` activa timing paranoid T1, escaneo mono-hilo, y retardos 5s+ para evasión IDS empresarial.
- **Playbooks de Remediación (v3.4.0+)**: Playbooks Markdown auto-generados por host/categoría en `<output_dir>/playbooks/` (TLS, cabeceras, CVE, web, puertos) (omitidos cuando `--encrypt` está activado).
- **Evitar Reposo Durante Escaneos (v3.5)**: Inhibición best-effort del reposo del sistema/pantalla mientras se ejecuta un escaneo (opt-out con `--no-prevent-sleep`).
- **CommandRunner Centralizado (v3.5)**: Punto único para comandos externos con timeouts, reintentos, redacción y soporte completo de `--dry-run`.
- **Interfaz Bilingüe**: Localización completa Inglés/Español

## Arquitectura

RedAudit opera como una capa de orquestación, gestionando hilos de ejecución concurrentes para la interacción de red y el procesamiento de datos. Implementa una arquitectura de dos fases: descubrimiento genérico seguido de escaneos profundos dirigidos.

| **Categoría** | **Herramientas** | **Propósito** |
|:---|:---|:---|
| **Escáner Core** | `nmap`, `python3-nmap` | Escaneo de puertos TCP/UDP, detección de servicios/versión, fingerprinting de SO. |
| **Reconocimiento Web** | `whatweb`, `curl`, `wget`, `nikto` | Analiza cabeceras HTTP, tecnologías y vulnerabilidades. |
| **Inteligencia de Exploits** | `searchsploit` | Búsqueda automática en ExploitDB para servicios con versiones detectadas. |
| **Inteligencia CVE** | NVD API | Correlación de CVE para versiones de servicios detectados (v3.0). |
| **Análisis SSL/TLS** | `testssl.sh` | Escaneo profundo de vulnerabilidades SSL/TLS (Heartbleed, POODLE, cifrados débiles). |
| **Captura de Tráfico** | `tcpdump`, `tshark` | Captura de paquetes de red para análisis detallado de protocolos. |
| **DNS/Whois** | `dig`, `whois` | Búsquedas DNS inversas e información de propiedad para IPs públicas. |
| **Análisis Diferencial** | Integrado | Compara reportes JSON para rastrear cambios en la red (v3.0). |
| **Pivoting** | Wrapper `proxychains` | Soporte de proxy SOCKS5 para acceso a redes internas (v3.0). |
| **Topología** | `arp-scan`, `ip route` | Descubrimiento L2, detección de VLANs y mapeo de gateways (v3.1+). |
| **Descubrimiento de Red** | `nbtscan`, `netdiscover`, `fping`, `avahi` | Descubrimiento broadcast/L2 mejorado para redes de invitados (v3.2+). |
| **Red Team Recon** | `snmpwalk`, `enum4linux`, `masscan`, `rpcclient`, `ldapsearch`, `bettercap`, `kerbrute`, `scapy` | Enumeración activa opcional (SNMP, SMB, LDAP, Kerberos, ataques L2) para análisis Blue Team profundo (v3.2+). |
| **HyperScan** | Python `asyncio` | Descubrimiento paralelo ultrarrápido: batch TCP, broadcast UDP IoT, ARP agresivo (v3.2.3). |
| **Orquestador** | `concurrent.futures` (Python) | Gestiona pools de hilos para escaneo paralelo de hosts. |
| **Ejecución de Comandos** | Integrado (`CommandRunner`) | Ejecución centralizada y segura (listas de args, timeouts, reintentos, redacción, despliegue `--dry-run`) (v3.5). |
| **Cifrado** | `python3-cryptography` | Cifrado AES-128 para reportes de auditoría sensibles. |
| **Playbooks de Remediación** | Integrado | Genera playbooks Markdown accionables por host/categoría (v3.4.0+). |

### Vista General del Sistema

![Vista General del Sistema](docs/images/system_overview_es_v3.png)

Los escaneos profundos se activan selectivamente: los módulos de auditoría web solo se lanzan tras la detección de servicios HTTP/HTTPS, y la inspección SSL se reserva para puertos cifrados.

### Estructura del Proyecto

```text
redaudit/
├── core/               # Funcionalidad principal
│   ├── auditor.py      # Clase orquestadora principal
│   ├── prescan.py      # Descubrimiento rápido asyncio
│   ├── scanner.py      # Lógica de escaneo Nmap + soporte IPv6
│   ├── crypto.py       # Cifrado/descifrado AES-128
│   ├── network.py      # Detección de interfaces (IPv4/IPv6)
│   ├── reporter.py     # Salida JSON/TXT/HTML/JSONL + playbooks
│   ├── html_reporter.py  # Generador de reporte HTML interactivo (v3.3)
│   ├── playbook_generator.py  # Generador de playbooks de remediación (v3.4)
│   ├── command_runner.py  # Ejecución centralizada de comandos externos (v3.5)
│   ├── power.py        # Inhibición best-effort de reposo/pantalla (v3.5)
│   ├── updater.py      # Auto-actualización fiable (git clone)
│   ├── verify_vuln.py  # Smart-Check filtrado falsos positivos
│   ├── entity_resolver.py  # Agrupación hosts multi-interfaz
│   ├── siem.py         # Integración SIEM profesional
│   ├── nvd.py          # Correlación CVE vía API NVD
│   ├── diff.py         # Análisis diferencial
│   ├── proxy.py        # Soporte proxy SOCKS5
│   ├── scanner_versions.py  # Detección de versiones (v3.1)
│   ├── evidence_parser.py   # Extracción de observaciones (v3.1)
│   ├── jsonl_exporter.py    # Exportaciones JSONL (v3.1)
│   ├── udp_probe.py     # Sondeo UDP asíncrono (v3.1.3)
│   ├── topology.py      # Descubrimiento de topología async (v3.1+)
│   ├── net_discovery.py # Descubrimiento de red mejorado (v3.2+)
│   └── hyperscan.py     # Descubrimiento paralelo ultrarrápido (v3.2.3)
├── templates/          # Templates de reporte HTML / diff
│   ├── report.html.j2  # Template dashboard HTML (v3.3)
│   └── diff.html.j2    # Template diff HTML (v3.3)
└── utils/              # Utilidades
	    ├── constants.py    # Constantes de configuración
	    ├── i18n.py         # Internacionalización
	    ├── config.py       # Configuración persistente
	    └── webhook.py      # Alertas webhook (v3.3)
```

## Instalación

RedAudit requiere un entorno basado en Debian (se recomienda Kali Linux). Se recomiendan privilegios `sudo` para todas las funciones (sockets raw, detección de SO, tcpdump). Existe un modo limitado sin root con `--allow-non-root`.

```bash
# 1. Clonar el repositorio
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit

# 2. Ejecutar el instalador (gestiona dependencias y aliases)
sudo bash redaudit_install.sh
```

### Activar el Alias

Después de la instalación, necesitas recargar la configuración de tu shell para usar el comando `redaudit`:

| Distribución | Shell por Defecto | Comando |
|:---|:---|:---|
| **Kali Linux** (2020.3+) | Zsh | `source ~/.zshrc` |
| **Debian / Ubuntu / Parrot** | Bash | `source ~/.bashrc` |

**O simplemente abre una nueva ventana de terminal.**

> **¿Por qué dos shells?** Kali Linux cambió de Bash a Zsh en 2020 para ofrecer características mejoradas y más personalización. La mayoría de otras distros basadas en Debian siguen usando Bash por defecto. El instalador detecta automáticamente tu shell y configura el archivo correcto.

### Verificación Post-Instalación

Verifica la integridad de la instalación:

```bash
# 1. Comprobar que el comando está disponible
which redaudit  # Debe devolver: /usr/local/bin/redaudit

# 2. Verificar versión
redaudit --version  # Debe mostrar: RedAudit v3.5.1

# 3. Verificar dependencias core
command -v nmap && command -v tcpdump && command -v python3  # Todos deben existir

# 4. Opcional: Ejecutar script de verificación
bash redaudit_verify.sh  # Verifica checksums, dependencias y configuración
```

**Configuración Opcional (v3.1.1):**

```bash
# Guardar clave API NVD para correlación CVE (setup único)
redaudit  # Lanza el Menú Principal Interactivo (Escanear / Actualizar / Diff)

# Establecer defaults persistentes para evitar repetir flags
redaudit --target 192.168.1.0/24 --threads 8 --rate-limit 1 --save-defaults --yes
# Las ejecuciones futuras usarán estos ajustes automáticamente
```

### Asistente Interactivo

El asistente te guiará:

1. **Selección de Objetivo**: Elige una subred local o introduce un CIDR manual (ej: `10.0.0.0/24`)
2. **Modo de Escaneo**: Selecciona RÁPIDO, NORMAL o COMPLETO
3. **Opciones**: Configura hilos, límite de velocidad y cifrado
4. **Autorización**: Confirma que tienes permiso para escanear

### Modo No Interactivo

Para automatización y scripting:

### Ejemplos de Uso

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

Para más ejemplos incluyendo IPv6, correlación CVE, pivoting SOCKS5 e integración SIEM, consulta:
📖 **[Guía Completa de Uso](docs/es/USAGE.md)**

**Opciones CLI Principales:**

- `-t, --target`: Red(es) objetivo en notación CIDR
- `-m, --mode`: Modo de escaneo (fast/normal/full, por defecto: normal)
- `-j, --threads`: Hilos concurrentes (1-16, por defecto: 6)
- `--rate-limit`: Retardo entre hosts en segundos (incluye jitter ±30%)
- `-e, --encrypt`: Cifrar reportes con AES-128
- `-o, --output`: Directorio de salida (por defecto: ~/Documents/RedAuditReports)
- `--topology`: Activar descubrimiento de topología de red **(v3.1+)**
- `--net-discovery`: Descubrimiento L2/broadcast mejorado **(v3.2+)**
- `--cve-lookup`: Correlación CVE vía API NVD **(v3.0)**
- `--diff OLD NEW`: Análisis diferencial entre escaneos **(v3.0)**
- `--html-report`: Genera dashboard HTML interactivo **(v3.3)**
- `--webhook URL`: Envía alertas en tiempo real a endpoint webhook **(v3.3)**
- `Playbooks`: Playbooks de remediación auto-generados en `<output_dir>/playbooks/` **(v3.4.0+, sin flag; omitido con `--encrypt`)**
- `--ipv6`: Modo solo IPv6 **(v3.0)**
- `-y, --yes`: Omitir confirmaciones (modo automatización)

Consulta `redaudit --help` o [USAGE.md](docs/es/USAGE.md) para la lista completa de más de 40 opciones.

## 7. Configuración y Parámetros Internos

### Concurrencia (Hilos)

RedAudit usa `ThreadPoolExecutor` de Python para escanear múltiples hosts simultáneamente.

- **Parámetro**: `threads` (Defecto: 6).
- **Rango**: 1–16.
- **Comportamiento**: Son *hilos* (threads), no procesos independientes. Comparten memoria pero ejecutan instancias de Nmap por separado.
  - **Alto (10-16)**: Escaneo más rápido, pero mayor carga de CPU y ruido en la red. Riesgo de congestión.
  - **Bajo (1-4)**: Más lento, más sigiloso y amable con redes antiguas o saturadas.

### Rate Limiting (Sigilo)

Controlado por el parámetro `rate_limit_delay`.

- **Mecanismo**: Introduce un `time.sleep(N)` *antes* de iniciar la tarea de escaneo de cada host.
- **Ajustes**:
  - **0s**: Velocidad máxima. Ideal para laboratorios o CTFs.
  - **1-5s**: Equilibrado. Recomendado para auditorías internas para evitar disparar limitadores simples.
  - **>5s**: Paranoico/Conservador. Úsalo en entornos de producción sensibles.

### Deep Scan Adaptativo

RedAudit aplica un escaneo adaptativo inteligente de 3 fases para maximizar la recopilación de información:

1. **Fase 1 - TCP Agresivo**: Escaneo completo de puertos con detección de versión (`-A -p- -sV -Pn`)
2. **Fase 2a - UDP Prioritario**: Escaneo rápido de 17 puertos UDP comunes (DNS, DHCP, SNMP, NetBIOS)
3. **Fase 2b - UDP extendido de identidad**: Solo en modo `full` si no se encontró identidad (`-O -sU --top-ports N`, configurable con `--udp-ports`)

**Características de Deep Scan:**

- **Captura PCAP Concurrente**: El tráfico se captura durante escaneos profundos (no después)
- **Banner Grab Fallback**: Usa `--script banner,ssl-cert` para puertos no identificados
- **Precisión de Estado de Host**: Nuevos tipos (`up`, `filtered`, `no-response`, `down`)
- **Salto Inteligente**: Las Fases 2a/2b se omiten si ya se detectó MAC/SO

- **Activación**: Automática según heurísticas (pocos puertos, servicios sospechosos, etc.)
- **Salida**: Logs completos, datos MAC/Vendor, y (si se captura) metadata PCAP en `host.deep_scan.pcap_capture`

### Auto-Actualización Fiable

RedAudit puede verificar e instalar actualizaciones automáticamente:

- **Verificación al Inicio**: Pregunta si deseas buscar actualizaciones en modo interactivo
- **Instalación Staged**: Las actualizaciones usan staging atómico con rollback automático en caso de fallo (v3.2.2+)
- **Auto-Instalación**: Descarga e instala actualizaciones vía `git clone`
- **Reinicio post-actualización**: Tras instalar una actualización, RedAudit muestra un aviso de reinicio y sale. Inicia un nuevo terminal para cargar la nueva versión.
- **Flag de Omisión**: Usa `--skip-update-check` para desactivar la verificación

> **Nota**: El actualizador verifica hashes de commit de git para integridad pero no realiza verificación de firmas criptográficas. Ver [SECURITY.md](docs/es/SECURITY.md#7-auto-actualización-fiable) para detalles.

**Invocación alternativa:**

```bash
python -m redaudit --help
```

## 8. Reportes, Cifrado y Descifrado

Los reportes se guardan en `~/Documents/RedAuditReports` (por defecto) con fecha y hora (home del usuario invocador, incluso bajo `sudo`).

### Cifrado (`.enc`)

Si activas **"¿Cifrar reportes?"** durante la configuración:

1. Se genera un salt aleatorio de 16 bytes.
2. Tu contraseña deriva una clave de 32 bytes vía **PBKDF2HMAC-SHA256** (480,000 iteraciones).
3. Los archivos se cifran usando **Fernet (AES-128-CBC)**.
    - `report.json` → `report.json.enc`
    - `report.txt` → `report.txt.enc`
    - Se guarda un archivo `.salt` junto a ellos.

### Descifrado

Para leer tus reportes, **debes** tener el archivo `.salt` y recordar tu contraseña.

```bash
python3 redaudit_decrypt.py /ruta/a/report_NOMBRE.json.enc
```

*El script localiza automáticamente el archivo `.salt` correspondiente.*

## 9. Logging y Monitor de Actividad (Heartbeat)

### Logs de Aplicación

Logs de depuración y auditoría se guardan en `~/.redaudit/logs/`.

- **Rotación**: Mantiene los últimos 5 archivos, máx 10MB cada uno.
- **Contenido**: Rastrea PID de usuario, argumentos de comandos y excepciones.

### Monitor de Actividad (Heartbeat)

Un hilo en segundo plano (`threading.Thread`) monitoriza el estado del escaneo cada 30 segundos.

- **<60s silencio**: Normal (sin salida).
- **60-300s silencio**: Registra un **WARNING** indicando que la herramienta puede estar ocupada.
- **>300s silencio**: Registra un **WARNING** con el mensaje "La herramienta activa sigue ejecutándose; esto es normal en hosts lentos o filtrados."
- **Propósito**: Asegurar al operador que la herramienta sigue viva durante operaciones largas (ej: escaneos profundos, nikto, testssl).

## 10. Script de Verificación

Verifica la integridad de tu entorno (checksums, dependencias, alias) en cualquier momento:

```bash
bash redaudit_verify.sh
```

*Útil tras actualizaciones del sistema o `git pull`.*

## 11. Glosario

### Infraestructura y Criptografía

- **Fernet**: Estándar de cifrado simétrico usando AES-128-CBC y HMAC-SHA256, proporcionando cifrado autenticado para confidencialidad de reportes.
- **PBKDF2**: Password-Based Key Derivation Function 2. Transforma contraseñas de usuario en claves criptográficas mediante 480,000 iteraciones para resistir ataques de fuerza bruta.
- **Salt**: Dato aleatorio de 16 bytes añadido al hash de contraseñas para prevenir ataques de rainbow table, guardado en archivos `.salt` junto a reportes cifrados.
- **Thread Pool**: Colección de workers concurrentes gestionados por `ThreadPoolExecutor` para escaneo paralelo de hosts (por defecto: 6 hilos, configurable vía `-j`).
- **Heartbeat**: Hilo de monitorización en segundo plano que verifica el progreso del escaneo cada 30s y advierte si las herramientas están silenciosas por >300s, indicando posibles bloqueos.
- **Rate Limiting**: Retardo inter-host configurable con jitter ±30% para evadir detección por umbral IDS (activado vía `--rate-limit`).
- **ECS**: Compatibilidad Elastic Common Schema v8.11 para integración SIEM con tipado de eventos, puntuación de riesgo (0-100) y hashing observable para deduplicación.
- **Finding ID**: Hash determinístico SHA256 (`asset_id + scanner + port + signature + title`) para correlación entre escaneos y deduplicación.
- **CPE**: Common Platform Enumeration v2.3 formato usado para matching de versiones de software contra base de datos NVD CVE.
- **JSONL**: Formato JSON Lines - un objeto JSON por línea, optimizado para ingesta streaming en pipelines SIEM/IA.

### Operación y Reporting

- **Entity Resolution**: Consolidación de dispositivos multi-interfaz en `unified_assets[]` para tracking de activos más limpio e ingesta SIEM.
- **Deep Scan / Refinamiento de Identidad**: Escalado selectivo (fingerprinting TCP + UDP) para mejorar identificación en hosts ambiguos o filtrados.
- **Playbook de Remediación**: Guía Markdown auto-generada por host/categoría con pasos de remediación y referencias (guardada en `<output_dir>/playbooks/`).
- **Dry Run (`--dry-run`)**: Muestra los comandos externos que se ejecutarían sin ejecutarlos (soporte completo; no se ejecuta ningún comando externo).
- **CommandRunner**: Módulo central que ejecuta comandos externos con timeouts, reintentos y redacción de secretos (base de `--dry-run`).
- **Inhibición de Reposo**: Prevención best-effort del reposo del sistema/pantalla durante escaneos (activado por defecto; opt-out con `--no-prevent-sleep`).

**Nota**: Para explicaciones detalladas de estrategias de escaneo (Deep Scan, Smart-Check, Topology Discovery, etc.), ver la sección Características arriba.

## 12. Solución de Problemas

Para una guía completa de resolución de problemas cubriendo todos los escenarios, consulta la guía completa:
📖 **[Guía Completa de Solución de Problemas](docs/es/TROUBLESHOOTING.md)**

**Enlaces Rápidos**:

- [Problemas de Instalación](docs/es/TROUBLESHOOTING.md#1-permission-denied--root-privileges-required)
- [Problemas de Escaneo](docs/es/TROUBLESHOOTING.md#5-scan-appears-frozen--long-pauses)
- [Problemas de Network Discovery](docs/es/TROUBLESHOOTING.md#12-net-discovery-missing-tools--tool_missing-v32)
- [Cifrado/Descifrado](docs/es/TROUBLESHOOTING.md#8-decryption-failed-invalid-token)
- [Optimización de Rendimiento](docs/es/TROUBLESHOOTING.md#15-scans-too-slow-on-large-networks)

## 13. Historial de Cambios

Consulta [CHANGELOG_ES.md](CHANGELOG_ES.md) para el historial completo de versiones y notas de lanzamiento detalladas.

## 14. Contribución

¡Agradecemos las contribuciones! Consulta [CONTRIBUTING_ES.md](.github/CONTRIBUTING_ES.md) para más detalles.

## 15. Licencia

RedAudit se distribuye bajo la **GNU General Public License v3.0 (GPLv3)**.
Consulta el archivo [LICENSE](LICENSE) para ver el texto completo y las condiciones.

## 16. Internos & Glosario (Por qué RedAudit se comporta así)

### Pool de hilos (`threads`)

RedAudit utiliza un *pool* de hilos para escanear varios hosts en paralelo.
El parámetro `threads` controla cuántos hosts se analizan simultáneamente:

- Valor bajo (2–4): más lento, pero más sigiloso y con menos ruido.
- Valor medio (por defecto, 6): buen equilibrio para la mayoría de entornos.
- Valor alto (10–16): más rápido, pero puede generar más ruido y más timeouts.

### Limitación de tasa (*rate limiting*)

Para no saturar la red, RedAudit puede introducir un pequeño retardo entre host y host.
Esto sacrifica velocidad a cambio de estabilidad y menor huella en entornos sensibles.

### Heartbeat y watchdog

En escaneos largos, RedAudit muestra mensajes de *heartbeat* cuando lleva un tiempo sin imprimir nada.
Sirve para distinguir un escaneo "silencioso pero sano" de un bloqueo real.

### Reportes cifrados

Los reportes pueden cifrarse con contraseña.
La clave se deriva con PBKDF2-HMAC-SHA256 (480k iteraciones) y se acompaña de un archivo `.salt` para poder descifrarlos posteriormente con `redaudit_decrypt.py`.

## 17. Aviso Legal

**RedAudit** es una herramienta de seguridad únicamente para **auditorías autorizadas**.
Escanear redes sin permiso es ilegal. Al usar esta herramienta, aceptas total responsabilidad por tus acciones y acuerdas usarla solo en sistemas de tu propiedad o para los que tengas autorización explícita.

---
[Documentación Completa](docs/README.md) | [Esquema de Reporte](docs/es/REPORT_SCHEMA.md) | [Especificaciones de Seguridad](docs/es/SECURITY.md)
