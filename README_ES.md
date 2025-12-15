# RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](README.md)

RedAudit es una herramienta CLI para auditoría de red estructurada y hardening en sistemas Kali/Debian.

![Versión](https://img.shields.io/badge/versión-3.2.1-blue?style=flat-square)
![Python](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square)
![Licencia](https://img.shields.io/badge/licencia-GPLv3-green?style=flat-square)

![CI/CD](https://github.com/dorinbadea/RedAudit/actions/workflows/tests.yml/badge.svg?style=flat-square)

```text
 ____          _    _             _ _ _   
|  _ \ ___  __| |  / \  _   _  __| (_) |_ 
| |_) / _ \/ _` | / _ \| | | |/ _` | | __|
|  _ <  __/ (_| |/ ___ \ |_| | (_| | | |_ 
|_| \_\___|\__,_/_/   \_\__,_|\__,_|_|\__|
                                      v3.2.1
      Herramienta Interactiva de Auditoría de Red
```

## Visión General

RedAudit automatiza las fases de descubrimiento, enumeración y reporte en evaluaciones de seguridad de red. Está diseñado para su uso en entornos de laboratorio controlados, flujos de trabajo de hardening defensivo y ejercicios de seguridad ofensiva autorizados. Al orquestar herramientas estándar de la industria en un pipeline concurrente coherente, reduce la carga manual y garantiza una generación de resultados consistente.

La herramienta cubre la brecha entre el escaneo ad-hoc y la auditoría formal, proporcionando artefactos estructurados (JSON/TXT) listos para su ingesta en frameworks de reporte o análisis SIEM.

## Características

- **Deep Scan Adaptativo de 3 Fases**: Escalado inteligente (TCP agresivo → UDP prioritario → UDP identidad completa) disparado por ambigüedad del host
- **Sondeo UDP Prioritario Async (v3.1.3)**: Sondeo asyncio concurrente rápido de puertos UDP prioritarios durante deep scan para triage de servicios
- **Descubrimiento de Topología Async (v3.1.3)**: Recolección L2/L3 paralelizada (ARP/VLAN/LLDP + gateway/rutas) para mapeo de red más rápido
- **Filtrado Smart-Check de Falsos Positivos**: Verificación de 3 capas (Content-Type, checks de tamaño, validación magic bytes) reduce ruido Nikto en 90%
- **Cross-Validation (v3.1.4)**: Detecta falsos positivos de Nikto comparando hallazgos con cabeceras curl/wget
- **Títulos Descriptivos (v3.1.4)**: Los títulos de hallazgos ahora describen el tipo de problema, no solo la URL
- **Descubrimiento de Red Mejorado (v3.2)**: Descubrimiento broadcast/L2 opcional (DHCP/NetBIOS/mDNS/UPNP/ARP/fping) + bloque de recon Red Team con guardas en reportes
- **Descubrimiento de Topología de Red**: Mapeo best-effort L2/L3 (ARP/VLAN/LLDP + gateway/rutas) para detección de redes ocultas
- **Inteligencia CVE**: Integración NVD API 2.0 con matching CPE 2.3, caché de 7 días, y finding IDs determinísticos
- **Exportaciones SIEM**: Auto-generación de archivos planos JSONL (findings, assets, summary) con cumplimiento ECS v8.11
- **Entity Resolution**: Consolidación de dispositivos multi-interfaz vía fingerprinting hostname/NetBIOS/mDNS
- **Defaults Persistentes**: Preferencias de usuario guardadas en `~/.redaudit/config.json` para automatización de workflows
- **Análisis Diferencial**: Motor de comparación de reportes JSON para rastrear cambios de red en el tiempo
- **Soporte IPv6 + Proxy**: Escaneo dual-stack completo con capacidades de pivoting SOCKS5
- **Cifrado de Reportes**: AES-128-CBC (Fernet) con derivación de claves PBKDF2-HMAC-SHA256 (480k iteraciones)
- **Rate Limiting con Jitter**: Retardo inter-host configurable (randomización ±30%) para evasión IDS
- **Menú Principal Interactivo (v3.2)**: Asistente amigable para escaneo, configuración y análisis diff (sin argumentos)
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
| **Net Discovery** | `nbtscan`, `netdiscover`, `fping`, `avahi` | Descubrimiento mejorado broadcast/L2 para redes de invitados (v3.2+). |
| **Orquestador** | `concurrent.futures` (Python) | Gestiona pools de hilos para escaneo paralelo de hosts. |
| **Cifrado** | `python3-cryptography` | Cifrado AES-128 para reportes de auditoría sensibles. |

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
│   ├── reporter.py     # Salida JSON/TXT + SIEM
│   ├── updater.py      # Auto-actualización segura (git clone)
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
│   └── net_discovery.py # Descubrimiento de red mejorado (v3.2+)
└── utils/              # Utilidades
    ├── constants.py    # Constantes de configuración
    ├── i18n.py         # Internacionalización
    └── config.py       # Configuración persistente
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
redaudit --version  # Debe mostrar: RedAudit v3.2.1

# 3. Verificar dependencias core
command -v nmap && command -v tcpdump && command -v python3  # Todos deben existir

# 4. Opcional: Ejecutar script de verificación
bash redaudit_verify.sh  # Verifica checksums, dependencias y configuración
```

**Configuración Opcional (v3.1.1):**

```bash
# Guardar clave API NVD para correlación CVE (setup único)
redaudit  # Lanza el Menú Principal Interactivo (Escáner, Diff, Config)

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

#### Escaneo Básico

```bash
# 1. Descubrimiento rápido de hosts (modo fast)
sudo redaudit --target 192.168.1.0/24 --mode fast --yes

# 2. Auditoría de seguridad estándar
sudo redaudit --target 192.168.1.0/24 --mode normal --yes

# 3. Auditoría exhaustiva con todas las comprobaciones
sudo redaudit --target 192.168.1.0/24 --mode full --yes

# 4. Múltiples redes simultáneamente
sudo redaudit --target "192.168.1.0/24,10.0.0.0/24,172.16.0.0/16" --mode normal --threads 8
```

#### Sigilo y Rendimiento

```bash
# 5. Escaneo sigiloso con rate limiting y jitter
sudo redaudit --target 10.0.0.0/24 --mode normal --rate-limit 2 --threads 4 --yes

# 6. Escaneo rápido con optimización pre-scan
sudo redaudit --target 192.168.0.0/16 --prescan --prescan-ports 1-1024 --threads 12 --yes

# 7. Cobertura UDP personalizada para escaneo de identidad
sudo redaudit --target 192.168.1.0/24 --mode full --udp-mode full --udp-ports 200 --yes
```

#### Cifrado y Seguridad

```bash
# 8. Reportes cifrados (contraseña auto-generada)
sudo redaudit --target 192.168.1.0/24 --mode normal --encrypt --yes

# 9. Reportes cifrados (contraseña personalizada)
sudo redaudit --target 192.168.1.0/24 --mode full --encrypt --encrypt-password "Contr4s3ña!2024" --yes
```

#### Características Avanzadas v3.0

```bash
# 10. Escaneo de redes IPv6
sudo redaudit --target "2001:db8::/64" --ipv6 --mode normal --yes

# 11. Correlación CVE con inteligencia NVD
sudo redaudit --target 192.168.1.0/24 --mode normal --cve-lookup --nvd-key TU_API_KEY --yes

# 12. Escaneo a través de proxy SOCKS5 (pivoting)
sudo redaudit --target 10.internal.0.0/24 --proxy socks5://pivot-host:1080 --mode normal --yes

# 13. Análisis diferencial (comparar dos escaneos)
redaudit --diff ~/reports/baseline_lunes.json ~/reports/actual_viernes.json
```

#### Integración SIEM v3.1

```bash
# 14. Generar exportaciones JSONL para SIEM (sin cifrado)
sudo redaudit --target 192.168.1.0/24 --mode full --yes
# Salida: findings.jsonl, assets.jsonl, summary.json junto al reporte JSON
```

#### Topología y Persistencia v3.1.1

```bash
# 15. Solo descubrimiento de topología (mapeo de red)
sudo redaudit --target 192.168.1.0/24 --topology-only --yes

# 16. Escaneo completo con contexto de topología
sudo redaudit --target 192.168.1.0/24 --mode normal --topology --yes

# 17. Guardar ajustes preferidos como defaults
sudo redaudit --target 192.168.1.0/24 --mode normal --threads 8 \
  --rate-limit 1 --topology --udp-mode full --save-defaults --yes
# Las ejecuciones futuras reutilizarán estos ajustes automáticamente
```

#### Descubrimiento de Red Mejorado v3.2

```bash
# 18. Descubrimiento basado en broadcast (DHCP/NetBIOS/mDNS/UPNP/ARP/fping)
sudo redaudit --target 192.168.1.0/24 --net-discovery --yes

# 19. Seleccionar solo algunos protocolos
sudo redaudit --target 192.168.1.0/24 --net-discovery dhcp,netbios --yes

# 20. Incluir bloque opcional de recon Red Team (best-effort)
sudo redaudit --target 192.168.1.0/24 --net-discovery --redteam --yes

# 21. Tuning opcional (interfaz + límites)
sudo redaudit --target 192.168.1.0/24 --net-discovery --redteam \
  --net-discovery-interface eth0 --redteam-max-targets 50 --snmp-community public --yes
```

#### Workflows del Mundo Real

```bash
# 22. Workflow de auditoría semanal
# Paso 1: Escaneo baseline
sudo redaudit --target 192.168.0.0/16 --mode normal --yes
# Paso 2: Comparación semanal
sudo redaudit --target 192.168.0.0/16 --mode normal --yes
redaudit --diff ~/Documents/RedAuditReports/RedAudit_BASELINE/redaudit_*.json \
              ~/Documents/RedAuditReports/RedAudit_LATEST/redaudit_*.json

# 23. Auditoría de red empresarial multi-VLAN
sudo redaudit --target "10.10.0.0/16,10.20.0.0/16,10.30.0.0/16" \
  --mode normal --topology --threads 10 --rate-limit 0.5 --yes

# 24. Verificación post-escaneo y exportación
sudo redaudit --target 192.168.1.0/24 --mode full --cve-lookup --yes
# Verificar que se generaron exportaciones JSONL
ls -lh ~/Documents/RedAuditReports/RedAudit_*/findings.jsonl
# Ingestar en tu SIEM
cat ~/Documents/RedAuditReports/RedAudit_*/findings.jsonl | tu-herramienta-ingestion-siem
```

**Opciones CLI Disponibles:**

- `--target, -t`: Red(es) objetivo en notación CIDR (requerido para modo no interactivo)
- `--mode, -m`: Modo de escaneo (fast/normal/full, por defecto: normal)
- `--threads, -j`: Hilos concurrentes (1-16, por defecto: 6)
- `--rate-limit`: Retardo entre hosts en segundos (por defecto: 0)
- `--encrypt, -e`: Cifrar reportes con contraseña
- `--encrypt-password`: Contraseña personalizada para cifrado (opcional, defecto: generada aleatoriamente)
- `--output, -o`: Directorio de salida (por defecto: ~/Documents/RedAuditReports)
- `--max-hosts`: Máximo de hosts encontrados a escanear (por defecto: todos)
- `--no-vuln-scan`: Desactivar escaneo de vulnerabilidades web
- `--no-txt-report`: Desactivar generación de reporte TXT
- `--no-deep-scan`: Desactivar deep scan adaptativo
- `--prescan`: Activar pre-escaneo rápido asyncio antes de nmap
- `--prescan-ports`: Rango de puertos para pre-scan (defecto: 1-1024)
- `--prescan-timeout`: Timeout de pre-scan en segundos (defecto: 0.5)
- `--udp-mode`: Modo de escaneo UDP: quick (defecto) o full
- `--udp-ports`: Número de top puertos UDP usado en `--udp-mode full` (50-500, defecto: 100) **(v3.1+)**
- `--topology`: Activar descubrimiento de topología (ARP/VLAN/LLDP + gateway/rutas) **(v3.1+)**
- `--no-topology`: Desactivar descubrimiento de topología (anula defaults persistentes) **(v3.1+)**
- `--topology-only`: Ejecutar solo topología (omitir escaneo de hosts) **(v3.1+)**
- `--save-defaults`: Guardar ajustes CLI como defaults persistentes (`~/.redaudit/config.json`) **(v3.1+)**
- `--defaults {ask,use,ignore}`: Comportamiento de defaults persistentes (en interactivo pregunta; en no-interactivo mantiene el comportamiento actual) **(v3.2.1+)**
- `--use-defaults`: Atajo para `--defaults use` **(v3.2.1+)**
- `--ignore-defaults`: Atajo para `--defaults ignore` **(v3.2.1+)**
- `--net-discovery [PROTO,...]`: Activar descubrimiento de red mejorado (all, o lista: dhcp,netbios,mdns,upnp,arp,fping) **(v3.2+)**
- `--redteam`: Incluir bloque opcional de recon Red Team en net discovery **(v3.2+)**
- `--net-discovery-interface IFACE`: Interfaz para net discovery y capturas L2 (ej: eth0) **(v3.2+)**
- `--redteam-max-targets N`: Máximo de IPs muestreadas para checks redteam (1-500, defecto: 50) **(v3.2+)**
- `--snmp-community COMMUNITY`: Comunidad SNMP para SNMP walking (defecto: public) **(v3.2+)**
- `--dns-zone ZONE`: Pista de zona DNS para intento AXFR (ej: corp.local) **(v3.2+)**
- `--kerberos-realm REALM`: Pista de realm Kerberos (ej: CORP.LOCAL) **(v3.2+)**
- `--kerberos-userlist PATH`: Lista opcional de usuarios para userenum Kerberos (requiere kerbrute) **(v3.2+)**
- `--redteam-active-l2`: Activar checks L2 adicionales potencialmente más ruidosos (bettercap/scapy sniff; requiere root) **(v3.2+)**
- `--skip-update-check`: Omitir verificación de actualizaciones al iniciar
- `--yes, -y`: Saltar advertencia legal (usar con precaución)
- `--lang`: Idioma (en/es)
- `--ipv6`: Activar modo solo IPv6 **(v3.0)**
- `--proxy URL`: Proxy SOCKS5 para pivoting (socks5://host:port) **(v3.0)**
- `--diff OLD NEW`: Comparar dos reportes JSON y mostrar cambios **(v3.0)**
- `--cve-lookup`: Activar correlación CVE vía API NVD **(v3.0)**
- `--nvd-key KEY`: Clave API NVD para límites de velocidad más rápidos **(v3.0)**

Ver `redaudit --help` para detalles completos.

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

### Auto-Actualización Segura

RedAudit puede verificar e instalar actualizaciones automáticamente:

- **Verificación al Inicio**: Pregunta si deseas buscar actualizaciones en modo interactivo
- **Auto-Instalación**: Descarga e instala actualizaciones vía `git clone`
- **Auto-Reinicio**: Se reinicia automáticamente con el nuevo código usando `os.execv()`
- **Flag de Omisión**: Usa `--skip-update-check` para desactivar la verificación

**Invocación alternativa:**

```bash
python -m redaudit --help
```

## 8. Reportes, Cifrado y Descifrado

Los reportes se guardan en `~/Documents/RedAuditReports` (por defecto) con fecha y hora.

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

**Nota**: Para explicaciones detalladas de estrategias de escaneo (Deep Scan, Smart-Check, Topology Discovery, etc.), ver la sección Características arriba.

## 12. Solución de Problemas

Para solución integral cubriendo todos los escenarios, consulta la guía completa:  
📖 **[Guía Completa de Solución de Problemas](docs/es/TROUBLESHOOTING.md)**

**Enlaces Directos**:

- [Problemas de Instalación](docs/es/TROUBLESHOOTING.md#1-permission-denied--se-requieren-privilegios-root)
- [Problemas de Escaneo](docs/es/TROUBLESHOOTING.md#5-el-escaneo-parece-congelado--pausas-largas)
- [Problemas de Network Discovery](docs/es/TROUBLESHOOTING.md#12-net-discovery-herramientas-faltantes--tool_missing-v32)
- [Cifrado/Descifrado](docs/es/TROUBLESHOOTING.md#8-fallo-en-el-descifrado-token-inválido)

### Problemas Comunes de Instalación

#### 1. "Permission denied" / Privilegios root requeridos

- **Causa**: Ejecutar sin `sudo` (nmap requiere raw sockets)
- **Solución**: Añadir `sudo` al comando, o usar `--allow-non-root` para modo limitado
- **Verificar**: `id -u` debe devolver 0 al ejecutar con sudo

#### 2. "nmap: command not found"

- **Causa**: nmap no instalado o no está en PATH
- **Solución**: `sudo apt update && sudo apt install nmap`
- **Verificar**: `which nmap` debe mostrar `/usr/bin/nmap`

#### 3. "ModuleNotFoundError: cryptography"

- **Causa**: Dependencias Python faltantes
- **Solución**: `sudo bash redaudit_install.sh` o `sudo apt install python3-cryptography python3-nmap python3-netifaces`

#### 4. Alias no funciona tras instalación

- **Causa**: Configuración del shell no recargada
- **Solución**: Ejecutar `source ~/.zshrc` (Kali) o `source ~/.bashrc` (Debian/Ubuntu), o abrir nueva terminal

### Problemas de Escaneo

#### 5. "El escaneo parece congelado" / Pausas largas

- **Causa**: Deep scan legítimamente toma 90-150s por host complejo
- **Verificar**: Buscar marcador `[deep]` en salida - es normal
- **Monitorear**: Revisar `~/.redaudit/logs/` para mensajes de heartbeat
- **Solución alternativa**: Usar `--no-deep-scan` o reducir `--threads` a 4

#### 6. "Demasiados hosts, nunca termina"

- **Causa**: Escanear redes /16 grandes sin optimización
- **Solución**: Usar `--prescan` para descubrimiento rápido, o `--max-hosts N` para limitar alcance
- **Ejemplo**: `sudo redaudit -t 192.168.0.0/16 --prescan --max-hosts 100 --yes`

#### 7. Avisos de Heartbeat en logs

- **Causa**: Nikto/TestSSL ejecutándose lentamente en hosts filtrados
- **Estado**: Normal - las herramientas siguen ejecutándose
- **Acción**: Esperar o reducir `--rate-limit` si es demasiado agresivo

### Cifrado y Descifrado

#### 8. "Decryption failed: Invalid token"

- **Causa**: Contraseña incorrecta o archivo `.salt` corrupto
- **Solución**: Verificar contraseña (sensible a mayúsculas), asegurar que archivo `.salt` existe en mismo directorio
- **Verificar**: Archivo `.salt` debe tener 16 bytes: `ls -lh *.salt`

#### 9. Aviso "Cryptography not available"

- **Causa**: Paquete `python3-cryptography` faltante
- **Impacto**: Opciones de cifrado estarán deshabilitadas
- **Solución**: `sudo apt install python3-cryptography`

### Red y Conectividad

#### 10. Escaneo IPv6 no funciona

- **Causa**: IPv6 deshabilitado en sistema o nmap compilado sin soporte IPv6
- **Verificar**: `ip -6 addr show` y `nmap -6 ::1`
- **Solución**: Habilitar IPv6 en `/etc/sysctl.conf` o usar objetivos IPv4

#### 11. Errores de rate limit NVD API

- **Causa**: Usar API NVD sin clave (limitado a 5 peticiones/30s)
- **Solución**: Obtener clave API gratuita de <https://nvd.nist.gov/developers/request-an-api-key>
- **Uso**: `--nvd-key TU_CLAVE` o guardar en `~/.redaudit/config.json`

#### 12. Conexión Proxy fallida

- **Causa**: `proxychains` no instalado o proxy inalcanzable
- **Solución**: `sudo apt install proxychains4` y probar proxy: `curl --socks5 host:port http://example.com`
- **Formato**: `--proxy socks5://host:port`

### Salida y Reportes

#### 13. Exportaciones JSONL no generadas

- **Causa**: Cifrado de reportes está habilitado (JSONL solo se genera cuando cifrado está desactivado)
- **Solución**: Ejecutar sin flag `--encrypt` para generar `findings.jsonl`, `assets.jsonl`, `summary.json`

#### 14. "Output directory not found"

- **Causa**: Ruta de salida personalizada no existe
- **Solución**: Crear directorio primero: `mkdir -p /ruta/a/salida` o dejar que RedAudit use default (`~/Documents/RedAuditReports`)

### Optimización de Rendimiento

#### 15. Escaneos muy lentos en redes grandes

- **Optimización 1**: Usar `--prescan` para descubrimiento asyncio rápido
- **Optimización 2**: Aumentar `--threads` a 12-16 (pero vigilar congestión de red)
- **Optimización 3**: Usar `--mode fast` para inventario rápido, luego escaneos `full` específicos
- **Ejemplo**: `sudo redaudit -t 10.0.0.0/16 --prescan --threads 12 --mode fast --yes`

#### 16. Alto uso de CPU/memoria

- **Causa**: Demasiados hilos concurrentes o deep scans en muchos hosts
- **Solución**: Reducir `--threads` a 4-6, usar `--no-deep-scan`, o añadir `--rate-limit 1`

#### 17. Congestión de red / Alertas IDS

- **Causa**: Escaneo agresivo disparando sistemas de seguridad
- **Solución**: Añadir `--rate-limit 2` (con jitter ±30%) y reducir `--threads` a 4
- **Modo sigiloso**: `sudo redaudit -t OBJETIVO --mode normal --rate-limit 3 --threads 2 --yes`

## 13. Historial de Cambios

### Características v3.1

- **Exportaciones JSONL**: `findings.jsonl`, `assets.jsonl`, `summary.json` para pipelines SIEM/IA (solo cuando el cifrado está desactivado)
- **IDs de Hallazgo**: Hashes determinísticos para correlación entre escaneos
- **Clasificación por Categoría**: surface/misconfig/crypto/auth/info-leak/vuln
- **Severidad Normalizada**: Escala 0-10 estilo CVSS con severidad original preservada
- **Observaciones Estructuradas**: Extracción de salida Nikto/TestSSL
- **Versiones de Escáners**: Detección de versiones de herramientas
- **Descubrimiento de Topología (best-effort)**: ARP/VLAN/LLDP + gateway/rutas (`--topology`, `--topology-only`)
- **Defaults Persistentes**: `--save-defaults` guarda ajustes comunes en `~/.redaudit/config.json`
- **Cobertura UDP Configurable**: `--udp-ports` para ajustar la cobertura del UDP full de identidad

### Características v3.0

- **Soporte IPv6**: Escaneo completo de redes IPv6
- **Correlación CVE (NVD)**: Inteligencia de vulnerabilidades via API NIST NVD
- **Análisis Diferencial**: Comparar reportes para detectar cambios (`--diff`)
- **Proxy Chains (SOCKS5)**: Soporte para pivoting via proxychains
- **Validación Magic Bytes**: Detección mejorada de falsos positivos

### Mejoras v2.9

- **Smart-Check**: Filtrado automático de falsos positivos de Nikto
- **UDP Taming**: Escaneo 50-80% más rápido con estrategia optimizada
- **Entity Resolution**: Consolidación de hosts multi-interfaz
- **SIEM Profesional**: Cumplimiento ECS v8.11, puntuación de severidad

Para el changelog detallado, consulta [CHANGELOG.md](CHANGELOG.md)

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
