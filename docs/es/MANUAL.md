# Manual de Usuario de RedAudit v3.5.0 (ES)

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](../en/MANUAL.md)

**Versión:** 3.5.0
**Fecha:** Diciembre 2025
**Audiencia objetivo:** Analistas de seguridad, pentesters, administradores de sistemas / redes
**Licencia:** GPLv3

---

## Tabla de contenidos

1. [Introducción](#1-introducción)
2. [Requisitos del sistema](#2-requisitos-del-sistema)
3. [Instalación](#3-instalación)
   - 3.1 [Instalación rápida](#31-instalación-rápida)
   - 3.2 [Qué hace el instalador](#32-qué-hace-el-instalador)
   - 3.3 [Instalación / desinstalación manual](#33-instalación--desinstalación-manual)
4. [Conceptos y arquitectura](#4-conceptos-y-arquitectura)
   - 4.1 [Objetivos](#41-objetivos)
   - 4.2 [Flujo de trabajo general](#42-flujo-de-trabajo-general)
   - 4.3 [Modos de escaneo](#43-modos-de-escaneo)
5. [Uso desde la línea de comandos](#5-uso-desde-la-línea-de-comandos)
   - 5.1 [Sintaxis básica](#51-sintaxis-básica)
   - 5.2 [Opciones principales](#52-opciones-principales)
   - 5.3 [Escenarios típicos](#53-escenarios-típicos)
6. [Informes y salida](#6-informes-y-salida)
   - 6.1 [Estructura de directorios](#61-estructura-de-directorios)
   - 6.2 [Estructura del informe JSON](#62-estructura-del-informe-json)
   - 6.3 [Resumen en texto (TXT)](#63-resumen-en-texto-txt)
7. [Cifrado y descifrado](#7-cifrado-y-descifrado)
8. [Modelo de seguridad](#8-modelo-de-seguridad)
   - 8.1 [Seguridad de entrada y comandos](#81-seguridad-de-entrada-y-comandos)
   - 8.2 [Modelo de privilegios](#82-modelo-de-privilegios)
   - 8.3 [Seguridad operacional](#83-seguridad-operacional)
   - 8.4 [Uso ético y legal](#84-uso-ético-y-legal)
9. [Herramientas externas](#9-herramientas-externas)
10. [Monitorización y resolución de problemas](#10-monitorización-y-resolución-de-problemas)
11. [Contribución y pruebas](#11-contribución-y-pruebas)
12. [Licencia y aviso legal](#12-licencia-y-aviso-legal)

---

## 1. Introducción

RedAudit es un asistente de auditoría y endurecimiento de redes para sistemas Kali / Debian y derivados. Su objetivo es guiar al operador a través de un flujo ordenado:

- Descubrimiento de equipos vivos.
- Enumeración de puertos y servicios.
- Fingerprinting web y TLS cuando aplica.
- Análisis profundo opcional sobre hosts "interesantes".
- Generación de informes JSON preparados para SIEM y resúmenes legibles, con opción de cifrado.

RedAudit no explota vulnerabilidades por sí mismo. Su función es ofrecer visibilidad y estructura para que el analista humano decida qué acciones tomar.

### Características clave

- CLI de un solo comando para reconocimiento y auditoría de redes completas.
- Tres modos de escaneo (fast, normal, full) con flujo adaptativo.
- Activación automática de herramientas externas (nmap, whatweb, nikto, testssl.sh, etc.) según lo que se descubra.
- Esquema JSON estable y documentado, diseñado para ingestión automática.
- Cifrado opcional de informes con `cryptography` (Fernet).
- Limitación de velocidad y jitter configurables.
- Defaults persistentes guardados en `~/.redaudit/config.json` (opcional, para automatización).
- Descubrimiento de topología opcional (ARP/VLAN/LLDP + gateway/rutas) para contexto L2 y pistas de "redes ocultas".
- Descubrimiento de red mejorado opcional (`--net-discovery`) con señales broadcast/L2 y un bloque de recon `--redteam` (best-effort).
- **Dashboard HTML Interactivo** (`--html-report`): Reporte visual autocontenido con gráficos y búsqueda. (v3.3)
- **Alertas Webhook** (`--webhook`): Notificaciones de hallazgos en tiempo real a servicios externos. (v3.3)
- **Playbooks de Remediación**: Playbooks Markdown auto-generados por host/categoría en `<output_dir>/playbooks/`. (v3.4)
- Mensajes bilingües (inglés / español).

---

## 2. Requisitos del sistema

| Requisito    | Mínimo / soportado                                   |
|--------------|------------------------------------------------------|
| Sistema      | Kali Linux, Debian 11+, Ubuntu 20.04+, Parrot OS     |
| Python       | 3.9+ (Python del sistema)                            |
| Privilegios  | sudo / root recomendado (sockets raw, nmap, tcpdump) |
| Disco        | ~50 MB para código y dependencias + espacio para informes |
| Red          | Alcance de red hacia los objetivos                   |

RedAudit está pensado para Linux. No está diseñado para ejecutarse de forma nativa en Windows o macOS.

Nota: existe un modo limitado sin root mediante `--allow-non-root`, pero algunas funciones de escaneo pueden fallar o omitirse.

---

## 3. Instalación

### 3.1 Instalación rápida

```bash
# 1) Clonar el repositorio
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit

# 2) Ejecutar el instalador con sudo
sudo bash redaudit_install.sh
```

Durante la instalación se te pedirá:

- Seleccionar idioma por defecto (inglés / español).
- Confirmar la instalación de un conjunto de herramientas adicionales recomendadas.

Tras finalizar, recarga la configuración de tu shell:

```bash
# Zsh (Kali reciente)
source ~/.zshrc

# Bash
source ~/.bashrc
```

Después de esto, el comando `redaudit` debería estar disponible.

---

### 3.2 Qué hace el instalador

El script `redaudit_install.sh` realiza, de forma resumida, lo siguiente:

1. **Comprobaciones iniciales**
   - Verifica que existe `apt` (sistemas tipo Debian).
   - Verifica que se ejecuta con sudo o como root.

2. **Dependencias principales**
   Instala o valida paquetes como:
   - `curl`, `wget`, `openssl`, `git`
   - `nmap`
   - `tcpdump`, `tshark`
   - `whois`, `bind9-dnsutils`
   - `python3-nmap`, `python3-cryptography`, `python3-netifaces`
   - `exploitdb` (para searchsploit)
   - `nbtscan`, `netdiscover`, `fping`, `avahi-utils` (para descubrimiento mejorado)
   - `snmp`, `snmp-mibs-downloader`, `enum4linux`, `smbclient`, `samba-common-bin` (rpcclient), `masscan`, `ldap-utils`, `bettercap`, `python3-scapy`, `proxychains4` (para recon Red Team)
   - `kerbrute` (descargado desde GitHub)

3. **Despliegue del código**
   - Copia el paquete Python `redaudit/` a `/usr/local/lib/redaudit`.
   - Ajusta permisos de ejecución en directorios relevantes.
   - Inyecta el idioma seleccionado en `utils/constants.py` como configuración por defecto.

4. **Lanzador de la CLI**
   - Instala un script `redaudit` en un directorio del PATH (p. ej. `/usr/local/bin`).
   - Añade o actualiza un alias en tu `.bashrc` / `.zshrc` para que `redaudit` invoque la herramienta.

5. **Extras opcionales**
   - Ofrece instalar en bloque un conjunto de utilidades recomendadas mediante `apt`.

No se instala ningún servicio permanente: RedAudit es una herramienta sin estado que se ejecuta bajo demanda.

---

### 3.3 Instalación / desinstalación manual

Si prefieres evitar el instalador:

1. Clona el repositorio:

   ```bash
   git clone https://github.com/dorinbadea/RedAudit.git
   cd RedAudit
   ```

2. Instala las dependencias con apt (ejemplo):

   ```bash
   sudo apt update
   sudo apt install curl wget openssl nmap tcpdump tshark \
                    whois bind9-dnsutils python3-nmap \
                    python3-cryptography python3-netifaces exploitdb \
                    nbtscan netdiscover fping avahi-utils snmp ldap-utils samba-common-bin proxychains4
   ```

3. Instalar `kerbrute` (paso manual):

   ```bash
   sudo wget -O /usr/local/bin/kerbrute https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
   sudo chmod +x /usr/local/bin/kerbrute
   ```

4. Ejecuta RedAudit como módulo:

   ```bash
   sudo python3 -m redaudit
   ```

**Para desinstalar:**

- Elimina `/usr/local/lib/redaudit` (o la ruta donde lo hayas desplegado).
- Elimina el script `redaudit` y el alias de tu `.bashrc` / `.zshrc`.
- Opcionalmente desinstala las dependencias si las instalaste solo para RedAudit.

---

## 4. Conceptos y arquitectura

### 4.1 Objetivos

Los principios de diseño de RedAudit son:

- **Seguro por defecto:** validación estricta de entrada, timeouts razonables, cifrado opcional de informes.
- **Determinista y analizable:** salida JSON con esquema claro.
- **Guiado por el operador:** la herramienta asiste al analista, no decide por él.

### 4.2 Flujo de trabajo general

En un ciclo normal de ejecución, RedAudit realiza:

1. **Configuración Interactiva (Asistente)**
   - Si se ejecuta interactivamente, el usuario selecciona una acción desde el **Menú Principal**.
   - Input de rangos objetivo y selección de **Modo Topología** (Full, Standard o Topology Only).

2. **Descubrimiento de Red (Opcional, v3.2)**
   - Si se activa (`--net-discovery` o desde el asistente interactivo), lanza sondas broadcast vía ARP, mDNS, NetBIOS y DHCP para encontrar hosts ocultos.
   - Recon Red Team opt-in disponible (`--redteam` o la opción B del wizard); el L2 activo requiere `--redteam-active-l2`.
   - La enumeración Kerberos con Kerbrute solo se ejecuta si se habilita explícitamente y se proporciona una lista de usuarios (solo con autorización).

3. **Descubrimiento**
   - Uso de `nmap -sn` para detectar hosts vivos en los rangos indicados.

4. **Descubrimiento de topología (Opcional, v3.1+)**
   - Mapping best-effort de gateway/rutas + pistas L2 (ARP/VLAN/LLDP) cuando hay herramientas y privilegios.

5. **Escaneo de puertos y servicios**
   - Uso de `nmap -sV` para descubrir puertos abiertos y versiones de servicios.
   - En modo `full`, el escaneo es más exhaustivo (más puertos y scripts adicionales).

6. **Análisis web y TLS condicional**
   - Si detecta puertos HTTP/HTTPS:
     - `whatweb` identifica tecnologías y CMS.
     - `curl` y `wget` extraen cabeceras.
     - En `full`, se activan `nikto` y `testssl.sh` para un análisis más profundo.

7. **Escaneo profundo / refinamiento de identidad (selectivo)**
   - Si un host es ambiguo o especialmente interesante (pocos puertos, servicios raros, fingerprint incompleto), se dispara un escaneo más agresivo:
     - Más sondas de `nmap`, posible captura de tráfico con `tcpdump` y resumen con `tshark`.

8. **Post-procesado e informes**
   - Se consolida toda la información en un informe JSON estructurado.
   - Se genera un informe TXT para lectura rápida (si está habilitado).
   - Se generan playbooks de remediación en Markdown en `<output_dir>/playbooks/`.
   - Genera un Dashboard HTML interactivo (`--html-report`).
   - Exporta artefactos JSONL para pipelines SIEM/AI (si el cifrado está desactivado).
   - Si se ha solicitado cifrado, los informes se protegen con `cryptography` (Fernet).

> **Nota de cifrado**: Cuando el cifrado está activado, RedAudit escribe artefactos JSON/TXT cifrados (más un archivo `.salt`) y omite artefactos en claro (HTML/JSONL/playbooks).

---

### 4.3 Modos de escaneo

RedAudit dispone de tres modos, con nombres de parámetro en inglés. Es importante:

- La opción CLI se pasa como `fast`, `normal` o `full`.
- La interfaz puede mostrar etiquetas localizadas ("Rápido", "Normal", "Completo"), pero el valor del parámetro es siempre en inglés.

| Modo | Valor CLI | Descripción | Caso de uso típico |
|---|---|---|---|
| Rápido | `fast` | Solo descubrimiento de hosts (`nmap -sn`). | Inventario rápido; verificar accesibilidad. |
| Normal | `normal` | Puertos principales + versiones de servicios. | Auditoría de seguridad estándar. |
| Completo | `full` | Puertos extendidos + scripts + web/TLS + **net discovery** (v3.2.1). | Auditoría integral / revisión pre-pentest. |

El modo elegido afecta a cuántos puertos se analizan y qué herramientas externas se activan.

---

## 5. Uso desde la línea de comandos

### 5.1 Sintaxis básica

RedAudit se puede usar en modo interactivo (sin argumentos) o no interactivo.

```bash
# Modo interactivo (lanza el Menú Principal)
sudo redaudit
```

Cuando se inicia sin argumentos, RedAudit presenta un **Menú Principal Interactivo**:

1. **Iniciar escaneo (wizard)**: Inicia el asistente guiado para escanear.
2. **Buscar actualizaciones**: Ejecuta el actualizador interactivo (requiere `sudo`).
3. **Comparar reportes (JSON)**: Compara 2 reportes JSON para ver diferencias.
0. **Salir**: Salir.

Tras una actualización exitosa, RedAudit muestra un aviso de "reiniciar el terminal" y sale para asegurar una carga limpia de la nueva versión.

Si eliges escanear, el asistente te guiará por:

- Selección de objetivo (IP/CIDR).
- **Modo Topología**: Elige entre Escaneo Completo (+Topología), Estándar (Sin Topología) o Solo Topología.
- Modo de Escaneo (Fast, Normal, Full).
- Opciones adicionales (Cifrado, Defaults).

#### Modo Interactivo vs No-Interactivo

| Aspecto | Modo Interactivo | Modo No-Interactivo |
|--------|------------------|---------------------|
| **Lanzamiento** | `sudo redaudit` | `sudo redaudit --target X --yes` |
| **Configuración** | Asistente con prompts | Todo por flags CLI |
| **Menú Principal** | Sí (Escanear / Actualizar / Diff / Salir) | No (ejecución directa) |
| **Valores por Defecto** | Prompt para usar/guardar | Especificar `--use-defaults` o `--ignore-defaults` |
| **Caso de uso** | Auditorías manuales, exploración | Automatización, scripts, CI/CD |
| **Check de actualizaciones** | Prompt al inicio | Omitido (usar `--skip-update-check` explícito) |

### Modo no interactivo (automatización)

```bash
sudo redaudit --target 192.168.1.0/24 --mode normal --yes
```

También se puede invocar como módulo:

```bash
sudo python3 -m redaudit [OPCIONES]
```

---

### 5.2 Opciones principales

Para ver la ayuda completa:

```bash
redaudit --help
```

Las opciones más importantes:

| Opción                       | Descripción                                                                                                             |
|------------------------------|-------------------------------------------------------------------------------------------------------------------------|
| `-t`, `--target CIDR`        | Red(es) objetivo en notación CIDR. Se admiten varias separadas por comas.                                              |
| `-m`, `--mode {fast,normal,full}` | Selección del modo de escaneo (ver tabla anterior). Por defecto: `normal`.                                        |
| `-j`, `--threads N`          | Número de hilos concurrentes. El rango está limitado por constantes internas seguras.                                  |
| `--max-hosts N`              | Número máximo de hosts encontrados a escanear. Por defecto: todos. *(Es un límite, no un selector de host/IP.)*        |
| `--rate-limit SEGUNDOS`      | Retraso entre hosts para reducir ruido. Por defecto: 0.                                                                 |
| `--dry-run`                  | Muestra los comandos que se ejecutarían sin ejecutarlos (no se ejecuta ningún comando externo). **(v3.5+)**          |
| `--no-prevent-sleep`         | No inhibir reposo del sistema/pantalla mientras se ejecuta el scan. **(v3.5)**                                          |
| `-e`, `--encrypt`            | Activa el cifrado de los informes generados.                                                                            |
| `--encrypt-password PASS`    | Contraseña de cifrado en modo no interactivo. Si se omite con `--encrypt`, se pedirá por consola o se generará una aleatoria. |
| `--no-vuln-scan`             | Desactiva el escaneo de vulnerabilidades web (omite nikto y ciertas pruebas HTTP).                                      |
| `--no-txt-report`            | Evita generar el resumen en texto (TXT).                                                                                |
| `-o`, `--output DIR`         | Directorio base destino para los informes. Por defecto: `~/Documents/RedAuditReports` (usuario invocador bajo `sudo`; se crea `RedAudit_...` con timestamp). |
| `--yes`                      | Modo no interactivo: asume "sí" a las preguntas. Imprescindible para automatización.                                    |
| `--prescan`                  | Activa el pre-escaneo asíncrono antes de lanzar nmap sobre grandes rangos.                                        |
| `--prescan-ports`            | Rango de puertos para pre-scan (ej: `1-1000` o `top-1000`). Defecto: `1-1024`.                                          |
| `--prescan-timeout`          | Timeout por puerto en segundos. Defecto: `0.5`.                                                                         |
| `--udp-mode {quick,full}`    | Modo UDP del deep scan: `quick` (puertos prioritarios) o `full` (top puertos UDP para identidad). Por defecto: `quick`. |
| `--udp-ports N`              | Número de top puertos UDP usados en `--udp-mode full` (rango: 50-500). Defecto: 100. **(v3.1+)**                        |
| `--topology`                 | Activa descubrimiento de topología (ARP/VLAN/LLDP + gateway/rutas). **(v3.1+)**                                         |
| `--no-topology`              | Desactiva descubrimiento de topología (anula defaults persistentes). **(v3.1+)**                                       |
| `--topology-only`            | Ejecuta solo topología (omite escaneo de hosts). **(v3.1+)**                                                           |
| `--save-defaults`            | Guarda ajustes CLI como defaults persistentes (`~/.redaudit/config.json`). **(v3.1+)**                                  |
| `--net-discovery [PROTO,...]` | Activa descubrimiento de red mejorado (all, o lista: dhcp,netbios,mdns,upnp,arp,fping). **(v3.2+)**                 |
| `--redteam`                  | Incluye bloque opt-in de recon Red Team en net discovery (best-effort, más lento/más ruido). **(v3.2+)**              |
| `--net-discovery-interface IFACE` | Interfaz para net discovery y capturas L2 (ej: eth0). **(v3.2+)**                                                 |
| `--redteam-max-targets N`    | Máximo de IPs muestreadas para checks redteam (1-500, defecto: 50). **(v3.2+)**                                       |
| `--snmp-community COMMUNITY` | Comunidad SNMP para SNMP walking (defecto: public). **(v3.2+)**                                                       |
| `--dns-zone ZONE`            | Pista de zona DNS para intento AXFR (ej: corp.local). **(v3.2+)**                                                     |
| `--kerberos-realm REALM`     | Pista de realm Kerberos (ej: CORP.LOCAL). **(v3.2+)**                                                                 |
| `--kerberos-userlist PATH`   | Lista opcional de usuarios para userenum Kerberos (requiere kerbrute; solo con autorización). **(v3.2+)**             |
| `--redteam-active-l2`        | Activa checks L2 adicionales potencialmente más ruidosos (bettercap/scapy sniff; requiere root). **(v3.2+)**          |
| `--skip-update-check`        | Omitir la verificación de actualizaciones al iniciar.                                                             |
| `--ipv6`                     | Activa modo solo IPv6. **(v3.0)**                                                                                 |
| `--proxy URL`                | Proxy SOCKS5 para pivoting (ej: `socks5://host:1080`). **(v3.0)**                                                 |
| `--diff OLD NEW`             | Compara dos reportes JSON y genera análisis diferencial. **(v3.0)**                                               |
| `--cve-lookup`               | Activa correlación CVE vía API NVD. **(v3.0)**                                                                    |
| `--nvd-key KEY`              | Clave API NVD para límites de velocidad más rápidos (opcional). **(v3.0)**                                        |
| `--html-report`              | Genera dashboard HTML interactivo. **(v3.3)**                                                                     |
| `--webhook URL`              | Envía hallazgos POST a esta URL (ej: Slack/Teams webhook). **(v3.3)**                                             |
| `-V`, `--version`            | Muestra la versión de RedAudit y termina.                                                                               |

Defaults persistentes: si se usa `--save-defaults`, RedAudit guarda ajustes en `defaults` dentro de `~/.redaudit/config.json` y los reutiliza como valores por defecto en ejecuciones futuras.

Nota (modo interactivo): cuando se pregunte “Número máximo de hosts a escanear”, pulsa ENTER para escanear **todos** los hosts encontrados, o escribe un número para aplicar un límite global.

Para más ejemplos de uso, consulta [USAGE.md](USAGE.md).

---

### 5.3 Escenarios típicos

**1. Inventario rápido de la LAN**

```bash
sudo redaudit --target 192.168.1.0/24 --mode fast --yes
```

**2. Auditoría estándar con cifrado**

```bash
sudo redaudit \
  --target 10.0.0.0/24 \
  --mode normal \
  --encrypt \
  --encrypt-password "ContraseñaFuerte123!" \
  --yes
```

**3. Auditoría completa de una subred pequeña**

```bash
sudo redaudit \
  --target 172.16.10.0/28 \
  --mode full \
  --threads 4 \
  --rate-limit 2 \
  --prescan \
  --yes
```

**4. Descubrimiento de red mejorado (v3.2)**

```bash
# Solo descubrimiento broadcast
sudo redaudit --target 192.168.1.0/24 --net-discovery --yes

# Con recon redteam opt-in (best-effort)
sudo redaudit --target 192.168.1.0/24 --net-discovery --redteam --net-discovery-interface eth0 --yes
```

---

## 6. Informes y salida

### 6.1 Estructura de directorios

Tras cada ejecución, RedAudit crea un directorio con sello temporal (v2.8+):

```text
~/Documents/RedAuditReports/
└── RedAudit_2025-01-15_21-30-45/
    ├── redaudit_20250115_213045.json
    ├── redaudit_20250115_213045.txt
    ├── report.html                   # v3.3 Dashboard Interactivo (nombre fijo)
    ├── findings.jsonl                # Exportación plana de hallazgos (SIEM/IA)
    ├── assets.jsonl                  # Exportación plana de activos (SIEM/IA)
    ├── summary.json                  # Resumen compacto para dashboards
    ├── run_manifest.json             # Manifiesto de la carpeta (archivos + métricas)
    ├── playbooks/                    # Playbooks de remediación (Markdown)
    └── traffic_192_168_1_*.pcap      # Capturas opcionales
```

Cada sesión de escaneo obtiene su propia subcarpeta para mejor organización.

Si el cifrado está activado, los informes terminarán en `.enc` y aparecerán ficheros `.salt` asociados.
Por seguridad, los artefactos en claro (HTML/JSONL/playbooks/manifiestos) se generan solo cuando el cifrado está desactivado.

---

### 6.2 Estructura del informe JSON

El esquema detallado se documenta en [REPORT_SCHEMA.md](REPORT_SCHEMA.md). A alto nivel:

- **Objeto raíz**
  - Metadatos de ejecución: versión de la herramienta, hora de inicio/fin, opciones usadas, estado final.
  - Información de objetivo: rangos, nombres de host resueltos, etc.
  - Bloque opcional de topología (`topology`) si se activa el descubrimiento de topología.

- **hosts[]**
  - Un objeto por host descubierto:
    - `ip`, `hostname`, `os_guess`, `mac_address`
    - `ports[]` con:
      - `port`, `protocol`, `state`, `service`, `product`, `version`
      - `known_exploits[]` (resultado de searchsploit)
    - `dns` (búsquedas inversas y otros registros).
    - `whois_summary` (para IPs públicas).

- **vulnerabilities[]**
  - Hallazgos por host/servicio:
    - Fingerprints de `whatweb`.
    - `nikto_findings` (si se ejecuta).
    - `curl_headers`, `wget_headers`.
    - `tls_info` y `testssl_analysis` para puertos HTTPS.

- **deep_scan (opcional)**
  - Solo presente si se ha activado el escaneo profundo:
    - Fingerprints adicionales.
    - Metadatos de capturas pcap y resúmenes tshark.

El esquema es estable y versionado, pensado para su integración en SIEMs o scripts propios.

#### 6.2.1 Integración SIEM (v3.1)

Cuando el cifrado está desactivado, RedAudit genera exportaciones planas optimizadas para ingesta SIEM/IA:

**findings.jsonl** - Una vulnerabilidad por línea:

```json
{"finding_id":"...","asset_ip":"192.168.1.10","port":80,"url":"http://192.168.1.10/","severity":"low","normalized_severity":1.0,"category":"surface","title":"Missing HTTP Strict Transport Security Header","timestamp":"...","session_id":"...","schema_version":"...","scanner":"RedAudit","scanner_version":"..."}
```

**assets.jsonl** - Un host por línea:

```json
{"asset_id":"...","ip":"192.168.1.10","hostname":"webserver.local","status":"up","risk_score":62,"total_ports":3,"web_ports":1,"finding_count":7,"tags":["web"],"timestamp":"...","session_id":"...","schema_version":"...","scanner":"RedAudit","scanner_version":"..."}
```

**summary.json** - Métricas para dashboards:

```json
{"schema_version":"...","generated_at":"...","session_id":"...","scan_duration":"0:05:42","total_assets":15,"total_findings":47,"severity_breakdown":{"critical":2,"high":8,"medium":21,"low":16,"info":0},"targets":["..."],"scanner_versions":{"redaudit":"..."},"redaudit_version":"..."}
```

**run_manifest.json** - Manifiesto de la carpeta con métricas y lista de ficheros:

```json
{"session_id":"...","redaudit_version":"...","counts":{"hosts":15,"findings":47,"pcaps":3},"artifacts":[{"path":"report.html","size_bytes":12345}]}
```

**Ejemplos de ingesta:**

```bash
# Elasticsearch
cat findings.jsonl | curl -X POST "localhost:9200/redaudit-findings/_bulk" \
  -H 'Content-Type: application/x-ndjson' --data-binary @-

# Splunk HEC
cat findings.jsonl | while read line; do
  curl -k "https://splunk:8088/services/collector" \
    -H "Authorization: Splunk TU_TOKEN" -d "{\"event\":$line}"
done

# Procesamiento personalizado
jq -r 'select(.normalized_severity >= 7.0) | "\(.asset_ip) - \(.title)"' findings.jsonl
```

---

### 6.3 Resumen en texto (TXT)

El informe TXT está orientado a la lectura humana:

- Descripción de alto nivel de la ejecución (objetivos, modo, duración).
- Listado sintetizado de hosts y puertos abiertos.
- Resumen de posibles problemas interesantes.

Usa el JSON para automatización y el resumen para revisiones manuales, informes ejecutivos o anexos.

---

## 7. Cifrado y descifrado

Si se activa `--encrypt`, RedAudit utiliza la librería `cryptography` (Fernet) para proteger el contenido de los informes.

### Modelo de cifrado

- Cifrado simétrico con AES-128-CBC + HMAC-SHA256 (especificación Fernet).
- Derivación de clave a partir de contraseña mediante PBKDF2-HMAC-SHA256, con alto número de iteraciones y salt aleatorio por sesión.
- La salida cifrada incluye una firma para detectar manipulaciones.

**Política de contraseña (aplicada por la herramienta):**

- Longitud mínima 12 caracteres.
- Se recomienda mezclar mayúsculas, minúsculas y dígitos.

### Descifrado de informes

Utiliza `redaudit_decrypt.py`:

```bash
# Descifra un informe JSON cifrado (se pedirá la contraseña)
python3 redaudit_decrypt.py /ruta/a/redaudit_20250115_213045.json.enc
```

El script:

1. Localiza el fichero `.salt` correspondiente.
2. Deriva la clave de cifrado.
3. Verifica integridad y descifra.
4. Escribe el resultado junto al fichero cifrado (mismo nombre sin `.enc`, salvo que elijas otro nombre cuando te lo pida).

Si se pierde la contraseña, no hay forma de recuperar el contenido de los informes. No existe mecanismo de "reset".

Para más detalles sobre el modelo de seguridad, consulta [SECURITY.md](SECURITY.md).

---

## 8. Modelo de seguridad

Para documentación completa de seguridad, consulta [SECURITY.md](SECURITY.md).

### 8.1 Seguridad de entrada y comandos

Todo dato externo se trata como no confiable:

- Validación estricta de tipos y formato (p. ej. CIDR, hostnames).
- Uso de `subprocess.run` con listas de argumentos, nunca `shell=True`.
- No se interpolan directamente valores del usuario en comandos de shell.

Esto reduce el riesgo de:

- Inyección de comandos.
- Ejecución accidental de código arbitrario.

---

### 8.2 Modelo de privilegios

- RedAudit necesita `sudo` principalmente por las operaciones de `nmap` y `tcpdump`.
- No instala demonios ni servicios persistentes con privilegios.
- Los artefactos e informes se crean con permisos restrictivos (p. ej. `0o600`) para evitar fugas hacia otros usuarios locales.

**Buena práctica:** solo personal de confianza debería lanzar RedAudit sobre redes de producción.

---

### 8.3 Seguridad operacional

Para reducir ruido e impacto:

- **Rate-limit y jitter configurables** para espaciar y variar las peticiones.
- **Capturas acotadas:** las capturas de `tcpdump` tienen duración limitada para evitar "sniffs" indefinidos.
- **Timeouts y reintentos** en procesos y conexiones para evitar bloqueos silenciosos.

Si algo falla, RedAudit intenta fallar de forma explícita, no silenciosa.

---

### 8.4 Uso ético y legal

RedAudit es una herramienta potente de escaneo. Úsala con responsabilidad:

- Ejecuta la herramienta solo sobre sistemas para los que tengas autorización explícita.
- Respeta políticas internas, ventanas de mantenimiento y legislación aplicable.
- No tomes decisiones críticas basadas únicamente en el output automatizado; siempre requiere revisión humana.

El autor y los colaboradores declinan cualquier responsabilidad por usos indebidos.

---

## 9. Herramientas externas

RedAudit orquesta varias herramientas de terceros. Resumen:

| Herramienta  | Condición de activación                 | Modo(s)              | Dónde aparece en el informe              |
|--------------|-----------------------------------------|----------------------|------------------------------------------|
| `nmap`       | Siempre                                 | Todos                | `host.ports[]`                           |
| `searchsploit` | Servicio con versión detectada        | Todos                | `ports[].known_exploits[]`               |
| `whatweb`    | Puerto HTTP/HTTPS detectado             | Todos                | `vulnerabilities[].whatweb`              |
| `nikto`      | Puerto HTTP/HTTPS detectado             | `full`               | `vulnerabilities[].nikto_findings`       |
| `curl`       | Puerto HTTP/HTTPS detectado             | Todos                | `vulnerabilities[].curl_headers`         |
| `wget`       | Puerto HTTP/HTTPS detectado             | Todos                | `vulnerabilities[].wget_headers`         |
| `openssl`    | Puerto HTTPS detectado                  | Todos                | `vulnerabilities[].tls_info`             |
| `testssl.sh` | Puerto HTTPS detectado                  | `full`               | `vulnerabilities[].testssl_analysis`     |
| `tcpdump`    | Escaneo profundo (PCAP) o captura L2 con `--redteam` | Todos (si aplica) | `deep_scan.pcap_capture` / `net_discovery.redteam.*` |
| `tshark`     | Tras capturar con tcpdump               | Todos (si aplica)    | `deep_scan.pcap_capture.tshark_summary`  |
| `dig` / `host` | Tras el escaneo de puertos            | Todos                | `host.dns`                               |
| `whois`      | Solo para IPs públicas                  | Todos                | `host.dns.whois_summary`                 |
| `fping`      | `--net-discovery` activado              | Todos                | `net_discovery.alive_hosts`              |
| `nbtscan`    | `--net-discovery netbios` activado      | Todos                | `net_discovery.netbios_hosts`            |
| `netdiscover` | `--net-discovery arp` activado         | Todos                | `net_discovery.arp_hosts`                |
| `avahi-browse` | `--net-discovery mdns` activado        | Todos                | `net_discovery.mdns_services`            |
| `snmpwalk`   | `--redteam` activado                    | Todos                | `net_discovery.redteam.snmp`             |
| `enum4linux` | `--redteam` activado (SMB)              | Todos                | `net_discovery.redteam.smb`              |
| `rpcclient`  | `--redteam` activado (RPC)              | Todos                | `net_discovery.redteam.rpc`              |
| `ldapsearch` | `--redteam` activado (LDAP)             | Todos                | `net_discovery.redteam.ldap`             |
| `kerbrute`   | `--redteam` activado (Kerberos; lista)  | Todos                | `net_discovery.redteam.kerberos.userenum` |
| `masscan`    | `--redteam` activado (opcional)         | Todos                | `net_discovery.redteam.masscan`          |

RedAudit no modifica la configuración de estas herramientas; las invoca con parámetros explícitos y analiza su salida.

---

## 10. Solución de Problemas

### Monitorización

Durante la ejecución, RedAudit muestra:

- Un "heartbeat" periódico indicando progreso (p. ej. "analizando host X de Y").
- Mensajes claros por fase: descubrimiento, escaneo de puertos, análisis web/TLS, escaneo profundo, generación de informes.

Para ejecuciones largas, basta con vigilar el heartbeat para confirmar que el proceso sigue avanzando.

### Problemas frecuentes (resumen)

1. **"Permission denied" / falta de root**
   - **Causa:** ejecución sin `sudo` (el modo completo requiere operaciones con sockets raw).
   - **Solución:** añadir `sudo` y comprobar que el usuario está en sudoers, o usar `--allow-non-root` para modo limitado.

2. **"Command not found" para nmap, whatweb, etc.**
   - **Causa:** dependencias sin instalar o instalación incompleta.
   - **Solución:** re-ejecutar `redaudit_install.sh` o instalar manualmente los paquetes con `apt`.

3. **"Decryption failed: Invalid token"**
   - **Causa:** contraseña incorrecta o fichero `.salt` ausente/corrupto.
   - **Solución:** revisar la contraseña, verificar que el fichero `.salt` está presente y válido.

4. **Escaneos aparentemente "congelados"**
   - **Causa:** escaneo profundo sobre un host complejo; es normal que algunos pasos tarden minutos.
   - **Solución:** comprobar el heartbeat; si es necesario, reducir el alcance, bajar concurrencia o usar `fast`/`normal`.

5. **Alias no disponible tras la instalación**
   - **Causa:** no se ha recargado el shell o el instalador se ejecutó como otro usuario.
   - **Solución:** `source ~/.bashrc` o `source ~/.zshrc`, y asegurarse de ejecutar el instalador desde el usuario final con `sudo`.

Para más detalles, consulta [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

---

## 11. Contribución y pruebas

El proyecto incluye un conjunto de pruebas y un script de verificación.

- **Pruebas con pytest:**

  ```bash
  cd /ruta/a/RedAudit
  pytest
  ```

- **Verificación rápida de la instalación:**

  ```bash
  bash redaudit_verify.sh
  ```

Al contribuir:

- Mantener el modelo de seguridad (nada de `shell=True`, ni ejecución de código arbitrario).
- Evitar cambios disruptivos en el esquema de informes salvo que sea imprescindible.
- Aportar pruebas para nuevas funcionalidades.

Consulta [CONTRIBUTING_ES.md](../../.github/CONTRIBUTING_ES.md) para las pautas detalladas.

---

## 12. Licencia y aviso legal

RedAudit se distribuye bajo la **Licencia Pública General de GNU, versión 3 (GPLv3)**:

- Puedes ejecutar, estudiar, modificar y redistribuir el software bajo las condiciones de la GPLv3.
- Cualquier obra derivada que redistribuyas debe mantener la misma licencia y poner su código fuente a disposición.

El software se ofrece "tal cual", sin garantías de ningún tipo, explícitas o implícitas, incluyendo, sin limitación, garantías de idoneidad para un propósito concreto.

El uso de RedAudit contra sistemas sin autorización puede constituir un delito. El autor declina toda responsabilidad derivada de usos indebidos.

---

**Documentación relacionada:**

- [README (Inglés)](../../README.md)
- [README (Español)](../../README_ES.md)
- [USAGE.md](USAGE.md) - Ejemplos de uso detallados
- [SECURITY.md](SECURITY.md) - Detalles del modelo de seguridad
- [REPORT_SCHEMA.md](REPORT_SCHEMA.md) - Esquema del informe JSON
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Resolución de problemas
- [CONTRIBUTING_ES.md](../../.github/CONTRIBUTING_ES.md) - Guía de contribución
- [CHANGELOG_ES.md](../../CHANGELOG_ES.md) - Historial de versiones
