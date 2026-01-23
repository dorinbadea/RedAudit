# Manual de Usuario de RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](MANUAL.en.md)

**Audiencia:** Analistas de seguridad, pentesters y administradores de sistemas.

**Alcance:** Instalación, operación, artefactos de salida y modelo de seguridad.

**Qué NO cubre este documento:** Técnicas de explotación y detalles internos del código.

**Fuente de verdad:** `redaudit --help`, `redaudit/core/auditor.py`

---

## 1. Qué Es (y Qué No Es) RedAudit

RedAudit es un **framework de auditoría de red automatizado** para Linux (familia Debian). Orquesta un toolchain completo (`nmap`, `nikto`, `nuclei`, `whatweb`, `testssl.sh`, `sqlmap`, `rustscan` y más) en un pipeline unificado y produce informes estructurados.

**Es:**

- Un orquestador de reconocimiento y descubrimiento de vulnerabilidades
- Un generador de informes (JSON, TXT, HTML, JSONL)
- Una herramienta para evaluaciones de seguridad autorizadas

**NO es:**

- Un framework de explotación
- Un reemplazo del análisis manual
- Diseñado para Windows o macOS

---

## 2. Requisitos y Permisos

| Requisito | Detalles |
| :--- | :--- |
| **SO** | Kali Linux, Debian 11+, Ubuntu 20.04+, Parrot OS |
| **Python** | 3.9+ |
| **Privilegios** | `sudo` / root requerido para: detección de SO, escaneos UDP, captura de paquetes (tcpdump) y descubrimiento ARP/L2 |
| **Dependencias** | El instalador proporciona el toolchain recomendado (nmap, whatweb, nikto, nuclei, searchsploit, tcpdump, tshark, etc.) e instala `testssl.sh` desde GitHub |

**Modo limitado:** `--allow-non-root` habilita funcionalidad reducida sin root (la detección de SO, UDP y tcpdump pueden fallar).

---

## 3. Instalación

### Instalación Estándar

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit && sudo bash redaudit_install.sh
```

El instalador:

1. Instala dependencias del sistema vía `apt`
2. Copia el código a `/usr/local/lib/redaudit`
3. Crea el alias `redaudit` en el shell
4. Solicita preferencia de idioma (EN/ES)

Política de versiones del toolchain (opcional):

```bash
# Usa versiones latest para herramientas descargadas de GitHub (testssl, kerbrute)
REDAUDIT_TOOLCHAIN_MODE=latest sudo bash redaudit_install.sh

# O fija versiones específicas
TESTSSL_VERSION=v3.2 KERBRUTE_VERSION=v1.0.3 RUSTSCAN_VERSION=2.3.0 sudo bash redaudit_install.sh
```

### Instalación Manual (sin instalador)

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo apt install nmap whatweb nikto tcpdump tshark exploitdb python3-nmap python3-cryptography
sudo python3 -m redaudit --help
```

### Instalación de Desarrollador / Reproducible (vía pip)

Para coincidencia exacta de dependencias (cumplimiento Fase 5), usa un entorno virtual:

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.lock
pip install .
```

Usuarios de Poetry pueden apoyarse en `poetry.lock` para evaluacion; pip-tools sigue siendo la fuente de verdad de los lockfiles.

Los checks TLS profundos requieren `testssl.sh`. El instalador lo instala desde GitHub como parte del toolchain principal.

### Docker (opcional)

Ejecuta la imagen oficial en GHCR:

```bash
docker pull ghcr.io/dorinbadea/redaudit:latest

docker run --rm --network host \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v "$(pwd)/reports:/reports" \
  ghcr.io/dorinbadea/redaudit:latest \
  --target 192.168.1.0/24 --mode normal --yes --output /reports
```

### Actualización

RedAudit verifica actualizaciones al iniciar (modo interactivo). Para omitir: `--skip-update-check`.
Si mantienes un checkout git en `~/RedAudit`, el updater refresca tags y hace fast‑forward de `main` cuando el repo está limpio para evitar prompts desfasados. Los cambios locales o ramas distintas de `main` no se tocan.

---

## 4. Guía Completa del Asistente Interactivo (The Wizard)

El asistente interactivo es la forma recomendada de usar RedAudit. Le guía paso a paso para configurar el escaneo perfecto según sus necesidades.

### Flujo de Trabajo

1. **Inicio y Actualizaciones:** Al ejecutar `sudo redaudit`, la herramienta verifica automáticamente si hay nuevas versiones (a menos que use `--skip-update-check`).
2. **Selección de Perfil:** Elija un preset o configure manualmente.
3. **Selección de Objetivos:** Elija redes detectadas o introduzca objetivos manuales; el asistente muestra los objetivos normalizados con hosts estimados.
4. **Configuración de Autenticación:** (Nuevo en v4.0) Configure credenciales SSH/SMB/SNMP para auditorías profundas.
5. **Confirmación:** Revise el resumen antes de iniciar.

### Perfiles de Escaneo

Los perfiles preconfigurados ajustan docenas de parámetros automáticamente:

#### 1. Express (Rápido / Inventario)

**Objetivo:** Obtener una lista de hosts vivos y sus fabricantes en segundos.

- **Técnica:** Ping Sweep (ICMP/ARP), sin escaneo de puertos.
- **Ideal para:** Inventario de activos inicial, verificar conectividad.
- **Tiempo estimado:** < 30s para /24.

#### 2. Standard (Equilibrado / Auditoría General)

**Objetivo:** Identificar servicios comunes y vulnerabilidades obvias.

- **Técnica:** Top 100 puertos TCP (`-F`), detección de versiones y SO.
- **Web:** Revisa cabeceras y tecnologías básicas (WhatWeb).
- **Autenticación:** Configuración opcional de credenciales SSH/SMB/SNMP.
- **Ideal para:** Auditorías regulares, validación de políticas.

#### 3. Exhaustive (Profundo / Cumplimiento)

**Objetivo:** Encontrar TODO.

- **Técnica:** 65535 puertos TCP, escaneo UDP, scripts de vulnerabilidad (NSE).
- **Web:** Escaneo completo (Nikto, Nuclei, SSL).
- **Autenticación:** Configuración opcional de credenciales SSH/SMB/SNMP.
- **Ideal para:** Pentesting, compliance (PCI-DSS, ISO 27001), validación pre-producción.

#### 4. Custom (A Medida)

**Objetivo:** Control total.

- **Permite configurar:**
  - **Modo Nmap:** Fast/Normal/Full.
  - **Temporización:** Sigiloso/Normal/Agresivo.
  - **Rendimiento:** Hilos (1-16) y Rate Limit (segundos entre peticiones).
  - **Topología & Discovery:** Activar/desactivar mapeo L2 y protocolos de descubrimiento (mDNS, UPnP, etc.).
  - **UDP:** Activar escaneo UDP (lento pero exhaustivo).
  - **Autenticación:** Configurar credenciales para escaneo autenticado.
  - **Verificación Sin Agente:** Habilitar/deshabilitar comprobaciones ligeras.
  - **Web & Vulnerabilidades:** Activar/desactivar Nikto, Nuclei, CVE lookup.

### Menú de Autenticación (Fase 4)

Si selecciona los perfiles **Standard**, **Exhaustive** o **Custom**, el asistente le preguntará:
`¿Desea configurar escaneo autenticado? [s/n]`

Si responde **Sí**, accederá al sub-menú de credenciales:

1. **SSH (Linux/Unix):**
    - Usuario y Contraseña O Clave Privada.
    - Permite auditoría de paquetes, hardening (Lynis) y configuraciones internas.
2. **SMB (Windows):**
    - Usuario, Contraseña y Dominio (opcional).
    - Permite enumerar usuarios, recursos compartidos y políticas de contraseña.
3. **SNMP v3 (Red):**
    - Usuario, Protocolos de Autenticación (MD5/SHA) y Privacidad (DES/AES).
    - Permite extraer tablas de enrutamiento y configuraciones de dispositivos de red.

**Nota:** Las credenciales se pueden guardar de forma segura en el anillo de claves del sistema (Keyring) para futuros usos.

### Ejemplos de Escenarios (Tutorial)

#### Escenario A: Auditoría Rápida de Inventario

1. Ejecute `sudo redaudit`.
2. Seleccione **Express**.
3. Introduzca el rango IP del cliente (ej. `192.168.10.0/24`).
4. Resultado: En minutos tendrá un `assets.jsonl` con todos los dispositivos vivos y sus fabricantes.

#### Escenario B: Auditoría de Hardening de Servidores Linux

1. Ejecute `sudo redaudit`.
2. Seleccione **Custom**.
3. Modo: **Normal**.
4. Autenticación habilitada: **Sí**.
    - Configure usuario `root` (o sudoer) y clave SSH.
5. Habilitar Lynis: **Sí** (si se pregunta o vía flag `--lynis`).
6. Resultado: El informe incluirá el "Hardening Index" de Lynis y detalles internos de los servidores.

#### Escenario C: Red Team / Stealth

1. Ejecute `sudo redaudit`.
2. Seleccione **Custom**.
3. Modo: **Stealth** (reduce velocidad, evita detección IDS simple).
4. Topología: **Pasiva** (solo escucha, sin ARP agresivo).
5. Resultado: Mapeo de red con mínima huella de ruido.

---

## 5. Operación

### Modos de Ejecución

| Modo | Invocación | Comportamiento |
| :--- | :--- | :--- |
| **Interactivo** | `sudo redaudit` | Wizard basado en texto; solicita objetivo, modo, opciones |
| **No interactivo** | `sudo redaudit --target X --yes` | Ejecución directa; todas las opciones vía flags CLI |

### Modos de Escaneo (`--mode`)

| Modo | Comportamiento nmap | Herramientas Adicionales |
| :--- | :--- | :--- |
| `fast` | `-sn` (solo descubrimiento de hosts) | Ninguna |
| `normal` | Top 100 puertos (`-F`), detección de versiones | whatweb, searchsploit |
| `full` | Los 65535 puertos, scripts, detección de SO | whatweb, nikto, testssl.sh, nuclei (instalado y habilitado explícitamente), searchsploit |

**Guía (beneficios/riesgos):**

- **fast**: Mínimo ruido y más rápido. Ideal para inventario o entornos frágiles; sin detalle de servicios.
- **normal**: Equilibrio entre tiempo y cobertura. Recomendado como opción por defecto en la mayoría de LAN.
- **full**: Máxima cobertura e identidad más profunda. Mayor duración y más ruido; puede estresar dispositivos frágiles.

**Comportamiento de timeout:** Los escaneos de host están limitados por el `--host-timeout` de nmap del modo elegido
(full: 300s). RedAudit aplica un timeout duro y marca el host como sin respuesta si se supera, manteniendo el escaneo
fluido en dispositivos IoT/embebidos.

### Presets de Velocidad (Wizard)

La velocidad controla la agresividad del scheduling (timing de nmap y comportamiento de hilos).

- **Sigiloso**: El más lento y con menos ruido. Útil en redes sensibles a la detección.
- **Tecnología Smart-Check**: Correlaciona puertos abiertos (Nmap) con vulnerabilidades (Nuclei) para eliminar falsos positivos.
- **Descubrimiento Paralelo (v4.6.32)**: Ejecuta DHCP, ARP, mDNS, UPnP y Fping simultáneamente para un mapeo ultra-rápido.
- **Interfaz de descubrimiento DHCP**: Por defecto usa la interfaz de la ruta por defecto; en modo `completo` prueba todas las interfaces IPv4 activas con un timeout corto.
- **HyperScan**: Utiliza paquetes asíncronos TCP/SYN para escanear 65,535 puertos en segundos (integración RustScan).

### Deep Scan Adaptativo

Cuando está habilitado (por defecto), RedAudit realiza escaneos adicionales en hosts donde los resultados iniciales son ambiguos o indican infraestructura virtual:

**Condiciones de disparo:**

- Menos de 3 puertos abiertos encontrados (cuando la identidad es débil)
- Servicios identificados como `unknown` o `tcpwrapped`
- Información MAC/fabricante no obtenida
- Sin versión de servicio y sin evidencia fuerte de identidad (título/servidor o tipo de dispositivo)
- **Detección de Gateway VPN**: El host comparte la dirección MAC con el gateway pero tiene una IP diferente (interfaz virtual)

**Comportamiento:**

0. (Opcional) Fase 0 de enriquecimiento de bajo impacto (DNS reverso, mDNS unicast, SNMP sysDescr) al activarlo en el asistente o con `--low-impact-enrichment`
1. Fase 1: TCP agresivo (`-A -p- -sV -Pn`)
2. Fase 2a: Sonda UDP prioritaria (17 puertos comunes incluyendo 500/4500)
3. Fase 2b: UDP top-ports (`--udp-ports`) cuando el modo es `full` y la identidad sigue débil
4. Hosts silenciosos con fabricante detectado y cero puertos abiertos pueden recibir una sonda HTTP/HTTPS breve en rutas habituales para resolver identidad antes

Deshabilitar con `--no-deep-scan`.

SmartScan usa una puntuación de identidad (umbral por defecto: 3; modo full usa 4) para decidir si escalar.

La clasificación VPN se realiza mediante heurísticas de tipado de activo (MAC/IP de gateway, puertos VPN, patrones de hostname).

### Smart-Throttle (Control de Congestión Adaptativo)

RedAudit v4.4+ introduce **Smart-Throttle**, un sistema de límite de tasa adaptativo para operaciones HyperScan.

- **Algoritmo**: Utiliza un algoritmo de Incremento Aditivo, Decremento Multiplicativo (AIMD) similar al control de congestión TCP.
- **Comportamiento**:
  - Comienza con un tamaño de lote conservador (500 paquetes).
  - **Acelera** (Linealmente) cuando la red es estable (timeouts < 1%).
  - **Estrangula** (Multiplicativamente) cuando se detecta congestión (timeouts > 5%).
- **Beneficio**: Previene la pérdida de paquetes en redes SOHO/VPN mientras maximiza la velocidad en enlaces de Data Center (escalando hasta 20,000 pps).
- **Feedback**: La velocidad de escaneo y eventos de throttling (▼/▲) se muestran en tiempo real en la barra de progreso.
- **Salida de progreso**: Cuando HyperScan usa barra Rich, se suprimen líneas por host para evitar UI mixta. La barra muestra detalle por IP.

**Ejecución Paralela:**
A partir de v4.2, los deep scans se ejecutan en un pool de hilos dedicado (hasta 50 hilos), desacoplado del bucle principal de descubrimiento. Esto asegura que los escaneos profundos lentos no bloqueen el progreso global.

### Seguridad de Aplicaciones Web (v4.2+)

RedAudit ahora integra herramientas especializadas para evaluación profunda de aplicaciones web:

- **sqlmap**: Prueba automáticamente fallos de inyección SQL en parámetros sospechosos. Configurable vía Perfil de Mago (Niveles 1-5, Riesgos 1-3).
- **OWASP ZAP**: Escaneo DAST opcional para spidering y escaneo activo. Se activa vía Perfil Custom o config.
  - Ambas herramientas se omiten en dispositivos de infraestructura cuando la evidencia de identidad indica router/switch/AP.

### Ejecuciones Parciales de Nuclei

Cuando los lotes de Nuclei agotan tiempo, la ejecución se marca como parcial y el informe incluye los índices de lotes con timeout y fallidos.
Durante lotes largos, la CLI muestra progreso dentro del batch basado en tiempo (con tiempo transcurrido) para confirmar actividad.

### Perfiles y Cobertura de Nuclei (v4.17+)

Nuclei tiene dos controles independientes en el asistente:

- **Perfil (plantillas)**: `full`, `balanced`, `fast` controla qué plantillas y severidades se ejecutan.
- **Cobertura completa (objetivos)**: "Escanear TODOS los puertos HTTP detectados?" controla cuántas URLs HTTP por host se escanean.
  - **No** (por defecto en balanced/fast): Máx 2 URLs por host multipuerto (prioriza 80/443).
  - **Sí** (por defecto en full): Escanea todos los puertos HTTP detectados por host (además de 80/443).

Estas opciones son distintas: el perfil define el alcance de plantillas y la cobertura completa define el alcance de objetivos.

### Auto-Exclusión

Las direcciones IP del propio auditor se detectan automáticamente y se excluyen de la lista de objetivos para evitar bucles de auto-escaneo redundantes.

### Verificación sin agente (Opcional)

Cuando está habilitado, RedAudit ejecuta scripts ligeros de Nmap sobre hosts con SMB/RDP/LDAP/SSH/HTTP para enriquecer la
identidad (pistas de SO, dominio, títulos/cabeceras y fingerprints básicos). No usa credenciales y es opt-in para mantener el ruido
controlado.

- Activar desde el asistente o con `--agentless-verify`.
- Limitar alcance con `--agentless-verify-max-targets` (defecto: 20).

---

## 6. Escaneo Autenticado (Fase 4)

RedAudit v4.0+ soporta el escaneo autenticado para obtener datos de alta fidelidad de los hosts objetivo, incluyendo versiones de SO, paquetes instalados y configuraciones.

### Protocolos Soportados

| Protocolo | SO Objetivo | Requisitos | Features de Descubrimiento |
| :--- | :--- | :--- | :--- |
| **SSH** | Linux/Unix | Credenciales estándar (contraseña o clave privada) | SO Preciso (kernel), Paquetes Instalados, Hostname, Uptime |
| **SMB/WMI** | Windows | librería `impacket`, credenciales de Administrador | Versión SO, Dominio/Grupo de Trabajo, Recursos Compartidos, Usuarios |

### Prerrequisitos

- **SSH**: Requiere `paramiko` (instalado por el instalador).
- **SMB/WMI**: Requiere `impacket` (instalado por el instalador).
- **SNMP v3**: Requiere `pysnmp` (instalado por el instalador).

  ```bash
  # Si se necesita instalacion manual:
  pip install paramiko impacket pysnmp
  ```

### Configuración

#### Interactivo (Wizard)

Cuando se pregunte "¿Habilitar escaneo autenticado (SSH/SMB)?", seleccione Sí. Si hay credenciales guardadas, el asistente ofrece cargarlas primero y luego pregunta si deseas añadir más. Los ajustes se pueden guardar en un anillo de claves seguro o archivo de configuración.

#### Argumentos CLI

```bash
# SSH
sudo redaudit -t 192.168.1.10 --ssh-user root --ssh-key ~/.ssh/id_rsa
sudo redaudit -t 192.168.1.10 --ssh-user admin --ssh-pass "S3cr3t"

# SMB (Windows)
sudo redaudit -t 192.168.1.50 --smb-user Administrator --smb-pass "WinPass123" --smb-domain WORKGROUP
```

### Nota de Seguridad

Las credenciales se usan ÚNICAMENTE para el escaneo y no se almacenan en los informes. Si se usa la integración con `keyring`, se almacenan en el anillo de claves del sistema.

---

## 7. Referencia CLI (Completa)

Flags verificadas contra `redaudit --help` (v4.5.2):

### Core

| Flag | Descripción |
| :--- | :--- |
| `-t, --target CIDR` | Objetivos (CIDR/IP/rango), separados por comas |
| `-m, --mode {fast,normal,full}` | Intensidad del escaneo (defecto: normal) |
| `-o, --output DIR` | Directorio de salida (defecto: `~/Documents/RedAuditReports` o `~/Documentos/RedAuditReports`) |
| `-y, --yes` | Omitir prompts de confirmación |
| `-V, --version` | Imprimir versión y salir |

### Rendimiento

| Flag | Descripción |
| :--- | :--- |
| `-j, --threads 1-100` | Workers concurrentes por host (autodetectado) |
| `--rate-limit SECONDS` | Retardo entre hosts (se aplica jitter ±30%) |
| `--max-hosts N` | Limitar hosts a escanear |
| `--no-deep-scan` | Deshabilitar deep scan adaptativo |
| `--low-impact-enrichment` | Enriquecimiento de bajo impacto (DNS/mDNS/SNMP) antes del escaneo TCP |
| `--deep-scan-budget N` | Máximo de hosts que pueden ejecutar deep scan agresivo por ejecución (0 = sin límite) |
| `--identity-threshold N` | Umbral mínimo de identity_score para omitir deep scan (defecto: 3) |
| `--stealth` | Timing T1, 1 hilo, retardo 5s (entornos sensibles a la detección) |

### Escaneo UDP

| Flag | Descripción |
| :--- | :--- |
| `--udp-mode {quick,full}` | quick = solo puertos prioritarios; full = top N puertos |
| `--udp-ports N` | Número de top ports para modo full (50-500, defecto: 100) |

### Topología y Descubrimiento

| Flag | Descripción |
| :--- | :--- |
| `--topology` | Habilitar descubrimiento de topología L2/L3 |
| `--no-topology` | Deshabilitar descubrimiento de topología |
| `--topology-only` | Ejecutar solo topología, omitir escaneo de hosts |
| `--net-discovery [PROTOCOLS]` | Descubrimiento broadcast (all, o: dhcp,netbios,mdns,upnp,arp,fping) |
| `--net-discovery-interface IFACE` | Interfaz para descubrimiento |
| `--redteam` | Incluir técnicas Red Team (SNMP, SMB, LDAP, Kerberos) |
| `--redteam-max-targets N` | Máximo de objetivos para checks redteam (defecto: 50) |
| `--redteam-active-l2` | Habilitar checks L2 más ruidosos (bettercap/scapy) |
| `--snmp-community COMMUNITY` | Comunidad SNMP para walking (defecto: public) |
| `--dns-zone ZONE` | Hint de zona DNS para AXFR (opcional) |
| `--kerberos-realm REALM` | Hint de reino Kerberos (opcional) |
| `--kerberos-userlist PATH` | Lista de usuarios para userenum Kerberos (opcional; requiere kerbrute) |

### Seguridad

| Flag | Descripción |
| :--- | :--- |
| `-e, --encrypt` | Cifrar informes (AES-128-CBC vía Fernet) |
| `--encrypt-password PASSWORD` | Contraseña para cifrado (o se genera aleatoriamente) |
| `--allow-non-root` | Ejecutar sin sudo (funcionalidad limitada) |

### Autenticación (Credenciales)

| Flag | Descripción |
| :--- | :--- |
| `--auth-provider {env,keyring}` | Proveedor de credenciales (variables de entorno o keyring del sistema) |
| `--ssh-user USER` | Usuario SSH para escaneo autenticado |
| `--ssh-key PATH` | Ruta a la clave privada SSH |
| `--ssh-key-pass PASSPHRASE` | Frase de paso de la clave privada SSH |
| `--ssh-trust-keys` | Confiar en claves SSH desconocidas (usar con precaución) |
| `--smb-user USER` | Usuario SMB/Windows |
| `--smb-pass PASSWORD` | Contraseña SMB/Windows |
| `--smb-domain DOMAIN` | Dominio SMB/Windows |
| `--snmp-user USER` | Usuario SNMP v3 |
| `--snmp-auth-proto {SHA,MD5,...}` | Protocolo de autenticación SNMP v3 |
| `--snmp-auth-pass PASSWORD` | Contraseña de autenticación SNMP v3 |
| `--snmp-priv-proto {AES,DES,...}` | Protocolo de privacidad SNMP v3 |
| `--snmp-priv-pass PASSWORD` | Contraseña de privacidad SNMP v3 |
| `--lynis` | Ejecutar auditoría de hardening Lynis en hosts Linux (requiere SSH) |
| `--credentials-file PATH` | Fichero JSON con lista de credenciales (detecta protocolo automáticamente) |
| `--generate-credentials-template` | Generar plantilla de credenciales vacía y salir |

#### Soporte Multi-Credencial (Universal)

RedAudit soporta **credential spraying universal**: proporcionas pares usuario/contraseña sin especificar el protocolo, y RedAudit detecta automáticamente qué protocolo usar basándose en los puertos abiertos descubiertos durante el escaneo.

**Cómo funciona:**

1. Configuras credenciales mediante el asistente (modo Universal) o `--credentials-file`
2. RedAudit escanea la red y descubre puertos abiertos
3. Para cada host, mapea puertos abiertos a protocolos:
   - Puerto 22 → SSH
   - Puerto 445/139 → SMB
   - Puerto 161 → SNMP
   - Puerto 3389 → RDP
   - Puerto 5985/5986 → WinRM
4. Prueba cada credencial hasta que una funcione (máx. 3 intentos por host para evitar bloqueos)

**Modo Legado (SSH/SMB Individual):**

Si necesitas utilizar una clave SSH específica o un par de credenciales único para un protocolo (comportamiento legado), selecciona el modo **Avanzado** en el asistente o usa los flags específicos (`--ssh-user`, `--ssh-key`, etc.). Estos tendrán preferencia para ese protocolo o servirán como respaldo si las credenciales universales fallan.

**Usando el asistente (recomendado):**

```text
? ¿Habilitar escaneo autenticado? [s/n]: s
Modo de configuración de credenciales:
  [0] Universal (simple): detectar protocolo automáticamente
  [1] Avanzado: configurar SSH/SMB/SNMP por separado
> 0

--- Credencial 1 ---
? Usuario: admin
? Contraseña (oculta): ****
? ¿Añadir otra credencial? [s/n]: s

--- Credencial 2 ---
? Usuario: root
? Contraseña (oculta): ****
? ¿Añadir otra credencial? [s/n]: n

Configuradas 2 credenciales para detección automática de protocolo.
```

**Usando un fichero de credenciales:**

```bash
# Generar plantilla
redaudit --generate-credentials-template

# Editar ~/.redaudit/credentials.json
{
  "credentials": [
    {"user": "admin", "pass": "admin123"},
    {"user": "root", "pass": "toor"},
    {"user": "administrator", "pass": "P@ssw0rd", "domain": "WORKGROUP"}
  ]
}

# Ejecutar escaneo con credenciales
sudo redaudit -t 192.168.1.0/24 --credentials-file ~/.redaudit/credentials.json --yes
```

**Consideraciones de seguridad:**

- Los ficheros de credenciales se guardan con permisos `0600` (solo lectura/escritura del propietario)
- Las contraseñas nunca se registran en los informes
- Usar keyring para entornos de producción (`--auth-provider keyring`)

### HyperScan

| Flag | Descripción |
| :--- | :--- |
| `--hyperscan-mode {auto,connect,syn}` | Modo HyperScan: auto (defecto), connect o syn |

### Informes

| Flag | Descripción |
| :--- | :--- |
| `--html-report` | Generar dashboard HTML interactivo |
| `--webhook URL` | POST alertas para hallazgos high/critical |
| `--no-txt-report` | Omitir generación de informe TXT |
| `--no-vuln-scan` | Omitir escaneo nikto/vulnerabilidades web |
| `--nuclei` | Habilitar escaneo de plantillas Nuclei (requiere `nuclei`) |
| `--no-nuclei` | Deshabilitar Nuclei (ignora defaults) |
| `--nuclei-timeout N` | Timeout por lote de Nuclei en segundos (defecto: 300) |
| `--profile {fast,balanced,full}` | Intensidad de escaneo Nuclei (v4.11+) |

### Verificación (Sin Agente)

| Flag | Descripción |
| :--- | :--- |
| `--agentless-verify` | Verificación sin agente (SMB/RDP/LDAP/SSH/HTTP) |
| `--no-agentless-verify` | Desactivar verificación sin agente (sobrescribe defaults) |
| `--agentless-verify-max-targets N` | Límite de objetivos (1-200, defecto: 20) |

### Correlación CVE

| Flag | Descripción |
| :--- | :--- |
| `--cve-lookup` | Habilitar correlación API NVD |
| `--nvd-key KEY` | Clave API para rate limits más rápidos |

### Comparación

| Flag | Descripción |
| :--- | :--- |
| `--diff OLD NEW` | Comparar dos informes JSON (sin escaneo) |

### Otros

| Flag | Descripción |
| :--- | :--- |
| `--dry-run` | Imprimir comandos sin ejecutar |
| `--no-prevent-sleep` | No inhibir suspensión del sistema durante escaneo |
| `--ipv6` | Modo solo IPv6 |
| `--proxy URL` | Proxy SOCKS5 (socks5://host:port; requiere proxychains4, solo TCP) |
| `--lang {en,es}` | Idioma de interfaz |
| `--no-color` | Deshabilitar salida con colores |
| `--save-defaults` | Guardar ajustes actuales en ~/.redaudit/config.json |
| `--defaults {ask,use,ignore}` | Controlar cómo se aplican los defaults persistentes |
| `--use-defaults` | Usar defaults guardados sin preguntar |
| `--ignore-defaults` | Ignorar defaults guardados |
| `--skip-update-check` | Omitir verificación de actualizaciones al iniciar |

**Nota:** `--proxy` envuelve herramientas externas con `proxychains4` y solo afecta sondas TCP (connect). El descubrimiento UDP/ARP/ICMP es directo.

---

## 8. Artefactos de Salida

Ruta de salida por defecto: `~/Documents/RedAuditReports/RedAudit_YYYY-MM-DD_HH-MM-SS/` o `~/Documentos/RedAuditReports/RedAudit_YYYY-MM-DD_HH-MM-SS/`

### Ficheros Generados

| Fichero | Condición | Descripción |
| :--- | :--- | :--- |
| `redaudit_*.json` | Siempre | Resultados estructurados completos |
| `redaudit_*.txt` | A menos que `--no-txt-report` | Resumen legible por humanos |
| `report.html` | Si `--html-report` | Dashboard interactivo |
| `findings.jsonl` | Si cifrado deshabilitado | Eventos JSONL para SIEM (campos alineados con ECS vía configs) |
| `assets.jsonl` | Si cifrado deshabilitado | Inventario de activos |
| `summary.json` | Si cifrado deshabilitado | Métricas para dashboards |
| `run_manifest.json` | Si cifrado deshabilitado | Metadatos de sesión + snapshot de config/pipeline |
| `playbooks/*.md` | Si cifrado deshabilitado | Guías de remediación |
| `traffic_*.pcap` | Si se dispara deep scan y tcpdump disponible | Capturas de paquetes |
| `session_logs/session_*.log` | Siempre | Logs de sesión (raw con ANSI) |
| `session_logs/session_*.txt` | Siempre | Logs de sesión (texto limpio) |

### Comportamiento del Cifrado

Cuando se usa `--encrypt`:

- `.json` y `.txt` se convierten en `.json.enc` y `.txt.enc`
- Se crea un fichero `.salt` junto a cada fichero cifrado
- **Los artefactos en texto plano NO se generan:** HTML, JSONL, playbooks y ficheros manifest se omiten por seguridad

**Evidencia y transparencia del pipeline:**

- El JSON principal incluye metadatos de evidencia por hallazgo (herramienta fuente, matched_at, hash/ref de salida cruda si aplica).
- El HTML muestra los args/timing de Nmap, ajustes de deep scan, el resumen HyperScan vs final y el resultado del escaneo autenticado cuando existe.

**Descifrado:**

```bash
python3 redaudit_decrypt.py /ruta/a/informe.json.enc
```

---

## 9. Modelo de Seguridad

### Cifrado

- Algoritmo: AES-128-CBC (especificación Fernet)
- Derivación de clave: PBKDF2-HMAC-SHA256 con salt aleatorio
- Política de contraseña: el prompt interactivo exige 12+ caracteres con complejidad; `--encrypt-password` no se valida

### Modelo de Privilegios

- Root requerido para: detección de SO con nmap, tcpdump, escaneo ARP
- Ficheros creados con permisos 0o600 (solo lectura/escritura del propietario)
- No se instalan servicios en segundo plano ni demonios

### Validación de Entrada

- Todos los argumentos CLI validados contra restricciones de tipo y rango
- Sin `shell=True` en llamadas subprocess
- CIDR de objetivo validado antes de usar

---

## 10. Integración

### Ingesta SIEM

Ver [SIEM_INTEGRATION.en.md](SIEM_INTEGRATION.en.md) para guías completas (Elastic Stack y otros SIEM).

Cuando el cifrado está deshabilitado, `findings.jsonl` proporciona eventos JSONL para SIEM (alineados a ECS vía configs).
El ejemplo de Splunk HEC a continuación es opcional y requiere configuración externa de Splunk.

```bash
# Ingesta bulk a Elasticsearch
cat findings.jsonl | curl -X POST "localhost:9200/redaudit/_bulk" \
  -H 'Content-Type: application/x-ndjson' --data-binary @-

# Splunk HEC
cat findings.jsonl | while read line; do
  curl -k "https://splunk:8088/services/collector" \
    -H "Authorization: Splunk TOKEN" -d "{\"event\":$line}"
done
```

### Alertas Webhook

`--webhook URL` envía HTTP POST para cada hallazgo high/critical. Compatible con endpoints que aceptan JSON (p. ej., Slack, Teams, PagerDuty).

---

## 11. Solución de Problemas

| Síntoma | Causa | Solución |
| :--- | :--- | :--- |
| Permission denied | Ejecutando sin sudo | Usar `sudo redaudit` |
| nmap: command not found | Dependencia faltante | Ejecutar `sudo bash redaudit_install.sh` |
| Decryption failed: Invalid token | Contraseña incorrecta o .salt corrupto | Verificar contraseña; asegurar que existe fichero .salt |
| El escaneo parece congelado | Deep scan o host lento | Revisar `session_logs/` para ver la herramienta activa; reducir alcance con `--max-hosts` |
| No se generan playbooks | Cifrado habilitado | Los playbooks requieren que `--encrypt` esté deshabilitado |

Ver [TROUBLESHOOTING.es.md](TROUBLESHOOTING.es.md) para referencia completa de errores.

---

## 12. Herramientas Externas

RedAudit orquesta (no modifica ni instala):

| Herramienta | Condición de Invocación | Campo del Informe |
| :--- | :--- | :--- |
| `nmap` | Siempre | `hosts[].ports` |
| `whatweb` | HTTP/HTTPS detectado | `vulnerabilities[].whatweb` |
| `nikto` | HTTP/HTTPS + modo full | `vulnerabilities[].nikto_findings` |
| `sqlmap` | HTTP/HTTPS + modo full (v4.2+) | `vulnerabilities[].sqlmap_findings` |
| `zaproxy` | HTTP/HTTPS + modo full (si habilitado) | `vulnerabilities[].zap_findings` |
| `testssl.sh` | HTTPS + modo full | `vulnerabilities[].testssl_analysis` |
| `nuclei` | HTTP/HTTPS + modo full (si está instalado y habilitado) | `vulnerabilities[].nuclei_findings` |
| `searchsploit` | Servicios con versión detectada | `ports[].known_exploits` |
| `tcpdump` | Se dispara deep scan | `deep_scan.pcap_capture` |
| `tshark` | Tras captura tcpdump | `deep_scan.tshark_summary` |

---

[Volver al README](../ES/README_ES.md) | [Índice de Documentación](INDEX.md)
