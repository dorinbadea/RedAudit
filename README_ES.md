# RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](README.md)

RedAudit es una herramienta CLI para auditoría de red estructurada y hardening en sistemas Kali/Debian.

![Version](https://img.shields.io/badge/version-3.0.1-blue?style=flat-square)
![License](https://img.shields.io/badge/license-GPLv3-red?style=flat-square)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey?style=flat-square)
![CI/CD](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/dorinbadea/81671a8fffccee81ca270f14d094e5a1/raw/redaudit-tests.json&style=flat-square&label=CI%2FCD)

```text
 ____          _    _             _ _ _   
|  _ \ ___  __| |  / \  _   _  __| (_) |_ 
| |_) / _ \/ _` | / _ \| | | |/ _` | | __|
|  _ <  __/ (_| |/ ___ \ |_| | (_| | | |_ 
|_| \_\___|\__,_/_/   \_\__,_|\__,_|_|\__|
                                     v3.0.1
     Herramienta Interactiva de Auditoría de Red
```

## Visión General

RedAudit automatiza las fases de descubrimiento, enumeración y reporte en evaluaciones de seguridad de red. Está diseñado para su uso en entornos de laboratorio controlados, flujos de trabajo de hardening defensivo y ejercicios de seguridad ofensiva autorizados. Al orquestar herramientas estándar de la industria en un pipeline concurrente coherente, reduce la carga manual y garantiza una generación de resultados consistente.

La herramienta cubre la brecha entre el escaneo ad-hoc y la auditoría formal, proporcionando artefactos estructurados (JSON/TXT) listos para su ingesta en frameworks de reporte o análisis SIEM.

## Arquitectura

RedAudit opera como una capa de orquestación, gestionando hilos de ejecución concurrentes para la interacción de red y el procesamiento de datos. Implementa una arquitectura de dos fases: descubrimiento genérico seguido de escaneos profundos dirigidos.

| **Categoría** | **Herramientas** | **Propósito** |
|:---|:---|:---|
| **Escáner Core** | `nmap`, `python3-nmap` | Escaneo de puertos TCP/UDP, detección de servicios/versión, fingerprinting de SO. |
| **Reconocimiento Web** | `whatweb`, `curl`, `wget`, `nikto` | Analiza cabeceras HTTP, tecnologías y vulnerabilidades. |
| **Inteligencia de Exploits** | `searchsploit` | Búsqueda automática en ExploitDB para servicios con versiones detectadas. |
| **Análisis SSL/TLS** | `testssl.sh` | Escaneo profundo de vulnerabilidades SSL/TLS (Heartbleed, POODLE, cifrados débiles). |
| **Captura de Tráfico** | `tcpdump`, `tshark` | Captura de paquetes de red para análisis detallado de protocolos. |
| **DNS/Whois** | `dig`, `whois` | Búsquedas DNS inversas e información de propiedad para IPs públicas. |
| **Orquestador** | `concurrent.futures` (Python) | Gestiona pools de hilos para escaneo paralelo de hosts. |
| **Cifrado** | `python3-cryptography` | Cifrado AES-128 para reportes de auditoría sensibles. |

### Vista General del Sistema

![Vista General del Sistema](docs/images/system_overview_es_v3.png)

Los escaneos profundos se activan selectivamente: los módulos de auditoría web solo se lanzan tras la detección de servicios HTTP/HTTPS, y la inspección SSL se reserva para puertos cifrados.

## Instalación

RedAudit requiere un entorno basado en Debian (se recomienda Kali Linux) y privilegios `sudo` para acceso a sockets raw.

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

### Asistente Interactivo

El asistente te guiará:

1. **Selección de Objetivo**: Elige una subred local o introduce un CIDR manual (ej: `10.0.0.0/24`)
2. **Modo de Escaneo**: Selecciona RÁPIDO, NORMAL o COMPLETO
3. **Opciones**: Configura hilos, límite de velocidad y cifrado
4. **Autorización**: Confirma que tienes permiso para escanear

### Modo No Interactivo

Para automatización y scripting:

```bash
# Escaneo básico
sudo redaudit --target 192.168.1.0/24 --mode normal

# Escaneo completo con cifrado
sudo redaudit --target 10.0.0.0/24 --mode full --threads 8 --encrypt --output /tmp/reports

# Múltiples objetivos
sudo redaudit --target "192.168.1.0/24,10.0.0.0/24" --mode normal --threads 6

    # Saltar advertencia legal (para automatización)
    sudo redaudit --target 192.168.1.0/24 --mode fast --yes

    # Con cifrado (contraseña aleatoria generada)
    sudo redaudit --target 192.168.1.0/24 --mode normal --encrypt --yes

    # Con cifrado (contraseña personalizada)
    sudo redaudit --target 192.168.1.0/24 --mode normal --encrypt --encrypt-password "MiContraseñaSegura123" --yes
```

**Opciones CLI Disponibles:**

- `--target, -t`: Red(es) objetivo en notación CIDR (requerido para modo no interactivo)
- `--mode, -m`: Modo de escaneo (fast/normal/full, por defecto: normal)
- `--threads, -j`: Hilos concurrentes (1-16, por defecto: 6)
- `--rate-limit`: Retardo entre hosts en segundos (por defecto: 0)
- `--encrypt, -e`: Cifrar reportes con contraseña
- `--encrypt-password`: Contraseña personalizada para cifrado (opcional, defecto: generada aleatoriamente)
- `--output, -o`: Directorio de salida (por defecto: ~/Documents/RedAuditReports)
- `--max-hosts`: Máximo de hosts a escanear (por defecto: todos)
- `--no-vuln-scan`: Desactivar escaneo de vulnerabilidades web
- `--no-txt-report`: Desactivar generación de reporte TXT
- `--no-deep-scan`: Desactivar deep scan adaptativo
- `--prescan`: Activar pre-escaneo rápido asyncio antes de nmap
- `--prescan-ports`: Rango de puertos para pre-scan (defecto: 1-1024)
- `--prescan-timeout`: Timeout de pre-scan en segundos (defecto: 0.5)
- `--udp-mode`: Modo de escaneo UDP: quick (defecto) o full
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
3. **Fase 2b - UDP Completo**: Solo en modo `full` si no se encontró identidad (`-O -sSU -p-`)

**Características de Deep Scan:**

- **Captura PCAP Concurrente**: El tráfico se captura durante el escaneo (no después)
- **Banner Grab Fallback**: Usa `--script banner,ssl-cert` para puertos no identificados
- **Precisión de Estado de Host**: Nuevos tipos (`up`, `filtered`, `no-response`, `down`)
- **Salto Inteligente**: Las Fases 2a/2b se omiten si ya se detectó MAC/SO

- **Activación**: Automática según heurísticas (pocos puertos, servicios sospechosos, etc.)
- **Salida**: Logs completos, datos MAC/Vendor, y PCAP en `host.deep_scan`

## Arquitectura Modular

RedAudit está organizado como un paquete Python modular:

```text
redaudit/
├── core/           # Funcionalidad principal
│   ├── auditor.py  # Clase orquestadora principal
│   ├── prescan.py  # Descubrimiento rápido asyncio
│   ├── scanner.py  # Lógica de escaneo Nmap + soporte IPv6
│   ├── crypto.py   # Cifrado/descifrado AES-128
│   ├── network.py  # Detección de interfaces (IPv4/IPv6)
│   ├── reporter.py # Salida JSON/TXT + SIEM
│   ├── updater.py  # Auto-actualización segura (git clone)
│   ├── verify_vuln.py  # Smart-Check filtrado falsos positivos
│   ├── entity_resolver.py  # Agrupación hosts multi-interfaz
│   ├── siem.py     # Integración SIEM profesional
│   ├── nvd.py      # Correlación CVE vía API NVD (v3.0)
│   ├── diff.py     # Análisis diferencial (v3.0)
│   └── proxy.py    # Soporte proxy SOCKS5 (v3.0)
└── utils/          # Utilidades
    ├── constants.py # Constantes de configuración
    ├── i18n.py      # Internacionalización
    └── config.py    # Configuración persistente (v3.0.1)
```

### Auto-Actualización Segura

RedAudit puede verificar e instalar actualizaciones automáticamente:

- **Verificación al Inicio**: Pregunta si deseas buscar actualizaciones en modo interactivo
- **Auto-Instalación**: Descarga e instala actualizaciones vía `git pull`
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
- **60-300s silencio**: Registra un **WARNING** indicando que Nmap puede estar ocupado.
- **>300s silencio**: Registra un **WARNING** con el mensaje "Nmap sigue ejecutándose; esto es normal en hosts lentos o filtrados."
- **Propósito**: Asegurar al operador que la herramienta sigue viva durante operaciones largas de Nmap (ej: escaneos `-p-`).

## 10. Script de Verificación

Verifica la integridad de tu entorno (checksums, dependencias, alias) en cualquier momento:

```bash
bash redaudit_verify.sh
```

*Útil tras actualizaciones del sistema o `git pull`.*

## 11. Glosario

- **Fernet**: Estándar de cifrado simétrico usando AES-128 y HMAC-SHA256.
- **Heartbeat**: Tarea en segundo plano que asegura que el proceso principal responde.
- **Deep Scan**: Escaneo de respaldo automático (`-A`) disparado cuando un host devuelve datos limitados.
- **PBKDF2**: Función de derivación de claves que encarece los ataques de fuerza bruta (configurada a 480k iteraciones).
- **Salt**: Dato aleatorio añadido al hash de contraseña para evitar ataques de rainbow table, guardado en archivos `.salt`.
- **Thread Pool**: Colección de hilos trabajadores que ejecutan tareas (escaneos de host) concurrentemente.

## 12. Solución de Problemas

Consulta [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) para soluciones detalladas.

- **"Permission denied"**: Asegúrate de usar `sudo`.
- **"Cryptography missing"**: Ejecuta `sudo apt install python3-cryptography`.
- **"Scan frozen"**: Revisa `~/.redaudit/logs/` o reduce `rate_limit_delay`.

## 13. Historial de Cambios (v3.0.0)

### Características v3.0

- **Soporte IPv6**: Escaneo completo de redes IPv6 con flag `-6` automático
- **Correlación CVE (NVD)**: Inteligencia profunda de vulnerabilidades via API NIST NVD con caché de 7 días
- **Análisis Diferencial**: Comparar dos reportes para detectar cambios de red (`--diff`)
- **Proxy Chains (SOCKS5)**: Soporte para pivoting via wrapper proxychains
- **Validación Magic Bytes**: Detección mejorada de falsos positivos con verificación de firmas
- **Auto-Update Mejorado**: Enfoque git clone con verificación y copia a carpeta home

### Mejoras v2.9

- **Smart-Check**: Filtrado automático de falsos positivos de Nikto via Content-Type
- **UDP Taming**: Escaneo 50-80% más rápido con `--top-ports 100` y timeouts estrictos
- **Entity Resolution**: Consolidación de hosts multi-interfaz (`unified_assets`)
- **SIEM Profesional**: Cumplimiento ECS v8.11, severidad, risk scores, auto-tags

### Características Principales

- **Deep Scan Adaptativo**: Estrategia de 3 fases (TCP agresivo → UDP prioritario → UDP completo)
- **Captura PCAP Concurrente**: Tráfico capturado durante escaneos
- **Motor Pre-scan**: Descubrimiento rápido asyncio antes de nmap
- **Inteligencia de Exploits**: Integración SearchSploit para versiones detectadas
- **Análisis SSL/TLS**: Escaneo profundo TestSSL.sh

Para el changelog detallado, consulta [CHANGELOG.md](CHANGELOG.md)

## 14. Licencia

RedAudit se distribuye bajo la **GNU General Public License v3.0 (GPLv3)**.  
Consulta el archivo [LICENSE](LICENSE) para ver el texto completo y las condiciones.

## 15. Internos & Glosario (Por qué RedAudit se comporta así)

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

## 16. Aviso Legal

**RedAudit** es una herramienta de seguridad únicamente para **auditorías autorizadas**.
Escanear redes sin permiso es ilegal. Al usar esta herramienta, aceptas total responsabilidad por tus acciones y acuerdas usarla solo en sistemas de tu propiedad o para los que tengas autorización explícita.

---
[Documentación Completa](docs/) | [Esquema de Reporte](docs/REPORT_SCHEMA.md) | [Especificaciones de Seguridad](docs/SECURITY.md)
