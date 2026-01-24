# Guía de Uso de RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](USAGE.en.md)

**Audiencia:** Pentesters, operadores de seguridad y Blue Teamers.

**Alcance:** Opciones CLI, ejemplos de uso, configuración y opciones de ejecución.

**Qué NO cubre este documento:** Teoría de redes y desarrollo de exploits.

**Fuente de verdad:** `redaudit --help`

---

## 1. Inicio Rápido

Ejecuta estos comandos para comenzar de inmediato.

### Asistente Interactivo (Recomendado para primera vez)

Navegación paso a paso con opción "Cancelar" (v4.0.1+). La configuración de webhooks y opciones de descubrimiento está disponible en el asistente; las exportaciones SIEM se generan automáticamente cuando el cifrado está desactivado. Si hay credenciales guardadas, el asistente ofrece cargarlas y luego pregunta si deseas añadir más. La Fase 0 de bajo impacto puede activarse desde el asistente (por defecto desactivada) o con `--low-impact-enrichment`. La entrada manual de objetivos admite valores CIDR, IP o rango separados por comas. El asistente muestra los objetivos normalizados con hosts estimados antes de confirmar el inicio.

```bash
sudo redaudit
```

**Modos del asistente (resumen):**

- **fast**: Solo discovery, mínimo ruido, el más rápido.
- **normal**: Puertos principales, equilibrio tiempo/cobertura (recomendado).
- **full**: Todos los puertos + scripts + herramientas web, el más lento y ruidoso.

**Presets de velocidad (wizard):**

- **Sigiloso**: El más lento y con menos ruido.
- **Normal**: Equilibrio entre velocidad y fiabilidad.
- **Agresivo**: El más rápido, más ruido; puede perder servicios lentos/filtrados.

### Inventario rápido (LAN)

```bash
sudo redaudit -t 192.168.1.0/24 -m fast --yes
```

### Auditoría Estándar (Host Único)

```bash
sudo redaudit -t 10.10.10.5 -m normal --html-report
```

### Descubrimiento de Gateways VPN

Escanea una red para identificar interfaces VPN y endpoints virtuales:

```bash
sudo redaudit -t 10.0.0.0/24 --mode full --yes
# Ver resultados de assets VPN
cat redaudit_*.json | jq '.hosts[] | select(.asset_type == "vpn")'
```

Nota: Si la VPN está inactiva, la interfaz VPN puede aparecer como un activo separado con la misma MAC que el gateway y sin puertos abiertos. Es un comportamiento esperado.

---

## 2. Ejemplos por Escenario

### Lab / CTF (Agresivo)

Enfoque en velocidad y máxima recolección de información.

```bash
sudo redaudit -t 192.168.56.101 \
  --mode full \
  --udp-mode full \
  --threads 100 \
  --no-prevent-sleep
```

**Artefactos:** JSON/TXT, HTML opcional, JSONL, manifiesto de salida, PCAP (deep scan + tcpdump), playbooks (si hay categorías compatibles y sin cifrado).

### Escaneo Sigiloso (Modo Red Team)

Enfoque en bajo ruido, artefactos fiables y cifrado para cadena de custodia.

```bash
sudo redaudit -t 10.20.0.0/24 \
  --stealth \
  --encrypt \
  --encrypt-password "ProyectoCliente2025!"
```

**Notas:** `stealth` fuerza timing T1 y retardo de 5s. El cifrado deshabilita HTML/JSONL/playbooks/manifest.

### Blue Team / NetOps (Descubrimiento)

Enfoque en identificar dispositivos no autorizados y fugas de red.

```bash
sudo redaudit -t 172.16.0.0/16 \
  --mode fast \
  --net-discovery arp,mdns,upnp \
  --topology \
  --allow-non-root
```

**Notas:** `allow-non-root` ejecuta en modo limitado; la detección de SO, los escaneos UDP y la captura con tcpdump pueden fallar.

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
| :--- | :--- |
| `-t, --target CIDR` | IP, rango o CIDR (soporta lista separada por comas) |
| `-m, --mode` | `fast` (descubrimiento de hosts), `normal` (top 100), `full` (todos los puertos + scripts/detección de SO) |
| `-j, --threads N` | Hosts paralelos 1-100 (autodetectado; respaldo: 6) |
| `--max-hosts N` | Número máximo de hosts a escanear (defecto: todos) |
| `--rate-limit S` | Retardo entre hosts en segundos (jitter ±30%) |
| `--deep-scan-budget N` | Máximo de hosts elegibles para deep scan agresivo (0 = sin límite) |
| `--identity-threshold N` | Umbral mínimo de identidad para omitir deep scan (0-100) |
| `--no-deep-scan` | Desactivar deep scan adaptativo |
| `--stealth` | Fuerza timing T1, 1 hilo, 5s retardo |
| `--dry-run` | Muestra comandos sin ejecutarlos |
| `--profile {fast,balanced,full}` | Definir intensidad/velocidad de escaneo Nuclei (v4.11+) |
| `--dead-host-retries N` | Abandonar host tras N tiempos de espera consecutivos (v4.13+) |

### Conectividad y Proxy

| Flag | Descripción |
| :--- | :--- |
| `--proxy URL` | Proxy SOCKS5 (socks5://host:port; requiere proxychains4, solo TCP) |
| `--ipv6` | Activa modo escaneo solo IPv6 |
| `--no-prevent-sleep` | No inhibir suspensión del sistema |

**Nota:** `--proxy` envuelve herramientas externas con `proxychains4` y solo afecta sondas TCP (connect). El descubrimiento UDP/ARP/ICMP es directo.

### Descubrimiento Avanzado

| Flag | Descripción |
| :--- | :--- |
| `-y, --yes` | Auto-confirmar todos los prompts |
| `--net-discovery [PROTOCOLS]` | Protocolos broadcast (dhcp,netbios,mdns,upnp,arp,fping) |
| `--net-discovery-interface IFACE` | Interfaz de red para discovery y capturas L2 |
| `--scan-routed` | Incluir redes enrutadas descubiertas por gateways locales |
| `--follow-routes` | Incluir redes remotas descubiertas por routing/SNMP |
| `--topology` | Mapeo de topología L2/L3 (rutas/gateways) |
| `--no-topology` | Desactivar descubrimiento de topología |
| `--topology-only` | Ejecutar solo topología (sin escaneo de hosts) |
| `--hyperscan-mode MODE` | `auto`, `connect`, o `syn` (defecto: auto) |
| `--trust-hyperscan, --trust-discovery` | Confiar en resultados HyperScan para Deep Scan (evitar -p-) |
| `--udp-mode` | `quick` (puertos prioritarios) o `full` (top ports) |
| `--udp-ports N` | Número de puertos UDP top a escanear en modo full |
| `--redteam` | Añade técnicas de recon AD/Kerberos/SNMP |
| `--redteam-max-targets N` | Máximo de IPs muestreadas para redteam (1-500) |
| `--redteam-active-l2` | Habilita sondeo activo L2 más ruidoso |
| `--snmp-community COMMUNITY` | Comunidad SNMP para discovery (defecto: public) |
| `--dns-zone ZONE` | Zona DNS para intentos AXFR |
| `--kerberos-realm REALM` | Hint de realm Kerberos para discovery |
| `--kerberos-userlist PATH` | Lista opcional de usuarios para Kerberos userenum |
| `--agentless-verify` | Verificación sin agente (SMB/RDP/LDAP/SSH/HTTP) |
| `--no-agentless-verify` | Desactivar verificación sin agente (sobrescribe defaults) |
| `--agentless-verify-max-targets N` | Límite de objetivos para verificación (1-200, defecto: 20) |

### Escaneo Autenticado (Fase 4)

| Flag | Descripción |
| :--- | :--- |
| `--auth-provider {env,keyring}` | Backend de credenciales (defecto: keyring/llavero) |
| `--credentials-file PATH` | Cargar lista universal de credenciales desde JSON |
| `--generate-credentials-template` | Crear plantilla `credentials.json` y salir |
| `--ssh-user USER` | Usuario SSH |
| `--ssh-key PATH` | Ruta a Clave Privada |
| `--ssh-key-pass PASS` | Passphrase de la clave privada SSH |
| `--ssh-trust-keys` | Auto-aceptar claves desconocidas de hosts (¡Precaución!) |
| `--smb-user USER` | Usuario SMB/Windows |
| `--smb-pass PASS` | Contraseña SMB (preferible vía asistente/env) |
| `--smb-domain DOMAIN` | Dominio Windows |
| `--snmp-user USER` | Usuario SNMPv3 |
| `--snmp-auth-proto {SHA,MD5...}` | Protocolo Auth SNMPv3 |
| `--snmp-auth-pass PASS` | Password Auth SNMPv3 |
| `--snmp-priv-proto {AES,DES...}` | Protocolo Privacidad SNMPv3 |
| `--snmp-priv-pass PASS` | Password de privacidad SNMPv3 |
| `--snmp-topology` | Habilitar consultas SNMP de topología profunda |
| `--lynis` | Habilitar auditoría de hardening con Lynis (requiere SSH) |

### Informes e Integración

| Flag | Descripción |
| :--- | :--- |
| `-o, --output DIR` | Directorio de salida personalizado |
| `--lang` | Idioma de interfaz/reporte (en/es) |
| `--html-report` | Generar dashboard interactivo (HTML) |
| `--no-txt-report` | Desactivar generacion de reporte TXT |
| `--webhook URL` | Enviar alertas webhook (JSON) para hallazgos high/critical |
| `--nuclei` | Habilitar escaneo de plantillas con Nuclei (requiere `nuclei`; solo en modo full; DESACTIVADO por defecto) |
| `--nuclei-timeout S` | Timeout por lote de Nuclei en segundos (defecto: 300) |
| `--no-nuclei` | Deshabilitar Nuclei (defecto) |
| `--no-vuln-scan` | Omitir escaneo de vulnerabilidades Web/Nikto |
| `--cve-lookup` | Correlar servicios con datos CVE NVD |
| `--nvd-key KEY` | Clave API NVD para consultas CVE |

Notas:

- Los escáneres de aplicaciones web (sqlmap/ZAP) se omiten en UIs de infraestructura cuando la evidencia de identidad indica router/switch/AP.
- Las ejecuciones de Nuclei pueden marcarse como parciales si hay timeouts de lotes; revisa `nuclei.partial`, `nuclei.timeout_batches` y `nuclei.failed_batches` en los informes.
- **Nuclei en redes con alta densidad web:** En redes con muchos servicios HTTP/HTTPS (p. ej., labs Docker, microservicios), los escaneos Nuclei pueden tardar significativamente mas (30-90+ minutos). Usa `--nuclei-timeout 600` para aumentar el timeout por lote, o `--no-nuclei` para omitir Nuclei si la velocidad es critica.

### Configuracion de Nuclei (v4.17+)

El escaneo con Nuclei tiene dos opciones de configuracion independientes:

**1. Perfil de escaneo (`--profile`)**

Controla que plantillas se ejecutan:

| Perfil | Descripcion | Tiempo Estimado |
|:-------|:------------|:----------------|
| `full` | Todas las plantillas, todos los niveles de severidad | ~2 horas |
| `balanced` | Templates esenciales (cve, default-login, exposure, misconfig) | ~1 hora (recomendado) |
| `fast` | Solo CVEs criticos | ~30-60 minutos |

**2. Cobertura completa (solo en asistente)**

Durante el modo interactivo, el asistente pregunta "Escanear TODOS los puertos HTTP detectados?" Esto controla que puertos HTTP se escanean por host:

| Opcion | Comportamiento |
|:-------|:---------------|
| **No (por defecto en balanced/fast)** | Max 2 URLs por host multipuerto (prioriza 80, 443) |
| **Si (por defecto en full)** | Escanea TODOS los puertos HTTP detectados en cada host (además de 80/443) |

Nota: Esta opcion solo esta disponible en el asistente interactivo, no via flags CLI.
Cuando la cobertura completa esta activada, se omite el cambio automatico a auto-fast para respetar el perfil seleccionado.

**Cuando usar cada combinacion:**

| Escenario | Configuracion Recomendada |
|:----------|:--------------------------|
| Comprobacion rapida de vulnerabilidades | `--profile fast` |
| Auditoria estandar | `--profile balanced` (asistente: No a cobertura completa) |
| Pentest exhaustivo | `--profile full` (asistente: Si a cobertura completa) |
| Auditoria con tiempo limitado | `--profile fast` |

**Notas de rendimiento:**

- Hosts con muchos puertos HTTP (p. ej., FRITZ!Box con 8+ puertos) pueden dominar el tiempo de escaneo.
- El modo audit-focus (por defecto) reduce significativamente el tiempo en hosts multipuerto.
- Habilitar cobertura completa solo cuando se requiere escaneo HTTP exhaustivo.

**Mejora de rendimiento opcional:**

Instala [RustScan](https://github.com/RustScan/RustScan) para descubrimiento de puertos mas rapido:

```bash
# Ubuntu/Debian
cargo install rustscan
```

RustScan se detecta automaticamente y se usa para HyperScan cuando esta disponible.

### Politica del Toolchain del Instalador

El instalador puede anclar o usar versiones latest para herramientas descargadas desde GitHub:

```bash
# Latest para testssl y kerbrute
REDAUDIT_TOOLCHAIN_MODE=latest sudo bash redaudit_install.sh

# Overrides de version explicitos
TESTSSL_VERSION=v3.2 KERBRUTE_VERSION=v1.0.3 RUSTSCAN_VERSION=2.3.0 sudo bash redaudit_install.sh
```

### Seguridad y Privacidad

| Flag | Descripción |
| :--- | :--- |
| `-e, --encrypt` | Cifrar todos los artefactos sensibles (AES-128) |
| `--allow-non-root` | Ejecutar sin sudo (capacidad limitada) |

### Configuración

| Flag | Descripción |
| :--- | :--- |
| `--save-defaults` | Guardar argumentos CLI actuales en `~/.redaudit/config.json` |
| `--defaults {ask,use,ignore}` | Controlar cómo se aplican los defaults persistentes |
| `--use-defaults` | Cargar argumentos desde config.json automáticamente |
| `--ignore-defaults` | Forzar valores de fábrica |
| `-v, --verbose` | Habilitar logging detallado |
| `-V, --version` | Mostrar version del programa y salir |
| `-h, --help` | Mostrar ayuda del CLI y salir |
| `--no-color` | Deshabilitar salida a color |
| `--skip-update-check` | Saltar comprobación de actualizaciones al inicio |

---

## 4. Salida y Rutas

**Ruta por Defecto:**
`<Documentos>/RedAuditReports/RedAudit_<TIMESTAMP>/` (usa la carpeta Documentos del usuario invocante)

Para cambiar la ruta por defecto permanentemente:

```bash
sudo redaudit --output /opt/redaudit/reports --save-defaults --yes
```

**Manifiesto de Artefactos:**

- **.json**: Modelo de datos completo (siempre creado).
- **.txt**: Resumen legible por humanos.
- **.html**: Dashboard (requiere `--html-report`, deshabilitado por `--encrypt`).
- **.jsonl**: Eventos streaming para SIEM (deshabilitado por `--encrypt`).
- **playbooks/*.md**: Guías de remediación (deshabilitado por `--encrypt`).
- **run_manifest.json**: Manifiesto de salida con snapshot de config/pipeline (deshabilitado por `--encrypt`).
- **.pcap**: Capturas de paquetes (solo si Deep Scan + tcpdump + Root).
- **session_*.log**: Salida de terminal raw con códigos de color (en `session_logs/`).
- **session_*.txt**: Salida de terminal en texto plano limpio (en `session_logs/`).

**Evidencia y transparencia del pipeline:**

- El JSON principal incluye metadatos de evidencia por hallazgo (herramienta fuente, matched_at, hash/ref de salida cruda si aplica).
- El HTML muestra los args/timing de Nmap, ajustes de deep scan y el resumen HyperScan vs final (cuando exista).

**Notas de Progreso/ETA:**

- `ETA≤` muestra el límite superior basado en timeouts para el lote actual.
- `ETA≈` es una estimación dinámica basada en hosts completados.

---

## 5. Errores Comunes

**`Permission denied` (socket error)**
RedAudit necesita root para:

- Detección de SO y algunos tipos de escaneo Nmap
- Escaneo UDP y sondas con raw sockets
- Generación de PCAP con `tcpdump`
**Solución:** Ejecutar con `sudo` o usar `--allow-non-root` (modo limitado).

**`nmap: command not found`**
Dependencias faltantes en el PATH.
**Solución:** Ejecutar `sudo bash redaudit_install.sh` o revisar `/usr/local/lib/redaudit`.

**`testssl.sh not found`**
Los checks TLS profundos se omiten en modo full.
**Solución:** Ejecutar `sudo bash redaudit_install.sh` para instalar el toolchain principal.

**`Decryption failed`**
Falta el archivo `.salt` o contraseña incorrecta.
**Solucion:** Asegurar que el archivo `.salt` esta en el mismo directorio que el `.enc`.

**VLANs ocultas no detectadas (802.1Q)**
RedAudit descubre redes mediante tablas de enrutamiento (`ip route`) y vecinos ARP.
Las VLANs aisladas en Capa 2 (ej: VLANs IPTV del ISP taggeadas por switches gestionados) **no son descubribles** desde el host auditor.
**Soluciones alternativas:**

- Consultar router/switch via SNMP (`--redteam` con SNMP habilitado)
- Anadir VLANs conocidas manualmente a la lista de objetivos
- En entornos Cisco, usar `--net-discovery` con CDP/LLDP si los switches emiten topologia

---

[Volver al README](../ES/README_ES.md) | [Índice de Documentación](INDEX.md)
