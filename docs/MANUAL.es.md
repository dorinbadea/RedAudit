# Manual de Usuario de RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](MANUAL.en.md)

**Audiencia:** Analistas de seguridad, pentesters, administradores de sistemas
**Alcance:** Instalación, operación, artefactos de salida, modelo de seguridad
**Qué NO cubre este documento:** Técnicas de explotación, internos del código
**Fuente de verdad:** `redaudit --help`, `redaudit/core/auditor.py`

---

## 1. Qué Es (y Qué No Es) RedAudit

RedAudit es un **framework de auditoría de red automatizado** para Linux (familia Debian). Orquesta herramientas externas (`nmap`, `whatweb`, `nikto`, `testssl.sh`, `nuclei`, `searchsploit`) en un pipeline unificado y produce informes estructurados.

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
cd RedAudit
sudo bash redaudit_install.sh
source ~/.zshrc  # o ~/.bashrc
```

El instalador:

1. Instala dependencias del sistema vía `apt`
2. Copia el código a `/usr/local/lib/redaudit`
3. Crea el alias `redaudit` en el shell
4. Solicita preferencia de idioma (EN/ES)

### Instalación Manual (sin instalador)

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo apt install nmap whatweb nikto tcpdump tshark exploitdb python3-nmap python3-cryptography
sudo python3 -m redaudit --help
```

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

---

## 4. Selector de Perfil del Wizard (v3.9.0+)

Al ejecutar `sudo redaudit` en modo interactivo, el asistente pregunta qué perfil de escaneo usar. Los perfiles preconfigurados son:

### Express

**Caso de uso**: Reconocimiento rápido de hosts vivos.

- **Modo**: `fast` (solo descubrimiento de hosts, sin escaneo de puertos)
- **Features deshabilitadas**: Escaneos de vulnerabilidades, Nuclei, correlación CVE, verificación sin agente
- **Descubrimiento habilitado**: Topología + Net Discovery
- **Timing**: Rápido
- **Preguntas**: Mínimas (prompt de Fase 0, nombre auditor, directorio salida)
- **Ideal para**: Reconocimiento inicial, contar hosts vivos

### Standard

**Caso de uso**: Evaluación balanceada de vulnerabilidades.

- **Modo**: `normal` (nmap `-F` / top 100 puertos + detección de versiones)
- **Features**: escaneo web habilitado (whatweb; nikto/testssl solo en full), searchsploit si está disponible, topología + discovery de red
- **Timing**: Elegido por preset (Stealth/Normal/Agresivo)
- **Preguntas**: Selección de perfil + timing + prompt de Fase 0 + prompts de auditor/salida
- **Ideal para**: La mayoría de auditorías de seguridad

### Exhaustive

**Caso de uso**: Máximo descubrimiento y correlación para evaluaciones exhaustivas.

- **Modo**: `completo` (todos los 65535 puertos + scripts/detección de SO)
- **Threads**: MAX (16) o reducido en preset Stealth (2)
- **UDP**: top 500 puertos para deep scan (solo cuando se activa)
- **Features habilitadas**: Vulnerabilidades, Topología, Net Discovery, Red Team, Verificación sin agente; Nuclei si está instalado
- **Correlación CVE**: Habilitada si hay API key de NVD configurada
- **Timing**: Elegido por preset (Stealth/Normal/Agresivo)
- **Preguntas**: Prompt de Fase 0 + nombre auditor y directorio (todo lo demás auto-configurado)
- **Ideal para**: Pentesting, auditorías de cumplimiento, validación pre-producción

### Custom

**Caso de uso:** Control total sobre todas las opciones de configuración.

- **Comportamiento**: Wizard completo de 8 pasos con navegación atrás
- **Preguntas**: Modo de escaneo, hilos/retardo + prompt de Fase 0, vulnerabilidades, CVE, salida/auditor, UDP/topología, discovery/red team, verificación sin agente + webhook
- **Ideal para**: Escaneos personalizados con requisitos específicos

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

**Comportamiento de timeout:** Los escaneos de host están limitados por el `--host-timeout` de nmap del modo elegido
(full: 300s). RedAudit aplica un timeout duro y marca el host como sin respuesta si se supera, manteniendo el escaneo
fluido en dispositivos IoT/embebidos.

### Deep Scan Adaptativo

Cuando está habilitado (por defecto), RedAudit realiza escaneos adicionales en hosts donde los resultados iniciales son ambiguos o indican infraestructura virtual:

**Condiciones de disparo:**

- Menos de 3 puertos abiertos encontrados (cuando la identidad es débil)
- Servicios identificados como `unknown` o `tcpwrapped`
- Información MAC/fabricante no obtenida
- **Detección de Gateway VPN**: El host comparte la dirección MAC con el gateway pero tiene una IP diferente (interfaz virtual)

**Comportamiento:**

0. (Opcional) Fase 0 de enriquecimiento de bajo impacto (DNS reverso, mDNS unicast, SNMP sysDescr) al activarlo en el asistente o con `--low-impact-enrichment`
1. Fase 1: TCP agresivo (`-A -p- -sV -Pn`)
2. Fase 2a: Sonda UDP prioritaria (17 puertos comunes incluyendo 500/4500)
3. Fase 2b: UDP top-ports (`--udp-ports`) cuando el modo es `full` y la identidad sigue débil
4. Hosts silenciosos con fabricante detectado y cero puertos abiertos pueden recibir una sonda HTTP/HTTPS breve en rutas habituales

Deshabilitar con `--no-deep-scan`.

SmartScan usa una puntuación de identidad (umbral por defecto: 3; modo full usa 4) para decidir si escalar.

La clasificación VPN se realiza mediante heurísticas de tipado de activo (MAC/IP de gateway, puertos VPN, patrones de hostname).

### Verificación sin agente (Opcional)

Cuando está habilitado, RedAudit ejecuta scripts ligeros de Nmap sobre hosts con SMB/RDP/LDAP/SSH/HTTP para enriquecer la
identidad (pistas de SO, dominio, títulos/cabeceras y fingerprints básicos). No usa credenciales y es opt-in para mantener el ruido
controlado.

- Activar desde el asistente o con `--agentless-verify`.
- Limitar alcance con `--agentless-verify-max-targets` (defecto: 20).

---

## 5. Referencia CLI (Completa)

Flags verificadas contra `redaudit --help` (v3.10.0):

### Core

| Flag | Descripción |
| :--- | :--- |
| `-t, --target CIDR` | Red(es) objetivo, separadas por comas |
| `-m, --mode {fast,normal,full}` | Intensidad del escaneo (defecto: normal) |
| `-o, --output DIR` | Directorio de salida (defecto: `~/Documents/RedAuditReports` o `~/Documentos/RedAuditReports`) |
| `-y, --yes` | Omitir prompts de confirmación |
| `-V, --version` | Imprimir versión y salir |

### Rendimiento

| Flag | Descripción |
| :--- | :--- |
| `-j, --threads 1-16` | Workers concurrentes por host (autodetectado) |
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

### Reportes

| Flag | Descripción |
| :--- | :--- |
| `--html-report` | Generar dashboard HTML interactivo |
| `--webhook URL` | POST alertas para hallazgos high/critical |
| `--no-txt-report` | Omitir generación de informe TXT |
| `--no-vuln-scan` | Omitir escaneo nikto/vulnerabilidades web |
| `--nuclei` | Habilitar escaneo de plantillas Nuclei (requiere `nuclei`) |
| `--no-nuclei` | Deshabilitar Nuclei (ignora defaults) |

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
| `--proxy URL` | Proxy SOCKS5 (socks5://host:port) |
| `--lang {en,es}` | Idioma de interfaz |
| `--no-color` | Deshabilitar salida con colores |
| `--save-defaults` | Guardar ajustes actuales en ~/.redaudit/config.json |
| `--defaults {ask,use,ignore}` | Controlar cómo se aplican los defaults persistentes |
| `--use-defaults` | Usar defaults guardados sin preguntar |
| `--ignore-defaults` | Ignorar defaults guardados |
| `--skip-update-check` | Omitir verificación de actualizaciones al iniciar |

---

## 6. Artefactos de Salida

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
| `run_manifest.json` | Si cifrado deshabilitado | Metadatos de sesión |
| `playbooks/*.md` | Si cifrado deshabilitado | Guías de remediación |
| `traffic_*.pcap` | Si se dispara deep scan y tcpdump disponible | Capturas de paquetes |
| `session_logs/session_*.log` | Siempre | Logs de sesión (raw con ANSI) |
| `session_logs/session_*.txt` | Siempre | Logs de sesión (texto limpio) |

### Comportamiento del Cifrado

Cuando se usa `--encrypt`:

- `.json` y `.txt` se convierten en `.json.enc` y `.txt.enc`
- Se crea un fichero `.salt` junto a cada fichero cifrado
- **Los artefactos en texto plano NO se generan:** HTML, JSONL, playbooks y ficheros manifest se omiten por seguridad

**Descifrado:**

```bash
python3 redaudit_decrypt.py /ruta/a/reporte.json.enc
```

---

## 7. Modelo de Seguridad

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

## 8. Integración

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

## 9. Solución de Problemas

| Síntoma | Causa | Solución |
| :--- | :--- | :--- |
| Permission denied | Ejecutando sin sudo | Usar `sudo redaudit` |
| nmap: command not found | Dependencia faltante | Ejecutar `sudo bash redaudit_install.sh` |
| Decryption failed: Invalid token | Contraseña incorrecta o .salt corrupto | Verificar contraseña; asegurar que existe fichero .salt |
| El escaneo parece congelado | Deep scan o host lento | Revisar `session_logs/` para ver la herramienta activa; reducir alcance con `--max-hosts` |
| No se generan playbooks | Cifrado habilitado | Los playbooks requieren que `--encrypt` esté deshabilitado |

Ver [TROUBLESHOOTING.es.md](TROUBLESHOOTING.es.md) para referencia completa de errores.

---

## 10. Herramientas Externas

RedAudit orquesta (no modifica ni instala):

| Herramienta | Condición de Invocación | Campo del Reporte |
| :--- | :--- | :--- |
| `nmap` | Siempre | `hosts[].ports` |
| `whatweb` | HTTP/HTTPS detectado | `vulnerabilities[].whatweb` |
| `nikto` | HTTP/HTTPS + modo full | `vulnerabilities[].nikto_findings` |
| `testssl.sh` | HTTPS + modo full | `vulnerabilities[].testssl_analysis` |
| `nuclei` | HTTP/HTTPS + modo full (si está instalado y habilitado) | `vulnerabilities[].nuclei_findings` |
| `searchsploit` | Servicios con versión detectada | `ports[].known_exploits` |
| `tcpdump` | Se dispara deep scan | `deep_scan.pcap_capture` |
| `tshark` | Tras captura tcpdump | `deep_scan.tshark_summary` |

---

[Volver al README](../ES/README_ES.md) | [Índice de Documentación](INDEX.md)
