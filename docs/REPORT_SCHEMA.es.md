# Esquema de Informes RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](REPORT_SCHEMA.en.md)

**Audiencia:** Desarrolladores, Ingenieros SIEM
**Alcance:** Estructura JSON, definiciones de campos, tipos de datos.
**Fuente de verdad:** `redaudit/core/reporter.py`

---

## Visión General

RedAudit genera informes legibles por máquina en formato JSON. Este documento describe la estructura del esquema para los artefactos `redaudit_<timestamp>.json`.

**Tipos de Datos**: Tipos JSON estándar (`string`, `number`, `boolean`, `array`, `object`).
**Nullable**: Los campos son nullable a menos que se especifique lo contrario.
**Módulo Fuente**: `redaudit/core/reporter.py`

## Vistas de Exportación Adicionales (v3.1)

En el mismo directorio de salida, RedAudit también puede generar archivos planos optimizados para pipelines SIEM e IA:

- `findings.jsonl`: Un hallazgo por línea
- `assets.jsonl`: Un activo por línea
- `summary.json`: Resumen compacto para dashboards
- `run_manifest.json`: Manifiesto de la carpeta de salida (archivos + métricas)

Estas exportaciones se generan solo cuando el cifrado de informes está **desactivado**, para evitar crear artefactos en texto plano junto a informes cifrados.

### Manifiesto de Ejecución (run_manifest.json) (v3.1+)

Metadatos del manifiesto usados para inventariar artefactos de salida en pipelines de automatización.

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `schema_version` | string | Versión de esquema del manifiesto |
| `generated_at` | string | Marca de tiempo de generación del manifiesto (ISO 8601) |
| `timestamp` | string | Marca de tiempo de inicio del escaneo (best-effort) |
| `timestamp_end` | string | Marca de tiempo de fin del escaneo (best-effort) |
| `session_id` | string | UUID de la sesión de escaneo |
| `partial` | boolean | True cuando la ejecución fue interrumpida o alguna herramienta reportó salida parcial (ej.: timeouts de Nuclei) |
| `encryption_enabled` | boolean | Indica si el cifrado de informes estaba activado |
| `redaudit_version` | string | Versión de RedAudit |
| `scanner_versions` | object | Versiones de herramientas externas capturadas en tiempo de ejecución |
| `targets` | array | Redes objetivo o rangos IP |
| `counts` | object | Conteos de hosts, hallazgos y PCAPs |
| `counts.findings_raw` | integer | (Opcional) Conteo bruto de hallazgos antes de normalizar |
| `artifacts` | array | Lista de archivos con `path` relativo y `size_bytes` |

## Definición del Esquema

### Objeto Raíz

El contenedor de nivel superior para la sesión de escaneo.

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `schema_version` | `string` | Versión del esquema (puede diferir de la versión de la app) |
| `generated_at` | `string` | Marca de tiempo de generación (ISO 8601) **(v3.1)** |
| `event_type` | `string` | Tipo de evento para ingesta SIEM ("redaudit.scan.complete") |
| `session_id` | `string` | UUID único para esta sesión de escaneo |
| `timestamp` | `string` | Marca de tiempo de inicio (ISO 8601) |
| `timestamp_end` | `string` | Marca de tiempo de fin (ISO 8601) |
| `version` | `string` | Versión de RedAudit |
| `scanner` | `object` | Metadatos del escáner: `name`, `version`, `mode` |
| `scanner_versions` | `object` | Versiones detectadas de herramientas (nmap, nikto, etc.) **(v3.1)** |
| `targets` | `array` | Lista de redes objetivo escaneadas |
| `network_info` | `array` | Lista de objetos de interfaz de red |
| `topology` | `object` | (Opcional) Salida best-effort de descubrimiento de topología (ARP/VLAN/LLDP + gateway/rutas) **(v3.1+)** |
| `net_discovery` | `object` | (Opcional) Salida de descubrimiento de red mejorado (DHCP/NetBIOS/mDNS/UPNP) **(v3.2+)** |
| `agentless_verify` | `object` | (Opcional) Resumen de verificación sin agente (SMB/RDP/LDAP/SSH/HTTP) **(v3.8+)** |
| `nuclei` | `object` | (Opcional) Resumen de escaneo Nuclei (targets, hallazgos, estado) **(v3.7+)** |
| `config_snapshot` | `object` | Snapshot de configuración (sin secretos) **(v3.7+)** |
| `pipeline` | `object` | Resumen del pipeline (net discovery, host scan, agentless, nuclei, vuln scan) **(v3.7+)** |
| `smart_scan_summary` | `object` | Resumen SmartScan (identity score, deep scans) **(v3.7+)** |
| `hosts` | `array` | Lista de objetos `Host` (ver abajo) |
| `vulnerabilities` | `array` | Lista de hallazgos de vulnerabilidades |
| `summary` | `object` | Estadísticas agregadas |

### summary.json (Resumen para dashboards)

Resumen compacto para dashboards y automatización (se genera solo cuando el cifrado de informes está deshabilitado).

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `schema_version` | `string` | Versión del esquema del resumen |
| `generated_at` | `string` | Marca de tiempo de generación (ISO 8601) |
| `session_id` | `string` | UUID de la sesión de escaneo |
| `scan_duration` | `string` | Duración del escaneo (HH:MM:SS) |
| `total_assets` | `integer` | Total de activos descubiertos |
| `total_findings` | `integer` | Total de hallazgos |
| `total_findings_raw` | `integer` | Total de hallazgos antes de consolidar |
| `severity_breakdown` | `object` | Hallazgos por severidad (critical/high/medium/low/info) |
| `severity_counts` | `object` | Alias de `severity_breakdown` |
| `category_breakdown` | `object` | Hallazgos por categoría (surface/vuln/...) |
| `max_risk_score` | `integer` | Puntuación de riesgo máxima |
| `high_risk_assets` | `integer` | Activos por encima del umbral de alto riesgo |
| `targets` | `array` | Redes objetivo escaneadas |
| `scanner_versions` | `object` | Versiones de herramientas detectadas |
| `scan_mode` | `string` | Modo de escaneo (rapido/normal/completo) |
| `scan_mode_cli` | `string` | Modo CLI (best-effort) |
| `options` | `object` | Snapshot compacto de config (threads/udp/topología/net-discovery/nuclei/etc.) |
| `pipeline` | `object` | Resumen del pipeline (mismo formato que el informe principal) |
| `smart_scan_summary` | `object` | Resumen de SmartScan |
| `redaudit_version` | `string` | Versión de RedAudit |

### Objeto Verificación sin agente (Opcional) (v3.8+)

Este bloque solo aparece si la verificación sin agente está habilitada.

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `enabled` | boolean | Indica si la verificación sin agente estaba habilitada |
| `targets` | integer | Número de objetivos elegibles seleccionados |
| `completed` | integer | Número de verificaciones completadas |
| `signals` | object | Conteos por protocolo (smb/rdp/ldap/ssh/http) |
| `domains` | array | Pistas de dominios detectadas (best-effort) |

### Objeto Resumen Nuclei (Opcional) (v3.7+)

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `enabled` | boolean | True cuando Nuclei se ejecutó (best-effort) |
| `targets` | integer | Targets HTTP/HTTPS enviados a Nuclei |
| `findings` | integer | Hallazgos Nuclei parseados |
| `findings_total` | integer | Hallazgos Nuclei totales antes de filtrar falsos positivos |
| `findings_suspected` | integer | Hallazgos Nuclei marcados como falsos positivos sospechados |
| `suspected` | array | (Opcional) Lista mínima de sospechosos (template_id/matched_at/fp_reason) |
| `success` | boolean | Archivo de salida generado y sin lotes fallidos |
| `partial` | boolean | (Opcional) Uno o más lotes con timeout; resultados incompletos |
| `timeout_batches` | array | (Opcional) Índices de lotes con timeout |
| `failed_batches` | array | (Opcional) Índices de lotes fallidos tras reintento |
| `output_file` | string | Ruta relativa al archivo de salida (best-effort) |
| `error` | string | Error si Nuclei falló (best-effort, p. ej., timeout) |

### Config Snapshot (v3.7+)

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `targets` | array | Redes objetivo |
| `scan_mode` | string | Modo de escaneo |
| `scan_mode_cli` | string | Modo CLI (best-effort) |
| `threads` | integer | Concurrencia usada |
| `rate_limit_delay` | number | Retardo entre hosts (segundos) |
| `udp_mode` | string | Modo UDP |
| `udp_top_ports` | integer | Cobertura UDP |
| `topology_enabled` | boolean | Topología habilitada |
| `topology_only` | boolean | Modo solo topología |
| `net_discovery_enabled` | boolean | Net Discovery habilitado |
| `net_discovery_redteam` | boolean | Red Team habilitado |
| `net_discovery_active_l2` | boolean | Checks L2 activos habilitados |
| `net_discovery_kerberos_userenum` | boolean | Userenum Kerberos habilitado |
| `windows_verify_enabled` | boolean | Verificación sin agente |
| `windows_verify_max_targets` | integer | Máx. objetivos para verificación sin agente |
| `scan_vulnerabilities` | boolean | Vuln web habilitado |
| `nuclei_enabled` | boolean | Nuclei habilitado |
| `cve_lookup_enabled` | boolean | Enriquecimiento NVD |
| `dry_run` | boolean | Modo dry-run |
| `prevent_sleep` | boolean | Inhibición de suspensión habilitada |
| `auditor_name` | string | Nombre de auditor (si aplica) |

### Resumen del Pipeline (v3.7+)

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `host_scan` | object | Targets + threads |
| `net_discovery` | object | Conteos DHCP/ARP/NetBIOS/UPNP + redteam |
| `agentless_verify` | object | Targets + completados + conteos por protocolo |
| `nuclei` | object | Resumen Nuclei |
| `vulnerability_scan` | object | Total de hallazgos + fuentes (+ conteo raw) |

### findings.jsonl (Campos Seleccionados)

Exportación plana, un hallazgo por línea para SIEM.

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `title` | string | Título corto y legible (con fallback) |
| `descriptive_title` | string | Título enriquecido derivado de observaciones (best-effort) |
| `severity` | string | Severidad (critical/high/medium/low/info) |
| `source` | string | Herramienta principal (nikto/testssl/nuclei/etc.) |

### Resumen SmartScan (v3.7+)

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `hosts` | integer | Hosts evaluados por SmartScan |
| `identity_score_avg` | number | Promedio de identidad |
| `deep_scan_triggered` | integer | Hosts que dispararon deep scan |
| `deep_scan_executed` | integer | Hosts con deep scan ejecutado |
| `signals` | object | Conteos de señales |
| `reasons` | object | Razones de activación |

### Objeto Net Discovery (Opcional) (v3.2+)

Este campo aparece solo si el descubrimiento de red fue habilitado (CLI: `--net-discovery`).

El descubrimiento de red es **best-effort**: herramientas faltantes reducirán la visibilidad pero no fallarán el escaneo.

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `enabled` | boolean | Siempre true cuando el bloque está presente |
| `generated_at` | string | Marca de tiempo (ISO 8601) |
| `protocols_used` | array | Lista de protocolos usados (dhcp, netbios, mdns, upnp, arp, fping) |
| `redteam_enabled` | boolean | True si las técnicas Red Team fueron habilitadas |
| `tools` | object | Flags de disponibilidad de herramientas (nmap, fping, nbtscan, etc.) |
| `dhcp_servers` | array | Servidores DHCP descubiertos (ver abajo) |
| `alive_hosts` | array | IPs respondiendo al sweep fping |
| `netbios_hosts` | array | Hosts Windows descubiertos vía NetBIOS |
| `arp_hosts` | array | Hosts descubiertos vía ARP/netdiscover |
| `mdns_services` | array | Servicios mDNS/Bonjour descubiertos |
| `upnp_devices` | array | Dispositivos UPNP descubiertos |
| `candidate_vlans` | array | Potenciales redes de invitados/VLANs detectadas |
| `redteam` | object | (Opcional) Resultados de recon Red Team (SNMP/SMB/RPC/LDAP/Kerberos/DNS + señales L2 pasivas) |
| `errors` | array | Errores best-effort encontrados |

**Entradas dhcp_servers[]:**

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `ip` | string | Dirección IP del servidor DHCP |
| `subnet` | string | Máscara de subred ofrecida |
| `gateway` | string | Gateway por defecto ofrecido |
| `dns` | array | Servidores DNS ofrecidos |
| `domain` | string | (Opcional) Pista de dominio desde DHCP (best-effort) |
| `domain_search` | string | (Opcional) Pista de búsqueda de dominio desde DHCP (best-effort) |

**Entradas netbios_hosts[]:**

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `ip` | string | Dirección IP del host |
| `name` | string | Nombre NetBIOS |
| `workgroup` | string | (Opcional) Grupo de trabajo Windows |
| `mac` | string | (Opcional) Dirección MAC |

**Entradas candidate_vlans[]:**

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `source` | string | Método de detección (ej: "dhcp_server") |
| `gateway` | string | IP del gateway de la potencial VLAN |
| `subnet` | string | Máscara de subred |
| `description` | string | Descripción legible |

**Objeto `redteam`** (cuando está activado):

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `enabled` | boolean | Siempre true cuando el bloque está presente |
| `interface` | string | (Opcional) Interfaz usada para capturas L2 (si se define) |
| `targets_considered` | integer | Número de objetivos candidatos seleccionados para checks Red Team |
| `targets_sample` | array | Muestra de IPs objetivo (primeras 10) |
| `snmp` | object | Resumen de enumeración SNMP (best-effort, solo lectura) |
| `smb` | object | Resumen de enumeración SMB (best-effort, solo lectura) |
| `rpc` | object | Resumen de enumeración RPC (best-effort) |
| `ldap` | object | Resumen RootDSE LDAP (best-effort) |
| `kerberos` | object | Descubrimiento de realm Kerberos + userenum opcional (best-effort) |
| `dns_zone_transfer` | object | Resumen de intento AXFR DNS (best-effort; requiere pista de zona) |
| `masscan` | object | Resumen opcional de masscan (requiere root; se omite en rangos grandes) |
| `vlan_enum` | object | Pistas de VLAN/DTP (pasivo; requiere tcpdump + root) |
| `stp_topology` | object | Pistas BPDU STP (pasivo; requiere tcpdump + root) |
| `hsrp_vrrp` | object | Pistas presencia HSRP/VRRP (pasivo; requiere tcpdump + root) |
| `llmnr_nbtns` | object | Muestras de queries LLMNR/NBT-NS (pasivo; requiere tcpdump + root) |
| `router_discovery` | object | Routers multicast candidatos (best-effort) |
| `ipv6_discovery` | object | Muestra caché de vecinos IPv6 (best-effort) |
| `bettercap_recon` | object | Salida opcional de bettercap (requiere opt-in explícito) |
| `scapy_custom` | object | Bloque opcional de sniff pasivo con scapy (requiere opt-in explícito) |

### Objeto Host

Representa una única dirección IP objetivo.

Campos adicionales a nivel de host:

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `os_detected` | string | (Opcional) Fingerprint de SO (best-effort; normalmente desde salida de deep scan) **(v3.1.4+)** |
| `agentless_probe` | object | (Opcional) Salida raw de probes SMB/RDP/LDAP/SSH/HTTP **(v3.8.5)** |
| `agentless_fingerprint` | object | (Opcional) Hints normalizados de identidad (ver abajo) **(v3.8.5+)** |

```json
{
  "ip": "192.168.1.10",
  "status": "up",
  "ports": [
    {
      "port": 80,
      "asset_type": "workstation",  // router, vpn, server, printer, media, mobile, iot, etc.
      "state": "open",
      "protocol": "tcp",
      "service": "http",
      "product": "Apache httpd",
      "version": "2.4.41",
      "banner": "Apache/2.4.41 (Ubuntu)",
      "ssl_cert": {
        "subject": "CN=example.com",
        "issuer": "Let's Encrypt"
      },
      "known_exploits": [
        {
          "title": "Apache 2.4.41 - Remote Code Execution",
          "id": "EDB-12345",
          "url": "https://www.exploit-db.com/exploits/12345"
        }
      ]
    }
  ]
}
```

### Objeto Fingerprint sin agente (Opcional) (v3.8.5+)

Hints normalizados derivados de probes SMB/RDP/LDAP. Todos los campos son opcionales.

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `domain` | string | Pista de dominio DNS o NetBIOS |
| `computer_name` | string | Hostname desde hints RDP/SMB |
| `product_version` | string | Versión de producto RDP (best-effort) |
| `os` | string | Hint de SO desde scripts SMB |
| `workgroup` | string | Workgroup SMB |
| `smb_signing_enabled` | boolean | SMB signing habilitado (best-effort) |
| `smb_signing_required` | boolean | SMB signing requerido (best-effort) |
| `smbv1_detected` | boolean | Presencia de SMBv1 detectada |
| `upnp_device_name` | string | Nombre de dispositivo desde descubrimiento UPnP (best-effort) |
| `http_title` | string | Título HTTP desde probe sin agente o probe HTTP rápido |
| `http_server` | string | Header Server HTTP desde probe sin agente o probe HTTP rápido |
| `http_source` | string | Origen de las pistas HTTP: `upnp`, `probe` o `enrichment` |
| `ssh_hostkeys` | array | Fingerprints de host key SSH (best-effort) |
| `defaultNamingContext` | string | LDAP RootDSE default naming context |
| `rootDomainNamingContext` | string | LDAP RootDSE root domain naming context |
| `dnsHostName` | string | LDAP RootDSE DNS host name |
| `ldapServiceName` | string | LDAP RootDSE service name |

**Tipos de Estado de Host**:

- `up`: El host respondió y tiene puertos abiertos
- `down`: Sin respuesta en absoluto
- `filtered`: MAC/vendor detectado pero puertos filtrados
- `no-response`: Deep scan intentado pero sin datos significativos

### Objeto Deep Scan (Opcional)

Este campo aparece solo si se activó el escaneo profundo automático.

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `strategy` | string | Identificador de estrategia (p. ej., `adaptive_v2.8`) |
| `mac_address` | string | (Opcional) Dirección MAC si se detectó |
| `vendor` | string | (Opcional) Fabricante de hardware si se detectó |
| `os_detected` | string | (Opcional) Fingerprint de SO extraído desde salida de Nmap **(v3.1.4+)** |
| `phase2_skipped` | boolean | True si la Fase 2 (UDP/SO) se omitió porque la Fase 1 encontró identidad |
| `phase2b_skipped` | boolean | True si se omitió el escaneo UDP extendido de identidad (modo quick) |
| `udp_mode` | string | Modo de escaneo UDP usado: `quick` o `full` |
| `udp_top_ports` | integer | (Opcional) Número de top puertos UDP usados en Fase 2b (50-500) **(v3.1+)** |
| `commands` | array | Lista de comandos Nmap ejecutados, logs y duraciones |
| `commands[].command` | string | Línea de comando completa ejecutada |
| `commands[].returncode` | integer | Código de salida del comando |
| `commands[].stdout` | string | Salida estándar (truncada a 8000 chars) |
| `commands[].stderr` | string | Error estándar (truncado a 2000 chars) |
| `commands[].duration_seconds` | float | Tiempo de ejecución en segundos |
| `commands[].error` | string | (Opcional) Mensaje de error si el comando falló |
| `pcap_capture` | object | (Opcional) Detalles sobre la micro-captura de tráfico |
| `pcap_capture.pcap_file` | string | Nombre de archivo relativo portable (p. ej., `traffic_192_168_1_1_235959.pcap`) **(v3.1.4)** |
| `pcap_capture.pcap_file_abs` | string | (Opcional) Ruta absoluta - para uso interno **(v3.1.4)** |
| `pcap_capture.iface` | string | Interfaz de red usada para la captura |
| `pcap_capture.tshark_summary` | string | (Opcional) Estadísticas de protocolos de alto nivel si tshark está instalado |
| `pcap_capture.tshark_error` | string | (Opcional) Error de tshark si falló |
| `pcap_capture.tcpdump_error` | string | (Opcional) Error de tcpdump si falló |

### Objeto Topology (Opcional) (v3.1+)

Este campo aparece solo si se activó el descubrimiento de topología (CLI: `--topology` / `--topology-only`, o mediante pregunta en modo interactivo).

El descubrimiento es **best-effort**: si faltan herramientas, permisos o tráfico, habrá menos visibilidad, pero no debería fallar el escaneo principal.

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `enabled` | boolean | Siempre true cuando el bloque está presente |
| `generated_at` | string | Marca de tiempo (ISO 8601) |
| `tools` | object | Flags de disponibilidad (`ip`, `tcpdump`, `arp-scan`, `lldpctl`) |
| `routes` | array | Salida de `ip route show` parseada en objetos |
| `default_gateway` | object | (Opcional) Gateway por defecto con `ip`, `interface`, `metric` |
| `interfaces` | array | Objetos de topología por interfaz (ARP, VLAN, LLDP, etc.) |
| `candidate_networks` | array | Redes en la tabla de rutas no incluidas en objetivos ni redes locales |
| `errors` | array | Errores best-effort durante el descubrimiento |

**interfaces[]** (alto nivel):

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `interface` | string | Nombre de interfaz (p. ej., `eth0`) |
| `ip` | string | (Opcional) IP de la interfaz |
| `networks` | array | Redes locales asociadas a la interfaz |
| `arp` | object | Salida de descubrimiento ARP (`method`, `hosts`, `error`) |
| `neighbor_cache` | object | Entradas parseadas de `ip neigh` (si está disponible) |
| `vlan` | object | VLAN IDs observados (`ids`, `sources`) |
| `lldp` | object | Resumen de vecinos LLDP (si está disponible) |
| `cdp` | object | Observaciones CDP raw (best-effort, si se capturan) |

### Campos de Enriquecimiento CVE (Opcional)

Estos campos aparecen solo cuando la correlación CVE está activada (por ejemplo, `--cve-lookup`) y hay datos de enriquecimiento disponibles.
El enriquecimiento solo se realiza para servicios con información de versión detectada (o un CPE con versión).

**Campos a nivel de puerto** (dentro de `hosts[].ports[]`):

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `cves` | array | (Opcional) Lista de CVEs (top 10) asociados al servicio |
| `cves[].cve_id` | string | Identificador CVE (ej: `CVE-2024-12345`) |
| `cves[].cvss_score` | number | (Opcional) Puntuación base CVSS |
| `cves[].cvss_severity` | string | (Opcional) Severidad CVSS (LOW/MEDIUM/HIGH/CRITICAL) |
| `cves[].description` | string | (Opcional) Descripción corta (truncada) |
| `cves[].published` | string | (Opcional) Fecha de publicación (ISO 8601) |
| `cve_count` | integer | (Opcional) Número total de CVEs asociados (puede ser >10) |
| `cve_max_severity` | string | (Opcional) Severidad máxima entre CVEs asociados |

**Campos a nivel de host** (dentro de `hosts[]`):

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `cve_summary` | object | (Opcional) Estadísticas agregadas de CVE para el host |
| `cve_summary.total` | integer | Total de CVEs en todos los puertos |
| `cve_summary.critical` | integer | Número de puertos con severidad máxima CRITICAL |
| `cve_summary.high` | integer | Número de puertos con severidad máxima HIGH |

### Objeto DNS (Opcional)

Aparece en registros de host cuando se realizó enriquecimiento DNS/whois.

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `reverse` | array | Lista de registros PTR de DNS reverso |
| `whois_summary` | string | (Opcional) Información whois para IPs públicas (primeras 25 líneas) |

## Array de Vulnerabilidades

Lista de hallazgos de vulnerabilidades web. Cada entrada contiene:

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `host` | string | Dirección IP del host |
| `vulnerabilities` | array | Lista de hallazgos de vulnerabilidades por URL |
| `vulnerabilities[].url` | string | URL completa testeada |
| `vulnerabilities[].port` | integer | Número de puerto |
| `vulnerabilities[].service` | string | Nombre del servicio |
| `vulnerabilities[].findings` | array | Lista de strings de vulnerabilidades |
| `vulnerabilities[].whatweb` | string | (Opcional) Salida de WhatWeb |
| `vulnerabilities[].nikto_findings` | array | (Opcional) Hallazgos de Nikto (si modo FULL) |
| `vulnerabilities[].testssl_analysis` | object | Resultados de TestSSL.sh para HTTPS en modo full (requiere `testssl.sh`) |
| `vulnerabilities[].severity` | string | Severidad: critical/high/medium/low/info |
| `vulnerabilities[].severity_score` | integer | Severidad numérica (0-100) |
| `vulnerabilities[].finding_id` | string | Hash determinístico para deduplicación **(v3.1)** |
| `vulnerabilities[].category` | string | Clasificación: surface/misconfig/crypto/auth/info-leak/vuln **(v3.1)** |
| `vulnerabilities[].normalized_severity` | float | Puntuación CVSS (0.0-10.0) **(v3.1)** |
| `vulnerabilities[].original_severity` | object | Severidad original de la herramienta **(v3.1)** |
| `vulnerabilities[].parsed_observations` | array | Hallazgos estructurados de Nikto/TestSSL **(v3.1)** |
| `vulnerabilities[].raw_tool_output_sha256` | string | (Opcional) Hash del output raw **(v3.1)** |
| `vulnerabilities[].raw_tool_output_ref` | string | (Opcional) Ruta a evidencia externalizada **(v3.1)** |
| `vulnerabilities[].curl_headers` | string | (Opcional) Cabeceras HTTP de curl |
| `vulnerabilities[].wget_headers` | string | (Opcional) Salida de spider de Wget (cabeceras de respuesta desde stderr) |
| `vulnerabilities[].tls_info` | string | (Opcional) Info de certificado TLS |
| `vulnerabilities[].nikto_filtered_count` | integer | Número de falsos positivos de Nikto filtrados |
| `vulnerabilities[].severity_note` | string | (Opcional) Explicación cuando la severidad fue ajustada **(v3.1.4)** |
| `vulnerabilities[].potential_false_positives` | array | (Opcional) Contradicciones detectadas en cross-validación **(v3.1.4)** |
| `vulnerabilities[].affected_ports` | array | (Opcional) Lista de puertos compartiendo este hallazgo cuando está consolidado **(v3.6.1)** |

### Campos de Captura PCAP (v3.1.4)

Desde v3.1.4, las referencias a archivos PCAP usan rutas relativas portables:

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `pcap_file` | string | Nombre de archivo relativo (ej: `traffic_192.168.1.1.pcap`) - portable |
| `pcap_file_abs` | string | Ruta absoluta - para uso interno |

## Objeto Scan Summary

```json
{
  "networks": 1,
  "hosts_found": 15,
  "hosts_scanned": 12,
  "vulns_found": 3,
  "duration": "0:02:05"
}
```

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `networks` | integer | Número de redes objetivo escaneadas |
| `hosts_found` | integer | Total de hosts descubiertos (up) |
| `hosts_scanned` | integer | Hosts que se sometieron a escaneo de puertos completo |
| `vulns_found` | integer | Total de vulnerabilidades web encontradas |
| `duration` | string | Duración total del escaneo (formato HH:MM:SS) |

## Array Network Info

Lista de interfaces de red detectadas.

```json
[
  {
    "interface": "eth0",
    "ip": "192.168.1.100",
    "network": "192.168.1.0/24",
    "hosts_estimated": 253,
    "type": "Ethernet"
  }
]
```
