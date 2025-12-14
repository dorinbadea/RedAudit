# Esquema de Reportes RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](../en/REPORT_SCHEMA.md)

## Visión General

RedAudit genera reportes legibles por máquina en formato JSON. Este documento describe la estructura del esquema para los artefactos `redaudit_<timestamp>.json`.

**Tipos de Datos**: Tipos JSON estándar (`string`, `number`, `boolean`, `array`, `object`).
**Nullable**: Los campos son nullable a menos que se especifique lo contrario.
**Módulo Fuente**: `redaudit/core/reporter.py`

## Vistas de Exportación Adicionales (v3.1)

En el mismo directorio de salida, RedAudit también puede generar archivos planos optimizados para pipelines SIEM e IA:

- `findings.jsonl`: Un hallazgo por línea
- `assets.jsonl`: Un activo por línea
- `summary.json`: Resumen compacto para dashboards

Estas exportaciones se generan solo cuando el cifrado de reportes está **desactivado**, para evitar crear artefactos en texto plano junto a reportes cifrados.

## Definición del Esquema

### Objeto Raíz

El contenedor de nivel superior para la sesión de escaneo.

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `schema_version` | `string` | Versión del esquema ("3.1") |
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
| `hosts` | `array` | Lista de objetos `Host` (ver abajo) |
| `vulnerabilities` | `array` | Lista de hallazgos de vulnerabilidades |
| `summary` | `object` | Estadísticas agregadas |

### Objeto Host

Representa una única dirección IP objetivo.

```json
{
  "ip": "192.168.1.10",
  "status": "up",
  "ports": [
    {
      "port": 80,
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

**Tipos de Estado de Host**:

- `up`: El host respondió y tiene puertos abiertos
- `down`: Sin respuesta en absoluto
- `filtered`: MAC/vendor detectado pero puertos filtrados
- `no-response`: Deep scan intentado pero sin datos significativos

### Objeto Deep Scan (Opcional)

Este campo aparece solo si se activó el escaneo profundo automático.

| Campo | Tipo | Descripción |
|---|---|---|
| `strategy` | string | Identificador de estrategia (p. ej., `adaptive_v2.8`) |
| `mac_address` | string | (Opcional) Dirección MAC si se detectó |
| `vendor` | string | (Opcional) Fabricante de hardware si se detectó |
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
| `pcap_capture.pcap_file` | string | Ruta absoluta al archivo .pcap generado |
| `pcap_capture.iface` | string | Interfaz de red usada para la captura |
| `pcap_capture.tshark_summary` | string | (Opcional) Estadísticas de protocolos de alto nivel si tshark está instalado |
| `pcap_capture.tshark_error` | string | (Opcional) Error de tshark si falló |
| `pcap_capture.tcpdump_error` | string | (Opcional) Error de tcpdump si falló |

### Objeto Topology (Opcional) (v3.1+)

Este campo aparece solo si se activó el descubrimiento de topología (CLI: `--topology` / `--topology-only`, o mediante pregunta en modo interactivo).

El descubrimiento es **best-effort**: si faltan herramientas, permisos o tráfico, habrá menos visibilidad, pero no debería fallar el escaneo principal.

| Campo | Tipo | Descripción |
|---|---|---|
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
|---|---|---|
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
|---|---|---|
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
|---|---|---|
| `cve_summary` | object | (Opcional) Estadísticas agregadas de CVE para el host |
| `cve_summary.total` | integer | Total de CVEs en todos los puertos |
| `cve_summary.critical` | integer | Número de puertos con severidad máxima CRITICAL |
| `cve_summary.high` | integer | Número de puertos con severidad máxima HIGH |

### Objeto DNS (Opcional)

Aparece en registros de host cuando se realizó enriquecimiento DNS/whois.

| Campo | Tipo | Descripción |
|---|---|---|
| `reverse` | array | Lista de registros PTR de DNS reverso |
| `whois_summary` | string | (Opcional) Información whois para IPs públicas (primeras 25 líneas) |

## Array de Vulnerabilidades

Lista de hallazgos de vulnerabilidades web. Cada entrada contiene:

| Campo | Tipo | Descripción |
|---|---|---|
| `host` | string | Dirección IP del host |
| `vulnerabilities` | array | Lista de hallazgos de vulnerabilidades por URL |
| `vulnerabilities[].url` | string | URL completa testeada |
| `vulnerabilities[].port` | integer | Número de puerto |
| `vulnerabilities[].service` | string | Nombre del servicio |
| `vulnerabilities[].findings` | array | Lista de strings de vulnerabilidades |
| `vulnerabilities[].whatweb` | string | (Opcional) Salida de WhatWeb |
| `vulnerabilities[].nikto_findings` | array | (Opcional) Hallazgos de Nikto (si modo FULL) |
| `vulnerabilities[].testssl_analysis` | object | (Opcional) Resultados de TestSSL.sh |
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
| `vulnerabilities[].wget_spider` | string | (Opcional) Salida de spider de Wget |
| `vulnerabilities[].tls_info` | string | (Opcional) Info de certificado TLS |

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
|---|---|---|
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
