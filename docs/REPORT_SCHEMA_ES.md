# Esquema de Reportes RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](REPORT_SCHEMA.md)

## Visión General

RedAudit genera reportes legibles por máquina en formato JSON. Este documento describe la estructura del esquema para los artefactos `redaudit_report_<timestamp>.json`.

**Tipos de Datos**: Tipos JSON estándar (`string`, `number`, `boolean`, `array`, `object`).
**Nullable**: Los campos son nullable a menos que se especifique lo contrario.
**Módulo Fuente**: `redaudit/core/reporter.py` (v2.7+)

## Definición del Esquema

### Objeto Raíz

El contenedor de nivel superior para la sesión de escaneo.

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `schema_version` | `string` | Versión del esquema (v2.7+: "2.0") |
| `event_type` | `string` | Tipo de evento para ingesta SIEM ("redaudit.scan.complete") |
| `session_id` | `string` | UUID único para esta sesión de escaneo |
| `timestamp` | `string` | Marca de tiempo de inicio (ISO 8601) |
| `timestamp_end` | `string` | Marca de tiempo de fin (ISO 8601) |
| `version` | `string` | Versión de RedAudit |
| `scanner` | `object` | Metadatos del escáner: `name`, `version`, `mode` |
| `targets` | `array` | Lista de redes objetivo escaneadas |
| `network_info` | `array` | Lista de objetos de interfaz de red |
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

### Objeto Deep Scan (Opcional)

Este campo aparece solo si se activó el escaneo profundo automático.

| Campo | Tipo | Descripción |
|---|---|---|
| `strategy` | string | Identificador de estrategia ("adaptive_v2.5" - característica introducida en v2.5) |
| `mac_address` | string | (Opcional) Dirección MAC si se detectó |
| `vendor` | string | (Opcional) Fabricante de hardware si se detectó |
| `phase2_skipped` | boolean | True si la Fase 2 (UDP/SO) se omitió porque la Fase 1 encontró identidad |
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
| `vulnerabilities[].testssl_analysis` | object | (Opcional) Resultados de TestSSL.sh (si modo FULL y HTTPS). |
| `vulnerabilities[].curl_headers` | string | (Opcional) Cabeceras HTTP de curl |
| `vulnerabilities[].wget_spider` | string | (Opcional) Salida de spider de Wget |
| `vulnerabilities[].tls_info` | string | (Opcional) Info de certificado TLS de OpenSSL |

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
