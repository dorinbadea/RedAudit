# Guía de Integración SIEM

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](SIEM_INTEGRATION.en.md)

RedAudit produce exportaciones JSONL orientadas a SIEM y proporciona configuraciones de Filebeat/Logstash para ingestión alineada con ECS en Elastic Stack y otras plataformas.

## Inicio Rápido (Elastic Stack)

### 1. Configurar Filebeat

Copia la configuración incluida:

```bash
sudo cp siem/filebeat.yml /etc/filebeat/filebeat.yml
```

Edita las rutas y credenciales, luego:

```bash
sudo filebeat setup
sudo systemctl restart filebeat
```

### 2. Configurar Logstash (Opcional)

Para procesamiento adicional (normalización de severidad, extracción de CVE):

```bash
sudo cp siem/logstash.conf /etc/logstash/conf.d/redaudit.conf
sudo systemctl restart logstash
```

### 3. Importar Reglas Sigma

Convierte las reglas Sigma al formato de tu SIEM:

```bash
# Para Elasticsearch/Kibana
sigma convert -t elasticsearch -p ecs_windows siem/sigma/*.yml

# Para Splunk
sigma convert -t splunk siem/sigma/*.yml

# Para QRadar
sigma convert -t qradar siem/sigma/*.yml
```

## Esquema JSONL de RedAudit

Las exportaciones JSONL se generan solo cuando el cifrado de informes está desactivado.

### findings.jsonl

Cada línea contiene un hallazgo de vulnerabilidad:

```json
{
  "finding_id": "b6c5c8b5...",
  "asset_id": "7f3a2d1c...",
  "asset_ip": "192.168.1.100",
  "asset_hostname": "webserver",
  "port": 443,
  "url": "https://192.168.1.100/",
  "severity": "high",
  "normalized_severity": 8.2,
  "category": "vuln",
  "title": "Cifrado TLS débil",
  "descriptive_title": "Se detectó una suite TLS débil",
  "source": "testssl",
  "cve_ids": ["CVE-2021-12345"],
  "timestamp": "2025-12-18T12:00:00Z",
  "scan_mode": "normal",
  "session_id": "9db9b6b1-2c4c-4b2a-8d42-0b0a6f0b0a3f",
  "schema_version": "3.10.0",
  "scanner": "RedAudit",
  "scanner_version": "3.10.0"
}
```

Notas:
- `asset_hostname` usa fallback best-effort en este orden: `hostname`, luego `dns.reverse`, luego `phase0_enrichment.dns_reverse`.

### assets.jsonl

Cada línea contiene un host/servicio descubierto:

```json
{
  "asset_id": "7f3a2d1c...",
  "ip": "192.168.1.100",
  "hostname": "webserver",
  "status": "up",
  "risk_score": 72,
  "asset_type": "server",
  "os_detected": "Linux 5.x",
  "total_ports": 6,
  "web_ports": 2,
  "finding_count": 3,
  "tags": ["web", "linux"],
  "mac": "00:11:22:33:44:55",
  "vendor": "Dell Inc.",
  "timestamp": "2025-12-18T12:00:00Z",
  "scan_mode": "normal",
  "session_id": "9db9b6b1-2c4c-4b2a-8d42-0b0a6f0b0a3f",
  "schema_version": "3.10.0",
  "scanner": "RedAudit",
  "scanner_version": "3.10.0"
}
```

Notas:
- `hostname` usa fallback best-effort en este orden: `hostname`, luego `dns.reverse`, luego `phase0_enrichment.dns_reverse`.

### Flujos Brutos de Nuclei (Contrato NDJSON)

RedAudit también escribe flujos brutos de Nuclei en la carpeta del escaneo:

- `nuclei_output.json`: flujo NDJSON (un objeto JSON por cada línea no vacía).
- `nuclei_output_resume.json`: flujo NDJSON opcional para anexos de reanudación.

Estos ficheros son flujos brutos del escáner (no exportaciones SIEM normalizadas a ECS) y se validan con el gate de artefactos:

```bash
python scripts/check_scan_artifacts.py --run-dir <carpeta_scan> --strict
```

Comportamiento esperado:
- `nuclei_output.json` debe parsear como NDJSON.
- `nuclei_output_resume.json` puede quedar vacío cuando no se añadieron registros nuevos.

## Reglas Sigma Incluidas

| Regla | Descripción |
|-------|-------------|
| `redaudit_critical_vuln.yml` | Hallazgos de severidad crítica/alta |
| `redaudit_missing_headers.yml` | Problemas con cabeceras de seguridad web |
| `redaudit_ssl_tls_vuln.yml` | Vulnerabilidades SSL/TLS |

## Integración con Splunk

Para Splunk, usa el HTTP Event Collector (HEC) o tu canal de ingestión habitual. RedAudit no incluye configuraciones específicas de Splunk.

1. Crea un token HEC en Splunk
2. Configura tu agente de envío para enviar eventos JSONL a HEC
3. Mapea los campos de RedAudit a tus índices/sourcetypes

## Resolución de Problemas

- **¿No hay datos en Elasticsearch?** Revisa los logs de Filebeat: `journalctl -u filebeat -f`
- **¿Errores de parseo?** Valida explícitamente flujos delimitados por línea:
  - `jq -c . findings.jsonl >/dev/null`
  - `jq -c . assets.jsonl >/dev/null`
  - `jq -c . nuclei_output.json >/dev/null`
- **¿Faltan campos?** Verifica las transformaciones de Filebeat/Logstash y el mapeo ECS
