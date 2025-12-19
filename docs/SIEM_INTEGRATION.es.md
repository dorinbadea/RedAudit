# Guía de Integración SIEM

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](SIEM_INTEGRATION.en.md)

RedAudit produce exportaciones JSONL conformes a ECS v8.11 que se integran directamente con Elastic Stack, Splunk y otras plataformas SIEM.

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

### findings.jsonl

Cada línea contiene un hallazgo de vulnerabilidad:

```json
{
  "@timestamp": "2025-12-18T12:00:00Z",
  "event": {
    "module": "redaudit",
    "category": "vulnerability"
  },
  "host": {
    "ip": "192.168.1.100",
    "name": "webserver"
  },
  "vulnerability": {
    "id": "CVE-2021-44228",
    "severity": "critical",
    "score": 10.0,
    "description": "Log4Shell RCE"
  }
}
```

### assets.jsonl

Cada línea contiene un host/servicio descubierto:

```json
{
  "@timestamp": "2025-12-18T12:00:00Z",
  "event": {
    "module": "redaudit",
    "category": "host"
  },
  "host": {
    "ip": "192.168.1.100",
    "mac": "00:11:22:33:44:55",
    "vendor": "Dell Inc."
  },
  "service": {
    "name": "ssh",
    "version": "OpenSSH 8.9p1"
  }
}
```

## Reglas Sigma Incluidas

| Regla | Descripción |
|-------|-------------|
| `redaudit_critical_vuln.yml` | Hallazgos de severidad crítica/alta |
| `redaudit_missing_headers.yml` | Problemas con cabeceras de seguridad web |
| `redaudit_ssl_tls_vuln.yml` | Vulnerabilidades SSL/TLS |

## Integración con Splunk

Para Splunk, usa el HTTP Event Collector (HEC):

1. Crea un token HEC en Splunk
2. Configura Filebeat con `output.logstash` deshabilitado y `output.http` habilitado
3. Apunta a tu endpoint HEC de Splunk

## Resolución de Problemas

- **¿No hay datos en Elasticsearch?** Revisa los logs de Filebeat: `journalctl -u filebeat -f`
- **¿Errores de parseo?** Verifica que los archivos JSONL son válidos: `jq . < findings.jsonl`
- **¿Faltan campos?** Verifica la compatibilidad de versión ECS
