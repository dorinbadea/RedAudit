# Notas de Versión RedAudit v3.7.0

**Fecha de Lanzamiento:** 2025-12-18

[![View in English](https://img.shields.io/badge/🇬🇧_English-blue?style=flat-square)](RELEASE_NOTES_v3.7.0.md)

## Descripción

RedAudit v3.7.0 introduce **mejoras de UX en el Wizard** e **integración SIEM**, facilitando la configuración de opciones avanzadas y la exportación de resultados a plataformas de seguridad empresarial.

## Nuevas Funcionalidades

### Webhooks Interactivos

Configura webhooks de alertas en tiempo real desde el wizard:

- Soporta Slack, Microsoft Teams y PagerDuty
- Alerta de prueba opcional para verificar conectividad
- Persistido en `~/.redaudit/config.json`

### Net Discovery Avanzado en Wizard

Nuevos prompts del wizard para opciones expertas Red Team:

- Cadena de comunidad SNMP (por defecto: `public`)
- Zona DNS para intentos de transferencia de zona
- Máximo de objetivos para módulos Red Team

### Pipeline SIEM Nativo

Configuraciones empaquetadas para integración Elastic Stack:

- `siem/filebeat.yml` - Ingesta JSONL compatible con ECS v8.11
- `siem/logstash.conf` - Normalización de severidad y extracción de CVE
- `siem/sigma/` - 3 reglas de detección (vulns críticas, cabeceras, SSL/TLS)

### Verificación Osquery

Nuevo módulo para validación de hosts post-scan:

- Ejecuta consultas Osquery via SSH
- Verifica puertos abiertos, servicios activos, certificados SSL
- Confirma hallazgos del scan contra estado real del host

### Logging de Sesión

Salida de terminal capturada automáticamente durante escaneos:

```
<output_dir>/
└── session_logs/
    ├── session_<timestamp>.log  # Raw con colores ANSI
    └── session_<timestamp>.txt  # Limpio, legible
```

### Spinner de Progreso Nuclei

Feedback visual durante escaneos de templates Nuclei:

```
⠋ Nuclei escaneando 19 objetivos... 0:01:23
```

## Corregido

- **CI CodeQL**: Bajada de `codeql-action` a v3 por compatibilidad con GitHub Actions

## Instalación

```bash
# Actualizar instalación existente
pip install --upgrade redaudit

# O desde fuente
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit && pip install -e .
```

## Documentación

- [Guía de Integración SIEM](docs/SIEM_INTEGRATION.en.md)
- [Changelog Completo](../../ES/CHANGELOG_ES.md)
