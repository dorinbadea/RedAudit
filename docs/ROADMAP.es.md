# Roadmap y Propuestas Arquitectónicas

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](ROADMAP.en.md)

**Audiencia:** Colaboradores, Stakeholders
**Alcance:** Funcionalidades planeadas, propuestas autorizadas, historial.
**Fuente de verdad:** Estado del código en repositorio e historial Git

---

Este documento detalla el roadmap técnico, verifica las capacidades ya implementadas y documenta los enfoques descartados para RedAudit.

## 1. Roadmap Activo (Próximas Funcionalidades)

Estas características están aprobadas pero **aún no implementadas** en el código base.

### Seguridad e Integraciones (Prioridad: Alta)

| Característica | Estado | Descripción |
| :--- | :--- | :--- |
| **Pipeline SIEM Nativo** | 🎯 Planificado | Configuración empaquetada para Filebeat/Logstash para ingestar JSON ECS de RedAudit. Creación de reglas Sigma. |
| **Verificación Osquery** | 🎯 Planificado | Módulo post-scan para ejecutar queries Osquery en hosts vivos (vía fleet/SSH) para validar configs (firewall, servicios activos). |
| **Webhooks Interactivos** | 🎯 Planificado | Añadir configuración de URL de webhook al asistente interactivo (actualmente solo CLI vía `--webhook`). |

### Extensiones Red Team (Prioridad: Media)

*Requiere autorización especializada y salvaguardas.*

| Característica | Estado | Descripción |
| :--- | :--- | :--- |
| **Integración Impacket** | 🎯 Planificado | Módulo opcional `--redteam-deep` usando `smbexec`/`secretsdump` (vía librería Python) en sesiones nulas detectadas. |
| **Colector BloodHound** | 🎯 Planificado | Ejecución de SharpHound/BloodHound.py en hosts Windows vivos para generar grafos de ataque AD. |
| **Playbooks Red Team** | 🎯 Planificado | Generación automática de scripts PoC (sugerencias Python/Msfvenom) para hallazgos explotables verificados (Solo Labs). |

### Infraestructura (Prioridad: Baja)

| Característica | Estado | Descripción |
| :--- | :--- | :--- |
| **Distribución PyPI** | 🚧 Aplazado | Publicar `pip install redaudit`. Bloqueado por necesidad de testing multiplataforma extensivo. |
| **Contenedorización** | 🚧 Aplazado | Imagen Docker oficial. Aplazado a favor de la estabilidad de instalación estándar pip/venv. |
| **Motor de Plugins** | 🚧 Aplazado | Arquitectura "Plugin-first" para desacoplar el escáner core de las herramientas. |

---

## 2. Capacidades Implementadas (Verificado)

Funcionalidades presentes actualmente en `redaudit --version` >= v3.6.0.

### Escaneo Avanzado y Automatización

| Característica | Versión | Verificación |
| :--- | :--- | :--- |
| **Integración Nuclei** | v3.6.0 | Módulo `redaudit/core/nuclei.py`. Ejecuta templates Nuclei si la herramienta se encuentra. |
| **Generación Playbooks** | v3.4.0 | Módulo `redaudit/core/playbook_generator.py`. Crea guías de remediación MD en `playbooks/`. |
| **Red Team: Kerberos** | v3.2.0 | Módulo `redaudit/core/net_discovery.py`. Usa `kerbrute` para enumeración si está autorizado. |
| **Red Team: SNMP/SMB** | v3.2.0 | Módulo `redaudit/core/net_discovery.py`. Usa `snmpwalk` y `enum4linux`. |
| **Preparación SIEM** | v3.1.0 | Módulo `redaudit/core/siem.py`. Genera JSON/JSONL compatible con ECS v8.11. |
| **Análisis Diferencial** | v3.3.0 | Módulo `redaudit/core/diff.py`. Diff visual HTML entre dos escaneos. |

### Core y Estabilidad

| Característica | Versión | Verificación |
| :--- | :--- | :--- |
| **Versión Única** | v3.6.0 | `__init__.py` usa `importlib.metadata` desde pyproject.toml. |
| **CommandRunner Central** | v3.5.0 | `redaudit/core/command_runner.py` maneja todos los subprocesos de forma segura. |
| **Config Persistente** | v3.1.1 | `~/.redaudit/config.json` almacena defaults del usuario. |
| **Descubrimiento Async** | v3.1.3 | `redaudit/core/hyperscan.py` usa `asyncio` para sondeo rápido de puertos. |

---

## 3. Conceptos Descartados

Ideas consideradas pero rechazadas para mantener el foco del proyecto.

| Propuesta | Razón del Descarte |
| :--- | :--- |
| **GUI Web (Controlador)** | Incrementa superficie de ataque y peso. RedAudit está diseñado como herramienta CLI "headless" para automatización. |
| **Framework de Explotación** | Fuera de alcance. RedAudit es para *auditoría* y *descubrimiento*, no explotación armada (como Metasploit). |
| **Soporte Nativo Windows** | Demasiado complejo debido a requisitos de sockets raw. Usar WSL2 o Docker. |
| **Generación Reporte PDF** | Añade dependencias pesadas (LaTeX/ReportLab). Se prefiere salida JSON/HTML para flujos modernos. |

---

## 4. Contribuir

1. Revisa [Issues](https://github.com/dorinbadea/RedAudit/issues).
2. Lee [CONTRIBUTING.md](../.github/CONTRIBUTING.md).
3. Abre una Discusión antes de iniciar grandes funcionalidades.

[Volver al Índice de Documentación](INDEX.md)
