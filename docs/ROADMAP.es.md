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

*(No hay ítems de prioridad alta pendientes actualmente)*

### Extensiones Red Team (Prioridad: Media)

*(No hay elementos de prioridad media pendientes actualmente)*

### Infraestructura (Prioridad: Baja)

| Característica | Estado | Descripción |
| :--- | :--- | :--- |
| **Distribución PyPI** | 🚧 Aplazado | Publicar `pip install redaudit`. Bloqueado por necesidad de testing multiplataforma extensivo. |
| **Contenedorización** | 🚧 Aplazado | Imagen Docker oficial. Aplazado a favor de la estabilidad de instalación estándar pip/venv. |
| **Motor de Plugins** | 🚧 Aplazado | Arquitectura "Plugin-first" para desacoplar el escáner core de las herramientas. |

---

## 2. Capacidades Implementadas (Verificado)

Funcionalidades presentes actualmente en `redaudit --version` >= v3.6.0.

### UX e Integraciones (v3.7.0)

| Característica | Versión | Verificación |
| :--- | :--- | :--- |
| **Webhooks Interactivos** | v3.7.0 | `redaudit/core/wizard.py`. Configura Slack/Teams directamente en el wizard. |
| **Wizard: Net Discovery Avanzado** | v3.7.0 | `redaudit/core/wizard.py`. Configura SNMP/DNS/Targets interactivamente. |
| **Pipeline SIEM Nativo** | v3.7.0 | `siem/`. Configs para Filebeat/Logstash + reglas Sigma. |
| **Logging de Sesión** | v3.7.0 | `redaudit/utils/session_log.py`. Captura salida de terminal a `.log` y `.txt`. |
| **Progreso estable (HyperScan/Nuclei)** | v3.7.2 | `redaudit/core/net_discovery.py`, `redaudit/core/auditor.py`, `redaudit/core/nuclei.py`. Reduce flickering y muestra ETA. |

### Escaneo Avanzado y Automatización

| Característica | Versión | Verificación |
| :--- | :--- | :--- |
| **Integración Nuclei** | v3.6.0 | Módulo `redaudit/core/nuclei.py`. Ejecuta templates cuando Nuclei está instalado y se habilita explícitamente (wizard o `--nuclei`). |
| **Verificación sin agente** | v3.7.3 | `redaudit/core/agentless_verify.py`. Fingerprinting SMB/RDP/LDAP/SSH/HTTP opcional (wizard o `--agentless-verify`). |
| **Generación Playbooks** | v3.4.0 | Módulo `redaudit/core/playbook_generator.py`. Crea guías de remediación MD en `playbooks/`. |
| **Red Team: Kerberos** | v3.2.0 | Módulo `redaudit/core/net_discovery.py`. Usa `kerbrute` para enumeración si está autorizado. |
| **Red Team: SNMP/SMB** | v3.2.0 | Módulo `redaudit/core/net_discovery.py`. Usa `snmpwalk` y `enum4linux`. |
| **Preparación SIEM** | v3.1.0 | Módulo `redaudit/core/siem.py`. Genera JSON/JSONL compatible con ECS v8.11. |
| **Análisis Diferencial** | v3.3.0 | Módulo `redaudit/core/diff.py`. Diff visual HTML entre dos escaneos. |

### Core y Estabilidad

| Característica | Versión | Verificación |
| :--- | :--- | :--- |
| **Versión Única** | v3.5.4 | La versión ahora se resuelve de forma fiable en todos los modos: `importlib.metadata` cuando existe, más un fallback `redaudit/VERSION` para instalaciones vía script en `/usr/local/lib/redaudit`. |
| **CommandRunner Central** | v3.5.0 | `redaudit/core/command_runner.py` maneja todos los subprocesos de forma segura. |
| **Escaneos con Timeout** | v3.7.3 | `redaudit/core/auditor.py` aplica timeouts duros en nmap por host, manteniendo el progreso fluido. |
| **Config Persistente** | v3.1.1 | `~/.redaudit/config.json` almacena defaults del usuario. |
| **Descubrimiento Async** | v3.1.3 | `redaudit/core/hyperscan.py` usa `asyncio` para sondeo rápido de puertos. |
| **UI de Progreso Silenciosa (con detalle)** | v3.6.0 | `redaudit/core/auditor.py` reduce el ruido del terminal mientras hay barras de progreso y muestra “qué está haciendo” dentro de la propia línea de progreso. |

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
