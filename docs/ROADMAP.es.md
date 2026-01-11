# Roadmap y Propuestas Arquitectónicas

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](ROADMAP.en.md)

**Audiencia:** Colaboradores, responsables
**Alcance:** Funcionalidades planificadas, capacidades verificadas y conceptos descartados.
**Fuente de verdad:** Estado del código en el repositorio y el historial Git

---

Este documento describe el roadmap técnico, verifica las capacidades ya implementadas y registra los enfoques descartados para RedAudit.

## 1. Roadmap Activo (Próximas Funcionalidades)

Estas características están aprobadas pero **aún no implementadas** en el código base.

### v4.4 Cobertura de Código y Estabilidad (Prioridad: Alta) ✅

| Característica | Estado | Descripción |
| :--- | :--- | :--- |
| **Cobertura Topology 100%** | ✅ Hecho (v4.4.5) | Alcanzada cobertura completa de tests para `topology.py` (parseo de rutas, detección de bucles, grafado). |
| **Cobertura Updater >94%** | ✅ Hecho (v4.4.5) | Endurecido `updater.py` con tests robustos para operaciones Git, escenarios de rollback, fallos en casos borde. |
| **Cobertura Proyecto ~89%** | ✅ Hecho (v4.4.5) | Cobertura total del proyecto ahora en 88.75% (1619 tests pasando). |
| **Corrección Memory Leak** | ✅ Hecho (v4.4.5) | Corregido bucle infinito en mocks de tests que causaba pico de 95GB RAM. |

### v4.3 Mejoras al Risk Score (Prioridad: Alta) ✅

| Característica | Estado | Descripción |
| :--- | :--- | :--- |
| **Algoritmo Weighted Maximum Gravity** | ✅ Hecho | Refactorizado `calculate_risk_score()` para usar scores CVSS de datos NVD como factor principal. Fórmula: Base (max CVSS * 10) + Bonus densidad (log10) + Multiplicador exposición (1.15x para puertos externos). |

### v4.1 Optimizaciones de Rendimiento ✅ (En desarrollo)

| Característica | Estado | Descripción |
| :--- | :--- | :--- |
| **HyperScan-First Secuencial** | ✅ Hecho | Pre-escaneo de 65.535 puertos por host secuencialmente antes de nmap. Evita agotamiento de file descriptors. batch_size=2000. |
| **Escaneo Vulns Paralelo** | ✅ Hecho | nikto/testssl/whatweb concurrentemente por host. |
| **Pre-filtrado Nikto CDN** | ✅ Hecho | Omitir Nikto en Cloudflare/Akamai/AWS CloudFront. |
| **Reutilización puertos masscan** | ✅ Hecho | Pre-scan usa puertos de masscan si ya estaban descubiertos. |
| **CVE Lookup reordenado** | ✅ Hecho | CVE correlation movido después de Vuln Scan + Nuclei. |

### v4.2 Optimizaciones Pipeline ✅ (Liberado en v4.2.0)

| Característica | Estado | Descripción |
| :--- | :--- | :--- |
| **Enhanced Parallel Progress UI** | ✅ Hecho (v4.2.0) | Barras de progreso multi-hilo con Rich para Deep Scan y fases paralelas. |
| **Web App Vuln Scan (sqlmap)** | ✅ Hecho (v4.1.0) | Integración `sqlmap` con niveles configurables (level/risk) en wizard. |
| **Web App Vuln Scan (ZAP)** | ✅ Hecho (v4.2.0) | Integración OWASP ZAP para spidering de aplicaciones web. |
| **Parallel Deep Scan** | ✅ Hecho (v4.2.0) | Deep Scan decoupled con concurrencia hasta 50 threads y multi-bar UI. |
| **MAC Privado Indicator** | ✅ Hecho (v4.2.0) | Detecta MACs localmente administrados (bit 2 del primer byte) y muestra "(MAC privado)". |
| **Separación Deep Scan** | ✅ Hecho (v4.2.0) | Deep Scan extraído de `scan_host_ports()` como fase independiente `run_deep_scans_concurrent()`. |
| **Red Team → Agentless** | ✅ Hecho (v4.2.0) | Hallazgos SMB/LDAP de Red Team pasan a Agentless Verify. |
| **Wizard UX: Phase 0 auto** | ✅ Hecho (v4.2.0) | Phase 0 se activa automáticamente en perfil Exhaustivo. |
| **Wizard UX: Personalizado** | ✅ Hecho (v4.2.0) | Lógica mejorada para elección entre Masscan vs HyperScan. |
| **HyperScan naming cleanup** | ✅ Hecho (v4.2.0) | Funciones renombradas para clarificar propósito. |
| **Session log mejorado** | ✅ Hecho (v4.2.0) | Session log enriquecido con más detalle que cli.txt. |

### v4.0 Refactorización Arquitectónica ✅ (Liberado en v3.10.2)

Refactorización interna utilizando el patrón Strangler Fig:

1. ✅ **Fase 1**: UIManager - Clase de operaciones UI independiente
2. ✅ **Fase 2**: ConfigurationContext - Wrapper tipado de configuración
3. ✅ **Fase 3**: NetworkScanner - Utilidades de puntuación de identidad
4. ✅ **Fase 4**: Propiedades adaptador para migración gradual

**Estado**: Completado en v4.0.0. Orquestación por composición vía `AuditorRuntime`, con
herencia legacy eliminada y compatibilidad gestionada por componentes con adaptador.

### Infraestructura (Prioridad: Alta)

| Característica | Estado | Descripción |
| :--- | :--- | :--- |
| **Consolidación Suite Tests** | ✅ Hecho | Refactorizado 199 archivos → 123. Creado `conftest.py`. Eliminados 76 artefactos de coverage-gaming. 1130 tests al 85%. |

### Infraestructura (Prioridad: Baja)

| Característica | Estado | Descripción |
| :--- | :--- | :--- |
| **Distribución PyPI** | 🚧 Aplazado | Publicar `pip install redaudit`. Bloqueado por necesidad de testing multiplataforma extensivo. |
| **Motor de Plugins** | 🚧 Aplazado | Arquitectura "Plugin-first" para desacoplar el escáner core de las herramientas. |

### Fase 6: Escalabilidad Empresarial (>50 Hosts) ✅ (Liberado en v4.4.0)

Foco: Eliminar cuellos de botella en grandes redes corporativas.

| Característica | Estado | Descripción |
| :--- | :--- | :--- |
| **Targeting basado en Generadores** | ✅ Hecho (v4.4.0) | Refactorizado HyperScan para usar generadores lazy. Evita picos de memoria en subredes grandes (/16). |
| **Reporte JSON en Streaming** | 🚧 Planificado | Escritura incremental para reportes >500MB. |
| **Migración AsyncIO** | 🚧 Aplazado | Migración completa a AsyncIO aplazada a v5.0 tras estudio de viabilidad. |
| **Smart-Throttle (AIMD)** | ✅ Hecho (v4.4.0) | Control de congestión adaptativo AIMD en HyperScan. Ajusta batch_size dinámicamente. |

### Fase 7: Pulido UX y Cosméticos (Prioridad: Baja)

Mejoras menores identificadas durante la validación Gold Master de v4.4.0.

| Tarea | Estado | Descripción |
| :--- | :--- | :--- |
| **P7.1 Completitud Barras de Progreso** | Hecho (v4.6.8) | Evitar que las barras de vuln scan se actualicen tras finalizar un host para no confundir. |
| **P7.2 Visibilidad Timeout Nikto** | Planificado | Mostrar indicador "timeout" en lugar de progreso estancado cuando Nikto excede el umbral. |
| **P7.3 Reporte JSON en Streaming** | Planificado | Escritura incremental para reportes >500MB en redes muy grandes. |
| **P7.4 Backfill de Tag Web** | Hecho (v4.6.8) | Añadir la etiqueta `web` cuando existe `web_ports_count` aunque falten flags de puerto. |

---

## 2. Capacidades Implementadas (Verificado)

Funcionalidades presentes en versiones con `redaudit --version` >= v3.6.0, con rutas de verificación en el código.

### v4.5 Escaneo Autenticado (Fase 4)

| Característica | Versión | Verificación |
| :--- | :--- | :--- |
| **Gestión de Secretos** | v4.5.0 | `redaudit/core/credentials.py`. Almacenamiento seguro en entorno o Keyring. |
| **Escaneo SSH** | v4.5.0 | `redaudit/core/auth_ssh.py`. Auditoría remota Linux (OS, Paquetes, Servicios) vía Paramiko. |
| **Escaneo SMB/WMI** | v4.5.0 | `redaudit/core/auth_smb.py`. Enumeración Windows (Shares, Usuarios, OS) vía Impacket. |
| **SNMP v3** | v4.5.0 | `redaudit/core/auth_snmp.py`. Auditoría segura de red con protocolos Auth/Priv. |
| **Integración Lynis** | v4.5.0 | `redaudit/core/auth_lynis.py`. Ejecución remota de auditorías de hardening CIS. |
| **Soporte Multi-Credencial** | v4.5.2 | `redaudit/core/credentials_manager.py`. Spraying de credenciales con detección automática de protocolo. |
| **Wizard Auth Universal** | v4.5.2 | `redaudit/core/wizard.py`. Nuevo paso `ask_auth_config` con soporte para modos Universal y Avanzado. |

### UX e Integraciones (v3.7.0+)

| Característica | Versión | Verificación |
| :--- | :--- | :--- |
| **Detección Interfaces VPN** | v3.9.6 | `redaudit/core/entity_resolver.py`. Clasifica gateways VPN vía OUI del fabricante, puertos VPN (500/4500/1194/51820) y patrones de nombre de host. |
| **Pack de Firmas IoT** | v3.9.5 | `redaudit/core/udp_probe.py`, `redaudit/core/hyperscan.py`. Payloads UDP específicos para WiZ, Yeelight, Tuya/SmartLife, CoAP/Matter. |
| **Selector de Perfil del Wizard** | v3.9.0 | `redaudit/core/auditor.py`. Express/Estándar/Exhaustivo presets + modo Custom. |
| **Modos de Temporización Reales** | v3.9.0 | `redaudit/core/scanner/nmap.py`, `redaudit/core/auditor_scan.py`. Aplica nmap `-T1`/`-T4`/`-T5` con ajustes de delay/threads. |
| **Reportes HTML Mejorados** | v3.9.0 | `redaudit/templates/report*.html.j2`. Hallazgos expandibles, análisis smart scan, playbooks, evidencia. |
| **Detección FPs Nuclei** | v3.9.0 | `redaudit/core/verify_vuln.py`. Mapeo server header vs CPE para marcar FPs. |
| **Consistencia de Colores** | v3.8.4 | `redaudit/core/auditor.py`. Usa Rich console.print() cuando el progreso está activo para asegurar colores correctos. |
| **Identidad del Auditor** | v3.8.3 | `redaudit/core/wizard.py`. Prompt del asistente para nombre del auditor, visible en informes TXT/HTML. |
| **Informes HTML Bilingües** | v3.8.3 | `redaudit/core/reporter.py`. Cuando el idioma es ES, se genera `report_es.html` junto al HTML principal. |
| **Navegación del Asistente** | v3.8.1 | `redaudit/core/wizard.py`. Opción "< Volver" en menús del asistente para navegación paso a paso. |
| **Watermark HTML** | v3.8.2 | `redaudit/templates/report.html.j2`. Footer profesional con GPLv3, autor y enlace a GitHub. |
| **Webhooks Interactivos** | v3.7.0 | `redaudit/core/wizard.py`. Configura Slack/Teams directamente en el asistente. |
| **Asistente: Net Discovery Avanzado** | v3.7.0 | `redaudit/core/wizard.py`. Configura SNMP/DNS/Targets interactivamente. |
| **Pipeline SIEM Nativo** | v3.7.0 | `siem/`. Configs para Filebeat/Logstash + reglas Sigma. |
| **Logging de Sesión** | v3.7.0 | `redaudit/utils/session_log.py`. Captura salida de terminal a `.log` y `.txt`. |
| **Progreso estable (HyperScan/Nuclei)** | v3.7.2 | `redaudit/core/hyperscan.py`, `redaudit/core/auditor.py`, `redaudit/core/nuclei.py`. Reduce flickering y muestra ETA. |

### Escaneo Avanzado y Automatización

| Característica | Versión | Verificación |
| :--- | :--- | :--- |
| **Integración Nuclei** | v3.6.0 | Módulo `redaudit/core/nuclei.py`. Ejecuta plantillas cuando Nuclei está instalado y se habilita explícitamente (asistente o `--nuclei`). |
| **Verificación sin agente** | v3.7.3 | `redaudit/core/agentless_verify.py`. Fingerprinting SMB/RDP/LDAP/SSH/HTTP opcional (asistente o `--agentless-verify`). |
| **Sonda HTTP en hosts silenciosos** | v3.8.5 | `redaudit/core/auditor_scan.py`, `redaudit/core/scanner/enrichment.py`. Sonda HTTP/HTTPS breve en puertos comunes para hosts con fabricante y cero puertos abiertos. |
| **Generación Playbooks** | v3.4.0 | Módulo `redaudit/core/playbook_generator.py`. Crea guías de remediación MD en `playbooks/`. |
| **Red Team: Kerberos** | v3.2.0 | Módulo `redaudit/core/net_discovery.py`. Usa `kerbrute` para enumeración si está autorizado. |
| **Red Team: SNMP/SMB** | v3.2.0 | Módulo `redaudit/core/net_discovery.py`. Usa `snmpwalk` y `enum4linux`. |
| **Preparación SIEM** | v3.1.0 | Módulo `redaudit/core/siem.py`. Genera JSON/JSONL compatibles con SIEM y campos alineados con ECS. |
| **Análisis Diferencial** | v3.3.0 | Módulo `redaudit/core/diff.py`. Diff visual HTML entre dos escaneos. |

### Core y Estabilidad

| Característica | Versión | Verificación |
| :--- | :--- | :--- |
| **Versión Única** | v3.5.4 | La versión ahora se resuelve de forma fiable en todos los modos: `importlib.metadata` cuando existe, más un fallback `redaudit/VERSION` para instalaciones vía script en `/usr/local/lib/redaudit`. |
| **Imagen de Contenedor** | v3.8.4 | `Dockerfile` + `.github/workflows/docker.yml` publican imagen en GHCR. |
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
| **Escaneo Distribuido** | Demasiado complejo (FastAPI/Redis). RedAudit es una herramienta CLI táctica, no una plataforma SaaS. Arquitectura rechazada. |

---

## 4. Contribuir

1. Revisa [Issues](https://github.com/dorinbadea/RedAudit/issues).
2. Lee [CONTRIBUTING.md](../CONTRIBUTING.md).
3. Abre una Discusión antes de iniciar grandes funcionalidades.

[Volver al Índice de Documentación](INDEX.md)
