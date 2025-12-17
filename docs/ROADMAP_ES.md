# Roadmap y Propuestas Arquitectónicas

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](ROADMAP.md)

Este documento describe el roadmap técnico, las mejoras arquitectónicas planificadas y los enfoques descartados para RedAudit.

## Roadmap Activo (Próximos Pasos)

### Funcionalidades de Seguridad y Alta Prioridad (v3.5+)

| Prioridad | Característica | Estado | Descripción |
| :--- | :--- | :--- | :--- |
| **Alta** | **Pipeline SIEM Nativo** | 🎯 Planificado | Exporters directos: módulo Filebeat personalizado (autoconfig ingest Elasticsearch), mapping Sigma rules para findings comunes (Nikto, CVE, cifrados débiles). JSONL con ECS completo (risk_score calculado, rule.id). Flag `--siem-pipeline elk\|splunk\|qradar`. |
| ~~Media~~ | ~~Export Playbooks~~ | ✅ **Implementado (v3.4.0)** | Playbooks Markdown por hallazgo (TLS, cabeceras, CVE, web, puertos). Generados automáticamente en `<output_dir>/playbooks/`. |
| **Baja** | **Verificación Hardening con Osquery** | 🎯 Planificado | Módulo post-scan que ejecute queries Osquery (via fleet o directo) en hosts vivos para validar configs detectadas (firewall, servicios). Merge en reporte SIEM/HTML para closed-loop. |

### Extensiones Red Team (v3.5+)

| Prioridad | Característica | Estado | Descripción |
| :--- | :--- | :--- | :--- |
| **Media** | **Integración Impacket** | 🎯 Planificado | Módulo opcional `--redteam-deep` usando Impacket (smbexec, wmiexec, secretsdump) sobre credenciales dummy o null sessions detectadas. Genera evidencia PoC para validar detección Blue Team (SMB signing, LAPS). |
| **Media** | **BloodHound Collector Automático** | 🎯 Planificado | Ejecutar SharpHound/BloodHound.py en hosts Windows vivos (via psexec/winrm detectado). Importar JSON a Neo4j local y generar reporte paths ataque comunes (Kerberoast, AS-REProast). Ayuda Blue Team a priorizar hardening AD. |
| **Media** | **Automatización Nuclei** | 🎯 Planificado (v3.6) | Lanzar Nuclei sobre HTTP/HTTPS/servicios detectados con templates community + opción cargar custom. Output mergeado en findings con PoC URLs. Permite simular ataques modernos y generar Sigma rules defensivas. |
| **Baja** | **Generación Playbook Red Team** | 🎯 Planificado | Por finding exploitable (ej: CVE alto, auth débil), generar scripts PoC automáticos (sugerencias Python/Impacket/Msfvenom) en carpeta evidence. Incluye safeguards (solo labs, `--dry-run`). Facilita testing controles Blue Team (EDR, logging). |

### Experiencia de Desarrollador / Deuda Técnica

| Prioridad | Característica | Estado | Descripción |
| :--- | :--- | :--- | :--- |
| **Media** | **Contenedorización** | Aparcado | Dockerfile oficial y configuración Docker Compose para contenedores de auditoría efímeros. |
| **Media** | **CommandRunner Centralizado** | ✅ **Implementado (v3.5.0)** | Módulo único para ejecución de comandos externos: args como lista (anti-inyección), timeouts configurables, reintentos con backoff, redacción de secretos en logs, soporte dry-run. Refactoriza llamadas subprocess en el codebase. |
| **Media** | **Soporte Completo `--dry-run`** | ✅ **Implementado (v3.5.1)** | Propagar flag `--dry-run` a todos los módulos para que los comandos se impriman pero no se ejecuten (no se ejecuta ningún comando externo). Depende de CommandRunner. Útil para auditoría y debugging. |
| **Baja** | **UI de Progreso Silenciosa (ETA)** | ✅ **Implementado (v3.5.1)** | Sustituye avisos periódicos tipo "heartbeat" por barras de progreso Rich cuando sea posible (barras claras + ETA), manteniendo la salida del terminal limpia y amigable. |
| **Baja** | **Manifiesto de Carpeta de Salida** | ✅ **Implementado (v3.5.1)** | Añade `run_manifest.json` en cada carpeta de salida (si el cifrado está desactivado) con métricas + lista de artefactos para reproducibilidad y pipelines SIEM. |
| **Baja** | **Única Fuente de Versión** | 🎯 Planificado | Leer versión de `pyproject.toml` via `importlib.metadata` en vez de `VERSION = "x.y.z"` manual. Previene drift de versiones entre archivos. |
| **Baja** | **Autodetección TTY** | 🎯 Planificado | Desactivar colores automáticamente cuando stdout no es un TTY (pipes/CI). Flag `--no-color` ya existe pero el comportamiento no está completamente implementado. |
| **Baja** | **Webhook Interactivo** | 🎯 Planificado | Añadir prompt de URL webhook al wizard interactivo para usuarios avanzados. Actualmente webhook es solo CLI (`--webhook URL`). |
| **Baja** | **HTML Report Interactivo** | 🎯 Planificado | Añadir pregunta "¿Generar reporte HTML?" al wizard interactivo. Actualmente HTML report es solo CLI (`--html-report`). |

## Objetivos Futuros (Deep Dives)

### Descubrimiento de Topología de Red (Objetivo v4.0)

**Objetivo**: Reconocimiento rápido pre-scan para mapear la arquitectura de red antes del escaneo profundo.

**Estado actual (v3.1+)**: Existe una implementación base best-effort (rutas/gateway por defecto, ARP scan, pistas de VLAN, LLDP/CDP best-effort). v4.0 amplía esto con descubrimiento activo más rico (scripts broadcast de nmap, mapeo por traceroute, etc.).

| Capacidad | Herramienta | Salida |
| :--- | :--- | :--- |
| **Descubrimiento L2** | `arp-scan --localnet` | Direcciones MAC + vendor OUI |
| **Detección de VLAN** | `nmap --script broadcast-dhcp-discover,broadcast-arp` | IDs de VLAN, servidores DHCP |
| **Mapeo de Gateway** | `traceroute` + análisis de ICMP redirect | Rutas de routers, detección NAT |
| **Topología L2** | Parsing CDP/LLDP via `tcpdump -nn -v -c 50 ether proto 0x88cc` | Relaciones switch/puerto |
| **Redes Ocultas** | Detección de anomalías ARP + análisis de tabla de rutas | Subredes mal configuradas |

**Opciones CLI**:

```bash
redaudit --topology-only --target 192.168.0.0/16 --yes  # Solo topología (sin escaneo de hosts)
redaudit --topology --target 10.0.0.0/8 --yes           # Integrado con auditoría completa
```

## Referencia: Capacidades Implementadas Recientemente

### Descubrimiento de Red Mejorado (v3.2)

**Resumen**: Detectar redes de invitados, VLANs ocultas y servidores DHCP adicionales no visibles desde el segmento de red principal.
Funcionalidades permiten detectar:

- ✅ Descubrimiento DHCP y sweeps Fping
- ✅ Descubrimiento NetBIOS/mDNS/Bonjour/UPNP
- ✅ Recon Red Team (SNMP/SMB/RPC/LDAP/Kerberos/DNS)
- ✅ Análisis de candidatos VLAN y capturas L2 pasivas

**Herramientas de Descubrimiento Estándar**:

| Técnica | Herramienta |
| :--- | :--- |
| **Descubrimiento DHCP** | `nmap --script broadcast-dhcp-discover` |
| **NetBIOS/mDNS/UPNP** | `nbtscan`, `avahi-browse`, `nmap` |
| **Netdiscover** | `netdiscover -r <rango> -P` |

**Técnicas Red Team (Guardas/Opcional)**:

| Técnica | Herramienta | Qué Detecta |
| :--- | :--- | :--- |
| **SNMP Walking** | `snmpwalk -v2c -c public` | Puertos switch, VLANs |
| **Enum SMB** | `enum4linux`, `crackmapexec` | Usuarios, shares, políticas |
| **VLAN/STP/HSRP** | `tcpdump` | Pistas topología L2 pasiva |
| **Descubrimiento IPv6** | `ping6`, `ip -6 neigh` | Vecinos IPv6 |
| **Kerberos/LDAP** | Scripts `nmap` | Estructura AD, realms |

**Ejemplos CLI**:

```bash
redaudit --net-discovery --target 192.168.0.0/16 --yes
redaudit --net-discovery --redteam --target 10.0.0.0/8
```

## Propuestas Arquitectónicas

### 1. Motor de Plugins Modular

**Estado**: En Consideración
**Concepto**: Desacoplar el escáner principal de las herramientas. Permitir "Plugins" basados en Python para definir nuevos wrappers de herramientas sin modificar la lógica central.
**Beneficio**: Facilita contribución de la comunidad y extensibilidad.

**Nota**: La arquitectura "plugin-first" está aparcada por ahora; la prioridad es estabilidad y coherencia del core.

### 2. Escaneo Distribuido (Coordinador/Workers)

**Estado**: Largo plazo
**Concepto**: Separar el Orquestador de los workers de verificación.

- API Central (Coordinador) distribuye objetivos.
- Workers remotos (Nodos) ejecutan escaneos y devuelven JSON.

### 3. Configuración Persistente

**Estado**: ✅ Implementado (v3.1.1)
**Concepto**: Configuración de usuario en `~/.redaudit/config.json` anula valores por defecto (hilos, salida, rate-limit, UDP, topología, idioma). Importación/exportación YAML queda como mejora futura.

## Hitos Completados

### v3.5.0 (Release - Diciembre 2025) -> **ACTUAL**

*Release menor centrada en fiabilidad durante escaneos largos y ejecución más segura de comandos externos.*

- [x] **Evitar reposo durante escaneos**: Inhibición best-effort del reposo del sistema/pantalla mientras se ejecuta un escaneo (opt-out con `--no-prevent-sleep`).
- [x] **CommandRunner centralizado**: Ejecución unificada de herramientas externas con timeouts, reintentos, redacción de secretos y despliegue incremental de `--dry-run`.
- [x] **Mejoras en dry-run**: Más módulos respetan `--dry-run`, con documentación clara de que el despliegue es incremental.

### v3.4.4 (Hotfix - Diciembre 2025)

*Patch centrado en pulir el flujo de defaults y la UX tras actualizar.*

- [x] **UX de defaults**: "Usar defaults y continuar" aplica defaults correctamente; iniciar inmediatamente evita re-preguntar parámetros y puede reutilizar objetivos guardados cuando estén disponibles.
- [x] **Nota de actualización**: Añadida guía para reiniciar terminal o ejecutar `hash -r` cuando el banner no refresca la versión tras actualizar.

### v3.4.3 (Hotfix - Diciembre 2025)

*Patch centrado en mejorar la legibilidad de hallazgos y pulir defaults del wizard.*

- [x] **Títulos descriptivos de hallazgos**: Los hallazgos web ahora tienen un `descriptive_title` corto derivado de observaciones parseadas (mejora encabezados de playbooks, webhooks y legibilidad en HTML).
- [x] **Directorio de salida por defecto (wizard)**: Cuando el wizard iba a proponer `/root/...`, RedAudit ahora prefiere `Documentos` del usuario (usuario invocador bajo `sudo`, y un único usuario detectado bajo `/home/<usuario>` cuando se ejecuta como root sin `sudo`).
- [x] **Marcador de selección (wizard)**: Usa un marcador ASCII `>` para máxima compatibilidad con terminales/fuentes.

### v3.4.2 (Hotfix - Diciembre 2025)

*Patch centrado en corregir defaults persistidos de salida bajo `sudo` en el wizard interactivo.*

- [x] **Migración de output_dir en el wizard**: Si un default persistido antiguo apunta a `/root/...`, RedAudit lo reescribe automáticamente a `Documentos` del usuario invocador bajo `sudo`.

### v3.4.1 (Hotfix - Diciembre 2025)

*Patch centrado en guardar reportes bajo el usuario invocador cuando se ejecuta con `sudo`.*

- [x] **Salida por defecto bajo sudo**: La salida por defecto resuelve a `Documentos` del usuario invocador (en lugar de `/root`).
- [x] **Expansión de `~` bajo sudo**: `--output ~/...` y defaults persistidos expanden contra el usuario invocador.
- [x] **Endurecimiento de ownership**: `chown` best-effort del árbol del directorio de salida para evitar artefactos propiedad de root bajo el home del usuario.
- [x] **Tests unitarios**: Cobertura añadida para la lógica de resolución de rutas.

### v3.4.0 (Completado - Diciembre 2025)

*Release centrada en playbooks de remediación y alineación de documentación.*

- [x] **Playbooks de Remediación**: Playbooks Markdown auto-generados por host/categoría en `<output_dir>/playbooks/` (TLS, cabeceras HTTP, remediación CVE, hardening web, hardening puertos).
- [x] **Integración**: Playbooks generados automáticamente al finalizar el scan (sin flag; omitidos con `--encrypt`).
- [x] **Testing**: Tests unitarios añadidos para el generador de playbooks.
- [x] **Documentación**: README, manuales, uso, guía didáctica, troubleshooting, seguridad, changelogs y release notes actualizados y coherentes.

### v3.3 (Completado - Diciembre 2025)

*Release centrada en alertas SIEM, dashboards Blue Team y salida diff visual.*

- [x] **Webhook Alertas en Tiempo Real**: `--webhook URL` envía findings críticos (CVE alto, servicios expuestos) via POST JSON a Slack/Teams/PagerDuty/TheHive durante el scan.
- [x] **Dashboard HTML Interactivo**: Reporte HTML autogenerado (Jinja2 + Chart.js) con tablas ordenables, gráficos de severidad y top puertos. Flag `--html-report`.
- [x] **Diff Visual y Tracking Longitudinal**: Salida HTML comparativa para `--diff` (side-by-side, highlight nuevo/resuelto). Export diferencial JSONL para SIEM histórico.

### v3.2.2 (Completado - Diciembre 2025)

*Release centrado en pulido de UX, Menú Principal Interactivo y simplificación de Topología.*

- [x] **Menú Principal Interactivo**: Punto de entrada unificado para Escaneo, Actualizar, Diff y Salir.
- [x] **Topología Simplificada**: Wizard simplificado para elección de topología vs escaneo completo.
- [x] **Soporte Non-TTY**: Mejor compatibilidad con CI/Pipelines (sin colores/spinners).
- [x] **Defaults Consolidados**: Manejo de "Valores Base" y persistencia más limpia.
- [x] **i18n Completo**: Traducción completada de todos los prompts y menús CLI.

### v3.2.0 (Completado - Diciembre 2025)

*Versión centrada en descubrimiento de red mejorado (estándar + recon Red Team opcional), con documentación alineada.*

- [x] **Descubrimiento de Red Mejorado**: `--net-discovery` añade descubrimiento DHCP/NetBIOS/mDNS/UPNP/ARP/fping con análisis de VLANs candidatas.
- [x] **Recon Red Team (con guardas)**: SNMP/SMB/RPC/LDAP/Kerberos/DNS y capturas L2 pasivas detrás de `--redteam`.
- [x] **Nuevos flags de tuning**: Selección de interfaz y límites seguros (`--net-discovery-interface`, `--redteam-max-targets`, etc.).
- [x] **Documentación de esquema actualizada**: Bloques `net_discovery` y `redteam` documentados para v3.2.

### v3.1.4 (Completado - Diciembre 2025)

*Patch centrado en mejoras de calidad de salida para máximo scoring SIEM/IA.*

- [x] **Títulos descriptivos de hallazgos**: Títulos legibles basados en tipo (ej: "Cabecera X-Frame-Options Faltante" en vez de "Hallazgo en URL").
- [x] **Cross-validación Nikto**: `detect_nikto_false_positives()` compara hallazgos con cabeceras curl/wget para detectar contradicciones.
- [x] **Ajuste severidad RFC-1918**: Divulgación de IP interna en redes privadas ahora correctamente calificada como severidad "low".
- [x] **Extracción de fingerprint OS**: Nueva función `extract_os_detection()` para info OS estructurada desde salida Nmap.
- [x] **Rutas PCAP relativas**: Los reportes usan rutas relativas portables para archivos PCAP.
- [x] **Timeout TestSSL configurable**: Por defecto aumentado de 60s a 90s con parámetro configurable.
- [x] **Constante de versión de schema**: Constante `SCHEMA_VERSION` separada para claridad de versionado de reportes.

### v3.1.3 (Completado - Diciembre 2025)

*Patch centrado en mejoras de rendimiento con asyncio.*

- [x] **Sondeo UDP asíncrono**: Sondeo concurrente rápido de puertos UDP prioritarios durante deep scan.
- [x] **Topología asíncrona**: Recolección de comandos en paralelo (ARP/VLAN/LLDP + gateway).

### v3.1.2 (Completado - Diciembre 2025)

*Patch centrado en mejoras de UX del auto-update.*

- [x] **Notas de update CLI-friendly**: Renderizado amigable para terminal (sin ruido Markdown).
- [x] **Reinicio fiable**: Reinicio PATH-aware con instrucciones de fallback claras.
- [x] **Prompts más claros**: Presets UDP, clarificación topology-only, confirmación save-defaults.

### v3.1.1 (Completado - Diciembre 2025)

*Patch centrado en descubrimiento de topología, defaults persistentes y cobertura UDP configurable.*

- [x] **Descubrimiento de topología (best-effort)**: Mapping ARP/VLAN/LLDP + gateway/rutas (`--topology`, `--topology-only`).
- [x] **Defaults persistentes**: Guardado de ajustes comunes en `~/.redaudit/config.json` (`--save-defaults`).
- [x] **Cobertura UDP configurable**: `--udp-ports N` para ajustar la cobertura del UDP full de identidad.
- [x] **Docs y tests alineados**: Manuales, esquema y tests unitarios actualizados.

### v3.1.0 (Completado - Diciembre 2025)

*Release centrada en integraciones SIEM y exportaciones para pipelines de IA.*

- [x] **Exportaciones JSONL**: `findings.jsonl`, `assets.jsonl`, `summary.json` para ingesta plana.
- [x] **IDs determinísticos de hallazgo**: `finding_id` para correlación y deduplicación entre escaneos.
- [x] **Categorización de hallazgos**: surface/misconfig/crypto/auth/info-leak/vuln.
- [x] **Severidad normalizada**: `normalized_severity` (0-10) + severidad original de herramienta preservada.
- [x] **Observaciones estructuradas**: Extracción de Nikto/TestSSL (con externalización de evidencia raw cuando aplica).
- [x] **Versiones de herramientas**: Proveniencia (`scanner_versions`).

### v3.0.4 (Completado - Diciembre 2025)

*Patch centrado en mejorar la claridad del límite de hosts en modo interactivo y alinear documentación.*

- [x] **Límite de hosts por defecto = todos**: El prompt interactivo escanea todos los hosts encontrados por defecto (ENTER = todos / all).
- [x] **Texto más claro**: Los números significan un límite máximo global de hosts (no un selector de host/IP).

### v3.0.3 (Completado - Diciembre 2025)

*Patch centrado en transparencia del auto-update y preservación de idioma.*

- [x] **Idioma preservado en actualización**: El auto-update mantiene el idioma instalado (ej: Español sigue en Español).
- [x] **Salida de update más explícita**: Muestra ref/commit objetivo, cambios de ficheros (+/~/-) y pasos claros de instalación/backup.

### v3.0.2 (Completado - Diciembre 2025)

*Patch centrado en pulido del CLI, claridad de reportes y correlación CVE más segura.*

- [x] **Salida CLI thread-safe**: Evita líneas intercaladas y cortes a mitad de palabra.
- [x] **Mejoras de UX en Español**: Traducciones completadas para mensajes de estado/progreso.
- [x] **Visibilidad de PCAP**: Resumen final muestra contador de PCAP; reporte TXT incluye la ruta del PCAP si se captura.
- [x] **Seguridad en enriquecimiento NVD**: Evita CPEs comodín cuando la versión es desconocida; corrige mensajes sobre el origen de la API key.

### v3.0.1 (Completado - Diciembre 2025)

*Patch centrado en configuración, endurecimiento de update e higiene documental.*

- [x] **API Key NVD Persistente**: Guardar/leer la clave NVD vía archivo de config + variable de entorno.
- [x] **Verificación del Updater**: El auto-update resuelve el tag publicado y verifica el hash del commit antes de instalar.
- [x] **Instalación testssl.sh fijada**: El instalador fija `testssl.sh` a un tag/commit conocido y lo verifica antes de enlazar.
- [x] **Resiliencia NVD**: Reintentos con backoff en errores transitorios (429/5xx/red).
- [x] **Modo limitado sin root**: `--allow-non-root` permite ejecutar sin sudo (capacidad limitada).

### v3.0.0 (Completado - Diciembre 2025)

*Lanzamiento mayor con capacidades avanzadas.*

- [x] **Soporte IPv6**: Capacidades completas de escaneo para redes IPv6.
- [x] **Validación Magic Bytes**: Detección mejorada de falsos positivos con verificación de firmas.
- [x] **Correlación CVE (NVD)**: Inteligencia profunda de vulnerabilidades via API NIST NVD con caché de 7 días.
- [x] **Análisis Diferencial**: Comparar dos reportes JSON para detectar cambios de red.
- [x] **Proxy Chains (SOCKS5)**: Soporte para pivoting via wrapper proxychains.
- [x] **Auto-Update Mejorado**: Enfoque git clone con verificación y copia a carpeta home.

### v2.9.0 (Completado - Diciembre 2025)

*Enfoque en inteligencia, eficiencia y documentación profesional.*

- [x] **Smart-Check**: Reducción del 90% de falsos positivos en escaneo web.
- [x] **UDP Taming**: Escaneos 50-80% más rápidos mediante estrategia de 3 fases optimizada.
- [x] **Entity Resolution**: Agrupación de dispositivos multi-interfaz (Unified Assets).
- [x] **SIEM Profesional**: Cumplimiento ECS v8.11 y puntuación de riesgo.
- [x] **Documentación Limpia**: Eliminación completa de etiquetas de versión antiguas.

### v2.7-v2.8 (Completado)

*Enfoque en concurrencia, seguridad e integración de herramientas externas.*

- [x] **Deep Scan Adaptativo**: Estrategia de 3 fases (TCP agresivo → UDP prioritario → UDP completo)
- [x] **Captura PCAP Concurrente**: Tráfico capturado durante escaneos profundos
- [x] **Auto-Actualización Segura**: Integración GitHub con reinicio automático
- [x] **Motor Pre-scan**: Descubrimiento rápido asyncio antes de nmap
- [x] **Inteligencia de Exploits**: Integración SearchSploit para versiones detectadas
- [x] **Análisis SSL/TLS**: Escaneo profundo TestSSL.sh
- [x] **Endurecimiento de Seguridad**: Requisitos de contraseña fuerte (12+ chars)
- [x] **Seguridad CI/CD**: Dependabot + análisis estático CodeQL
- [x] **Mejoras UX**: Barras de progreso rich con fallback elegante

### v2.6 (Completado)

*Enfoque en calidad de código, testing y modularización.*

- [x] **Arquitectura Modular**: Refactorizado en estructura de paquete Python
- [x] **Pipeline CI/CD**: GitHub Actions para testing automatizado (Python 3.9-3.12)
- [x] **Suite de Tests**: Ampliación de tests automatizados e introducción de reporting de cobertura en CI (reportado por CI, sin fijar números aquí)
- [x] **Constantes Nombradas**: Todos los números mágicos reemplazados
- [x] **Compatibilidad hacia atrás**: `redaudit.py` original preservado como wrapper

## Conceptos Descartados

| Propuesta | Razón del Descarte |
| :--- | :--- |
| **GUI Web (Controlador)** | Incrementa superficie de ataque y peso de dependencias. RedAudit está diseñado como herramienta CLI "headless" para automatización. |
| **Explotación Activa** | Fuera de alcance. RedAudit es una herramienta de *auditoría* y *descubrimiento*, no un framework de explotación. |
| **Soporte Nativo Windows** | Demasiado complejo de mantener en solitario por requisitos de sockets raw. Usar WSL2 o Docker. |
| **Generación PDF** | Añade dependencias pesadas (LaTeX/ReportLab). La salida JSON debe ser consumida por herramientas de reporte externas. |

---

## Contribuir

Si deseas contribuir a alguna de estas features:

1. Revisa los [Issues](https://github.com/dorinbadea/RedAudit/issues) existentes.
2. Comenta antes de empezar para evitar duplicación.
3. Lee [CONTRIBUTING.md](../.github/CONTRIBUTING.md).
4. Abre una [Discusión](https://github.com/dorinbadea/RedAudit/discussions) para nuevas ideas.

---

**Mantenimiento Activo** | *Última actualización: Diciembre 2025*

*Si este documento no se actualiza en >6 meses, el proyecto puede estar pausado. En ese caso, considera hacer un fork o contactarme.*
