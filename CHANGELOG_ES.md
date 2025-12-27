# Registro de cambios

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](CHANGELOG.md)

Todos los cambios relevantes de este proyecto se documentarán en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
y este proyecto sigue [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.9.2] - 2025-12-27 (Hotfix de Version)

### Fixed

- **Deteccion de version en instalacion script**: Acepta sufijos con letra como `3.9.1a` en `redaudit/VERSION` para evitar `0.0.0-dev` tras auto-update.

## [3.9.1a] - 2025-12-27 (Hotfix de Reportes)

### Fixed

- **Títulos en reportes HTML ES**: El regex ahora localiza correctamente títulos de hallazgos comunes en `report_es.html`.
- **Metadatos en summary.json**: Se añadieron `scan_mode_cli`, `options` compacto y alias `severity_counts` para dashboards.

## [3.9.0] - 2025-12-27 (Selector de Perfiles y Reportes Mejorados)

### Añadido

- **Selector de Perfil del Wizard**: Nueva pregunta inicial para elegir tipo de auditoría:
  - **Express** — Escaneo rápido de descubrimiento, mínimas preguntas
  - **Estándar** — Escaneo equilibrado con análisis de vulnerabilidades
  - **Exhaustivo** — Máximo descubrimiento, auto-configura todo:
    - Modo: `completo`, Hilos: `MAX`, UDP: `full (500 puertos)`
    - Vulnerabilidades + Nuclei + Topología + Net Discovery + Red Team + Windows Verify
    - Correlación CVE de NVD habilitada si la API key está configurada
  - **Custom** — Wizard completo de 8 pasos para control total

- **Navegación del Wizard**: Opción "< Volver" desde el selector de timing regresa a la selección de perfil.

- **Diferencias Reales de Timing**: Los modos de timing ahora tienen efecto real en nmap:
  - **Sigiloso** — nmap `-T1` (paranoid) + 2s delay + 2 hilos (evasión IDS)
  - **Normal** — nmap `-T4` (aggressive) + sin delay + hilos por defecto
  - **Agresivo** — nmap `-T5` (insane) + sin delay + MAX hilos

- **Recordatorio de API Key NVD**: El wizard muestra un recordatorio con enlace para obtener la API key cuando se omite correlación CVE.

- **Reporte HTML Mejorado** (para auditores profesionales):
  - **Hallazgos Expandibles**: Click en cualquier hallazgo para ver observaciones técnicas (`parsed_observations`)
  - **Sección Smart Scan Analysis**: Muestra exactamente por qué se dispararon los deep scans (ej: `suspicious_service`, `many_ports`)
  - **Sección Playbooks de Remediación**: Grid visual de playbooks generados con IPs objetivo
  - **Sección Evidencia Capturada**: Lista todos los archivos PCAP capturados
  - **Resumen de Topología**: Gateway por defecto, conteo de interfaces, conteo de rutas
  - Plantillas EN y ES actualizadas

- **Filtrado de Logs de Sesión**: Reducción de ruido más inteligente que preserva mensajes de estado mientras filtra actualizaciones de spinner.

### Corregido

- **Timing de nmap no aplicado**: La configuración `nmap_timing` no se pasaba a `get_nmap_arguments()`, por lo que Sigiloso/Normal/Agresivo no tenía efecto en la ejecución real de nmap.
- **Playbooks no aparecían en reporte HTML**: Los playbooks se generaban DESPUÉS del reporte HTML, resultando en una sección vacía. Ahora se generan antes.

### Cambiado

- Selección de perfil por defecto es "Estándar" (índice 1)
- El perfil Express omite la pregunta de timing (siempre rápido)
- `save_playbooks()` ahora devuelve tupla `(count, playbook_data)` para integración en HTML

### Eliminado

- **prescan.py**: Módulo de código muerto superado por `hyperscan.py` que incluye descubrimiento TCP/UDP/ARP/IoT.

## [3.8.9] - 2025-12-25 (Corrección exportación Fingerprinting)

### Corregido

- **Campos de fingerprinting de dispositivo ahora exportados**: `device_vendor`, `device_model`, `device_type` ahora se incluyen en la salida `assets.jsonl` y en las señales `agentless_hints`.
  - Anteriormente estos campos se extraían pero se filtraban durante la exportación JSONL.

## [3.8.8] - 2025-12-25 (Fingerprinting de Dispositivos y UX)

### Añadido

- **Fingerprinting HTTP de Dispositivos**: Identificación automática de vendor/modelo desde títulos de interfaz web.
  - 40+ patrones: Vodafone, FRITZ!Box, TP-Link, NETGEAR, ASUS, Linksys, D-Link, Ubiquiti, MikroTik, Cisco, Hikvision, Dahua, Axis, Philips Hue, Synology, QNAP, y más.
  - Nuevos campos en fingerprint agentless: `device_vendor`, `device_model`, `device_type`.
  - Mejora la identificación de activos cuando hostname/vendor MAC no está disponible.

### Corregido

- **Ruido en salida CLI**: Frecuencia de actualización del spinner reducida de 10Hz a 4Hz (`refresh_per_second=4`).
  - Corrige archivos de log excesivamente grandes cuando el terminal se captura externamente (ej. comando `script`).
  - Aplicado a las 9 barras de progreso en módulos auditor, hyperscan, nuclei.

## [3.8.7] - 2025-12-23 (Correcciones de reportes y clasificación)

### Corregido

- **Identidad en hosts silenciosos**: El probe HTTP ahora inspecciona metatítulos y texto alt cuando el login no tiene título/encabezado.
- **Resumen de fuentes**: Las fuentes de vulnerabilidades se infieren desde señales del tool cuando faltan en el hallazgo.
- **Estado de host**: Hosts con puertos abiertos ahora se marcan como `up` aunque exista MAC/vendor.
- **Tipo de activo**: Fingerprints Chromecast/cast se clasifican como `media`, pistas de Android como `mobile`, y el gateway por defecto de topología se etiqueta como `router` para la resolución de entidades.

### Documentacion

- Diagramas de arquitectura EN/ES actualizados para reflejar los modulos actuales.
- Manuales EN/ES actualizados para aclarar el fallback HTTP de metatítulos en hosts silenciosos.

## [3.8.6] - 2025-12-22 (Fix de Build Docker)

### Corregido

- **Build de Docker**: Se instalan herramientas de compilacion para que `netifaces` compile durante `pip install`.
- **Identidad en hosts silenciosos**: El probe HTTP ahora usa fallback a H1/H2 cuando falta `<title>`, mejorando la deteccion de modelo en pantallas de login.

### Documentacion

- Se agregan badges EN/ES a las notas de version de v3.8.4 y v3.8.5.

## [3.8.5] - 2025-12-22 (Identidad de Hosts Silenciosos)

### Añadido

- **Probe HTTP en hosts silenciosos**: Probe HTTP/HTTPS breve en puertos comunes cuando el host tiene vendor pero cero puertos abiertos, para mejorar la identificación de modelo.

### Corregido

- **Clasificación de activos**: Se priorizan coincidencias específicas del hostname (p. ej. `iphone`, `msi`) antes de sufijos de router como `fritz` para evitar falsos positivos.
- **Nombre de activos**: Se usan pistas de `http_title` para nombrar activos sin hostname y clasificar modelos de switch con vendor/título.

### Documentación

- Manuales y esquema de reportes actualizados para incluir las pistas del probe HTTP.

## [3.8.4] - 2025-12-21 (Verificación sin Agente y Corrección de Colores)

### Añadido

- **Verificación sin agente**: Etapa opcional de fingerprinting SMB/RDP/LDAP/SSH/HTTP (wizard o `--agentless-verify`), con límite configurable de objetivos.
- **Flags CLI**: `--agentless-verify`, `--no-agentless-verify` y `--agentless-verify-max-targets`.

### Corregido

- **Colores de estado durante progreso**: Corregido el problema donde los mensajes `[INFO]` aparecían sin color cuando la barra de progreso Rich estaba activa. Ahora usa Rich console.print con markup adecuado (`bright_blue` para INFO, `green` para OK, `yellow` para WARN, `red` para FAIL) asegurando colores consistentes en todo momento.

## [3.8.3] - 2025-12-21 (Wizard y UX de reportes)

### Añadido

- **Identidad del auditor**: Prompt en el wizard para el nombre del auditor, reflejado en reportes TXT/HTML.
- **HTML bilingüe**: Cuando el idioma es ES, se genera `report_es.html` junto al HTML principal.

### Corregido

- **Duplicación en wizard**: Eliminada la repetición en las opciones del escaneo de vulnerabilidades.
- **Colores de detalle**: Los estados INFO/WARN/FAIL respetan colores mientras el progreso está activo.
- **Progreso Net Discovery**: Evita el 100% fijo durante fases largas antes de finalizar el último paso.

### Cambiado

- **Footer HTML**: Se neutraliza el footer (licencia + GitHub) sin crédito personal del autor.

## [3.8.2] - 2025-12-20 (Pulido UX)

### Añadido

- **Watermark HTML**: Footer profesional en reportes HTML con licencia GPLv3, autor (Dorin Badea) y enlace a GitHub.

### Corregido

- **Spinner Eliminado**: Eliminado spinner de barras de progreso (causaba congelación durante fases largas); ahora muestra barra limpia + porcentaje + tiempo transcurrido.

## [3.8.1] - 2025-12-20 (Corrección Feedback Visual)

### Añadido

- **Navegación del Wizard**: Nueva función `ask_choice_with_back` añade opción "< Volver" a los menús del wizard, permitiendo navegación paso a paso sin reiniciar toda la configuración.

### Corregido

- **ETA Eliminado**: Eliminadas estimaciones ETA poco fiables de barras de progreso (se congelaban o mostraban valores incorrectos); ahora solo muestra tiempo transcurrido.
- **Texto Truncado**: Corregido problema de truncamiento donde descripciones largas hacían ilegible la barra de progreso (`Escaneado 192.168.178… ETA≤ …`).
- **Mensajes Heartbeat**: Añadidos mensajes periódicos cada 30-60s durante fases largas (Net Discovery, Host Scan) para indicar actividad.
- **Detección Tipo Dispositivo**: Mejorada detección `device_type_hints`—añadido AVM/Fritz a patrones router, detección móvil basada en hostname (iPhone, iPad, Android).

### Cambiado

- **Display de Progreso**: Columnas de progreso simplificadas a: spinner + descripción + barra + porcentaje + tiempo transcurrido.
- **Labels Net Discovery**: Etiquetas de fase truncadas a 35 caracteres para evitar desbordamiento.

## [3.8.0] - 2025-12-20 (UX Net Discovery)

### Añadido

- **Barra de Progreso Net Discovery**: Spinner genérico reemplazado por barra Rich con porcentaje, descripción de fase y ETA durante el descubrimiento de red (~10 min de fase ahora muestra progreso real).
- **SmartScan Detección de Dispositivos**: Clasificación automática de tipo de dispositivo desde firmas vendor/UPNP/mDNS/servicio (móvil, impresora, router, IoT, smart_tv, hypervisor).
- **SmartScan Señales Topología**: El scoring de identidad ahora incluye resultados net_discovery (ARP, UPNP, mDNS) para mejores decisiones de deep scan.
- **Wizard UX Hints**: Añadidos ejemplos a prompts de SNMP community, DNS zone y webhook URL.

### Cambiado

- **Throttling HyperScan**: Umbral de actualización reducido de 3% a 1% e intervalo de 0.35s a 0.25s para feedback más suave y responsive durante el descubrimiento paralelo.
- **SmartScan Modo Completo**: El modo escaneo completo ya no desactiva heurísticas de deep scan; usa threshold de identidad más alto (4 vs 3) para descubrimiento más exhaustivo.
- **SmartScan Infraestructura de Red**: Routers y dispositivos de red ahora siempre activan deep scan para mapeo completo de infraestructura.

## [3.7.3] - 2025-12-20 (Confiabilidad del escaneo y precisión de reportes)

### Corregido

- **Parsing XML de Nmap**: Se conserva el XML completo y se extrae el bloque `<nmaprun>` para evitar errores de parseo
  que ocultaban identidades de hosts.
- **Timeout por modo**: Si no se define `--host-timeout`, el fallback respeta el modo de escaneo (completo = 300s) para
  evitar cortes prematuros.
- **Fallback de identidad por topología**: Si Nmap falla, se usa MAC/vendor de topología/vecinos para mantener la
  identidad del host en los reportes.
- **Conteo de reportes**: "Hosts Descubiertos" ahora deduplica objetivos para reflejar el conjunto único real.

## [3.7.2] - 2025-12-19 (Hotfix UX y Progreso)

### Corregido

- **Net Discovery (HyperScan)**: Actualizaciones de progreso limitadas (throttling) para reducir flickering en terminal.
- **UX Nuclei**: El escaneo de templates Nuclei ahora muestra progreso/ETA sin competir con otras UIs Rich (Live).
- **UX Defaults (Wizard)**: Si eliges "Revisar/modificar" y omites el resumen de defaults, RedAudit ya no pregunta si deseas
  iniciar inmediatamente con esos defaults.
- **Prompts Net Discovery (Wizard)**: Aclarado "ENTER usa el valor por defecto / ENTER para omitir" para comunidad SNMP y
  zona DNS.

## [3.7.1] - 2025-12-18 (Hotfix Crítico)

### Corregido

- **Logging de Sesión**: `TeeStream.encoding` cambiado de método a `@property` para corregir crash de consola Rich.
- **Deep Scan**: Corregido `TypeError: can't concat str to bytes` en `output_has_identity()` asegurando decodificación de stdout/stderr.
- **Progreso HyperScan**: Ahora usa el wrapper `hyperscan_with_progress` en net_discovery para spinner visible.

## [3.7.0] - 2025-12-18 (UX del Wizard e Integración SIEM)

### Añadido

- **Webhooks Interactivos**: El wizard ahora solicita URL de webhook Slack/Teams/PagerDuty con alerta de prueba opcional.
- **Net Discovery Avanzado en Wizard**: Cadena SNMP, zona DNS y máximo de objetivos ahora configurables en el wizard.
- **Pipeline SIEM Nativo**: Incluye `siem/filebeat.yml`, `siem/logstash.conf` y 3 reglas Sigma para integración ELK/Splunk.
- **Verificación Osquery**: Nuevo módulo `redaudit/core/osquery.py` para validación de configuración de hosts post-scan via SSH.
- **Logging de Sesión**: Salida de terminal capturada automáticamente a carpeta `session_logs/` (`.log` raw + `.txt` limpio).
- **Spinner de Progreso Nuclei**: Spinner animado Rich con tiempo transcurrido durante escaneos de templates Nuclei.

### Corregido

- **CI CodeQL**: Bajada de `codeql-action` a v3 por compatibilidad.

### Cambiado

- **Configuración webhook**: Ahora se persiste en `~/.redaudit/config.json` junto con otros defaults.

## [3.6.1] - 2025-12-18 (Calidad de Escaneo y UX)

### Añadido

- **Consolidación de hallazgos**: Los hallazgos duplicados en el mismo host (ej: "X-Frame-Options faltante" en 5 puertos) ahora se fusionan en uno con array `affected_ports`.
- **Fallback OUI online**: Nuevo módulo `redaudit/utils/oui_lookup.py` para consulta de vendor MAC via macvendors.com cuando la base local está incompleta.
- **Detección de puertos HTTPS**: Ampliada detección SSL/TLS para incluir puertos no estándar (8443, 4443, 9443, 49443).

### Corregido

- **Bug de integración Nuclei**: `get_http_targets_from_hosts()` usaba `state != "open"` pero los puertos de RedAudit no tienen campo `state`. Ahora usa correctamente el flag `is_web_service`.
- **Ruido en barra de progreso**: Comando nmap condensado de comando completo a `[nmap] IP (tipo de escaneo)` para display más limpio.
- **Manejo de falsos positivos**: Cuando la cross-validación detecta que Nikto reportó una cabecera faltante pero curl/wget la muestra presente, la severidad se degrada a `info` con `verified: false`.

### Cambiado

- **Ejecución testssl**: Ahora corre en todos los puertos HTTPS (8443, 49443, etc.), no solo en puerto 443.

## [3.6.0] - 2025-12-18 (Nuclei y UX)

### Añadido

- **Nuclei opt-in**: Los templates de Nuclei se pueden habilitar desde el wizard o por CLI (`--nuclei` / `--no-nuclei`) y guardarse como default persistente.
- **Progreso más informativo**: Las barras de progreso de hosts/vulns ahora muestran “qué está haciendo” dentro de la propia línea (sin inundar el terminal).
- **Defaults persistentes de Net Discovery**: Las opciones de Net Discovery / Red Team (incluyendo L2 activo y enumeración Kerberos) se pueden guardar y reutilizar.

### Cambiado

- **UX del instalador**: El instalador ahora muestra la versión real de RedAudit (leída de `redaudit/VERSION`) en lugar de un valor hard-coded.

### Corregido

- **Fase de hosts más silenciosa**: Se reduce el spam de estado `[nmap]` / `[banner]` mientras hay UI de progreso activa.

## [3.5.4] - 2025-12-18 (Hotfix)

### Corregido

- **Detección de versión en instalaciones del sistema**: Las instalaciones vía script en `/usr/local/lib/redaudit` ahora muestran la versión semántica correcta (se evita el bucle `v0.0.0-dev` del actualizador).

## [3.5.3] - 2025-12-18 (Documentación y Calidad)

### Highlights

- **Integridad Documental**: Documentación "sin humo" que coincide con la estructura y features.
- **Roadmap Veraz**: Separación estricta de features Planeadas vs Implementadas (verificado).
- **Recursos para Instructores**: Nueva `DIDACTIC_GUIDE` (EN/ES) enfocada en metodología de enseñanza.

### Fixed

- **Enlaces Rotos**: Corregido `pyproject.toml` que apuntaba a `docs/en/MANUAL.md` inexistente.
- **Estructura**: Eliminadas referencias legacy `docs/en/` y `docs/es/`; normalizado a `docs/*.en.md` y `docs/*.es.md`.
- **Linting**: Corregidos varios problemas de Markdown en READMEs (encabezados, bloques de código).

## [3.5.2] - 2025-12-18 (Hotfix)

### Añadido

- **Indicador de actividad en Net Discovery**: Las fases de descubrimiento de red ahora muestran feedback visible para que el terminal no parezca "bloqueado".
- **ETA consciente de timeouts**: Las barras de progreso muestran una cota superior conservadora (`ETA≤ …`) que tiene en cuenta los timeouts configurados.

### Cambiado

- **Salida más limpia**: La UI de progreso reduce el ruido de logs mientras está activa para mantener la experiencia legible.

### Corregido

- **Flujo post-actualización**: Tras instalar una actualización, RedAudit muestra un aviso grande de "reinicia el terminal", espera confirmación y sale para evitar ejecutar mezcla de versiones.

## [3.5.1] - 2025-12-17 (Hotfix)

### Añadido

- **Manifiesto de salida**: Cuando el cifrado está desactivado, RedAudit ahora escribe `run_manifest.json` en la carpeta de salida (métricas + lista de artefactos).
- **Campos de procedencia SIEM**: `findings.jsonl` / `assets.jsonl` ahora incluyen `session_id`, `schema_version`, `scanner`, `scanner_version`; `summary.json` añade `redaudit_version`.
- **UI de progreso silenciosa**: Las barras de progreso Rich ahora muestran ETA en fases de hosts/vulns, y los mensajes tipo "sin salida" del heartbeat dejan de spamear el terminal.

### Corregido

- **Soporte completo de `--dry-run`**: Propagado a los módulos restantes para que no se ejecute ningún comando externo, mostrando igualmente los comandos planificados.
- **UX del updater**: Si el system install se actualiza pero `~/RedAudit` tiene cambios locales git, RedAudit ahora omite actualizar la copia en home en vez de fallar toda la actualización.
- **Nota post-actualización**: Tras actualizar, RedAudit recuerda reiniciar el terminal o ejecutar `hash -r` si el banner/versión no se refresca.

## [3.5.0] - 2025-12-17 (Fiabilidad y Ejecución)

### Añadido

- **Evitar reposo durante escaneos**: Inhibición best-effort del reposo del sistema/pantalla mientras se ejecuta un escaneo (activado por defecto; opt-out con `--no-prevent-sleep`).
- **CommandRunner centralizado**: Nuevo `redaudit/core/command_runner.py` como punto único para comandos externos (timeouts, reintentos, redacción de secretos, despliegue incremental de `--dry-run`).

### Cambiado

- **Ejecución de comandos externos**: Más módulos ejecutan herramientas externas mediante CommandRunner (scanner/auditor/topology/net discovery), mejorando seguridad y haciendo `--dry-run` efectivo en más sitios (el despliegue sigue siendo incremental).
- **Documentación**: Manuales, uso, troubleshooting y roadmap actualizados para reflejar v3.5.0 y sus flags.

## [3.4.4] - 2025-12-17 (Hotfix)

### Corregido

- **Flujo de defaults**: Al elegir "Usar defaults y continuar" ahora sí se aplican; iniciar "inmediatamente" ya no re-pregunta parámetros, y puede reutilizar objetivos guardados cuando estén disponibles.
- **Docs**: Añadida nota sobre reiniciar el terminal / `hash -r` si el banner no refresca la versión tras actualizar.

## [3.4.3] - 2025-12-17 (Hotfix)

### Corregido

- **Títulos de hallazgos**: Los hallazgos web ahora tienen un `descriptive_title` corto derivado de observaciones parseadas (mejora títulos en HTML, webhooks y encabezados de playbooks).
- **Directorio de salida por defecto (wizard)**: Cuando el wizard iba a proponer `/root/...`, RedAudit ahora prefiere `Documentos` del usuario invocador (y, si se ejecuta como root sin `sudo`, usa un único usuario detectado bajo `/home/<usuario>` cuando no hay ambigüedad).
- **Marcador del menú (wizard)**: Se reemplaza el marcador Unicode por uno ASCII para que se renderice bien en cualquier terminal/fuente.

## [3.4.2] - 2025-12-17 (Hotfix)

### Corregido

- **Prompt del directorio de salida (sudo)**: Si un default persistido antiguo apunta a `/root/...`, RedAudit lo reescribe automáticamente a `Documentos` del usuario invocador cuando se ejecuta con `sudo`.

## [3.4.1] - 2025-12-17 (Hotfix)

### Corregido

- **Directorio de salida por defecto (sudo)**: Los reportes ahora se guardan por defecto en la carpeta Documentos del usuario que invoca `sudo` (en lugar de `/root`).
- **Expansión de `~` (sudo)**: `--output ~/...` y los defaults persistidos que usan `~` ahora se expanden contra el usuario invocador bajo `sudo`.
- **Propietario de archivos**: `chown` best-effort del directorio de salida al usuario invocador para evitar artefactos propiedad de root en el home del usuario.

## [3.4.0] - 2025-12-17 (Playbook Export)

### Añadido

- **Playbooks de Remediación**: Generación automática de guías de remediación accionables por hallazgo.
  - Nuevo módulo: `redaudit/core/playbook_generator.py`
  - Categorías: hardening TLS, cabeceras HTTP, remediación CVE, hardening web, hardening puertos
  - Salida: archivos Markdown en el directorio `<output_dir>/playbooks/`
  - Incluye: instrucciones paso a paso, comandos shell y enlaces de referencia
  - Deduplicación: un playbook por categoría por host

### Cambiado

- **reporter.py**: Ahora genera playbooks automáticamente después de finalizar el escaneo.
- **i18n.py**: Añadida clave de traducción `playbooks_generated`.

## [3.3.0] - 2025-12-17 (Mejoras DX)

### Añadido

- **Dashboard HTML Interactivo** (`--html-report`): Genera reportes HTML standalone con Bootstrap + Chart.js.
  - Tema oscuro con estética premium
  - Gráfico donut de distribución de severidad y gráfico de barras Top 10 puertos
  - Tablas ordenables de hosts y hallazgos
  - Colores de risk score (verde/naranja/rojo)
  - Columnas de MAC y vendor en tabla de hosts
  - Autocontenido: funciona offline, sin dependencias externas en runtime

- **Reporte Visual de Diff HTML** (`--diff`): Compara dos escaneos con salida visual lado a lado.
  - Nueva plantilla: `redaudit/templates/diff.html.j2`
  - Nueva función: `format_diff_html()` en `diff.py`
  - Resaltados: hosts nuevos (verde), hosts eliminados (rojo), puertos cambiados (amarillo)
  - Badges para cambios de severidad y deltas de puertos

- **Alertas Webhook** (`--webhook URL`): Alertas en tiempo real para hallazgos de alta severidad.
  - Nuevo módulo: `redaudit/utils/webhook.py`
  - Envía payloads JSON a cualquier endpoint webhook (Slack, Discord, Teams, custom)
  - Filtros: solo hallazgos HIGH y CRITICAL disparan alertas
  - Incluye: IP del activo, título del hallazgo, severidad, puerto, timestamp
  - Timeout: 10 segundos por request con manejo de errores

### Cambiado

- **reporter.py**: Ahora genera reporte HTML automáticamente cuando se usa el flag `--html-report`.
- **reporter.py**: Envía alertas webhook tras completar el escaneo cuando se provee `--webhook URL`.
- **cli.py**: Añadidos flags `--html-report` y `--webhook URL`.
- **pyproject.toml**: Directorio de templates incluido en package data.
- **Instalador**: Añadido `python3-jinja2` como dependencia para renderizado de templates HTML.

### Corregido

- **Visibilidad de Errores HTML Report**: Los errores durante generación HTML ahora se muestran en consola (no solo en log).
- **Bandit CI**: Configurado para saltar B101 (assert) en directorio de tests.

## [3.2.3] - 2025-12-16 (HyperScan + Modo Sigiloso)

### Añadido

- **Módulo HyperScan**: Nuevo `redaudit/core/hyperscan.py` (~1000 líneas) para descubrimiento paralelo ultrarrápido.
  - Escaneo TCP batch con 3000 conexiones concurrentes usando asyncio
  - Barrido UDP completo en 45+ puertos con payloads específicos por protocolo
  - Broadcast UDP IoT (WiZ, SSDP, Chromecast, Yeelight, LIFX)
  - Barrido ARP agresivo con 3 reintentos usando arp-scan + arping fallback
  - Detección de backdoors con niveles de severidad para puertos sospechosos (31337, 4444, 6666, etc.)
  - Modo deep scan: escaneo completo de 65535 puertos en hosts sospechosos

- **Modo Sigiloso**: Nuevo flag CLI `--stealth` para redes empresariales con IDS/rate limiters.
  - Usa template de timing nmap `-T1` (paranoid)
  - Fuerza escaneo secuencial con un solo hilo
  - Impone retardo mínimo de 5 segundos entre sondas
  - Jitter aleatorio ya integrado en rate limiting

- **Logging CLI**: Añadidos mensajes de progreso visibles para resultados de HyperScan mostrando conteos de hosts ARP/UDP/TCP y duración.

- **Spinners de Progreso**: Añadidos spinners animados para las fases topology y net_discovery mostrando tiempo transcurrido durante operaciones de descubrimiento largas.

### Corregido

- **Auto-Disparo Net Discovery**: Net discovery con HyperScan ahora se ejecuta automáticamente cuando topología está activada (no solo en modo `full`). Esto asegura que dispositivos IoT/WiZ se descubran en escaneos normales con topología.
- **Visibilidad HyperScan**: Añadida salida CLI visible para resultados de HyperScan mostrando conteos ARP/IoT/TCP y duración.
- **Detección IoT Mejorada**: Mejorada detección de bombillas inteligentes con payload de registro WiZ (38899), Yeelight (55443), TP-Link Tapo (20002), y sondas mDNS. Timeout aumentado para dispositivos IoT lentos.
- **Deduplicación de Redes**: "Escanear TODAS" ahora elimina correctamente CIDRs duplicados cuando la misma red se detecta en múltiples interfaces (ej: eth0 + eth1).
- **Visualización de Defaults**: La revisión de configuración interactiva ahora muestra 10 campos (antes 6) incluyendo scan_mode, web_vulns, cve_lookup, txt_report.
- **Persistencia de Config**: `DEFAULT_CONFIG` expandido a 12 campos para preservar ajustes completos.

## [3.2.2b] - 2025-12-16 (IoT & Descubrimiento Enterprise)

### Añadido

- **Descubrimiento UPNP Mejorado**: Timeout aumentado (10s → 25s), mecanismo de reintentos (2 intentos), fallback SSDP M-SEARCH.
- **Escaneo ARP Activo**: `netdiscover` ahora usa modo activo por defecto (flag `-f`), con soporte de interface para setups multi-homed.
- **Nuevo `arp_scan_active()`**: Función dedicada usando `arp-scan` con reintentos para descubrimiento IoT más fiable.
- **Descubrimiento ARP Dual**: Usa tanto `arp-scan` como `netdiscover` con deduplicación automática para máxima cobertura.
- **Tipos de Servicio mDNS IoT**: Añadidas queries específicas para `_amzn-wplay` (Alexa), `_googlecast` (Chromecast), `_hap` (HomeKit), `_airplay`.
- **Auto-Pivot `extract_leaked_networks()`**: Retorna CIDRs /24 escaneables de IPs filtradas para descubrimiento automático de redes ocultas.

### Cambiado

- **Timeout mDNS**: Aumentado de 5s a 15s para mejor captura de dispositivos IoT.
- **Timeout netdiscover**: Aumentado de 15s a 20s.
- **Versión**: Actualizada a 3.2.2b (desarrollo/testing).

### Corregido

- **Descubrimiento de Dispositivos IoT**: Escaneos anteriores solo encontraban 3 de 10+ dispositivos debido al modo ARP pasivo y timeouts cortos.
- **Sincronización JSON hidden_networks**: Las IPs de redes filtradas ahora correctamente populan `hidden_networks` y `leaked_networks_cidr` en JSON para pipelines SIEM/AI (antes solo aparecía en el reporte de texto).

## [3.2.2] - 2025-12-16 (Producción Hardening)

### Añadido

- **Instalación Atómica Staged**: La instalación de actualizaciones usa un directorio temporal `.new` antes del rename atómico, con rollback automático en caso de fallo.
- **Verificación Post-Instalación**: Valida que archivos clave existan tras instalar; rollback de sistema y home si falla.
- **Tests de Salida CLI**: 3 nuevos tests unitarios verificando mapeo de tokens (OKGREEN→OK, WARNING→WARN).

### Cambiado

- **Labels de Estado CLI**: `print_status` muestra labels user-friendly (`[OK]`, `[INFO]`, `[WARN]`) en vez de tokens internos (`[OKGREEN]`, `[OKBLUE]`, `[WARNING]`) en todos los modos de salida.
- **Documentación del Updater**: Renombrado de "Secure Update Module" a "Reliable Update Module" con documentación honesta del modelo de seguridad.
- **SECURITY.md**: Sección 7 renombrada a "Auto-Actualización Fiable" con nota explícita sobre verificación de integridad vs. autenticidad.

### Corregido

- **Fuga Visual de Tokens (B3)**: Los tokens internos de estado ya no aparecen como texto literal en la salida CLI.
- **Resolución de Tags Anotados**: Auto-update ahora resuelve correctamente los tags git anotados a su commit subyacente usando dereference `^{}`. Anteriormente, la comparación del hash del objeto tag vs. hash del commit siempre fallaba.

### Seguridad

- **Claims de Seguridad Honestos**: Documentado que el sistema de actualización verifica hashes de commit (integridad) pero NO realiza verificación criptográfica de firmas (autenticidad).

### Aviso de Actualización

> **⚠️ Usuarios en v3.2.1 o anterior**: La auto-actualización de v3.2.1 → v3.2.2 puede fallar debido al bug de tags anotados. Por favor reinstala manualmente:
>
> ```bash
> curl -sL https://raw.githubusercontent.com/dorinbadea/RedAudit/v3.2.2/redaudit_install.sh | sudo bash
> ```
>
> Después de esta actualización manual única, las futuras auto-actualizaciones funcionarán correctamente.

## [3.2.1] - 2025-12-15 (UX CLI)

### Añadido

- **Flags de control de defaults**: `--defaults {ask,use,ignore}`, `--use-defaults`, `--ignore-defaults`.
- **Fallback de idioma por locale**: El CLI detecta ES/EN desde env/locale cuando no existe preferencia guardada.

### Corregido

- **Salida del prompt de actualización**: Resumen legible en terminal (fecha/tipo/novedades), filtra ruido de Markdown y mantiene idioma consistente con nota de fallback clara.
- **UX de defaults en wizard**: Eliminadas confirmaciones redundantes al responder "no" a guardar defaults; añadido control explícito al inicio cuando existen defaults persistentes (usar/revisar/ignorar).

## [3.2.0] - 2025-12-15 (Descubrimiento de Red Mejorado)

### Añadido

- **Descubrimiento de Red Mejorado (v3.2)**: Nuevo bloque `net_discovery` en reportes con descubrimiento DHCP/NetBIOS/mDNS/UPNP/ARP/fping y análisis de VLANs candidatas (`--net-discovery`).
- **Recon Red Team (con guardas)**: Recon opt-in bajo `--redteam` con best-effort SNMP/SMB/RPC/LDAP/Kerberos/DNS + señales L2 pasivas en `net_discovery.redteam`.
- **Nuevos flags de tuning**: `--net-discovery-interface`, `--redteam-max-targets`, `--snmp-community`, `--dns-zone`, `--kerberos-realm`, `--kerberos-userlist`, `--redteam-active-l2`.

### Cambiado

- **Versión**: Actualizada a 3.2.0.

## [3.1.4] - 2025-12-15 (Calidad de salida)

### Añadido

- **Títulos descriptivos de hallazgos**: Genera títulos legibles según tipo de hallazgo (ej: "Cabecera X-Frame-Options Faltante" en vez de "Hallazgo en URL")
- **Extracción de fingerprint de SO**: Nueva función `extract_os_detection()` captura info de SO estructurada desde salida Nmap
- **Cross-validación Nikto**: `detect_nikto_false_positives()` compara hallazgos de Nikto con cabeceras curl/wget para detectar contradicciones
- **Ajuste de severidad RFC-1918**: `is_rfc1918_address()` reduce severidad para divulgación de IP interna en redes privadas
- **Constante de versión de schema**: Nueva constante `SCHEMA_VERSION` separada de `VERSION` para versionado de schema de reportes

### Cambiado

- **Timeout de TestSSL**: Por defecto aumentado de 60s a 90s, ahora configurable vía parámetro `timeout`
- **Rutas PCAP**: Los reportes usan rutas relativas (`pcap_file`) para portabilidad, con `pcap_file_abs` para uso interno
- **siem.py**: `enrich_vulnerability_severity()` añade campos `severity_note` y `potential_false_positives` cuando aplica

## [3.1.3] - 2025-12-15 (UDP y topología asíncronos)

### Añadido

- **Sondeo UDP asíncrono (best-effort)**: Sondeo concurrente rápido de puertos UDP prioritarios durante deep scan, registrado como `deep_scan.udp_priority_probe`.
- **Descubrimiento de topología asíncrono**: Recolección de comandos en paralelo para mapping ARP/VLAN/LLDP + gateway más rápido (best-effort).

### Cambiado

- **Estructura README**: Añadido módulo `udp_probe.py` a la estructura del proyecto
- **README Características**: Añadido Sondeo UDP Prioritario Async y Descubrimiento de Topología Async a sección Características
- **README Topología**: Actualizada descripción de topology.py para reflejar implementación async
- **Actualización ROADMAP**: Añadidos hitos v3.1.2/v3.1.3, marcado v3.1.3 como ACTUAL
- **DIDACTIC_GUIDE**: Actualizadas referencias de versión de v3.1.1 a v3.1.3

## [3.1.2] - 2025-12-14 (UX de actualización)

### Corregido

- **Vista previa de novedades**: Renderizado legible en terminal (limpia ruido Markdown y hace wrap de líneas largas).
- **Reinicio tras actualización**: Reinicio más robusto (PATH-aware) y mensajes claros si el reinicio falla.

### Cambiado

- **Prompts interactivos**: Presets de UDP en modo COMPLETO, texto más claro para “solo topología” y confirmación/explicación al guardar valores por defecto.

## [3.1.1] - 2025-12-14 (Topología, defaults y cobertura UDP)

### Añadido

- **Descubrimiento de Topología (best-effort)**: Mapping opcional ARP/VLAN/LLDP + gateway/rutas (`--topology`, `--topology-only`)
- **Defaults Persistentes**: Guardado de ajustes comunes en `~/.redaudit/config.json` mediante `--save-defaults` (se reutilizan como valores por defecto en ejecuciones futuras)
- **Cobertura UDP Configurable**: `--udp-ports N` (50-500) para ajustar la cobertura del UDP full de identidad

### Cambiado

- **Deep Scan UDP Fase 2b**: Usa `--top-ports N` configurable y registra `udp_top_ports` en el output de deep scan
- **Esquema de Reporte**: Añadido bloque opcional `topology` en el reporte raíz (cuando está activado)

## [3.1.0] - 2025-12-14 (SIEM y pipelines de IA)

### Añadido

- **Vistas de exportación JSONL**: Archivos planos auto-generados para ingesta SIEM/IA (cuando el cifrado de reportes está desactivado)
  - `findings.jsonl` - Un hallazgo por línea
  - `assets.jsonl` - Un activo por línea
  - `summary.json` - Resumen compacto para dashboards
  - Nuevo módulo: `redaudit/core/jsonl_exporter.py`

- **Deduplicación de hallazgos**: Hashes determinísticos `finding_id`
  - SHA256 de activo + escáner + puerto + firma + título
  - Habilita correlación entre escaneos y tracking

- **Clasificación por categoría**: Categorización automática de hallazgos
  - Categorías: surface, misconfig, crypto, auth, info-leak, vuln
  - Nueva función: `classify_finding_category()` en `siem.py`

- **Normalización de severidad**: Puntuación estilo CVSS
  - `normalized_severity`: escala 0.0-10.0
  - `original_severity`: Preserva el valor original de la herramienta
  - Enum: `info`, `low`, `medium`, `high`, `critical`

- **Observaciones estructuradas**: Extracción de evidencia con estructura
  - Nuevo módulo: `redaudit/core/evidence_parser.py`
  - Extrae hallazgos significativos desde salida raw de Nikto/TestSSL
  - Outputs grandes externalizados a la carpeta `evidence/` (solo cuando el cifrado está desactivado)

- **Versiones de escáneres**: Tracking de proveniencia de herramientas
  - Nuevo módulo: `redaudit/core/scanner_versions.py`
  - Detecta: nmap, nikto, testssl, whatweb, searchsploit
  - Añadido al reporte como objeto `scanner_versions`

### Cambiado

- **Versión de esquema**: Actualizada de 2.0 a 3.1
- **Metadatos de reporte**: Añadido timestamp `generated_at`
- **Versión**: Actualizada a 3.1.0

---

## [3.0.4] - 2025-12-14 (UX interactivo)

### Cambiado

- **Prompt de límite de hosts**: En modo interactivo el default ahora es "all" (`todos`/`all`) y la pregunta aclara que los números definen un máximo global de hosts (no un selector).
- **Documentación**: Aclara la semántica de `--max-hosts` y actualiza manuales.
- **Versión**: Actualizada a 3.0.4

---

## [3.0.3] - 2025-12-14 (UX de actualización)

### Añadido

- **Salida de auto-update más explícita**: Muestra ref/commit objetivo, cambios de ficheros (+/~/-) y pasos explícitos de install/backup.

### Corregido

- **Preservación de idioma en actualización**: El auto-update ya no reinicia el idioma instalado (ej. Español permanece en Español).

### Cambiado

- **Versión**: Actualizada a 3.0.3

---

## [3.0.2] - 2025-12-14 (UX, reporting y NVD)

### Añadido

- **Visibilidad de PCAP**: El resumen final incluye un contador de PCAP; los reportes TXT incluyen la ruta del PCAP cuando se captura.
- **Claridad del TXT**: Secciones de deep scan incluyen conteos de comandos (identity-only vs deep scan ejecutado).
- **Reporting CVE (TXT)**: Cuando hay enriquecimiento CVE, los reportes TXT incluyen resúmenes de CVE y conteos por puerto.

### Cambiado

- **Versión**: Actualizada a 3.0.2
- **Salida CLI**: `print` thread-safe + word-wrapping evita cortar palabras y líneas intercaladas en escaneos concurrentes.
- **UX en Español**: Traducciones completadas para mensajes de estado/progreso y deep scan.
- **Enriquecimiento NVD**: Omite consultas demasiado amplias (CPE comodín) cuando la versión del servicio es desconocida.

### Corregido

- **Mensajería NVD**: Corrige el origen de la API key (ya no reporta CLI si la key venía de config/env).

---

## [3.0.1] - 2025-12-13 (Configuración y UX)

### Añadido

- **Configuración de API Key NVD**: Almacenamiento persistente para correlación CVE
  - Nuevo módulo: `redaudit/utils/config.py`
  - Archivo de config: `~/.redaudit/config.json` (permisos 0600)
  - Soporte de variable de entorno: `NVD_API_KEY`
  - Prompt interactivo en auditor con 3 opciones de almacenamiento
  - El instalador solicita API key durante `redaudit_install.sh`
  - Traducciones EN/ES para todos los prompts nuevos

- **Prompt interactivo para correlación CVE**: Nueva pregunta en setup interactivo
  - "Enable CVE correlation via NVD?" (por defecto: no)
  - Si es sí y no hay key configurada, dispara el flujo de setup

### Cambiado

- **Versión**: Actualizada a 3.0.1
- **Hardening de auto-update**: Las actualizaciones resuelven el tag publicado y verifican el hash del commit antes de instalar.
- **Hardening de instalador**: La instalación de `testssl.sh` está fijada a un tag/commit conocido y verificada.
- **Resiliencia CVE**: Consultas NVD reintentan en errores transitorios (429/5xx/red) con backoff.
- **UX de privilegios**: Añade `--allow-non-root` para ejecutar en modo limitado sin sudo/root.

---

## [3.0.0] - 2025-12-12 (Release mayor)

### Añadido

- **Soporte IPv6**: Capacidades completas de escaneo para redes IPv6
  - Helpers `is_ipv6()`, `is_ipv6_network()` en `scanner.py`
  - `get_nmap_arguments_for_target()` añade `-6` automáticamente para objetivos IPv6
  - Detección de redes IPv6 en `network.py` (netifaces + fallback)
  - Flag CLI: `--ipv6` para modo de escaneo solo IPv6

- **Validación de magic bytes**: Detección mejorada de falsos positivos
  - `verify_magic_bytes()` en `verify_vuln.py`
  - Descarga los primeros 512 bytes y verifica firmas
  - Soporta: tar, gzip, zip, pem
  - Integrado como tercera capa de verificación en Smart-Check

- **Correlación CVE (NVD)**: Inteligencia de vulnerabilidades
  - Nuevo módulo: `redaudit/core/nvd.py`
  - Integración con NIST NVD API 2.0
  - Matching CPE 2.3 para CVE lookup más preciso
  - Caché de 7 días para uso offline y cumplimiento de rate limit
  - Flags CLI: `--nvd-key`, `--cve-lookup`

- **Análisis diferencial**: Comparar reportes de escaneo
  - Nuevo módulo: `redaudit/core/diff.py`
  - Identifica hosts nuevos, hosts eliminados y cambios de puertos
  - Genera salida JSON y Markdown
  - Flag CLI: `--diff OLD NEW`

- **Proxy Chains (SOCKS5)**: Soporte de pivoting en red
  - Nuevo módulo: `redaudit/core/proxy.py`
  - Clase `ProxyManager` para gestión de sesión
  - Integración wrapper con proxychains
  - Flag CLI: `--proxy URL`

- **Auto-update mejorado**: Sistema de update más fiable
  - Enfoque `git clone` (reemplaza `git pull`)
  - Ejecuta instalador con preferencia de idioma del usuario
  - Copia a `~/RedAudit` con toda la documentación
  - Verificación de instalación y fix de ownership

### Cambiado

- **Versión**: Bump mayor a 3.0.0
- **Auditor**: Añade `proxy_manager` y opciones de config v3.0

---

## [2.9.0] - 2025-12-12 (Smart improvements)

### Añadido

- **Módulo Smart-Check**: Filtrado de falsos positivos de Nikto
  - Nuevo módulo: `redaudit/core/verify_vuln.py`
  - Verificación Content-Type para detectar Soft 404
  - Validación de tamaño para archivos sospechosamente pequeños
  - Filtrado automático con conteo

- **Módulo de entity resolution**: Consolidación de hosts multi-interfaz
  - Nuevo módulo: `redaudit/core/entity_resolver.py`
  - Agrupa hosts por fingerprint de identidad (hostname/NetBIOS/mDNS)
  - Nuevo campo JSON: array `unified_assets`
  - Inferencia de tipo de activo (router, workstation, mobile, iot, etc.)

- **Mejoras SIEM profesionales**: Integración SIEM enterprise
  - Nuevo módulo: `redaudit/core/siem.py`
  - Cumplimiento ECS v8.11 para Elastic
  - Puntuación de severidad (critical/high/medium/low/info)
  - Risk scores (0-100) por host
  - Tags auto-generadas para categorización
  - Observable hash (SHA256) para dedup
  - Formato CEF para ArcSight/McAfee

- **Nuevos tests**: 46 tests unitarios para módulos nuevos

### Cambiado

- **UDP Taming**: Optimización de escaneo UDP (50-80% más rápido)
  - Usa `--top-ports 100` en vez de escaneo completo
  - `--host-timeout 300s` estricto por host
  - `--max-retries 1` para eficiencia en LAN

- **Versión**: Actualizada a 2.9.0

---

## [2.8.1] - 2025-12-11 (Mejoras UX)

### Añadido

- **Barra de progreso de vulnerabilidades**: Rich progress bar para fase de vulnerabilidades web
  - Muestra spinner, porcentaje, completados/total y tiempo transcurrido
  - Muestra el host actual
  - Fallback elegante si rich no está disponible

- **Indicadores de módulos**: Feedback visual de la herramienta activa durante vulnerabilidades
  - Prefijo `[testssl]` para análisis SSL/TLS profundo
  - Prefijo `[whatweb]` para fingerprinting web
  - Prefijo `[nikto]` para vulnerabilidades web
  - Actualiza `current_phase` para monitor de actividad

### Cambiado

- **Organización de PCAP**: PCAPs ahora se guardan dentro de la carpeta de resultados con timestamp
  - Carpeta creada ANTES de iniciar el escaneo (`_actual_output_dir`)
  - Todos los outputs (reportes + PCAPs) consolidados en un solo directorio
  - Corrige el problema donde PCAPs se guardaban en el directorio padre

- **Optimización de tamaño PCAP**: Reduce captura de ilimitada a 200 paquetes
  - PCAPs ahora ~50-150KB en vez de varios MB
  - Suficiente para análisis de protocolo sin exceso de almacenamiento
  - tcpdump se detiene automáticamente tras 200 paquetes

- **Directorio de salida por defecto**: Cambia de `~/RedAuditReports` a `~/Documents/RedAuditReports`
  - Reportes guardados por defecto en Documents del usuario
  - Ubicación más intuitiva

- **Versión**: Actualizada a 2.8.1

### Mejorado

- **Sistema de auto-update**: Mejorado de solo detección a instalación completa
  - Ahora hace `git reset --hard` para evitar conflictos
  - Copia automáticamente los ficheros a `/usr/local/lib/redaudit/`
  - Auto-reinicia con `os.execv()` tras update exitoso (no requiere reinicio manual)
  - Elimina la necesidad de `git pull` y reinstalación manual

### Corregido

- **Ctrl+C durante setup**: Corrige cuelgue al pulsar Ctrl+C antes de iniciar el escaneo
  - Añade manejo de `KeyboardInterrupt` en todos los métodos de input (`ask_yes_no`, `ask_number`, `ask_choice`, `ask_manual_network`)
  - Ahora sale inmediatamente si se interrumpe durante la fase de configuración
  - Solo intenta shutdown elegante cuando el escaneo realmente está corriendo

---

## [2.8.0] - 2025-12-11 (Completitud y fiabilidad)

### Añadido

- **Precisión de estado de host (Fase 1)**: Finalización inteligente de estado
  - Nuevos tipos de estado: `up`, `down`, `filtered`, `no-response`
  - `finalize_host_status()` evalúa el deep scan para determinar estado correcto
  - Hosts con MAC/vendor detectado pero sin respuesta inicial ahora aparecen como `filtered` en vez de `down`

- **Escaneo UDP inteligente (Fase 2)**: Estrategia adaptativa de deep scan en 3 fases
  - Fase 2a: Escaneo rápido de 17 puertos UDP prioritarios (DNS, DHCP, SNMP, NetBIOS, etc.)
  - Fase 2b: Escaneo UDP completo solo en modo `full` y si no se detecta identidad
  - Nueva config: `udp_mode` (por defecto: `quick`)
  - Nueva constante: `UDP_PRIORITY_PORTS` con servicios UDP más comunes

- **Captura PCAP concurrente (Fase 3)**: Captura sincronizada con el escaneo
  - `start_background_capture()` - Inicia tcpdump antes de comenzar el escaneo
  - `stop_background_capture()` - Recoge resultados tras finalizar el escaneo
  - Captura el tráfico real del escaneo en vez de ventanas vacías post-scan

- **Fallback banner grab (Fase 4)**: Identificación de servicios mejorada
  - `banner_grab_fallback()` - Usa nmap `--script banner,ssl-cert` para puertos no identificados
  - Se ejecuta automáticamente en puertos con `tcpwrapped` o servicio `unknown`
  - Fusiona resultados en registros de puerto con campos `banner` y `ssl_cert`

- **Sistema de auto-update seguro (Fase 5)**: Update checking integrado con GitHub
  - Nuevo módulo: `redaudit/core/updater.py`
  - Consulta GitHub API para latest releases al inicio (prompt interactivo)
  - Muestra release notes/changelog para versiones nuevas
  - Updates seguros basados en git con verificación de integridad
  - Flag CLI: `--skip-update-check` para desactivar
  - Traducciones para mensajes de update en inglés y español

- **Carpetas de reportes con timestamp (Fase 6)**: Estructura organizada
  - Reportes guardados en subcarpetas: `RedAudit_YYYY-MM-DD_HH-MM-SS/`
  - Cada sesión tiene su propio directorio
  - PCAPs y reportes organizados juntos

### Cambiado

- **Estrategia de deep scan**: Actualizada de `adaptive_v2.5` a `adaptive_v2.8`
  - Captura de tráfico concurrente durante toda la duración del escaneo
  - Estrategia UDP en tres fases para escaneos típicos más rápidos
  - Mensajería mejorada con estimaciones por fase

- **Constantes**: Nuevas constantes para features v2.8.0
  - `STATUS_UP`, `STATUS_DOWN`, `STATUS_FILTERED`, `STATUS_NO_RESPONSE`
  - `UDP_PRIORITY_PORTS`, `UDP_SCAN_MODE_QUICK`, `UDP_SCAN_MODE_FULL`
  - `DEEP_SCAN_TIMEOUT_EXTENDED`, `UDP_QUICK_TIMEOUT`

- **CLI**: Nuevos flags `--udp-mode` y `--skip-update-check`

- **Versión**: Actualizada a 2.8.0

### Técnico

- Nuevo módulo `redaudit/core/updater.py` con:
  - `parse_version()`, `compare_versions()`
  - `fetch_latest_version()`, `check_for_updates()`
  - `perform_git_update()`, `interactive_update_check()`

- Nuevas funciones en `scanner.py`:
  - `start_background_capture()` / `stop_background_capture()`
  - `banner_grab_fallback()`
  - `finalize_host_status()`

- Mejoras en `scan_host_ports()`:
  - Track de puertos unknown para banner fallback
  - Finaliza estado tras todos los enriquecimientos

- Actualización de `reporter.py`:
  - Crea subcarpetas con timestamp para reportes

---

## [2.7.0] - 2025-12-09 (Velocidad e integración)

### Añadido

- **Motor de pre-scan Asyncio (A1)**: Descubrimiento rápido usando asyncio TCP connect
  - Nuevo módulo: `redaudit/core/prescan.py`
  - Flags CLI: `--prescan`, `--prescan-ports`, `--prescan-timeout`
  - Hasta 500 checks concurrentes con batching configurable
  - Parsing de rangos: `1-1024`, `22,80,443`, o combinado `1-100,443,8080-8090`

- **Salida compatible con SIEM (A5)**: Reportes JSON mejorados para Splunk/Elastic
  - Nuevos campos: `schema_version`, `event_type`, `session_id`, `timestamp_end`
  - Metadatos del escáner: nombre, versión, modo
  - Array `targets` para escaneos multi-red

- **Bandit (A4)**: Linting de seguridad estático en CI
  - Añade Bandit al workflow de GitHub Actions
  - Escanea problemas de seguridad comunes (checks serie B)

### Cambiado

- **Rate limiting con jitter (A3)**: Añade varianza aleatoria ±30% al delay para evasión IDS
- **Versión**: Actualizada a 2.7.0

---

## [2.6.2] - 2025-12-09 (Hotfix de señal)

### Corregido

- **Limpieza de subprocess en signal handler (C1)**: SIGINT (Ctrl+C) ahora termina correctamente subprocesses activos (nmap, tcpdump, etc.) en vez de dejar procesos huérfanos
  - Añade métodos `register_subprocess()`, `unregister_subprocess()`, `kill_all_subprocesses()`
  - Los procesos hijos reciben SIGTERM y luego SIGKILL si siguen vivos tras 2 segundos
  - Implementación thread-safe con locks

- **Cancelación de futures (C2)**: Futures pendientes en ThreadPoolExecutor ahora se cancelan cuando hay interrupción
  - Evita trabajo innecesario si el usuario aborta
  - Aplicado tanto a rich progress bar como a modo fallback

### Cambiado

- **Versión**: Actualizada a 2.6.2

---

## [2.6.1] - 2025-12-08 (Intel de exploits y análisis SSL/TLS)

### Añadido

- **Integración SearchSploit**: Lookup automático en ExploitDB para servicios con versión detectada
  - Consulta `searchsploit` para exploits conocidos cuando se identifica producto+versión
  - Resultados visibles en reportes JSON y TXT
  - Timeout: 10s por consulta
  - Corre en todos los modos (fast/normal/full)
  - Nueva función: `exploit_lookup()` en `redaudit/core/scanner.py`

- **Integración TestSSL.sh**: Análisis profundo SSL/TLS para servicios HTTPS
  - Escaneo de vulnerabilidades SSL/TLS (Heartbleed, POODLE, BEAST, etc.)
  - Detección de cifrados débiles y problemas de protocolo
  - Solo corre en modo `full` (timeout 60s por puerto)
  - Resultados incluyen summary, vulnerabilities, weak ciphers y protocols
  - Nueva función: `ssl_deep_analysis()` en `redaudit/core/scanner.py`

- **Mejoras de reporting**:
  - Reportes TXT muestran exploits conocidos por servicio
  - Reportes TXT muestran hallazgos de vulnerabilidad de TestSSL
  - Reportes JSON incluyen automáticamente todos los campos nuevos

- **Internacionalización**: Traducciones EN/ES para features nuevas:
  - `exploits_found` - Notificaciones de descubrimiento de exploits
  - `testssl_analysis` - Mensajes de progreso SSL/TLS

### Cambiado

- **Instalación**: `redaudit_install.sh` actualizado para instalar `exploitdb` y `testssl.sh`
- **Verificación**: `redaudit_verify.sh` actualizado para chequear herramientas nuevas
- **Dependencias**: Añade searchsploit y testssl.sh a la lista de herramientas opcionales (12 en total)
- **Versión**: Actualizada a 2.6.1

### Filosofía

Ambas herramientas mantienen el enfoque adaptativo de RedAudit:

- **SearchSploit**: Ligero, corre automáticamente cuando hay info de versión
- **TestSSL**: Análisis pesado, solo en modo full para findings accionables

---

## [2.6.0] - 2025-12-08 (Arquitectura modular)

### Añadido

- **Estructura modular de paquete**: Refactor de `redaudit.py` monolítico (1857 líneas) a un paquete organizado:
  - `redaudit/core/auditor.py` - Orquestador principal
  - `redaudit/core/crypto.py` - Utilidades de cifrado/descifrado
  - `redaudit/core/network.py` - Detección de redes
  - `redaudit/core/reporter.py` - Generación de reportes
  - `redaudit/core/scanner.py` - Lógica de escaneo
  - `redaudit/utils/constants.py` - Constantes con nombre
  - `redaudit/utils/i18n.py` - Internacionalización
- **Pipeline CI/CD**: Workflow de GitHub Actions (`.github/workflows/tests.yml`)
  - Tests en Python 3.9, 3.10, 3.11, 3.12
  - Integración con Codecov para coverage
  - Linting con Flake8

- **Nuevas suites de tests**:
  - `tests/test_network.py` - Tests de detección de red con mocking
  - `tests/test_reporter.py` - Tests de generación de reportes y permisos de fichero
- **Entry point del paquete**: Soporte `python -m redaudit`

### Cambiado

- **Constantes con nombre**: Reemplaza magic numbers por constantes descriptivas
- **Cobertura de tests**: Expandida de ~25 a 34 tests automatizados
- **Versión**: Actualizada a 2.6.0

### Corregido

- **Compatibilidad Python 3.9**: Corrige sintaxis `str | None` en `test_sanitization.py` usando `Optional[str]`
- **Imports de tests**: `test_encryption.py` actualizado para usar funciones a nivel módulo (`derive_key_from_password`, `encrypt_data`) en vez de métodos inexistentes
- **Cumplimiento Flake8**: Resueltos todos los errores:
  - Eliminados espacios sobrantes en líneas en blanco (W293)
  - Eliminados 12 imports sin usar en `auditor.py`, `scanner.py`, `reporter.py` (F401)
  - Añade espacios alrededor de operadores aritméticos (E226)
  - Renombra variable ambigua `l` a `line` (E741)

### Compatibilidad hacia atrás

- `redaudit.py` original preservado como wrapper fino por compatibilidad
- Scripts y workflows existentes continúan funcionando sin cambios

---

## [2.5.0] - 2025-12-07 (Hardening de seguridad)

### Añadido

- **Seguridad de permisos de ficheros**: Reportes usan permisos seguros (0o600 - lectura/escritura solo para owner)
- **Tests de integración**: Suite completa (`test_integration.py`)
- **Tests de cifrado**: Cobertura completa de cifrado (`test_encryption.py`)

### Cambiado

- **Sanitizers endurecidos**: `sanitize_ip()` y `sanitize_hostname()` ahora:
  - Validan tipo de entrada (solo se acepta `str`)
  - Eliminan whitespace automáticamente
  - Devuelven `None` para tipos inválidos (int, list, etc.)
  - Aplican límites máximos de longitud
- **Manejo de cryptography**: Degradación elegante mejorada
  - `check_dependencies()` ahora verifica disponibilidad de cryptography
  - `setup_encryption()` soporta modo no interactivo con flag `--encrypt-password`
  - `setup_encryption()` no pide contraseña si cryptography no está disponible
  - Generación de contraseña aleatoria en modo no interactivo cuando no se provee
  - Mensajes de warning claros en inglés y español
- **Versión**: Actualizada a 2.5.0

### Seguridad

- **Validación de entrada**: Toda entrada del usuario validada por tipo y longitud
- **Permisos de ficheros**: Todos los reportes generados usan permisos seguros (0o600)
- **Manejo de errores**: Mejor manejo de excepciones reduce filtración de información

## [2.4.0] - 2025-12-07 (Adaptive Deep Scan)

### Añadido

- **Adaptive Deep Scan (v2.5)**: Implementa estrategia 2 fases (TCP agresivo -> fallback UDP+OS) para maximizar velocidad y datos.
- **Detección vendor/MAC**: Regex nativo para extraer vendor HW desde output de Nmap.
- **Instalador**: Refactor de `redaudit_install.sh` a operaciones de copia limpias sin Python embebido.

### Cambiado

- **Heartbeat**: Mensajería más profesional ("Nmap is still running") para reducir ansiedad durante escaneos largos.
- **Reporting**: Añade campos `vendor` y `mac_address` en reportes JSON/TXT.
- **Versión**: Actualizada a 2.4.0

## [2.3.1] - 2024-05-20 (Hardening de seguridad)

### Añadido

- **Hardening de seguridad**: Sanitización estricta de inputs (IPs, hostnames, interfaces) para prevenir command injection.
- **Cifrado de reportes**: Cifrado AES-128 opcional (Fernet) para reportes generados; incluye helper `redaudit_decrypt.py`.
- **Rate limiting**: Retardo configurable entre escaneos concurrentes para operaciones más sigilosas.
- **Logging profesional**: Logger rotativo en `~/.redaudit/logs/` para audit trail y debugging.
- **Truncado de puertos**: Truncado automático si >50 puertos en un host, reduciendo ruido.

### Cambiado

- **Dependencias**: Añade `python3-cryptography` como dependencia core para cifrado.
- **Configuración**: Setup interactivo actualizado con prompts de cifrado y rate limiting.

## [2.3.0] - 2024-05-18

### Añadido

- **Heartbeat Monitor**: Hilo en background que imprime estado cada 60s y advierte si Nmap se cuelga (>300s).
- **Salida elegante**: Maneja Ctrl+C (SIGINT) para guardar estado parcial antes de salir.
- **Deep Scan**: Dispara escaneo nmap agresivo + UDP si un host muestra pocos puertos abiertos.
- **Captura de tráfico**: Captura snippet PCAP pequeño (50 paquetes) para hosts activos usando `tcpdump`.
- **Enriquecimiento**:
  - **WhatWeb**: fingerprinting para servicios web.
  - **Nikto**: scan de vulnerabilidades web (solo en modo FULL).
  - **DNS/Whois**: reverse lookup y whois básico para IPs públicas.
  - **Curl/Wget/OpenSSL**: cabeceras HTTP e info de certificado TLS.

### Cambiado

- **Gestión de dependencias**: Se deja de usar `pip`. Dependencias via `apt` (python3-nmap, etc.) alineado con Kali/Debian.
- **Networking**: Reemplaza `netifaces` (a menudo ausente) por parsing robusto de `ip addr show` o `ifconfig`.
- **Arquitectura**: `redaudit_install.sh` ahora despliega el core Python directamente, eliminando descargas de `.py` separado.

### Corregido

- **Tracebacks**: Añade `try/except` extensivos para evitar crashes ante errores de escaneo.
- **Permisos**: Añade chequeo de `root` (sudo) al inicio.
