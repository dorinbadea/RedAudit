# Registro de cambios

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](../CHANGELOG.md)

Todos los cambios relevantes se documentan en este archivo.

El formato sigue [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
y este proyecto sigue [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Las notas de versión viven en `docs/releases/` para más contexto.

## [Sin lanzar]

## [4.19.8] - 2026-01-29

### Corregido

- **Resumenes en reanudacion**: Las reanudaciones ahora cuentan hosts desde resultados existentes y preservan redes objetivo en los resumenes.
- **Registro de objetivos Nuclei**: Las reanudaciones ya no sobrescriben `nuclei_targets.txt`; los pendientes quedan en `nuclei_pending.txt`.
- **Integridad de activos JSONL**: Se agregan activos minimos para hosts con hallazgos, evitando `asset_id` vacio.
- **Colores en logs de sesion**: Los flujos tee reportan TTY correctamente y mantienen INFO coloreado durante el escaneo.
- **Avisos de identidad profunda**: Las etiquetas de estrategia ya no muestran sufijos de version heredados.

### Mejorado

- **Contexto de progreso en reanudacion**: El progreso de reanudacion de Nuclei refleja el total de objetivos con contexto de reanudacion.

## [4.19.7] - 2026-01-28

### Corregido

- **Autoobjetivo en Red Team**: El descubrimiento Red Team ahora omite las IPs del auditor al seleccionar objetivos para evitar auto-enumeracion.

## [4.19.6] - 2026-01-28

### Corregido

- **Detalle de progreso de Nuclei**: El progreso paralelo informa el recuento de lotes completados sin indices engañosos.
- **Color INFO**: La salida INFO usa el azul estandar para visibilidad consistente.

## [4.19.5] - 2026-01-28

### Corregido

- **Metadatos en reanudacion de Nuclei**: Las reanudaciones preservan redes objetivo y duracion total en resumen/manifiesto.

## [4.19.4] - 2026-01-27

### Mejorado

- **Override de presupuesto en reanudacion**: La reanudacion permite cambiar el presupuesto (o desactivarlo) y la CLI acepta `--nuclei-max-runtime`.
- **Lotes con presupuesto**: Cuando hay presupuesto, RedAudit evita iniciar un lote nuevo si el tiempo restante no cubre el tiempo estimado del lote.

## [4.19.3] - 2026-01-27

### Mejorado

- **Calidad en CI**: Umbral de cobertura subido al 80% y ShellCheck aplicado.
- **Mapeo de protocolos SNMP v3**: Nombres de protocolos auth/priv se mapean a objetos PySNMP y respetan claves auth/priv.
- **Cobertura OUI offline**: El manuf local soporta prefijos /28 y /36.
- **Cobertura de auditoria**: Tests para exclusion de interfaces Docker y fallback de HyperScan con Masscan.

### Corregido

- **Topologia SNMP y CVE**: El procesamiento de topologia SNMP ya no asume una API key NVD inicializada.
- **Recuento WhatWeb en diff**: Los informes diferenciales cuentan WhatWeb con la clave correcta.
- **Timeout por defecto de Nuclei**: El default del ConfigurationContext se alinea a 300s como el CLI.
- **Alineacion documental**: Presets de velocidad ES y fallback de threads alineados al comportamiento.
- **Limpieza de emojis**: Docker y seguridad eliminan emojis segun la politica de documentacion.
- **ShellCheck**: Scripts de instalacion y Docker ahora pasan ShellCheck sin avisos.

## [4.19.2] - 2026-01-26

### Mejorado

- **Progreso en reanudacion de Nuclei**: Las reanudaciones muestran progreso Rich incluso con presupuesto de tiempo.
- **Orden de reanudaciones**: Las reanudaciones pendientes se ordenan por la fecha de ultima actualizacion.

### Corregido

- **Claridad en reanudacion**: Las reanudaciones con presupuesto/parcial ahora muestran avisos y el resumen guarda metadatos de presupuesto/timeouts.

## [4.19.1] - 2026-01-26

### Mejorado

- **Metadatos de Nuclei**: El resumen ahora incluye `budget_exceeded` cuando el presupuesto termina la ejecucion.

### Corregido

- **Presupuesto de Nuclei**: Los lotes se limitan al tiempo restante y se guardan objetivos pendientes si se agota en mitad de un lote.
- **Claridad en progreso**: Las lineas de detalle usan el color de estado y las paradas por presupuesto no muestran avisos de timeout.

## [4.19.0] - 2026-01-26

### Añadido

- **Presupuesto de tiempo y reanudacion de Nuclei**: Presupuesto opcional que crea `nuclei_resume.json` y `nuclei_pending.txt`, con pregunta de reanudacion y cuenta atras de 15 segundos.
- **Puntos de reanudacion**: Menu principal "Reanudar Nuclei (pendiente)" y flags `--nuclei-resume` / `--nuclei-resume-latest`.

### Mejorado

- **Snapshot y esquema**: El snapshot incluye `nuclei_max_runtime` y el resumen de Nuclei incluye metadatos de reanudacion.

## [4.18.22] - 2026-01-25

### Corregido

- **Suelo de timeout de Nuclei**: Los reintentos tras split mantienen el timeout configurado como suelo para evitar perder cobertura en objetivos lentos.

## [4.18.21] - 2026-01-25

### Mejorado

- **Actualizacion de home**: Las actualizaciones del sistema ahora crean backup si `~/RedAudit` tiene cambios y refrescan la copia local para mantener la documentacion al dia.

## [4.18.20] - 2026-01-25

### Mejorado

- **Contraste ANSI**: Las lineas de estado ahora aplican el color al texto completo para un contraste consistente fuera de Rich.

### Corregido

- **Sincronizacion de idioma UI**: El UI manager se resincroniza cuando cambia el idioma del CLI para evitar mezclas EN/ES.
- **Limite de paralelismo en Nuclei**: Los timeouts largos reducen los lotes paralelos para evitar timeouts del escaneo completo.

## [4.18.19] - 2026-01-25

### Mejorado

- **Estilo en progreso**: La salida Rich aplica el color de estado a todas las lineas para mantener el contraste.
- **Snapshot de configuracion**: El snapshot incluye `deep_id_scan`, `trust_hyperscan` y `nuclei_timeout`.

### Corregido

- **Sincronizacion de idioma**: Los cambios de idioma actualizan el UI manager para evitar mezclas EN/ES.
- **Filtrado de senales en progreso**: WARN detecta palabras clave en espanol durante el render.
- **Mensajes i18n**: Dependencias, fallos de autenticacion y errores de escaneo usan cadenas localizadas.

## [4.18.18] - 2026-01-24

### Añadido

- **Sonda HTTP de bajo impacto**: El enriquecimiento Phase 0 ahora permite una sonda HTTP/HTTPS corta para hosts con solo vendor y cero puertos abiertos cuando esta activado.

### Mejorado

- **Contraste del wizard**: Las opciones no seleccionadas se muestran en azul y los valores por defecto se resaltan en los prompts.
- **Timeouts tras split de Nuclei**: Los reintentos tras dividir lotes ahora limitan el timeout para evitar esperas largas en objetivos lentos.

### Corregido

- **Resumen Phase0**: El resumen smart scan ahora respeta `low_impact_enrichment` cuando la configuracion es `ConfigurationContext`.

## [4.18.17] - 2026-01-24

### Añadido

- **Conteo UDP de Net Discovery**: El resumen del pipeline ahora incluye el total de puertos UDP detectados por HyperScan para mayor claridad.

### Corregido

- **Alineación de HyperScan-First**: Las comparativas de HyperScan-First ahora reflejan solo TCP para coincidir con la salida del CLI.

## [4.18.16] - 2026-01-24

### Añadido

- **Regla de cobertura**: El workflow exige cobertura del 100% para el codigo modificado y rutas nuevas.

### Mejorado

- **Cobertura de tests**: Se amplio la bateria de tests hasta 98% y se cubrieron flujos del updater.

## [4.18.15] - 2026-01-24

### Mejorado

- **Almacen de pistas de hostname**: Las pistas basadas en hostname ahora se cargan desde el archivo de firmas para mantener configurable la clasificacion de identidad y activos.

## [4.18.14] - 2026-01-24

### Aniadido

- **Almacen de firmas**: Las pistas de vendors y los templates FP de Nuclei ahora cargan desde archivos de datos.

### Corregido

- **Fallback de exclusion del auditor**: Se anade un fallback best-effort de IPs locales cuando faltan network_info y topologia.

## [4.18.13] - 2026-01-24

### Añadido

- **Exclusiones del auditor**: Los manifiestos ahora incluyen las IPs del auditor excluidas y sus razones para transparencia en revisiones automáticas.

### Corregido

- **Parseo SMB de dominio**: El parser sin agente ya no arrastra líneas de FQDN cuando el campo de dominio está vacío.

## [4.18.12] - 2026-01-23

### Corregido

- **Métricas HyperScan-First**: El barrido HyperScan-First ahora gobierna las comparativas `hyperscan_vs_final` para evitar subcuentas de puertos en el discovery rápido.
- **Merge de masscan en HyperScan-First**: La detección con RustScan ahora fusiona puertos de masscan como fallback, en lugar de reemplazar el resultado completo.
- **Precisión de pistas DHCP**: Los timeouts DHCP ya no reportan falta de IPv4 cuando la ruta por defecto ya aporta dirección de origen.
- **Errores de auth en HTML (ES)**: Los informes HTML en español traducen los errores del escaneo autenticado.
- **Exclusión de IPs del auditor**: El filtrado excluye IPs locales de interfaces y rutas para evitar listar el propio nodo auditor.

## [4.18.11] - 2026-01-23

### Corregido

- **Precisión en pistas DHCP**: Evita indicar ausencia de IPv4 cuando no se pudo verificar la interfaz.
- **Errores del pipeline en HTML (ES)**: Los mensajes de error del pipeline se traducen en los informes en español.
- **Resumen autenticado en HTML**: El resultado del escaneo autenticado ya es visible en los informes HTML.
- **Sync del repo tras actualizar**: El updater refresca tags y hace fast‑forward de `main` cuando el repo está limpio para evitar prompts desfasados.
- **Crecimiento de logs del lab**: El script de instalación aplica rotación de logs de Docker para evitar crecimiento excesivo.
- **Despliegue SMB del lab**: El contenedor `.30` se recrea para evitar configuraciones obsoletas.

### Documentación

- **Limpieza del lab y rotación manual de logs**: Documentada la eliminación del lab y los flags de rotación para ejecuciones manuales (EN/ES).

## [4.18.10] - 2026-01-23

### Corregido

- **Pistas de timeout DHCP**: Añadidas pistas best-effort para timeouts de broadcast DHCP.
- **Detección de puerto SSH**: El escaneo autenticado reconoce SSH en puertos no estándar (ej. 2222).

## [4.18.9] - 2026-01-23

### Mejorado

- **Trazabilidad de Nuclei**: Los resúmenes del informe incluyen el perfil y la cobertura completa de Nuclei en los HTML.
- **Reducción de ruido de topología**: El descubrimiento ARP deduplica entradas IP/MAC idénticas para reducir el ruido.

### Corregido

- **Filtrado de redes ocultas**: Se filtran los objetivos en alcance de forma consistente para evitar falsos positivos de fuga de red.

## [4.18.8] - 2026-01-22

### Mejorado

- **Anclaje de toolchain en instalador**: Añadido `REDAUDIT_TOOLCHAIN_MODE=latest` para testssl/kerbrute y overrides de version (`TESTSSL_VERSION`, `KERBRUTE_VERSION`, `RUSTSCAN_VERSION`).
- **Poetry Lockfile**: Añadido `poetry.lock` para evaluacion junto a pip-tools.
- **Refactor Red Team**: Separado el descubrimiento Red Team en un modulo dedicado para reducir `net_discovery.py`.

### Corregido

- **Mensaje de kerbrute en instalador**: Evita reportar "ya instalado" tras una instalación nueva.

### Documentación

- **Política del toolchain**: Documentado el modo de toolchain y los overrides de versión en README y manuales.

## [4.18.7] - 2026-01-22

### Corregido

- **Recuento PCAP en CLI**: El resumen final usa metadatos del run para evitar contar capturas de otros runs.

## [4.18.6] - 2026-01-22

### Corregido

- **Salida de Lynis en autenticado**: Los objetos Host ahora guardan resultados de Lynis sin provocar `TypeError`.
- **Inicialización de filtro sin agente**: Eliminada la asignación duplicada de `host_agentless` en el filtro de falsos positivos de Nuclei.
- **Recuento de PCAPs**: El resumen CLI ahora cuenta todos los artefactos PCAP, incluido el full capture.
- **Validación de identity threshold**: `--identity-threshold` ahora se limita a 0-100 con fallback seguro.
- **Consistencia de docs**: Aclarado el fallback de hilos, el jitter, el rango de identity threshold y la numeración de USAGE.

## [4.18.5] - 2026-01-22

### Corregido

- **Truncamiento en Deep Scan**: Deep Scan ahora captura stdout completo para evitar perder puertos en ejecuciones Nmap verbosas.
- **Seguridad de FD en HyperScan**: El tamaño de lote TCP ahora se limita al 80% del soft limit de FD para evitar `Too many open files`.

## [4.18.4] - 2026-01-21

### Corregido

- **Trazabilidad de informes**: Los sospechosos de Nuclei ahora se listan en HTML/TXT para revisión manual.
- **Visibilidad de errores de discovery**: Los errores de Net Discovery ahora se muestran en secciones HTML/TXT.
- **Snapshot de configuración**: Se guardan perfil y cobertura completa de Nuclei en snapshots/resumen.
- **Claridad de DHCP discovery**: DHCP ahora usa la interfaz de la ruta por defecto, prueba todas las interfaces IPv4 en modo completo y reporta timeouts como sin respuesta.

## [4.18.3] - 2026-01-21

### Corregido

- **Salida de progreso HyperScan**: Se suprimen lineas por host durante el progreso Rich para evitar UI mixta.
- **Claridad del asistente Nuclei**: Las etiquetas de perfil describen alcance de plantillas; la pregunta de cobertura completa aclara el alcance de puertos.

## [4.18.2] - 2026-01-21

### Corregido

- **Consistencia de colores UI**: Los estados ahora se pintan correctamente durante el progreso de HyperScan.
- **Cobertura completa de Nuclei**: El valor por defecto es SI solo cuando el perfil de Nuclei es Full.
- **Fuentes en resumen**: Los conteos de fuentes ahora coinciden con los hallazgos consolidados.
- **Conteo de PCAP en manifiesto**: El conteo de PCAP ahora refleja todos los artefactos listados.

## [4.18.1] - 2026-01-20

### Corregido

- **Consistencia de informes Nuclei**: HTML/TXT ahora muestran estado parcial, lotes con timeout/fallidos y resultados solo sospechosos.
- **Resumen de fuentes de vulnerabilidades**: Los conteos de fuentes en el pipeline reflejan los hallazgos enriquecidos en lugar de `unknown`.
- **Cobertura completa vs Auto-Fast**: Se omite el cambio automatico a auto-fast cuando la cobertura completa esta activada para respetar el perfil seleccionado.

## [4.18.0] - 2026-01-20

### Corregido

- **Bugs de Color con Rich Progress**: Corregidos mensajes [WARN], [OK] e [INFO] que aparecían blancos durante barras de progreso.
  - Causa raíz: New Console() evitaba el Rich progress activo, perdiendo color.
  - Corrección: Añadido seguimiento `_active_progress_console` en UIManager.
  - Corregidos heartbeats de Deep Scan y Net Discovery para usar objetos `Text()`.

### Mejorado

- **Prompts Acortados del Wizard**: Reducida truncación en terminal acortando prompts:
  - `nuclei_full_coverage_q`: Acortado para evitar wrap de terminal.
  - `trust_hyperscan_q`: Simplificado para más claridad.

### Documentación

- **Sección Configuración Nuclei**: Añadida sección Nuclei completa a USAGE.en.md y USAGE.es.md explicando:
  - Perfiles de escaneo (fast/balanced/full) con estimaciones de tiempo.
  - Opción cobertura completa (solo wizard, no flag CLI).
  - RustScan como mejora de rendimiento opcional.
- **Actualizaciones Referencia CLI**: Añadidos flags faltantes `--profile` y `--nuclei-timeout` a referencia CLI del MANUAL.
- **Corregido**: `--nuclei-full` NO existe como flag CLI (opción solo en wizard).

## [4.17.0] - 2026-01-20

### Añadido

- **Opción Cobertura Completa Nuclei**: Nueva pregunta en wizard para escanear TODOS los puertos HTTP con Nuclei.
  - Modo Exhaustivo: por defecto SI (cobertura completa para escaneos tipo pentesting).
  - Modo Personalizado: por defecto NO (eficiencia audit-focus).
  - Clave config: `nuclei_full_coverage` omite limitación de targets cuando es true.

### Tests

- Añadidos `TestNucleiFullCoverage` (4 tests) y `TestNucleiFullCoverageI18n` (2 tests).

## [4.16.0] - 2026-01-19

### Añadido

- **Modo Audit-Focus Nuclei**: Hosts multi-puerto (3+ puertos HTTP) ahora limitados a 2 URLs para escaneo Nuclei.
  - Prioriza puertos estándar (80, 443, 8080, 8443) para eficiencia de auditoría.
  - Reduce significativamente el tiempo de escaneo (estimado 25min vs 1.5h para hosts complejos).
  - Mensaje visible al usuario muestra reducción: `Nuclei: 25 -> 8 targets (audit focus)`.

### Corregido

- **Corrección Bug de Color (de v4.15.1)**: Mensajes [INFO] ya no aparecen blancos durante barras de progreso.
  - Causa raíz: El markup Rich `[INFO]` se interpretaba como un tag desconocido.
  - Corrección: Usar objetos `Text()` de Rich para salida de color confiable.

## [4.15.0] - 2026-01-19

### Añadido

- **Barra de Progreso HyperScan**: Barra de progreso visual (magenta) mostrando completado de hosts durante la fase de descubrimiento HyperScan-First.
- **Perfil Auto-Fast Nuclei**: Detección automática de hosts con 3+ puertos HTTP, cambiando a perfil "fast" (solo plantillas CVE) para prevenir timeouts.

### Corregido

- **Paralelismo Real HyperScan**: Eliminado bloqueo de escaneo SYN que estaba serializando. RustScan/asyncio ahora ejecutan en modo paralelo real.
- **Emojis Minimalistas en Terminal**: Reemplazados emojis coloridos por alternativas Unicode monocromáticas:
  - `✅` -> `✔`
  - `❌` -> `✖`
  - `⚠️` -> `⚠`
- **Correcciones de Tests**: Actualizado `test_session_log.py` para usar nuevos emojis minimalistas.

### Pruebas

- Añadidos `test_hyperscan_start_sequential_key_en` y `test_hyperscan_start_sequential_key_es` para verificar claves i18n.

## [4.14.0] - 2026-01-19

### Añadido

- **Remediación Consciente del Dispositivo**: Nuevas plantillas en `playbook_generator.py` para dispositivos AVM (FRITZ!), Linux, Cisco/Red y Windows.
  - Dispositivos embebidos (ej. FRITZ!Box) ahora sugieren actualizaciones de firmware vía interfaz web en lugar de `apt/yum`.
  - Dispositivos de red sugieren actualizaciones de IOS/firmware.
  - Servidores Linux mantienen guía `apt/yum`.
- **Coincidencia de Modelos CVE**: Mejorado `verify_vuln.py` para soportar `expected_models` y `false_positive_models`.
  - Implementado para **CVE-2024-54767** (Acceso No Autorizado AVM): coincide solo con `7530`, excluye `7590` y Repetidores.
- **Fallback de Detalles Técnicos**: `evidence_parser.py` ahora genera observaciones robustas desde versiones de servicio, banners y cabeceras cuando falta salida específica de herramientas.

### Corregido

- **Títulos de Playbook**: Corregido problema donde títulos de hallazgos que contenían URLs (ej. `http://...`) se usaban como títulos de playbook. Ahora usa títulos descriptivos o nombres genéricos.
- **UX del Asistente**: Añadida lógica para sugerir configuración manual si el usuario rechaza cargar credenciales del llavero.
- **Estilo del Asistente**: Mejorado menú del asistente con colores profesionales (Tenue para navegación, Cian Negrita para selección).
- **Robustez del Código**: Completada auditoría exhaustiva de `playbook_generator.py`:
  - Corregida lógica de placeholder `{host}` en pasos.
  - Añadidas comprobaciones estrictas de tipos para procesamiento de vendor y tipo de dispositivo.

## [4.13.2] - 2026-01-18

### Corregido

- **Referencias en Informe HTML**: Corregido mismatch de claves (`reference` vs `references`) que causaba ausencia de detalles técnicos en la sección de Hallazgos.
- **Falso Positivo CVE-2022-26143**: Mejorada la detección de FRITZ!OS para incluir el cuerpo de la respuesta, no solo la cabecera Server.
- **Datos Enriquecidos de Nuclei**: Ahora se extraen `impact`, `remediation`, `cvss_score`, `cvss_metrics` y `extracted_results` de los hallazgos de Nuclei.
- **Observaciones Vacías**: Añadido fallback para usar la descripción de la vulnerabilidad cuando `parsed_observations` está vacío.
- **Atribución de Fuente**: Cambiado fuente por defecto de `unknown` a `redaudit` para hallazgos auto-generados. Añadida detección de WhatWeb.

## [4.13.0] - 2026-01-17

### Añadido

- **Reintentos de Host Muerto**: Nuevo flag CLI `--dead-host-retries` para abandonar hosts tras N timeouts consecutivos (predeterminado: 3). Evita atascos en hosts que no responden.
- **Integración ConfigurationContext**: Añadida propiedad `dead_host_retries` al wrapper de configuración tipada.

### Corregido

- **i18n Estimaciones Nuclei**: Corregidas estimaciones de tiempo de perfiles Nuclei en el asistente:
  - `fast`: ~15min -> ~30-60min
  - `balanced`: ~30min -> ~1h
- **Truncamiento de Texto en Asistente**: Acortadas las descripciones de perfiles del asistente en español para evitar truncamiento en terminales estrechos.

## [4.12.1] - 2026-01-17

### Añadido

- **Enriquecimiento de Topología**: Los resultados ARP en la fase de topología ahora resuelven vendors "(Unknown)" usando la base de datos OUI.
- **Optimización Nuclei**: Añadida configuración de `rate_limit` y `batch_size` a los perfiles de Nuclei.
  - El perfil `fast` ahora corre a 300 rps (antes 150) con batch size 15 (antes 10) para mayor velocidad.
- **Claridad del Asistente**: Actualizadas las descripciones de perfiles Express/Standard para indicar claramente la profundidad (solo discovery vs vulns).

### Corregido

- Corregida la interacción entre defaults de perfil Nuclei y parámetros explícitos (los parámetros explícitos ahora tienen prioridad).
- Corregidos problemas de tipado (mypy) en el módulo Nuclei usando `TypedDict`.

## [4.12.0] - 2026-01-17

### Añadido

- **Gating de Herramientas por Perfil**: El perfil Nuclei (`--profile`) ahora controla la ejecución de Nikto:
  - `fast`: Omite Nikto completamente para máxima velocidad.
  - `balanced`: Omite Nikto en dispositivos de infraestructura (routers, switches, APs).
  - `full`: Ejecuta Nikto en todos los hosts web (comportamiento original).
- **Detección de Infraestructura Mejorada**: Mejorado `is_infra_identity()` para detectar más patrones de dispositivos de red (Fritz!Box, MikroTik, Ubiquiti, Synology, QNAP, etc.).

### Cambiado

- **Optimización de Rendimiento**: La fase de escaneo de vulnerabilidades ahora respeta el perfil Nuclei para reducir el tiempo de escaneo en redes con muchos dispositivos de infraestructura.
- **Lógica de Gating de Nikto**: Movida de `_should_run_app_scans()` a un método dedicado `_should_run_nikto()` para una mejor separación de responsabilidades.

## [4.11.0] - 2026-01-17

### Añadido

- **Selector de Perfiles Nuclei**: Introducidos perfiles de escaneo optimizados (`--profile`) para equilibrar velocidad y cobertura:
  - `full`: Todas las plantillas (comportamiento por defecto).
  - `balanced`: Solo etiquetas de alto impacto (cve, rce, exposure, misconfig) - ~4x más rápido.
  - `fast`: Solo comprobaciones críticas (cve, critical) - ~10x más rápido.
- **Visibilidad IoT Mejorada**:
  - **Soporte Protocolo WiZ**: Detecta y reporta automáticamente bombillas inteligentes WiZ mediante inyección UDP en puerto 38899, resolviendo el problema de "cero puertos encontrados".
  - **IoT de Puerto Cerrado**: Documentación actualizada para clarificar el manejo de dispositivos que responden a multicast/UPnP pero no tienen puertos TCP abiertos.
- **Motor de Identidad Mejorado**:
  - **Base de Datos OUI**: Actualización masiva de 46 a **38.911 fabricantes** usando la base de datos de Wireshark, reduciendo significativamente las etiquetas de fabricante "Unknown".

### Cambiado

- **Optimización Nuclei**:
  - Reducido tamaño del lote de 25 a 10 objetivos para evitar timeouts.
  - Aumentado timeout de 300s a 600s por lote para mayor fiabilidad en redes densas.
  - Implementada lógica de "éxito parcial": los hallazgos se reportan incluso si algunos lotes fallan por timeout.
- **Timeouts**: Confirmados timeouts satisfactorios para Nikto (330s) y TestSSL (90s).

## [4.10.1] - 2026-01-16

### Fixed

- **Enriquecimiento de Hosts Inconsistente**: Solucionado un problema donde los hosts descubiertos vía Seguimiento de Rutas (Topología SNMP) no se enriquecían con datos CVE.
- **Error de Importación**: Resuelto un potencial `NameError` relacionado con importaciones locales en el módulo auditor.
- **Limpieza de Código**: Movidas las importaciones locales al nivel superior para mejor mantenibilidad.

## [4.10.0] - 2026-01-16

### Añadido

- **Descubrimiento L2/L3 Avanzado**:
  - **Topología SNMP**: Consultas autenticadas para tablas de rutas, tablas ARP e interfaces (`--snmp-topology`).
  - **Seguimiento de Rutas**: Expansión automática del alcance basada en tablas de enrutamiento descubiertas (`--follow-routes`).
  - **Descubrimiento L2 Pasivo**:
    - **LLDP**: Información de sistema/puerto vía `tcpdump` (macOS/Linux) y `lldpctl`.
    - **CDP**: Descubrimiento de Cisco vía `tcpdump`.
    - **Detección de VLAN**: Etiquetas 802.1Q desde `ifconfig`/`ip link` y rastreo pasivo.
  - **Integración con Asistente**: Mensajes interactivos para configurar topología y seguimiento de rutas.

### Corregido

- **Crítico**: Resuelto `AttributeError: 'set' object has no attribute 'append'` en el manejo de `Host.tags` durante la mejora de HyperScan.

## [4.9.1] - 2026-01-16

### Añadido

- **Implementación Quick Wins**:
  - **Visibilidad UDP IoT**: Puertos UDP especializados (ej. WiZ 38899) descubiertos por HyperScan ahora se exportan correctamente.
  - **Detección de Honeypot**: Nueva etiqueta `honeypot` para hosts con puertos abiertos excesivos (>100).
  - **Etiquetado Sin Respuesta**: Los hosts que fallan el escaneo Nmap se etiquetan como `no_response:nmap_failed`.

### Corregido

- **Prompt Nuclei en Asistente**: Corregida clave i18n `nuclei_enable_q` para usar la existente `nuclei_q`.

### Cambiado

- **Limpieza de Código**: Eliminado código muerto `masscan_scanner.py` (reemplazado por RustScan en v4.8.0).

### Documentación

- **Limitaciones VLAN**: Añadidas limitaciones de detección VLAN 802.1Q a la documentación de USO.

## [4.9.0] - 2026-01-16

### Añadido

- **Detección de Redes Ocultas**: Nueva función `detect_routed_networks()` en `net_discovery.py`.
  - Parsea `ip route` e `ip neigh` para descubrir redes enrutadas no locales.
  - Prompt interactivo en asistente: pregunta si incluir redes ocultas descubiertas.
  - Nuevo flag CLI `--scan-routed` para modo no interactivo.

### Cambiado

- **Selección de Red en Asistente**: `ask_network_range()` ahora detecta y ofrece redes enrutadas ocultas.

### Documentación

- Documentadas limitaciones de aislamiento VLAN (VLANs 802.1Q no descubribles sin acceso a switch/SNMP).
- Actualizado `task.md` con topología de red de usuario (Vodafone VLAN 100/105 via switch Zyxel).

## [4.8.1] - 2026-01-16

### Fixed

- Restaurar pregunta interactiva para activar Nuclei en perfil Exhaustivo (asistente).

## [4.8.3] - 2026-01-16

### Corregido

- **Arquitectura del Instalador**: Añadida detección de arquitectura ARM64/aarch64 para soporte de Raspberry Pi y VMs Apple Silicon.
  - Anteriormente intentaba descargar el .deb de amd64 en todas las plataformas.
  - Ahora hace fallback elegante a nmap/apt si el asset de RustScan no está disponible para la arquitectura.

## [4.8.2] - 2026-01-16

### Corregido

- **Rango de Puertos RustScan**: Forzado escaneo de rango completo (1-65535) en fase HyperScan.
  - Anteriormente usaba el default de RustScan (top 1000), perdiendo servicios en puertos no estándar.
  - Añadido parámetro de rango en `rustscan.py` e `hyperscan.py`.

## [4.8.0] - 2026-01-16

### Añadido

- **Integración RustScan**: Nuevo módulo `rustscan.py` para descubrimiento de puertos ultra-rápido.
  - RustScan encuentra los 65535 puertos en ~3 segundos (vs 142s masscan, 6s nmap).
  - Fallback automático a nmap si RustScan no está instalado.
  - Añadido al instalador (`redaudit_install.sh`) como dependencia opcional recomendada.

### Cambiado

- **Arquitectura HyperScan-First**: Reemplazado masscan por RustScan como escáner de puertos principal.
  - Basado en benchmark: RustScan+nmap (38s) vs masscan (142s) vs solo-nmap (43s).
  - El descubrimiento de rango completo de puertos es ahora significativamente más rápido en redes físicas.

- **Nuclei DESACTIVADO por defecto**: El escáner de plantillas Nuclei ahora está deshabilitado por defecto.
  - Use el flag `--nuclei` para habilitarlo explícitamente.
  - Razón: Lento en redes densas en web con valor marginal para auditorías de red.
  - Todavía disponible vía flag `--nuclei` cuando se necesite para pruebas de seguridad web específicas.

### Documentación

- Añadido `scan_results_private/HYPERSCAN_INVESTIGATION_2026-01-16.md` con datos completos del benchmark.

## [4.6.32] - 2026-01-15

### Rendimiento

- **Net Discovery Paralelo**: Todos los protocolos de descubrimiento (DHCP, ARP, mDNS, etc.) ahora corren concurrentemente.

## [4.6.31] - 2026-01-15

### Rendimiento

- **HyperScan Paralelo**: Convertido pre-escaneo secuencial a paralelo (hasta 8 workers) con batching adaptativo de FDs.

## [4.6.30] - 2026-01-15

### Seguridad

- **Zombie Reaper**: Implementada limpieza nativa con `pkill` para evitar procesos huérfanos de Nmap/Nuclei.
- **Auditoría**: Verificada seguridad de descriptores de archivo y manejo de excepciones en hilos.

## [4.6.29] - 2026-01-15

### Rendimiento

- **Desbloqueo de Hilos**: Incrementado `MAX_THREADS` de 16 a 100 para aprovechar hardware moderno.
- **Deep Scan**: Eliminado el límite de 50 hilos para respetar el límite global `MAX_THREADS`.

### Corregido

- **Config**: Añadido `nuclei_timeout` faltante en `ConfigurationContext`.

## [4.6.28] - 2026-01-15

### Corregido

- **Estabilidad Crítica**: Eliminado el uso global de `socket.setdefaulttimeout()` en `network_scanner.py`. Anteriormente, las búsquedas DNS inversas podían establecer inadvertidamente un timeout para TODOS los hilos y sockets activos de la aplicación, causando timeouts aleatorios en conexiones Nuclei, SSH y HTTP.

## [4.6.27] - 2026-01-15

### Corregido

- **Rendimiento HyperScan**: Corregido fallo logico donde puertos cerrados (RST) eran tratados como "timeouts" por el control de congestion adaptativo. Esto causaba que la velocidad bajara al minimo (lote 100) en lugar de acelerar (lote 20k), explicando la demora de "1 minuto por host". Los escaneos son ahora sustancialmente mas rapidos.

## [4.6.26] - 2026-01-15

### Corregido

- **Jitter en Barra de Progreso**: Corregido un bug UI donde lotes paralelos de Nuclei sobrescribian el progreso de otros, causando saltos erraticos. Implementada agregacion centralizada de progreso.

## [4.6.25] - 2026-01-15

### Corregido

- **Fix Concurrencia Paralela**: Anadido bloqueo de hilos para E/S de archivos y estadisticas en escaneos Nuclei para prevenir condiciones de carrera.
- **Paralelismo CLI**: Habilitada ejecucion paralela de lotes para usuarios CLI estandar (barra de progreso Rich).

## [4.6.24] - 2026-01-15

### Cambiado

- **Optimizacion Rendimiento Nuclei**: Batch reducido 25->10, corregido bug de reintento infinito, anadida ejecucion paralela hasta 4 batches via ThreadPoolExecutor. Escaneos Nuclei ~4x mas rapidos en redes grandes.

## [4.6.23] - 2026-01-14

### Anadido

- **Reintento Nuclei en Timeout**: En primer timeout, reintenta batch con timeout 1.5x antes de dividir. Reduce fallos en redes lentas.
- **Cobertura de Tests**: Anadidos 8 tests nuevos para funcionalidades v4.6.21-23 (X-Frame-Options, IoT lwIP, inyeccion CVE FTP).

## [4.6.22] - 2026-01-14

### Anadido

- **Etiquetado CVE FTP**: Backdoors detectados (vsftpd 2.3.4, etc.) ahora inyectan registros CVE en `port.cves` para propagacion automatica a JSONL.
- **Spray de Credenciales SMB**: Prueba todas las credenciales SMB del keyring hasta que una funcione, igual que SSH. Usa nuevo metodo `_resolve_all_smb_credentials()`.

## [4.6.21] - 2026-01-14

### Corregido

- **Severidad X-Frame-Options**: Anadidos patrones `anti-clickjacking.*x-frame-options` y `x-frame-options.*not present` a SEVERITY_OVERRIDES. Hallazgos de Nikto ahora correctamente clasificados como Low en lugar de High.
- **Falso Positivo IoT lwIP**: Anadida heuristica en `calculate_risk_score` para detectar dispositivos IoT con >20 puertos abiertos (stack lwIP responde SYN-ACK a todos los probes). Riesgo limitado a 30 para revision manual.

## [4.6.20] - 2026-01-14

### Anadido

- **Flag de Timeout para Nuclei**: Nuevo flag CLI `--nuclei-timeout` para configurar el timeout de batch (defecto 300s). Util para redes Docker/lentas donde el timeout por defecto causa escaneos parciales.

### Corregido

- **Deteccion de Backdoor vsftpd 2.3.4**: Corregida la deteccion de CVE-2011-2523 combinando campos service+product+version+banner en `calculate_risk_score`.
- **Consistencia de Titulos**: La exportacion JSONL ahora usa `descriptive_title` para ambos campos `title` y `descriptive_title`, coincidiendo con el comportamiento del reporte HTML.
- **Generacion Unificada de Titulos**: Consolidadas las funciones `_extract_title` de `jsonl_exporter` y `html_reporter` en un unico `extract_finding_title` en `siem.py`, eliminando 170 lineas de codigo duplicado.

### Mejorado

- **Calidad de Codigo**: Anadido `extract_finding_title` con cadena de fallback adecuada: descriptive_title, template_id de Nuclei, CVE IDs, parsed_observations, nikto_findings, fallback basado en puerto.

## [4.6.19] - 2026-01-14

### Anadido

- **Priorizacion de Hallazgos**: Nuevos campos `priority_score` (0-100) y `confirmed_exploitable` para clasificar mejor las vulnerabilidades.
- **Deteccion Clasica de Vulnerabilidades**: Deteccion automatica de servicios con backdoors conocidos (vsftpd 2.3.4, UnrealIRCd 3.2.8.1, etc.) basada en analisis de banners.
- **Calidad de Reporte**: Nuevo `confidence_score` (0.0-1.0) para hallazgos basado en senales de verificacion.
- **Titulos Mejorados**: Mejor generacion de titulos para hallazgos, detectando vulnerabilidades especificas (BEAST, POODLE) y titulos fallback mas claros (ej. "HTTP Service Finding").
- **Exportacion JSONL**: Anadidos campos de calidad (`confidence_score`, `priority_score`, `confirmed_exploitable`) a la salida JSONL para ingestion por SIEM.

### Mejorado

- **Interfaz Wizard**: El resumen de credenciales ahora muestra el conteo de entradas en listas de spray (ej. `(+5 spray)`).
- **Mapeo de Severidad**: Mapeo refinado para hallazgos genericos de escaneres para reducir ruido (ej. bajando severidad para revelacion de versiones).

## [4.6.18] - 2026-01-13

### Anadido

- **Spray de Credenciales SSH**: Probar todas las credenciales de la lista spray en keyring hasta autenticar exitosamente. Permite una sola lista para redes con distintos requisitos de autenticacion SSH.

### Corregido

- **Salida Parcial de Nuclei**: Persistir hallazgos parciales cuando los lotes hacen timeout a maxima profundidad de division recursiva, en lugar de dejar la salida vacia.
- **Codificacion URL NVD**: Codificar parametros de busqueda con espacios para evitar errores de URL.

## [4.6.17] - 2026-01-13

### Corregido

- **Keyring con sudo**: Preservar el contexto de DBus al cargar el keyring del usuario invocador para mostrar credenciales guardadas.

## [4.6.16] - 2026-01-13

### Mejorado

- **Fiabilidad de Nuclei**: Timeouts adaptativos por lote, divisiones recursivas y timeout/reintentos por peticion para reducir ejecuciones parciales.

## [4.6.15] - 2026-01-13

### Mejorado

- **Estabilidad del progreso de Nuclei**: Mantener el avance de objetivos sin retrocesos durante reintentos y timeouts.

### Corregido

- **Consistencia de hosts en informes**: Rellenar `hosts[].asset_name` y `hosts[].interfaces` desde assets unificados.

## [4.6.14] - 2026-01-13

### Añadido

- **Cancelar en el asistente de autenticación**: Permite cancelar los prompts de credenciales para salir de la configuración de auth.

### Mejorado

- **Etiqueta de navegación**: Cambia "Volver" por "Cancelar" y usa color de advertencia en la navegación.

### Corregido

- **Keyring con sudo**: Detecta credenciales guardadas del usuario que invoca al ejecutar con sudo.
- **Fecha en informes**: Actualiza el footer de licencia HTML a 2026.

## [4.6.13] - 2026-01-12

### Añadido

- **Objetivos en el Wizard**: Mostrar objetivos normalizados con hosts estimados antes de ejecutar.

### Mejorado

- **Progreso de Nuclei**: Mostrar avance por objetivos dentro de cada batch para evitar barras congeladas.
- **Progreso de Vulns**: Mostrar estado explícito de timeout de Nikto cuando supera su presupuesto.

### Corregido

- **Clasificación de Activos**: Servicios tipo Chromecast sobrescriben pistas genéricas de router en dispositivos multimedia.
- **Identidad Web**: Reconocer títulos de OWASP Juice Shop como activos de tipo servidor.
- **Manifiesto de Ejecución**: Marcar `run_manifest.json` como parcial cuando hay timeouts en Nuclei.

## [4.6.12] - 2026-01-12

### Mejorado

- **Progreso de Nuclei**: Mostrar avance basado en tiempo dentro de cada batch, con tiempo transcurrido, para evitar barras congeladas.

## [4.6.11] - 2026-01-12

### Añadido

- **Origen HTTP sin agente**: Se registra el origen de identidad HTTP (`http_source`, `upnp_device_name`) para distinguir pistas UPnP de señales HTTP reales.

### Cambiado

- **Progreso de Nuclei**: Emite actualizaciones de latido durante lotes largos para mostrar actividad y tiempo transcurrido.

### Corregido

- **Gating de Identidad HTTP**: Ignora títulos solo UPnP para el gating de escaneo web y el score de identidad; permite que el probe HTTP sobrescriba pistas UPnP.
- **Enriquecimiento Web**: Propaga cabeceras HTTP server desde el enriquecimiento de vulnerabilidades a los fingerprints sin agente.

## [4.6.10] - 2026-01-12

### Añadido

- **Objetivos Wizard**: La entrada manual acepta valores CIDR/IP/rango separados por comas y normaliza rangos a bloques CIDR.
- **Objetivos CLI**: Acepta rangos IP y normaliza IPs individuales a /32 para un escaneo consistente.

### Cambiado

- **Docs**: README/uso/manual actualizados y roadmap reordenado con eliminación de emojis.

## [4.6.9] - 2026-01-12

### Cambiado

- **Deep Scan**: Usa evidencia HTTP (título/servidor) y tipo de dispositivo para evitar deep scans innecesarios cuando la identidad ya es fuerte.
- **Escaneo Apps Web**: Omitir sqlmap/ZAP en UIs de infraestructura cuando la identidad indica router/switch/AP.

### Corregido

- **Informe Nuclei**: Marcar ejecuciones parciales cuando hay timeouts de lotes y exponer índices de lotes con timeout/fallidos en el informe.

## [4.6.8] - 2026-01-12

### Corregido

- **Progreso Vulns**: No actualizar barras de progreso de hosts ya finalizados para evitar movimientos engañosos.
- **Tags Web**: Añadir la etiqueta `web` cuando existe `web_ports_count`, aunque falten flags de puerto.

## [4.6.7] - 2026-01-11

### Corregido

- **Escaneos Auth**: Evitar consultas de credenciales en keyring durante el escaneo de puertos si la autenticación está desactivada.
- **Logs de sesión**: Deduplicadas las barras de progreso para reducir ruido.

## [4.6.6] - 2026-01-11

### Cambiado

- **UX**: Añadido el prompt "Trust HyperScan" en el perfil Exhaustivo (defecto: No).

## [4.6.5] - 2026-01-11

### Corregido

- **Updater**: Forzar `VERSION` al tag objetivo durante la actualización para evitar banners obsoletos.
- **Resolución de versión**: Priorizar `VERSION` empaquetado sobre metadata instalada para evitar sombras de pip.
- **Flujo de actualización**: Bloquear actualizaciones del sistema sin sudo para `/usr/local/bin/redaudit` y evitar instalaciones parciales.

### v4.6.3 (2026-01-11)

- **UX**: Añadido prompt "Trust HyperScan" faltante en el Asistente (Paso 2).
- **UX**: Activado Trust HyperScan por defecto en perfiles "Express" y "Standard".

## [4.6.4] - 2026-01-11

- **UX**: Prompt "Trust HyperScan" visible en perfil Estándar (antes oculto/auto-true).

## [4.6.2] - 2026-01-11

### Añadido

- **Optimización Trust HyperScan (Hosts Silenciosos)**: Ahora maneja hosts "mudos" (0 puertos) inteligentemente. En lugar de recurrir a un escaneo completo de 65k puertos, realiza una verificación de cordura (top 1000) si "Trust HyperScan" está activado.

## [4.6.0] - 2026-01-11

### Added

- **Optimización Trust HyperScan**: Nueva capacidad para reutilizar resultados de descubrimiento para Deep Scan, evitando el lento escaneo `-p-`.
  - Añadido flag CLI `--trust-hyperscan`.
  - Añadido prompt interactivo en el Asistente.
  - Reduce drásticamente el tiempo de escaneo para hosts identificados.

## [4.5.18] - 2026-01-11

### Corregido

- **Configuración Lab (Hotfix)**: `setup_lab.sh` ahora fuerza la recreación del contenedor `target-windows` (.30) usando la configuración correcta de `elswork/samba`, arreglando el uso de imágenes rotas u obsoletas.

## [4.5.17] - 2026-01-11

### Corregido

- **Lógica de Escaneo (BUG-01)**: Los puertos de HyperScan ahora se preservan estrictamente incluso si la fase de deep scan falla o devuelve cero puertos debido a timeouts.
- **Escaneo de Routers (UX-03)**: Lógica de deep scan optimizada para dispositivos de infraestructura:
  - Routers bien identificados (identidad fuerte, fabricante conocido, <= 20 puertos) ahora omiten el Deep Scan redundante.
  - Hosts sospechosos o ambiguos SIEMPRE reciben el barrido completo de 65k puertos.
  - Resuelve el problema de escaneos de router de 25+ minutos respetando estrictamente el diagrama de seguridad.
- **Manejo de Entrada**: Corregido crash por `Ctrl+C` en el asistente (salida elegante).
- **CLI**: Añadido argumento faltante `--verbose` / `-v`.

### Documentación

- **Instalación**: Actualizado README para aclarar que RedAudit tiene un mecanismo de actualización automática nativo vía asistente (`sudo redaudit`).
- **Compatibilidad**: Añadida guía específica para Ubuntu 24.04+ (Noble) sobre restricciones de pip.

## [4.5.16] - 2026-01-10

### Corregido

- **Smart Scan**: Preservar puertos descubiertos por HyperScan cuando nmap subreporta por problemas de timing/red.
- **SIEM Tags**: Etiqueta `deep-scanned` solo se agrega cuando deep scan fue realmente ejecutado.

## [4.5.15] - 2026-01-10

### Corregido

- **Smart Scan**: Corregida deteccion de Identidad Fantasma en `auditor_scan.py` (fix de v4.5.14 estaba en ruta de codigo incorrecta).
- **Auth SSH**: Cambiado `auth_ssh_trust_keys` por defecto a `True` para escaneo automatizado.

## [4.5.14] - 2026-01-10

### Fixed

- **Auth SSH**: Implementada `PermissivePolicy` robusta para evitar errores `Server not found in known_hosts` causados por checks estrictos o permisos de escritura.
- **Smart Scan**: Corregido problema de "Identidad Fantasma" donde hosts con pistas de Fase 0 (ej. SNMP) pero cero puertos abiertos no activaban Deep Scan.

## [4.5.13] - 2026-01-10

### Corregido

- **Crítico**: Resuelto `AttributeError: 'Host' object has no attribute 'get'` en la fase de Escaneo Autenticado. El escáner ahora maneja correctamente los objetos Host al acceder a la IP y almacenar resultados SSH.
- **Documentación**: Guías `LAB_SETUP` actualizadas con insignias de idioma y diferenciación clara entre Laboratorio (soporta Docker) y Máquina Auditora (recomienda Linux Nativo).

## [4.5.12] - 2026-01-10

### Corregido

- **Instalación Inteligente de Pip (Soporte PEP 668)**:
  - El instalador ahora detecta automáticamente fallos debidos a "entornos gestionados externamente" (común en Ubuntu 24.04 y Kali reciente) y reintenta la instalación con el flag `--break-system-packages` si es compatible. Esto asegura que dependencias como `pysnmp` e `impacket` se instalen correctamente incluso cuando faltan en los repositorios APT.

## [4.5.11] - 2026-01-10

### Corregido

- **Compatibilidad Universal del Instalador**:
  - La instalación de `python3-pysnmp` ahora es opcional/advertencia en el paso APT. Esto evita que el instalador aborte en distribuciones que eliminaron este paquete (ej: Ubuntu Noble 24.04).
  - Corregida una línea de instalación apt duplicada en `redaudit_install.sh`.

## [4.5.10] - 2026-01-10

### Mejorado

- **Robustez del Instalador**:
  - Añadido `python3-pysnmp` a dependencias APT (preferido sobre pip en sistemas Debian).
  - Eliminado `--quiet` de la instalación de pip para exponer errores si falla la instalación de paquetes.

## [4.5.9] - 2026-01-10

### Corregido

- **CI/Linting**: Suprimidas alertas de seguridad falsas positivas (Bandit) en `scripts/seed_keyring.py` por credenciales hardcodeadas de laboratorio.

## [4.5.8] - 2026-01-10

### Corregido

- **Soporte Keyring Root (Headless)**: Añadido soporte para `keyrings.alt` para gestionar credenciales como root sin sesión gráfica (común en servidores/Labs).
  - **Instalador**: Añadida dependencia `keyrings.alt`.
  - **Core**: `redaudit` y `seed_keyring.py` ahora usan `PlaintextKeyring` (basado en archivo) si el keyring del sistema no está disponible.

## [4.5.7] - 2026-01-10

### Corregido

- **Carga de Credenciales (Contexto Sudo)**: Corregido un problema donde las credenciales sembradas por un usuario normal no eran visibles para `sudo redaudit`.
  - **Updater**: El auto-seed ahora corre como root durante la actualizacion.
  - **Script Seeder**: Anadida advertencia si se ejecuta como no-root.
- **Estabilidad CI/Test**: Anadidos tests de integracion robustos para el flujo de carga de credenciales.

## [4.5.6] - 2026-01-10

### Anadido

- **Automatizacion del Laboratorio**: Anadido `scripts/setup_lab.sh` para automatizar el provisionamiento del lab Docker.
  - Comandos: `install`, `start`, `stop`, `remove`, `status`.
  - Provisiona 11 objetivos vulnerables.
- **Documentacion del Laboratorio**: Anadido `docs/LAB_SETUP.md` y `docs/LAB_SETUP_ES.md`.
  - Guia completa sobre como configurar el entorno de pruebas.
  - Enlazado desde el README principal.

## [4.5.5] - 2026-01-10

### Anadido

- **Script de Credenciales de Lab (Modo Spray)**: Anadido `scripts/seed_keyring.py` conteniendo TODAS las credenciales del laboratorio.
  - Pre-puebla el keyring con credenciales SSH (3), SMB (3) y SNMP (1).
  - Incluye referencia a credenciales web.

- **Updater Auto-Seed**: La actualizacion desde el asistente (Opcion 2) ahora ejecuta `seed_keyring.py` automaticamente si existe.
  - Asegura una configuracion de credenciales fluida tras la actualizacion.

## [4.5.4] - 2026-01-10

### Anadido

- **B5: Carga de Credenciales desde Keyring**: El asistente ahora detecta credenciales guardadas y ofrece cargarlas al inicio del escaneo.
  - Anadido `has_saved_credentials()` y `get_saved_credential_summary()` a `KeyringCredentialProvider`.
  - Anadido `_check_and_load_saved_credentials()` al flujo de autenticacion del asistente.
  - Elimina la necesidad de reintroducir credenciales en escaneos posteriores.

## [4.5.3] - 2026-01-10

### Añadido

- **Almacenamiento Seguro de Credenciales (Keyring)**: Paquete `keyring` ahora incluido como dependencia principal para almacenamiento seguro de credenciales vía keychain del SO (Linux Secret Service, macOS Keychain, Windows Credential Vault).
  - Añadido a dependencias principales e instalador (`python3-keyring` apt + pip).

### Corregido

- **Bugs de Auditoría de Escaneo (B2/B3/B4)**:
  - **B2**: Las barras de progreso de vulnerabilidades ahora siempre llegan al 100% (añadido bucle final en `auditor_vuln.py`).
  - **B3**: Tag INFO del heartbeat cambiado de `[grey50]` a `[cyan]` para visibilidad adecuada.
  - **B4**: La detección SSH en escaneos autenticados ahora maneja objetos `Host` (no solo dicts), corrigiendo falsos negativos "No se encontraron hosts con SSH".

## [4.5.2] - 2026-01-10

### Añadido

- **Soporte Multi-Credencial (Fase 4.1.1)**:
  - Añadido modo `Universal` en el asistente y soporte para flag `--credentials-file`.
  - Detección automática de protocolo (SSH/SMB/SNMP/RDP/WinRM).
  - Añadido `CredentialsManager` y generación de plantillas.
  - Fixes de "Auditoría Zero-Context": navegación segura y lógica unificada.

### Cambiado

- **Asistente**:
  - Refactorizado flujo de autenticación para modos `Universal` vs `Avanzado`.
  - Añadido soporte para "Volver" (`<`).
  - Añadidas pistas de UI para la estrategia de detección.

### Arreglado

- **Autenticación**: Corregida lógica legada en `auditor.py` que ignoraba la configuración del asistente.

## [4.5.0] - 2026-01-09

### Añadido

- **Escaneo Autenticado (SSH)**: Interrogación profunda de hosts Linux (Kernel, Paquetes, Uptime).
- **Escaneo Autenticado (SMB/WMI)**: Enumeración de Windows (SO, Dominio, Recursos compartidos, Usuarios) vía `impacket`.
- **Escaneo Autenticado (SNMP v3)**: Auditoría segura de dispositivos de red con protocolos Auth/Priv.
- **Integración con Lynis**: Ejecución remota de auditorías de hardening vía SSH.
- **Asistente Interactivo**: Nuevo Paso 8 para la configuración de Autenticación.
- **Integración con Keyring**: Almacenamiento seguro para credenciales de escaneo.

### Cambiado

- **Asistente (Wizard)**: Flujo de 9 pasos actualizado para acomodar opciones de autenticación.
- **Documentación**: Actualizaciones completas en las guías MANUAL y USAGE.

### Corregido

- **RecursionError**: en `AuditorRuntime.__getattr__`.
- **Tests**: Varias correcciones para iteradores Mock en pruebas del asistente.
- **Mypy**: Mejoras de seguridad de tipos en módulos de autenticación.

## [4.4.5] - 2026-01-09

### Mejorado

- **Push de Cobertura de Código**: Alcanzada cobertura del 100% en `topology.py` y >94% en `updater.py`, elevando la cobertura total del proyecto a ~89%.
  - Añadidos escenarios de test robustos para bucles de topología, crashes de red y excepciones de casos borde.
  - Refactorizados tests del updater con mocking dinámico para mayor estabilidad.
- **Estabilidad**: Resueltas intervenciones de hooks pre-commit e inconsistencias de formateo en archivos de test.

## [4.4.4] - 2026-01-09

### Mejorado

- **Push de Cobertura de Código**: Incrementada significativamente la cobertura de tests en módulos core (alcanzada ~90% de cobertura total).
  - Añadidos tests específicos para `siem.py` (desglose de riesgo, mapeo de severidad por herramienta, generación CEF).
  - Añadidos tests para `syn_scanner.py` (rutas de integración con scapy, fallos de sockets raw).
  - Añadidos tests para `reporter.py` (fallos en creación de archivos, verificación de resultados cifrados).
  - Añadidos tests para `auditor.py` e `hyperscan.py` (rutas de inicialización, lógica de conexión).

## [4.4.3] - 2026-01-08

### Añadido

- Script de paridad local `scripts/ci_local.sh` para ejecutar pre-commit y pytest en Python 3.9-3.12.

### Corregido

- El lock de desarrollo en Python 3.9 ahora selecciona versiones compatibles de iniconfig, pytest-asyncio, markdown-it-py, pycodestyle y pyflakes para evitar conflictos de resolución.
- El lock de runtime ahora selecciona una versión de markdown-it-py compatible con Python 3.9 al ejecutarse en 3.9.

### Cambiado

- Los tests de flujos completos de escaneo desactivan HyperScan-first para mantener el tiempo de ejecución acotado sin afectar el comportamiento en producción.

## [4.4.0] - 2026-01-08

### Añadido

- **Smart-Throttle (Control de Congestión Adaptativo)**: Nuevo algoritmo de limitación de velocidad basado en AIMD (`SmartThrottle`) en HyperScan. Ajusta dinámicamente el `batch_size` basándose en el feedback de timeouts de red, previniendo la pérdida de paquetes en redes congestionadas y acelerando en las estables.
- **Targeting basado en Generadores**: Refactorizado `HyperScan` para usar generadores perezosos en la expansión de objetivos. Esto permite escanear redes masivas (ej. subredes /16) sin picos de memoria de varios gigabytes.
- **Mejoras de Escalabilidad**: Optimizada la colección de hosts en `auditor_scan.py` para agilizar el procesamiento de grandes conjuntos de resultados.
- **Diseño de Arquitectura Distribuida**: Añadida documentación de diseño para el futuro modo de escaneo distribuido Controlador/Trabajador.
- **Investigación de Migración AsyncIO**: Completado estudio de viabilidad para migración completa a I/O no bloqueante (diferida a v5.0).

### Cambiado

- **HyperScan**: Ahora usa `itertools.product` para la generación de sondas.
- **UI**: La barra de progreso detallada en HyperScan ahora muestra el estado de regulación en tiempo real (▼/▲) y la velocidad efectiva.

## [4.3.3] - 2026-01-08

### Corregido

- **Integridad de Datos**: Los hallazgos de vulnerabilidades (Nikto, etc.) ahora se adjuntan correctamente a los objetos `Host` en memoria. Esto corrige el problema donde las vulnerabilidades faltaban en los informes JSON y los Risk Scores eran 0 a pesar de encontrar debilidades.
- **UI UX**: Corregido un glitch visual donde el mensaje de estado "heartbeat" ("Net Discovery en progreso...") duplicaba líneas de IP en el wizard. Ahora imprime de forma segura en la consola de progreso.

## [4.3.2] - 2026-01-08

### Corregido

- **Integridad del Lanzamiento**: Corregido desajuste de versión entre `pyproject.toml` y `VERSION` que causó fallos de CI en v4.3.1.
- **Mantenimiento**: Este lanzamiento reemplaza a v4.3.1 (que falló las autocomprobaciones de CI).

## [4.3.1] - 2026-01-08 [RETIRADO]

### Corregido

- **Regresiones de Tests CI**: Resueltos desajustes de mocks y alineación de arquitectura para tests de Wizard, Net Discovery y Smart Scan Spec V1.
  - Parcheado `_run_cmd_suppress_stderr` en tests de net discovery.
  - Actualizados tests de aceptación Deep Scan para reflejar arquitectura desacoplada v4.2.
  - Corregido `StopIteration` en tests interactivos del wizard ampliando inputs mockeados.

## [4.3.0] - 2026-01-07

### Añadido

- **Modo SYN de HyperScan**: Escaneo opcional de puertos basado en SYN usando scapy para ~10x más velocidad.
  - Nuevo flag CLI: `--hyperscan-mode auto|connect|syn`
  - Nuevo módulo: `redaudit/core/syn_scanner.py` con integración scapy
  - Modo auto: Intenta SYN si root + scapy disponibles, sino usa connect
  - Timing Stealth usa modo connect (más sigiloso que SYN)
  - Integración Wizard: Todos los perfiles (Express/Estándar/Exhaustivo/Personalizado) soportan selección de modo

- **Tooltip de Desglose de Risk Score**: Los informes HTML ahora muestran componentes detallados del risk score al pasar el ratón.
  - Componentes: CVSS Máximo, Puntuación Base, Bonus Densidad, Multiplicador Exposición
  - Nueva función: `calculate_risk_score_with_breakdown()` en `siem.py`

- **Visualización de Identity Score**: Los informes HTML muestran identity_score con código de colores.
  - Verde (≥3): Host bien identificado
  - Amarillo (=2): Parcialmente identificado
  - Rojo (<2): Identificación débil (disparó deep scan)
  - Tooltip muestra señales de identidad (hostname, vendor, mac, etc.)

- **Validación CPE de Smart-Check**: Detección mejorada de falsos positivos de Nuclei usando datos CPE.
  - Nuevas funciones: `parse_cpe_components()`, `validate_cpe_against_template()`, `extract_host_cpes()`
  - Valida hallazgos contra CPEs del host antes de comprobaciones de cabeceras HTTP

- **Gestión de PCAP**: Nuevas utilidades para organización de archivos PCAP.
  - `merge_pcap_files()`: Consolida archivos de captura usando mergecap
  - `organize_pcap_files()`: Mueve capturas raw a subdirectorio
  - `finalize_pcap_artifacts()`: Orquesta limpieza post-escaneo

- **Optimización Docker/Deep Scan (H2)**:
  - **Nikto**: Timeouts extendidos (5m) y limitación de tuning eliminada para mayor profundidad.
  - **Nuclei**: Incluidos hallazgos de severidad "low" (ej: fugas de información) en los resultados.

### Cambiado

- **Algoritmo de Risk Score (V2)**: Refactorizado para integrar plenamente la severidad de los hallazgos en la puntuación final. Hosts con fallos de configuración críticos ahora reflejan Riesgo Alto/Crítico incluso sin CVEs.
- **Supresión de Advertencias**: Silenciadas advertencias ruidosas de ARP/Scapy durante el descubrimiento L2.
- **Plantillas HTML**: Ambas plantillas EN y ES actualizadas con nuevas columnas y tooltips.

### Documentación

- Actualizadas descripciones de perfiles del wizard con selección de modo HyperScan.
- Añadidas traducciones i18n (EN/ES) para opciones de modo HyperScan.

## [4.2.1] - 2026-01-06

### Corregido

- **Documentación**: Corregido un error de formato en la lista "Vista General de Arquitectura" en `README.md` y `README_ES.md`.

## [4.2.0] - 2026-01-06

### Añadido

- **Escaneo Profundo Paralelo**: Fase de Escaneo Profundo desacoplada con concurrencia total (hasta 50 hilos) y UI multi-barra.
- **Escaneo de Apps Web**: Integración de `sqlmap` (detección SQLi) y `OWASP ZAP` (spidering) en la fase de vulnerabilidades.
- **Progreso Multi-barra**: Barras de progreso visuales paralelas para tareas de Escaneo Profundo.
- **i18n**: Traducciones completas al español para mensajes de estado de HyperScan y Escaneo Profundo.

### Cambiado

- **Pulido de UI**: Emojis de verificación estandarizados a ✅ en toda la CLI.
- **Configuración Deep Scan**: Eliminados límites artificiales de hilos; ahora respeta la configuración global `--threads`.

### Corregido

- **Hosts Duplicados**: Implementada sanitización agresiva de IPs (limpieza ANSI) en `Auditor` para prevenir duplicados "fantasma".
- **Glitches de Progreso**: Corregido problema donde HyperScan secuencial reportaba conteos de tareas incorrectos.

## [4.1.0] - 2026-01-06

### Añadido

- **Pre-escaneo HyperScan-First Secuencial**: Nuevo método `_run_hyperscan_prescan()` ejecuta descubrimiento completo de puertos (65,535) secuencialmente en todos los hosts *antes* del fingerprinting paralelo con nmap. Esto elimina el agotamiento de descriptores de archivo y permite `batch_size=2000` para escaneos más rápidos.
- **Reuso de Puertos Masscan**: Cuando masscan ya ha descubierto puertos para un host, HyperScan-First los reutiliza en lugar de re-escanear.
- **Lookup Online de Fabricante OUI**: Cuando arp-scan/netdiscover locales devuelven "Unknown", RedAudit ahora recurre a la API de macvendors.com para enriquecimiento de fabricante MAC.
- **Integración Básica de sqlmap**: Añadido `run_sqlmap()` al escaneo de vulnerabilidades para detección automática de inyección SQL en objetivos web. Ejecuta en modo batch con crawl de formularios y escaneo inteligente.
- **Auto-detección de sqlmap**: Añadido sqlmap a `TOOL_CONFIGS` para detección automática de versión e informe.

### Cambiado

- **Optimización de Comandos Nmap**: Eliminadas flags redundantes `-sV -sC` cuando se usa `-A` (ya que `-A` las incluye). Aplicado tanto a `auditor_scan.py` como a `nmap.py`.
- **Herramientas de Vuln en Paralelo**: Aumentados los workers de `ThreadPoolExecutor` de 3 a 4 para acomodar sqlmap junto a testssl, whatweb y nikto.

### Corregido

- **Bug de Recursión Infinita**: Corregido `hasattr(self, "_hyperscan_prescan_ports")` causando recursión infinita debido a `__getattr__` personalizado en clases Auditor. Cambiado a `"_hyperscan_prescan_ports" in self.__dict__`.

### Documentación

- **Roadmap v4.2**: Añadidas características planificadas: Escaneo de Vulns de Apps Web (sqlmap/ZAP completo), separación de Deep Scan, paso de datos Red Team → Agentless, mejoras UX del Wizard, limpieza de nombres HyperScan, mejora del log de sesión.

### Instalador

- **sqlmap**: Añadido a `EXTRA_PKGS` en `redaudit_install.sh` para instalación automática.

## [4.0.4] - 2026-01-05

### Corregido

- **Crítico: Integración de Puertos HyperScan**: Cuando HyperScan detecta puertos abiertos durante net_discovery pero el escaneo inicial de nmap no encuentra ninguno (debido al umbral de identidad), ahora forzamos un escaneo profundo. Esto corrige la brecha de detección de Metasploitable2 donde 10+ puertos fueron detectados por HyperScan pero ignorados.
- **Brecha en Detección de Vulnerabilidades**: Hosts con huellas HTTP ahora activan correctamente el escaneo de vulnerabilidades web.
- **Detección Web Basada en Puertos**: Añadida constante `WEB_LIKELY_PORTS` para puertos web comunes (3000, 8080, etc.).
- **Selección de Hosts para Escaneo de Vulns**: `scan_vulnerabilities_concurrent()` ahora incluye hosts con `agentless_fingerprint.http_title` o `http_server`.
- **Precisión del Resumen Agentless**: `_summarize_agentless()` ahora cuenta señales HTTP correctamente.
- **Prioridad de Títulos Descriptivos**: Los problemas SSL/TLS ahora tienen prioridad sobre fugas menores (ETag inode).
- **Regresión Visual de CLI**: Cambiado de markup Rich a objetos `rich.text.Text` para colores fiables.
- **Visualización de Barra de Progreso**: Ahora muestra la IP limpia en lugar de `Host(ip='...')`.
- **Spinner Restaurado**: Re-añadido `SpinnerColumn` para retroalimentación visual durante escaneos largos.
- **Sincronización de Estado UIManager**: Añadido `progress_active_callback` para colores consistentes en todos los code paths.

### Cambiado

- **Lógica de Escaneo Profundo**: Usa puertos HyperScan como señal (`hyperscan_ports_detected`). También fuerza `web_count` cuando HyperScan encuentra puertos web (80, 443, 3000, 8080, etc.).
- **Fallback HyperScan**: Cuando nmap hace timeout (returncode 124) o encuentra 0 puertos, ahora poblamos la lista de puertos desde datos de HyperScan con flag `hyperscan_fallback_used`.
- **Colores Rich**: Actualizado a variantes `bright_*` para mejor visibilidad en temas oscuros de terminal.

## [4.0.3] - 2026-01-05

### Añadido

- **Proxy routing**: El proxy ahora envuelve herramientas externas vía proxychains (nmap, probes
  agentless, enrichment, herramientas de vulnerabilidades, nuclei) para pivots TCP connect.
- **Ciclo de vida del proxy**: Estado de sesión y limpieza de configuraciones temporales de proxychains.

### Cambios

- **CommandRunner**: Soporte de wrapper de comandos para enrutamiento por proxy.
- **CLI**: `--proxy` valida proxychains y aclara el comportamiento solo TCP.

### Corregido

- **Soporte de Proxy**: `--proxy` ahora se aplica a flujos de scan/vuln/enrichment en lugar de
  ignorarse silenciosamente.

### Documentación

- **Alcance del proxy**: Aclarado requisito de proxychains y limitaciones TCP en docs EN/ES.

### Tests

- **Cobertura**: Añadidas pruebas de wiring del wrapper de proxy y gating de proxychains en CLI.

## [4.0.2] - 2026-01-05

### Cambios

- **Tests**: Reorganización de la suite en `tests/core`, `tests/cli`, `tests/utils`,
  `tests/integration` para mejorar la navegación.
- **Cobertura**: Añadidas pruebas significativas para componentes de auditoría,
  vulnerabilidades, asistente (wizard) e HyperScan.
- **Documentación**: Ajustadas las directrices de merge y CI en `AGENTS.md`.

### Corregido

- **Terminal Size**: Evitado el parcheo global de `shutil.get_terminal_size` que rompía
  `pytest` en CI.

## [4.0.1] - 2026-01-04

### Cambios

- **Arquitectura**: El auditor principal ahora delega el comportamiento de componentes vía
  `redaudit/core/auditor_runtime.py`, manteniendo la orquestación por composición.
- **Pruebas**: Endurecidas las pruebas de error de importación de OUI para evitar solicitudes
  externas y advertencias por desfase de tiempo.
- **Documentación**: Alineada la redacción del refactor de composición en roadmap y notas.

### Eliminado

- **Tests**: Eliminado `tests/test_entity_resolver_extra.py` (filler de cobertura).

## [4.0.0] - 2026-01-04

### Añadido

- **Modelos de Datos**: Nuevas dataclasses `Host`, `Service`, `Vulnerability` en `redaudit/core/models.py`.
- **Composición**: Clase `NetworkScanner` reemplazando a `AuditorScan`.
- **Arquitectura**: Migración completa a pipeline basado en objetos en `auditor_scan.py` y `reporter.py`.

### Cambiado

- **Refactorización**: Lógica de escaneo heredada basada en herencia reemplazada por escáner compuesto.
- **Informes**: `reporter.py` actualizado para serializar objetos `Host` para informes JSON/HTML.
- **Testing**: Limpieza mayor de la suite de pruebas, asegurando verificación lógica (48/48 pruebas core pasando).

### Eliminado

- Tests de "relleno de cobertura" heredados.
- Lógica de herencia obsoleta relacionada con manejo de diccionarios ad-hoc.

## [3.10.2] - 2026-01-04 (Nodo Auditor y Corrección de MAC)

### Añadido

- **Detección de Nodo Auditor**: Las interfaces de red propias del escáner ahora se marcan como `(Nodo Auditor)` en los informes HTML en lugar de `-` en la columna MAC.
- **Fundamentos de Arquitectura (Interno)**: Trabajo preparatorio para arquitectura modular v4.0:
  - Clase `UIManager` independiente para operaciones de UI
  - `ConfigurationContext` envoltorio tipado para configuración
  - `NetworkScanner` con utilidades de puntuación de identidad
  - Propiedades adaptador para compatibilidad hacia atrás

### Corregido

- **Visualización de MAC**: Corregido bug donde las direcciones MAC no aparecían en los informes HTML a pesar de capturarse correctamente. Causa raíz: discrepancia de clave (`host.get("mac")` vs `host.get("mac_address")`).

### Documentación

- Documentación de heurística de detección VPN por vendor OUI
- Wording de Subnet Leak actualizado a "Indicios de Fuga de Red"
- Añadidas flags CLI faltantes a las tablas README

## [3.10.1] - 2026-01-02 (Consistencia de Identidad y Hints de Vendor)

### Añadido

- **Vendor Hints**: Nuevo mecanismo de respaldo (`vendor_hints.py`) para inferir el fabricante del dispositivo desde patrones de hostname (ej: Pixel, Galaxy, iPhone) cuando el lookup OUI no está disponible.

### Corregido

- **Enriquecimiento Neighbor Cache**: Las direcciones MAC descubiertas vía neighbor cache pasivo (ARP/NDP) ahora disparan un lookup OUI online.
- **Consistencia de Hostname**: Consolidación de búsquedas DNS reversas de Fase 0 (bajo impacto) en el registro de host canónico, asegurando visualización consistente en todos los informes (HTML/TXT) y lógica de resolución de entidades.
- **Flujo de Datos**: Corregidas brechas donde datos de enriquecimiento de bajo impacto no se propagaban completamente a los consumidores posteriores.

## [3.10.0] - 2026-01-01 (Gobernanza SmartScan y Fase 0)

### Added

- **Enriquecimiento Fase 0 de bajo impacto (opt-in)**: Sondas opcionales y de timeout corto para reverse DNS, mDNS y SNMP sysDescr para reforzar señales de identidad.
- **Controles de gobernanza SmartScan**: Umbral de identidad y presupuesto de deep scan para mantener el escalado conservador por defecto.
- **Asistente con Fase 0**: Flujos Express, Standard, Exhaustive y Personalizado permiten activar el enriquecimiento de bajo impacto con defaults persistentes.

### Changed

- **Gating de escalado SmartScan**: El deep scan solo se dispara cuando la identidad es débil frente al umbral configurado.
- **Reordenación prioritaria UDP**: Solo aplica en hosts con poca visibilidad TCP e identidad muy débil; nunca en modo stealth.

### Fixed

- **Presupuesto de deep scan bajo concurrencia**: Reserva thread-safe para evitar ejecuciones por encima del presupuesto.
- **Fallback de DNS en Fase 0**: Evita efectos globales de timeout cuando `dig` no está disponible.
- **Localización del help CLI**: Los nuevos flags muestran ayuda según el idioma seleccionado.

## [3.9.9] - 2025-12-29 (Fix de heurística de impresoras)

### Corregido

- **Detección de impresoras por hostname**: Los tokens de impresora ahora tienen prioridad sobre marcas de workstation.

## [3.9.8] - 2025-12-29 (Ajuste de identidad de descubrimiento)

### Corregido

- **Normalización de sufijos**: El tipado de activos no depende de sufijos DNS locales (ej. `.fritz.box`).
- **Samsung**: Por defecto clasifica como media salvo señales móviles explícitas.
- **Vendors de router**: Sercomm/Sagemcom se mapean como router/CPE.

### Mejorado

- **Hints HTTP/agentless**: Los hints de tipo de dispositivo (router/repeater/access point) influyen en el tipado.
- **Android cast**: Hosts con señales cast/SSDP se clasifican como media.
- **Workstation hints**: Hostnames MSI/Dell/Lenovo/HP/Asus/Acer sobrescriben la heurística de RDP server.
- **Fingerprint de repetidor**: Patrón FRITZ!Repeater añadido para detectar routers.

## [3.9.7] - 2025-12-29 (Hotfix de calidad de auditoría)

### Corregido

- **Falsos positivos de Nuclei**: Los sospechosos se filtran antes de consolidar hallazgos, con conteo expuesto en el resumen de Nuclei.
- **Conteo de vulns web**: Summary/manifest ahora exponen conteo raw vs consolidado para evitar desajustes entre CLI y informes.
- **Títulos JSONL**: Añadido `descriptive_title` en findings.jsonl para mejor visualización downstream.

### Mejorado

- **Banner dinámico de SO**: El banner del CLI refleja el SO detectado con fallback seguro a `LINUX`.

## [3.9.6] - 2025-12-28 (Detección VPN)

- **Detección de Interfaces VPN**: Nueva heurística para clasificar interfaces de gateway VPN:
  - Misma MAC que gateway + IP diferente = IP virtual VPN
  - Puertos de servicio VPN (500, 4500, 1194, 51820) = endpoint IPSec/OpenVPN/WireGuard
  - Patrones de hostname (vpn, ipsec, wireguard, tunnel) = dispositivo VPN
  - Nuevo tipo de asset `vpn` con tag SIEM `vpn-endpoint`

## [3.9.5a] - 2025-12-28 (Instalador y Herramientas)

### Añadido

- **Instalador: Herramientas de Análisis Web**: Añadidos `whatweb`, `nikto` y `traceroute` a la lista de paquetes apt para análisis de vulnerabilidades web completo out-of-the-box.

### Corregido

- **Instalador: fiabilidad de testssl.sh**: Eliminada la verificación estricta de hash de commit que causaba fallos de instalación. Ahora usa el tag de versión `v3.2` con fallback automático a latest HEAD si el tag no está disponible.
- **CI: test_fping_sweep_logic**: Corregido el mock target para simular correctamente la no disponibilidad de `fping` en el runner de GitHub Actions (ahora mockea `shutil.which` + `_run_cmd` en vez de `CommandRunner`).
- **Badge de Cobertura**: Reemplazado el badge dinámico de Gist roto con badge estático de 84% de cobertura.

## [3.9.5] - 2025-12-28 (Pack de Firmas IoT + Hotfix NVD)

### Añadido

- **Pack de Firmas IoT**: Payloads UDP específicos por protocolo para detección de dispositivos smart home:
  - **Bombillas WiZ** (puerto 38899): Payload JSON método registration
  - **Yeelight** (puertos 1982, 55443): Payload comando discovery
  - **Tuya/SmartLife** (puertos 6666, 6667): Sondas específicas de protocolo
  - **CoAP/Matter** (puerto 5683): Payload GET .well-known/core
- **Fallback de Hostname por DNS Reverso**: Los informes HTML ahora muestran hostnames de dispositivos IoT desde DNS reverso cuando el hostname estándar está vacío

### Fixed

- **Nombres de Producto NVD**: Se relajó la expresión regular de sanitización en la búsqueda de CVEs para preservar puntos en nombres de productos (ej: `node.js` ya no se convierte en `nodejs`), corrigiendo la generación de CPE para múltiples frameworks.

## [3.9.4] - 2025-12-28 (Hotfix de parseo en Net Discovery)

### Fixed

- **Pistas de dominio DHCP**: El parseo de Domain Name/Domain Search ahora tolera prefijos de Nmap (`|`, `|_`, indentacion) y captura dominios internos de forma fiable.
- **Nombres NetBIOS**: El parseo de nbstat en Nmap ahora recorta puntuacion final para evitar ruido en inventario (ej: `SERVER01,`).

## [3.9.3] - 2025-12-27 (Hotfix de consolidacion de informes)

### Fixed

- **Consolidacion de hallazgos con TestSSL**: los merges preservan `testssl_analysis` y observaciones para no perder alertas TLS.
- **Títulos HTML con fallback**: cuando no hay `descriptive_title`, el HTML genera un título útil (ej: `Web Service Finding on Port 443`) en vez de la URL.

## [3.9.2] - 2025-12-27 (Hotfix de Version)

### Fixed

- **Deteccion de version en instalacion script**: Acepta sufijos con letra como `3.9.1a` en `redaudit/VERSION` para evitar `0.0.0-dev` tras auto-update.

## [3.9.1a] - 2025-12-27 (Hotfix de Informes)

### Fixed

- **Títulos en informes HTML ES**: El regex ahora localiza correctamente títulos de hallazgos comunes en `report_es.html`.
- **Metadatos en summary.json**: Se añadieron `scan_mode_cli`, `options` compacto y alias `severity_counts` para dashboards.

## [3.9.0] - 2025-12-27 (Selector de Perfiles y Informes Mejorados)

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

- **Informe HTML Mejorado** (para auditores profesionales):
  - **Hallazgos Expandibles**: Click en cualquier hallazgo para ver observaciones técnicas (`parsed_observations`)
  - **Sección Smart Scan Analysis**: Muestra exactamente por qué se dispararon los deep scans (ej: `suspicious_service`, `many_ports`)
  - **Sección Playbooks de Remediación**: Grid visual de playbooks generados con IPs objetivo
  - **Sección Evidencia Capturada**: Lista todos los archivos PCAP capturados
  - **Resumen de Topología**: Gateway por defecto, conteo de interfaces, conteo de rutas
  - Plantillas EN y ES actualizadas

- **Filtrado de Logs de Sesión**: Reducción de ruido más inteligente que preserva mensajes de estado mientras filtra actualizaciones de spinner.

### Corregido

- **Timing de nmap no aplicado**: La configuración `nmap_timing` no se pasaba a `get_nmap_arguments()`, por lo que Sigiloso/Normal/Agresivo no tenía efecto en la ejecución real de nmap.
- **Playbooks no aparecían en informe HTML**: Los playbooks se generaban DESPUÉS del informe HTML, resultando en una sección vacía. Ahora se generan antes.

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

## [3.8.7] - 2025-12-23 (Correcciones de informes y clasificación)

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

- Manuales y esquema de informes actualizados para incluir las pistas del probe HTTP.

## [3.8.4] - 2025-12-21 (Verificación sin Agente y Corrección de Colores)

### Añadido

- **Verificación sin agente**: Etapa opcional de fingerprinting SMB/RDP/LDAP/SSH/HTTP (wizard o `--agentless-verify`), con límite configurable de objetivos.
- **Flags CLI**: `--agentless-verify`, `--no-agentless-verify` y `--agentless-verify-max-targets`.

### Corregido

- **Colores de estado durante progreso**: Corregido el problema donde los mensajes `[INFO]` aparecían sin color cuando la barra de progreso Rich estaba activa. Ahora usa Rich console.print con markup adecuado (`bright_blue` para INFO, `green` para OK, `yellow` para WARN, `red` para FAIL) asegurando colores consistentes en todo momento.

## [3.8.3] - 2025-12-21 (Wizard y UX de informes)

### Añadido

- **Identidad del auditor**: Prompt en el wizard para el nombre del auditor, reflejado en informes TXT/HTML.
- **HTML bilingüe**: Cuando el idioma es ES, se genera `report_es.html` junto al HTML principal.

### Corregido

- **Duplicación en wizard**: Eliminada la repetición en las opciones del escaneo de vulnerabilidades.
- **Colores de detalle**: Los estados INFO/WARN/FAIL respetan colores mientras el progreso está activo.
- **Progreso Net Discovery**: Evita el 100% fijo durante fases largas antes de finalizar el último paso.

### Cambiado

- **Footer HTML**: Se neutraliza el footer (licencia + GitHub) sin crédito personal del autor.

## [3.8.2] - 2025-12-20 (Pulido UX)

### Añadido

- **Watermark HTML**: Footer profesional en informes HTML con licencia GPLv3, autor (Dorin Badea) y enlace a GitHub.

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

## [3.7.3] - 2025-12-20 (Confiabilidad del escaneo y precisión de informes)

### Corregido

- **Parsing XML de Nmap**: Se conserva el XML completo y se extrae el bloque `<nmaprun>` para evitar errores de parseo
  que ocultaban identidades de hosts.
- **Timeout por modo**: Si no se define `--host-timeout`, el fallback respeta el modo de escaneo (completo = 300s) para
  evitar cortes prematuros.
- **Fallback de identidad por topología**: Si Nmap falla, se usa MAC/vendor de topología/vecinos para mantener la
  identidad del host en los informes.
- **Conteo de informes**: "Hosts Descubiertos" ahora deduplica objetivos para reflejar el conjunto único real.

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
- **Pipeline SIEM Nativo**: Incluye `siem/filebeat.yml`, `siem/logstash.conf` y 3 reglas Sigma para integración ELK y otros SIEM.
- **Verificación Osquery**: Nuevo módulo `redaudit/core/osquery.py` para validación de configuración de hosts post-scan vía SSH.
- **Logging de Sesión**: Salida de terminal capturada automáticamente a carpeta `session_logs/` (`.log` raw + `.txt` limpio).
- **Spinner de Progreso Nuclei**: Spinner animado Rich con tiempo transcurrido durante escaneos de templates Nuclei.

### Corregido

- **CI CodeQL**: Bajada de `codeql-action` a v3 por compatibilidad.

### Cambiado

- **Configuración webhook**: Ahora se persiste en `~/.redaudit/config.json` junto con otros defaults.

## [3.6.1] - 2025-12-18 (Calidad de Escaneo y UX)

### Añadido

- **Consolidación de hallazgos**: Los hallazgos duplicados en el mismo host (ej: "X-Frame-Options faltante" en 5 puertos) ahora se fusionan en uno con array `affected_ports`.
- **Fallback OUI online**: Nuevo módulo `redaudit/utils/oui_lookup.py` para consulta de vendor MAC vía macvendors.com cuando la base local está incompleta.
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

- **Enlaces Rotos**: Corregido `pyproject.toml` que apuntaba a `docs/MANUAL.md` inexistente.
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

- **Directorio de salida por defecto (sudo)**: Los informes ahora se guardan por defecto en la carpeta Documentos del usuario que invoca `sudo` (en lugar de `/root`).
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

- **Dashboard HTML Interactivo** (`--html-report`): Genera informes HTML standalone con Bootstrap + Chart.js.
  - Tema oscuro con estética premium
  - Gráfico donut de distribución de severidad y gráfico de barras Top 10 puertos
  - Tablas ordenables de hosts y hallazgos
  - Colores de risk score (verde/naranja/rojo)
  - Columnas de MAC y vendor en tabla de hosts
  - Autocontenido: funciona offline, sin dependencias externas en runtime

- **Informe Visual de Diff HTML** (`--diff`): Compara dos escaneos con salida visual lado a lado.
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

- **reporter.py**: Ahora genera informe HTML automáticamente cuando se usa el flag `--html-report`.
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
- **Sincronización JSON hidden_networks**: Las IPs de redes filtradas ahora correctamente populan `hidden_networks` y `leaked_networks_cidr` en JSON para pipelines SIEM/AI (antes solo aparecía en el informe de texto).

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

- **Descubrimiento de Red Mejorado (v3.2)**: Nuevo bloque `net_discovery` en informes con descubrimiento DHCP/NetBIOS/mDNS/UPNP/ARP/fping y análisis de VLANs candidatas (`--net-discovery`).
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
- **Constante de versión de schema**: Nueva constante `SCHEMA_VERSION` separada de `VERSION` para versionado de schema de informes

### Cambiado

- **Timeout de TestSSL**: Por defecto aumentado de 60s a 90s, ahora configurable vía parámetro `timeout`
- **Rutas PCAP**: Los informes usan rutas relativas (`pcap_file`) para portabilidad, con `pcap_file_abs` para uso interno
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
- **Esquema de Informe**: Añadido bloque opcional `topology` en el informe raíz (cuando está activado)

## [3.1.0] - 2025-12-14 (SIEM y pipelines de IA)

### Añadido

- **Vistas de exportación JSONL**: Archivos planos auto-generados para ingesta SIEM/IA (cuando el cifrado de informes está desactivado)
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
  - Añadido al informe como objeto `scanner_versions`

### Cambiado

- **Versión de esquema**: Actualizada de 2.0 a 3.1
- **Metadatos de informe**: Añadido timestamp `generated_at`
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

- **Visibilidad de PCAP**: El resumen final incluye un contador de PCAP; los informes TXT incluyen la ruta del PCAP cuando se captura.
- **Claridad del TXT**: Secciones de deep scan incluyen conteos de comandos (identity-only vs deep scan ejecutado).
- **Reporting CVE (TXT)**: Cuando hay enriquecimiento CVE, los informes TXT incluyen resúmenes de CVE y conteos por puerto.

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

- **Análisis diferencial**: Comparar informes de escaneo
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
  - Campos alineados con ECS v8.11 para Elastic
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
  - Todos los outputs (informes + PCAPs) consolidados en un solo directorio
  - Corrige el problema donde PCAPs se guardaban en el directorio padre

- **Optimización de tamaño PCAP**: Reduce captura de ilimitada a 200 paquetes
  - PCAPs ahora ~50-150KB en vez de varios MB
  - Suficiente para análisis de protocolo sin exceso de almacenamiento
  - tcpdump se detiene automáticamente tras 200 paquetes

- **Directorio de salida por defecto**: Cambia de `~/RedAuditReports` a `~/Documents/RedAuditReports`
  - Informes guardados por defecto en Documents del usuario
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

- **Carpetas de informes con timestamp (Fase 6)**: Estructura organizada
  - Informes guardados en subcarpetas: `RedAudit_YYYY-MM-DD_HH-MM-SS/`
  - Cada sesión tiene su propio directorio
  - PCAPs y informes organizados juntos

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
  - Crea subcarpetas con timestamp para informes

---

## [2.7.0] - 2025-12-09 (Velocidad e integración)

### Añadido

- **Motor de pre-scan Asyncio (A1)**: Descubrimiento rápido usando asyncio TCP connect
  - Nuevo módulo: `redaudit/core/prescan.py`
  - Flags CLI: `--prescan`, `--prescan-ports`, `--prescan-timeout`
  - Hasta 500 checks concurrentes con batching configurable
  - Parsing de rangos: `1-1024`, `22,80,443`, o combinado `1-100,443,8080-8090`

- **Salida compatible con SIEM (A5)**: Informes JSON mejorados para Elastic y otros SIEM
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
  - Resultados visibles en informes JSON y TXT
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
  - Informes TXT muestran exploits conocidos por servicio
  - Informes TXT muestran hallazgos de vulnerabilidad de TestSSL
  - Informes JSON incluyen automáticamente todos los campos nuevos

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
  - `redaudit/core/reporter.py` - Generación de informes
  - `redaudit/core/scanner.py` - Lógica de escaneo
  - `redaudit/utils/constants.py` - Constantes con nombre
  - `redaudit/utils/i18n.py` - Internacionalización
- **Pipeline CI/CD**: Workflow de GitHub Actions (`.github/workflows/tests.yml`)
  - Tests en Python 3.9, 3.10, 3.11, 3.12
  - Integración con Codecov para coverage
  - Linting con Flake8

- **Nuevas suites de tests**:
  - `tests/test_network.py` - Tests de detección de red con mocking
  - `tests/test_reporter.py` - Tests de generación de informes y permisos de fichero
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

- **Seguridad de permisos de ficheros**: Informes usan permisos seguros (0o600 - lectura/escritura solo para owner)
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
- **Permisos de ficheros**: Todos los informes generados usan permisos seguros (0o600)
- **Manejo de errores**: Mejor manejo de excepciones reduce filtración de información

## [2.4.0] - 2025-12-07 (Adaptive Deep Scan)

### Añadido

- **Adaptive Deep Scan (v2.5)**: Implementa estrategia 2 fases (TCP agresivo -> fallback UDP+OS) para maximizar velocidad y datos.
- **Detección vendor/MAC**: Regex nativo para extraer vendor HW desde output de Nmap.
- **Instalador**: Refactor de `redaudit_install.sh` a operaciones de copia limpias sin Python embebido.

### Cambiado

- **Heartbeat**: Mensajería más profesional ("Nmap is still running") para reducir ansiedad durante escaneos largos.
- **Reporting**: Añade campos `vendor` y `mac_address` en informes JSON/TXT.
- **Versión**: Actualizada a 2.4.0

## [2.3.1] - 2024-05-20 (Hardening de seguridad)

### Añadido

- **Hardening de seguridad**: Sanitización estricta de inputs (IPs, hostnames, interfaces) para prevenir command injection.
- **Cifrado de informes**: Cifrado AES-128 opcional (Fernet) para informes generados; incluye helper `redaudit_decrypt.py`.
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

- **Gestión de dependencias**: Se deja de usar `pip`. Dependencias vía `apt` (python3-nmap, etc.) alineado con Kali/Debian.
- **Networking**: Reemplaza `netifaces` (a menudo ausente) por parsing robusto de `ip addr show` o `ifconfig`.
- **Arquitectura**: `redaudit_install.sh` ahora despliega el core Python directamente, eliminando descargas de `.py` separado.

### Corregido

- **Tracebacks**: Añade `try/except` extensivos para evitar crashes ante errores de escaneo.
- **Permisos**: Añade chequeo de `root` (sudo) al inicio.
