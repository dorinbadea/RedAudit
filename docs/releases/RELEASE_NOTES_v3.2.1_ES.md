# RedAudit v3.2.1 - Notas de la Versión

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](RELEASE_NOTES_v3.2.1.md)

**Fecha de Lanzamiento**: 15 de Diciembre de 2025
**Enfoque**: UX Profesional CLI, Menú Principal y Pulido de Interacción

---

## Resumen General

La versión 3.2.1 es un lanzamiento centrado en pulir significativamente la experiencia de usuario (UX), introduciendo un nuevo **Menú Principal Interactivo** como punto de entrada por defecto, simplificando el flujo de **Descubrimiento de Topología**, y resolviendo artefactos visuales en entornos no interactivos (CI/pipeline). También expande la internacionalización (i18n) para cubrir todas las cadenas CLI hardcodeadas restantes.

---

## Novedades en v3.2.1

### 1. Menú Principal Interactivo

El CLI ahora presenta un menú principal profesional cuando se ejecuta sin argumentos, sirviendo como hub central para todas las operaciones:

- **[1] Iniciar Auditoría (Wizard)**: Lanza el asistente de configuración estándar.
- **[2] Buscar Actualizaciones**: Comprueba manualmente nuevas versiones.
- **[3] Diff Informes (JSON)**: Nueva interfaz para comparar dos informes de escaneo anteriores.
- **[0] Salir**: Salida limpia.

### 2. Flujo de Topología Simplificado

El prompt de topología de múltiples pasos anterior se ha consolidado en una elección única y clara:

- **Opción 1**: Desactivado (escaneo estándar)
- **Opción 2**: Activado (escaneo + descubrimiento de topología)
- **Opción 3**: Solo Topología (saltar escaneo de hosts/puertos, enfocar en descubrimiento L2/L3)

### 3. Soporte Non-TTY / Pipelines CI

- Corregidos artefactos de código de color (`[OKGREEN]`, etc.) que aparecían en logs cuando la salida se redirigía a un archivo o sistema CI.
- La salida ahora detecta automáticamente entornos no-TTY y elimina códigos de color, reemplazándolos por etiquetas de texto neutras (ej: `[OK]`).

### 4. Valores por Defecto Consolidados ("Valores Base")

- Renombrado "Factory Values" a "Base Values" (Valores Base) para mayor claridad.
- Simplificado el flujo al final del wizard, reduciendo confirmaciones redundantes a un máximo de dos prompts (¿Guardar Defaults? -> ¿Iniciar Auditoría?).

### 5. Internacionalización (i18n)

- Añadidas más de 60 nuevas claves de traducción para cubrir cadenas en Inglés previamente hardcodeadas (errores de proxy, validación de objetivos, mensajes de generación de contraseñas aleatorias).
- Soporte completo en Inglés (EN) y Español (ES) para todos los nuevos menús e interfaces del wizard.

### 6. Mejoras del Instalador

- **Detección de Fugas**: Nuevo análisis heurístico para encontrar fugas de IPs privadas en cabeceras HTTP.
- **UI Mejorada**: Prompts interactivos más limpios con separadores coloreados.
- **Nuevas Herramientas**: Soporte nativo para instalar `kerbrute` (binario GitHub) y `proxychains4` (proxy SOCKS5).

### 7. Detección de Fugas de Subred (Análisis de Invitados)

Un nuevo módulo de post-procesamiento detecta automáticamente **Redes Ocultas Potenciales** (como VLANs de Invitados o subredes de Gestión) analizando "fugas" en servicios HTTP:

- **Análisis de Redirecciones**: Investiga cabeceras `Location` que apuntan a IPs privadas fuera del rango de escaneo.
- **Análisis de Contenido**: Revisa `Content-Security-Policy` y mensajes de error.
- **Informe**: Marca automáticamente estos hallazgos como "Potential Hidden Networks" en el informe final, facilitando el pivoting profesional.

---

## Notas de Actualización

- **Sin Cambios que Rompen Compatibilidad (Breaking Changes)**: Esta actualización se centra en la capa interactiva. Los scripts de automatización existentes que usan flags (ej: `redaudit --target ... --yes`) no se ven afectados.
- **Actualización de Configuración**: Los archivos de configuración incluirán automáticamente un nuevo campo de rastreo `topology_only`.

---

## Pruebas

```bash
# Menú Interactivo
redaudit

# Escaneo con flujo simplificado
redaudit --target 192.168.1.0/24

# Verificar salida limpia en modo no-interactivo
redaudit --target 192.168.1.1 --yes > clean_output.log
```
