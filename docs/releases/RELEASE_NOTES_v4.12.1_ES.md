# Notas de Versión v4.12.1

## Resumen

Esta versión parche se centra en la **optimización de rendimiento de Nuclei**, asegurando datos de topología consistentes mediante **enriquecimiento OUI**, y clarificando los perfiles de escaneo en el Asistente. También mejora la seguridad de tipos y corrige problemas de precedencia de parámetros.

## Cambios Detallados

### Optimización de Rendimiento

* **Perfil Nuclei Fast**: Optimizado el perfil `fast` para un rendimiento significativamente mayor.
  * **Rate Limit**: Incrementado de 150 a **300 peticiones/segundo**.
  * **Batch Size**: Incrementado de 10 a **15 plantillas/lote**.
  * Estos cambios reducen la duración del escaneo para grandes conjuntos de CVEs sin comprometer la estabilidad.

### Calidad de Datos

* **Enriquecimiento de Topología**: La fase de topología (`arp-scan`) ahora realiza automáticamente búsquedas OUI para fabricantes reportados como "(Unknown)". Esto asegura una identificación de fabricantes consistente en todos los módulos.

### Experiencia de Usuario

* **Claridad del Asistente**: Actualizadas las descripciones de perfiles para distinguir claramente entre modos de solo descubrimiento y modos con escaneo de vulnerabilidades.
  * **Express**: Marcado explícitamente como "Solo discovery, sin escaneo de vulns (~10 min)".
  * **Estándar**: Marcado explícitamente como "Discovery + escaneo de vulnerabilidades (~30 min)".

### Corrección de Errores

* **Precedencia de Parámetros**: Corregido un problema donde los parámetros explícitos de Nuclei (flags CLI o overrides internos) eran ignorados en favor de los valores por defecto del perfil. Los valores explícitos ahora tienen prioridad correctamente.
* **Seguridad de Tipos**: Resueltos errores de tipo `mypy` en el módulo Nuclei implementando estructuras `TypedDict` adecuadas para la configuración de perfiles.
