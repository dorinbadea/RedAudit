# RedAudit v4.0.0 Notas de Lanzamiento

## [ES] Reingeniería Mayor: Composición y Modelos de Datos

**RedAudit v4.0.0** marca la evolución arquitectónica más significativa en la historia del proyecto. Esta versión completa la transición de un monolito basado en mixins a una arquitectura moderna basada en composición y modelos de datos robustos. Este cambio garantiza seguridad de tipos, elimina clases enteras de errores por claves de diccionario y proporciona una base sólida para futuras extensiones sin cambios disruptivos.

### 🚀 Características Clave y Cambios

#### 1. Modelos de Datos Fuertes

- **Dataclass `Host`**: Reemplazo de diccionarios ad-hoc por un objeto formal `Host`. Esta única fuente de verdad ahora gobierna IP, MAC, Vendor, SO, Puertos y Vulnerabilidades a través de todo el flujo.
- **Seguridad de Tipos**: Nuevas dataclasses `Service` y `Vulnerability` aseguran un manejo de datos consistente desde el escaneo hasta el reporte.

#### 2. Composición Arquitectónica

- **Retiro de Mixins**: El antiguo `AuditorScanMixin` y otros mixins han sido refactorizados en un `NetworkScanner` compuesto y otros componentes modulares.
- **Núcleo Más Limpio**: El bucle principal en `auditor.py` es ahora un orquestador limpio que pasa objetos `Host` entre componentes especializados.

#### 3. Estabilidad y Calidad

- **Suite de Tests Saneada**: Se eliminaron cientos de líneas de tests "de relleno". La suite de pruebas (incluyendo `test_auditor_core.py`) es ahora ágil, significativa y verifica errores lógicos reales y casos borde.
- **Reportes Robustos**: El motor de reportes (`reporter.py`) ha sido totalmente adaptado para serializar objetos `Host`, asegurando 100% de compatibilidad hacia atrás con las plantillas de reporte JSON/HTML existentes.

### 🛠 Correcciones y Mejoras

- **Verificación Sin Agentes**: Lógica de selección actualizada para entender nativamente objetos `Host`, mejorando la fiabilidad de las pruebas post-escaneo.
- **Escaneo Profundo (Deep Scan)**: Metadatos de escaneo profundo integrados directamente en el modelo `Host`, simplificando la fusión de datos de SO e Identidad.
- **Manejo de Excepciones**: Estandarización del manejo de errores en `scan_host_ports` para asegurar que, incluso si una herramienta falla, el objeto host se preserve con un estado de error claro, evitando caídas del pipeline.
