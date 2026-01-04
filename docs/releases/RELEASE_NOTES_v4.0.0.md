# RedAudit v4.0.0 Release Notes

## [EN] Major Architecture Overhaul: Composition & Data Models

**RedAudit v4.0.0** marks the most significant architectural evolution in the project's history. This release completes the transition from a mixin-based monolith to a modern, composition-based architecture powered by robust data models. This shift guarantees type safety, eliminates entire classes of dictionary-key bugs, and provides a solid foundation for future extensibility without breaking changes.

### 🚀 Key Features & Changes

#### 1. Strong Data Models

- **`Host` Dataclass**: Replaced ad-hoc dictionaries with a formal `Host` object. This single source of truth now governs IP, MAC, Vendor, OS, Ports, and Vulnerabilities throughout the pipeline.
- **Type Safety**: New `Service` and `Vulnerability` dataclasses ensure consistent data handling from scanning to reporting.

#### 2. Architectural Composition

- **Mixin Retirement**: The legacy `AuditorScanMixin` and other mixins have been refactored into a composed `NetworkScanner` and other modular components.
- **Cleaner Core**: The main loop in `auditor.py` is now a clean orchestrator that passes `Host` objects between specialized components.

#### 3. Stability & Quality

- **Sanitized Test Suite**: Removed hundreds of lines of "filler" tests. The test suite (including `test_auditor_core.py`) is now lean, meaningful, and verifies real logic errors and edge cases.
- **Robust Reporting**: The reporting engine (`reporter.py`) has been fully adapted to serialize `Host` objects, ensuring 100% backward compatibility with existing JSON/HTML report templates.

### 🛠 Fixes & Improvements

- **Agentless Verification**: Updated targeting logic to natively understand `Host` objects, improving reliability of post-scan probes.
- **Deep Scan**: Integrated deep scan metadata directly into the `Host` model, simplifying how OS and Identity data is merged.
- **Exception Handling**: Standardized error handling in `scan_host_ports` ensures that even if a scan tool fails, the host object is preserved with a clear error status, preventing pipeline crashes.

---

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
