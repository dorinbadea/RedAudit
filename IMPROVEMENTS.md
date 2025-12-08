# Mejoras y Roadmap de RedAudit

> **📌 Nota Importante**: Este roadmap es una guía de desarrollo, no un 
> compromiso contractual. Las prioridades pueden cambiar según feedback 
> de la comunidad, hallazgos de seguridad o recursos disponibles.
> 
> **Última actualización**: Diciembre 2025  
> **Estado**: Mantenimiento Activo

---

## 🎯 Estado Actual y Puntos Fuertes (v2.5)

**1. Arquitectura Profesional**
- Diseño modular con manejo robusto de concurrencia (`ThreadPoolExecutor`).
- Sistema de heartbeat para monitorizar scans largos.
- Reportes duales (JSON + TXT) con timestamps.

**2. Seguridad Implementada**
- ✅ Encriptación AES-128 (Fernet) con PBKDF2-HMAC-SHA256 (480k iteraciones).
- ✅ Sanitización de inputs estricta (tipo, longitud, regex).
- ✅ Permisos seguros de archivos (0o600).
- ✅ Sin inyección de comandos (`subprocess.run` seguro).

**3. Experiencia de Usuario**
- Modos Interactivo y No-Interactivo (CLI completo).
- Instalador automatizado y gestión de dependencias.
- Soporte Multi-idioma (EN/ES).
- Rate limiting configurable para evasión/sigilo.

## 💡 Sugerencias de Mejora Detalladas

### 1. Testing & CI/CD
Establecer una suite de pruebas robusta y pipelines de integración continua.
```bash
tests/
├── test_input_validation.py  # Tests de sanitización (Existente)
├── test_encryption.py        # Tests de cifrado/descifrado (Existente)
├── test_network_discovery.py # Mocking de interfaces
└── test_scan_modes.py        # Mocking de Nmap
```
- **Acción**: Crear `.github/workflows/tests.yml` para ejecutar estos tests en cada PR.

### 2. Configuración Persistente
Eliminar valores hardcoded y permitir configuración de usuario.
- **Archivo**: `~/.redaudit/config.yaml`
```yaml
default:
  threads: 6
  rate_limit: 0
  output_dir: ~/RedAuditReports
  encrypt_by_default: false
  language: es
```

### 3. Nuevos Formatos de Exportación
- **PDF**: Reportes ejecutivos con gráficos de topología.
- **CSV**: Para importación en Excel/Pandas.
- **HTML**: Reportes interactivos con tablas y búsqueda.

### 4. Integración de CVEs
Enriquecer los resultados de versiones de servicios encontradas consultando bases de datos de vulnerabilidades.
```python
if service_version:
    cves = query_cve_database(service, version)
    host['potential_vulnerabilities'] = cves
```

### 5. Comparación de Auditorías (Diffing)
Detectar cambios entre dos escaneos para identificar desviaciones (nuevos puertos, servicios caídos).
```bash
redaudit --compare scan_ayer.json scan_hoy.json
# Salida: "[!] Nuevo puerto detectado: 3306/tcp en 192.168.1.50"
```

---

## 🚀 Roadmap Estratégico

### v2.6 (Corto Plazo: Consolidación)
Enfoque en calidad de código, testing y usabilidad de datos.
- [ ] **Suite de Tests**: Implementar tests unitarios y de integración faltantes.
- [ ] **Exportación**: Soporte para salida CSV y HTML básico.
- [ ] **Multilenguaje**: Facilitar la adición de más idiomas (refactorizar strings).
- [ ] **Comparación**: Implementar funcionalidad básica de `diff` entre reportes JSON.

**Fecha estimada**: Q1 2025

### v3.0 (Medio Plazo: Expansión)
Enfoque en integración y visualización.
- [ ] **Dashboard Web**: Servidor ligero (Flask/FastAPI) para visualizar reportes históricos.
- [ ] **Base de Datos**: Integración opcional con SQLite para historial de scans.
- [ ] **Docker**: Containerización oficial de la herramienta.
- [ ] **API REST**: Exponer el motor de escaneo vía API para integraciones de terceros.

**Fecha estimada**: Q2-Q3 2025

### v4.0 (Largo Plazo: Inteligencia)
Enfoque en análisis avanzado y gran escala.
- [ ] **Machine Learning**: Detección de anomalías en patrones de tráfico.
- [ ] **Modo Distribuido**: Orquestación de múltiples nodos de scanning.
- [ ] **Integración SIEM**: Conectores nativos para Splunk, ELK, Wazuh.

**Fecha estimada**: 2026+

---

## 🗑️ Ideas Descartadas

Propuestas que evaluamos pero no implementaremos:

- ❌ **Soporte Windows nativo**: Mejor usar WSL2/Docker
  - *Razón*: Complejidad de mantener dos codebases
- ❌ **GUI gráfica (GTK/Qt)**: Fuera del scope del proyecto
  - *Razón*: RedAudit se enfoca en automatización CLI/API

---

## 🤝 ¿Quieres Participar?

Si deseas contribuir a alguna de estas features:

1. 🔍 Revisa si ya existe un [Issue relacionado](https://github.com/dorinbadea/RedAudit/issues)
2. 💬 Comenta tu interés antes de empezar (evita duplicar trabajo)
3. 📖 Lee [CONTRIBUTING.md](https://github.com/dorinbadea/RedAudit/blob/main/CONTRIBUTING.md) para guidelines
4. 🐛 Para bugs o propuestas nuevas, abre un [Discussion](https://github.com/dorinbadea/RedAudit/discussions)

**Especialmente buscamos ayuda en:**
- Tests unitarios (ideal para empezar a contribuir)
- Traducción a otros idiomas
- Documentación y ejemplos de uso

---

## ⏸️ Estado del Proyecto

**Mantenimiento Activo** (última actualización: Diciembre 2025)

Si este documento no se actualiza en >6 meses, el proyecto puede estar pausado. 
En ese caso, considera hacer un fork o contactar al maintainer.
