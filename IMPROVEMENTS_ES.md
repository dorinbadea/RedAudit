# Roadmap y Propuestas Arquitectónicas

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](IMPROVEMENTS.md)

Este documento describe el roadmap técnico, las mejoras arquitectónicas planificadas y los enfoques descartados para RedAudit.

## Roadmap Inmediato (v2.7+)

| Prioridad | Característica | Descripción |
| :--- | :--- | :--- |
| **Alta** | **Integración CVE** | Integrar búsqueda de base de datos CVE local (vía NVD/Vulners) para correlacionar hallazgos NSE con IDs de CVE. |
| **Alta** | **Soporte IPv6** | Implementar soporte completo `nmap -6` y validación regex IPv6 en el módulo InputSanitizer. |
| **Media** | **Análisis Diferencial** | Crear módulo `diff` para comparar dos reportes JSON y resaltar deltas (nuevos puertos/vulns). |
| **Media** | **Proxy Chains** | Soporte nativo para proxies SOCKS5 para facilitar pivoting. |
| **Baja** | **Contenedorización** | Dockerfile oficial y configuración Docker Compose para contenedores de auditoría efímeros. |

## Propuestas Arquitectónicas

### 1. Motor de Plugins Modular

**Estado**: En Consideración
**Concepto**: Desacoplar el escáner principal de las herramientas. Permitir "Plugins" basados en Python para definir nuevos wrappers de herramientas (ej: escáneres IoT específicos) sin modificar la lógica central.
**Beneficio**: Facilita contribución de la comunidad y extensibilidad.

### 2. Escaneo Distribuido (Master/Slave)

**Estado**: Largo plazo
**Concepto**: Separar el Orquestador de los workers de verificación.

- API Central (Master) distribuye objetivos.
- Agentes Remotos (Slaves) ejecutan escaneos y devuelven JSON.

## Conceptos Descartados

### 1. GUI Web (Flask/Django)

**Razón**: Incrementa superficie de ataque y peso de dependencias. RedAudit apunta a servidores sin interfaz gráfica y flujos CLI.
Alternativa: Usar salida JSON para alimentar Dashboards externos (ej: ELK Stack).

### 2. Explotación Activa

**Razón**: Fuera de alcance. RedAudit es una herramienta de *auditoría* y *descubrimiento*, no un framework de explotación (como Metasploit).
**Política**: La herramienta permanecerá estrictamente de solo lectura/no destructiva.

```bash
tests/
├── test_input_validation.py  # Tests de sanitización (Existente)
├── test_encryption.py        # Tests de cifrado/descifrado (Existente)
├── test_network_discovery.py # Mocking de interfaces
└── test_scan_modes.py        # Mocking de Nmap
```

> **Acción**: Crear `.github/workflows/tests.yml` para ejecutar estos tests en cada PR.

### 2. Configuración Persistente

Eliminar valores hardcoded y permitir configuración de usuario en `~/.redaudit/config.yaml`.

```yaml
default:
  threads: 6
  rate_limit: 0
  output_dir: ~/RedAuditReports
  encrypt_by_default: false
  language: es
```

### 3. Nuevos Formatos de Exportación

- 📄 **PDF**: Reportes ejecutivos con gráficos de topología.

- 📊 **CSV**: Para importación en Excel/Pandas.
- 🌐 **HTML**: Reportes interactivos con tablas y búsqueda.

### 4. Integración de CVEs

Enriquecer los resultados consultando bases de datos de vulnerabilidades.

```python
if service_version:
    cves = query_cve_database(service, version)
    host['potential_vulnerabilities'] = cves
```

### 5. Comparación de Auditorías (Diffing)

Detectar cambios entre dos escaneos para identificar desviaciones.

```bash
redaudit --compare scan_ayer.json scan_hoy.json
# [!] Nuevo puerto detectado: 3306/tcp en 192.168.1.50
```

---

## 🚀 Roadmap Estratégico

### v2.6 (Completado - Diciembre 2026)

*Enfoque en calidad de código, testing y modularización.*

- [x] **Arquitectura Modular**: Refactorizado en estructura de paquete Python
- [x] **Pipeline CI/CD**: GitHub Actions para testing automatizado (Python 3.9-3.12)
- [x] **Suite de Tests**: Expandido a 34 tests automatizados
- [x] **Constantes Nombradas**: Todos los números mágicos reemplazados
- [x] **Compatibilidad hacia atrás**: `redaudit.py` original preservado como wrapper

### v2.7 (Corto Plazo: Usabilidad de Datos)

### v3.0 (Mediano Plazo: Expansión)

*Enfoque en integración y visualización.*

- [ ] **Dashboard Web**: Servidor ligero (Flask/FastAPI) para visualizar reportes históricos.
- [ ] **Base de Datos**: Integración opcional con SQLite para historial de escaneos.
- [ ] **Docker**: Contenedorización oficial de la herramienta.
- [ ] **API REST**: Exponer el motor de escaneo vía API para integraciones de terceros.

**Estimado**: Q2-Q3 2026

### v4.0 (Largo Plazo: Inteligencia)

*Enfoque en análisis avanzado y gran escala.*

- [ ] **Machine Learning**: Detección de anomalías en patrones de tráfico.
- [ ] **Modo Distribuido**: Orquestación de múltiples nodos de scanning.
- [ ] **Integración SIEM**: Conectores nativos para Splunk, ELK, Wazuh.

**Estimado**: 2026+

---

## Conceptos Descartados

Propuestas que evalué pero no implementaré:

| Propuesta | Razón del Descarte |
| :--- | :--- |
| **Soporte Nativo Windows** | Demasiado complejo de mantener en solitario. Usar WSL2/Docker. |
| **GUI (GTK/Qt)** | RedAudit es una herramienta de automatización CLI. Fuera de alcance. |

---

## Contribuir

Si deseas contribuir a alguna de estas features:

1. Revisa los [Issues](https://github.com/dorinbadea/RedAudit/issues) existentes.
2. Comenta antes de empezar para evitar duplicación.
3. Lee [CONTRIBUTING.md](https://github.com/dorinbadea/RedAudit/blob/main/CONTRIBUTING.md).
4. Abre una [Discusión](https://github.com/dorinbadea/RedAudit/discussions) para nuevas ideas.

**Especialmente busco ayuda en:**

- Tests unitarios (ideal para empezar).
- Traducción a otros idiomas.
- Documentación y ejemplos de uso.

---

<div align="center">

**Mantenimiento Activo**  
*Última actualización: Diciembre 2026*

<sub>Si este documento no se actualiza en >6 meses, el proyecto puede estar pausado. En ese caso, considera hacer un fork o contactarme.</sub>

</div>
