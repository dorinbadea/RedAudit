# Roadmap & Architecture Proposals

This document outlines the technical roadmap, planned architectural improvements, and discarded approaches for RedAudit.

## Immediate Roadmap (v2.6+)

| Priority | Feature | Description |
| :--- | :--- | :--- |
| **High** | **CVE Integration** | Integrate local CVE database lookup (via NVD/Vulners) to correlate NSE findings with CVE IDs. |
| **High** | **IPv6 Support** | Implement full `nmap -6` support and IPv6 regex validation in the InputSanitizer module. |
| **Medium** | **Differential Analysis** | Create a `diff` module to compare two JSON reports and highlight delta (new ports/vulns). |
| **Medium** | **Proxy Chains** | Native support for SOCKS5 proxies to facilitate pivoting. |
| **Low** | **Containerization** | Official Dockerfile and Docker Compose setup for ephemeral audit containers. |

## Architectural Proposals

### 1. Modular Plugin Engine
**Status**: Under Consideration
**Concept**: Decouple the core scanner from tools. Allow Python-based "Plugins" to define new tool wrappers (e.g., specific IoT scanners) without modifying core logic.
**Benefit**: easier community contribution and extensibility.

### 2. Distributed Scanning (Master/Slave)
**Status**: Long-term
**Concept**: Separate the Orchestrator from verify workers.
- Central API (Master) distributes targets.
- Remote Agents (Slaves) execute scans and return JSON.

## Discarded Concepts

### 1. Web GUI (Flask/Django)
**Reason**: Increases attack surface and dependency weight. RedAudit targets headless servers and CLI workflows.
Alternative: Use JSON output to feed external Dashboards (e.g., ELK Stack).

### 2. Active Exploitation
**Reason**: Out of scope. RedAudit is an *auditing* and *discovery* tool, not an exploitation framework (like Metasploit).
**Policy**: The tool will remain strictly read-only/non-destructive.

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
*   📄 **PDF**: Reportes ejecutivos con gráficos de topología.
*   📊 **CSV**: Para importación en Excel/Pandas.
*   🌐 **HTML**: Reportes interactivos con tablas y búsqueda.

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

### v2.6 (Short Term: Consolidation)
*Focus on code quality, testing, and data usability.*

- [ ] **Test Suite**: Implement missing unit and integration tests.
- [ ] **Export**: Support for CSV and basic HTML output.
- [ ] **Multi-language**: Facilitate adding more languages (refactor strings).
- [ ] **Comparison**: Implement basic `diff` functionality between JSON reports.

**Estimate**: Q1 2026

### v3.0 (Mid Term: Expansion)
*Focus on integration and visualization.*

- [ ] **Web Dashboard**: Lightweight server (Flask/FastAPI) to visualize historical reports.
- [ ] **Database**: Optional integration with SQLite for scan history.
- [ ] **Docker**: Official tool containerization.
- [ ] **API REST**: Exponer el motor de escaneo vía API para integraciones de terceros.

**Estimado**: Q2-Q3 2026

### v4.0 (Largo Plazo: Inteligencia)
*Enfoque en análisis avanzado y gran escala.*

- [ ] **Machine Learning**: Detección de anomalías en patrones de tráfico.
- [ ] **Modo Distribuido**: Orquestación de múltiples nodos de scanning.
- [ ] **Integración SIEM**: Conectores nativos para Splunk, ELK, Wazuh.

**Estimado**: 2026+

---

## Discarded Concepts

Propuestas que evalué pero no implementaré:

| Propuesta | Razón del Descarte |
| :--- | :--- |
| **Native Windows Support** | Too complex to maintain solo. Use WSL2/Docker. |
| **GUI (GTK/Qt)** | RedAudit is a CLI automation tool. Out of scope. |

---

## Contributing

Si deseas contribuir a alguna de estas features:

1.  Check existing [Issues](https://github.com/dorinbadea/RedAudit/issues).
2.  Comment before starting to avoid duplication.
3.  Read [CONTRIBUTING.md](https://github.com/dorinbadea/RedAudit/blob/main/CONTRIBUTING.md).
4.  Open a [Discussion](https://github.com/dorinbadea/RedAudit/discussions) for new ideas.

**Especialmente busco ayuda en:**
*   Tests unitarios (ideal para empezar).
*   Traducción a otros idiomas.
*   Documentación y ejemplos de uso.

---

<div align="center">

**Mantenimiento Activo**  
*Última actualización: Diciembre 2026*

<sub>Si este documento no se actualiza en >6 meses, el proyecto puede estar pausado. En ese caso, considera hacer un fork o contactarme.</sub>

</div>

