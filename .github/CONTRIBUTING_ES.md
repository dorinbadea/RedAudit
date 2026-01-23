# Guía de Contribución

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](CONTRIBUTING.md)

## Bienvenido

¡Gracias por considerar contribuir a RedAudit! Este documento describe el proceso de desarrollo y los estándares para contribuir.

## Configuración del Entorno de Desarrollo

### Flujo de Trabajo de Ingeniería (Recomendado)

Para un timeline limpio y releases consistentes, ver `AGENTS.md` (ramas, agrupación de commits, hooks pre-commit, CI y checklist de release).

### Prerrequisitos

- **SO**: Kali Linux, Debian 11+, Ubuntu 20.04+, o Parrot OS
- **Python**: 3.9 o superior
- **Git**: Última versión estable
- **Herramientas**: nmap, tcpdump, curl, wget (ver `redaudit_install.sh` para lista completa)

### Primeros Pasos

1. **Fork y Clone**

   ```bash
   git clone https://github.com/TU_USUARIO/RedAudit.git
   cd RedAudit
   ```

2. **Crear Entorno Virtual** (Opcional pero recomendado)

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Instalar Dependencias**

   ```bash
   # Dependencias principales
   pip3 install -r requirements.txt

   # Dependencias de desarrollo (opcional)
   pip3 install -e ".[dev]"
   ```

4. **Instalar Dependencias del Sistema**

   ```bash
   sudo bash redaudit_install.sh
   ```

5. **Verificar Instalación**

   ```bash
   bash redaudit_verify.sh
   ```

### Ejecutar Tests

```bash
# Ejecutar todos los tests
pytest tests/ -v

# Ejecutar archivo de test específico
pytest tests/test_network.py -v

# Ejecutar con cobertura
pytest tests/ --cov=redaudit --cov-report=term-missing
```

### Verificaciones de Calidad de Código

```bash
# Formatear código
black redaudit/ tests/

# Linting
flake8 redaudit/ tests/ --max-line-length=100

# Verificaciones de seguridad
bandit -r redaudit/
```

---

## Estándares de Código

### Python

- **Formato**: Compatible con PEP 8 (límite de 100 caracteres por línea)
- **Type Hinting**: Las firmas de funciones deben incluir type hints
- **Seguridad**: No usar `shell=True` en subprocess. Sanitizar toda entrada de usuario
- **Concurrencia**: Las operaciones de I/O de red deben ser thread-safe
- **Documentación**: Docstrings para todas las funciones y clases públicas

### Estructura del Paquete

El código está organizado como un paquete Python:

- `redaudit/core/`: Funcionalidad principal (auditor, scanner, net_discovery, crypto, reporter, network, nvd, diff, proxy)
- `redaudit/utils/`: Utilidades (constants, i18n, config, paths)
- `tests/`: Suites de tests con pytest

### Requisitos de Testing

- **Cobertura**: Las nuevas features deben incluir tests
- **Validación Local**: Ejecuta `pytest tests/` antes de enviar PRs
- **Script de Verificación**: Ejecuta `bash redaudit_verify.sh` para comprobaciones de entorno
- **CI/CD**: GitHub Actions ejecuta tests automáticamente en PRs (Python 3.9-3.12)

---

## Proceso de Pull Request

### 1. Estrategia de Branching

- Crea ramas de feature desde `main`
- Convención de nombres:
  - `feature/descripcion-corta` (nuevas features)
  - `fix/numero-issue` o `fix/descripcion-breve` (corrección de bugs)
  - `docs/tema` (actualizaciones de documentación)
  - `refactor/componente` (refactorización de código)

### 2. Mensajes de Commit

Usa mensajes de commit semánticos:

```
feat: añadir soporte de escaneo IPv6
fix: corregir validación de tamaño del thread pool
docs: actualizar MANUAL.es.md con opciones v3.0
refactor: modularizar scanner.py
test: añadir unit tests para módulo diff
chore: actualizar dependencias
```

### 3. Directrices de Pull Request

- **Título**: Resumen claro y descriptivo
- **Descripción**:
  - ¿Qué cambios se hicieron?
  - ¿Por qué se hicieron?
  - ¿Cómo se probaron?
- **Documentación**: Actualizar README.md y docs/ para cambios arquitectónicos
- **Tests**: Incluir cobertura de tests para nueva funcionalidad
- **Commits**: Mantener commits atómicos y bien descritos

### 4. Proceso de Revisión

- Todos los PRs requieren al menos una revisión
- CI/CD debe pasar (tests, linting, comprobaciones de seguridad)
- Responder al feedback de revisores prontamente
- Hacer squash de commits antes del merge (si se solicita)

---

## Reportar Issues

### Bug Reports

Incluir:

- **Pasos para reproducir**
- **Comportamiento esperado vs actual**
- **Entorno**: Versión de SO, versión de Python, versión de RedAudit
- **Logs**: Logs sanitizados de `~/.redaudit/logs/` (¡eliminar datos sensibles!)
- **Capturas de pantalla**: Si aplica

### Solicitudes de Features

Incluir:

- **Caso de uso**: ¿Qué problema resuelve?
- **Solución propuesta**: ¿Cómo debería funcionar?
- **Alternativas consideradas**: Otros enfoques que hayas pensado

### Issues de Seguridad

**¡No reportar vulnerabilidades de seguridad via issues públicos!**

Email: `dorinidtech@gmail.com`

Ver [SECURITY.md](../docs/SECURITY.es.md) para nuestra política de divulgación de vulnerabilidades.

---

## Estilo de Código

### Convenciones Python

- **Imports**: Agrupar stdlib, third-party, locales por separado
- **Naming**: `snake_case` para funciones/variables, `PascalCase` para clases
- **Comentarios**: Usar `#` para comentarios inline, docstrings para funciones
- **Longitud de línea**: Máximo 100 caracteres

### Scripts de Shell

- **Compatibilidad**: Compatible con POSIX o claramente específico de Bash (usar `#!/usr/bin/env bash`)
- **Manejo de errores**: Verificar códigos de salida, usar `set -e` cuando sea apropiado
- **Quoting**: Siempre entrecomillar variables: `"${VAR}"`

---

## Documentación

### Cuándo Actualizar Docs

- **Nuevas features**: Actualizar README.md, USAGE.md, MANUAL.en/es.md
- **Cambios en CLI**: Actualizar texto de --help y toda la documentación
- **Cambios en API**: Actualizar REPORT_SCHEMA.md si cambia la estructura JSON
- **Breaking changes**: Actualizar CHANGELOG.md y guía de migración

### Estilo de Documentación

- **Claro y conciso**
- **Ejemplos**: Incluir ejemplos prácticos
- **Bilingüe**: Actualizar versiones EN y ES cuando sea posible

---

## Licencia

Al contribuir a RedAudit, aceptas que tus contribuciones serán licenciadas bajo la **GNU General Public License v3.0 (GPLv3)**.

Ver [LICENSE](../LICENSE) para detalles.

---

## ¿Preguntas?

- **Issues**: Usa [GitHub Issues](https://github.com/dorinbadea/RedAudit/issues) para bugs/features
- **Contacto**: Ver README.md para información de contacto

¡Gracias por contribuir a RedAudit!
