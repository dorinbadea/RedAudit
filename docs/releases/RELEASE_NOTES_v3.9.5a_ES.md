# RedAudit v3.9.5a — Instalador y Herramientas

[![View in English](https://img.shields.io/badge/English-blue?style=flat-square)](RELEASE_NOTES_v3.9.5a.md)

**Fecha de Lanzamiento**: 2025-12-28

## Puntos Destacados

Esta versión asegura que las herramientas de análisis de vulnerabilidades web estén disponibles de forma inmediata tras la instalación, corrigiendo problemas de fiabilidad con la instalación de `testssl.sh`.

## Añadido

### Instalador: Herramientas de Análisis Web

Se añadieron `whatweb`, `nikto` y `traceroute` a la lista de paquetes apt en `redaudit_install.sh`:

```bash
EXTRA_PKGS="... whatweb nikto traceroute"
```

Estas herramientas permiten un análisis más profundo de vulnerabilidades web en el modo de escaneo **completo**:

- **whatweb**: Fingerprinting de tecnologías web
- **nikto**: Escáner de vulnerabilidades de servidor web
- **traceroute**: Análisis de rutas de red para descubrimiento de topología

## Corregido

### Instalador: Fiabilidad de testssl.sh

**Problema**: El instalador anterior usaba verificación estricta de hash de commit para `testssl.sh` que fallaba si la estructura de tags del repositorio upstream cambiaba.

**Solución**: Se eliminó la verificación estricta de commit. Ahora usa el tag de versión `v3.2` con fallback automático a latest HEAD si el tag no está disponible:

```bash
# Intenta el tag de versión primero, fallback a latest
if git clone --depth 1 --branch "$TESTSSL_VERSION" "$TESTSSL_REPO" /opt/testssl.sh; then
    echo "[OK] Cloned testssl.sh $TESTSSL_VERSION"
elif git clone --depth 1 "$TESTSSL_REPO" /opt/testssl.sh; then
    echo "[OK] Cloned testssl.sh (latest)"
fi
```

### CI: test_fping_sweep_logic

Se corrigió el target del mock en `tests/test_net_discovery_features.py` para simular correctamente la no disponibilidad de `fping` en el runner de GitHub Actions. Ahora mockea tanto `shutil.which` como `_run_cmd` en vez de `CommandRunner`.

### Badge de Cobertura

Se reemplazó el badge dinámico de Gist roto con un badge estático de 84% de cobertura en los archivos README.

## Instrucciones de Actualización

```bash
# Para instalaciones nuevas
curl -sL https://raw.githubusercontent.com/dorinbadea/RedAudit/v3.9.5a/redaudit_install.sh | sudo bash

# Para instalaciones existentes, re-ejecutar el instalador para obtener las nuevas herramientas
sudo redaudit_install.sh
```

Después de la instalación, verificar que las herramientas se detectan:

```bash
redaudit --version
# No debe mostrar warnings sobre herramientas faltantes
```

---

**Changelog Completo**: [CHANGELOG_ES.md](../../ES/CHANGELOG_ES.md)
