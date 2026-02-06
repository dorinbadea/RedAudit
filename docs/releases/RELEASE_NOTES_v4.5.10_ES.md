# Notas de la Version v4.5.10

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.5.10/docs/releases/RELEASE_NOTES_v4.5.10.md)

**Fecha de lanzamiento:** 2026-01-10

## Resumen

Esta versión mejora la robustez del script de instalación, abordando específicamente los errores de `PySNMP missing` en sistemas Debian/Kali modernos donde `pip install` puede estar restringido o ser poco fiable para paquetes del sistema.

## Mejorado

- **Instalador (`redaudit_install.sh`)**:
  - **Nueva Dependencia**: Añadido `python3-pysnmp` a la lista de paquetes APT. Esta es la forma preferida de instalar la librería en sistemas basados en Debian, evitando posibles regresiones de pip.
  - **Pip Verboso**: Eliminado el flag `--quiet` del comando `pip install`. Si pip falla al instalar paquetes auxiliares, el error será claramente visible en la consola en lugar de ser suprimido.

## Verificación

Si experimentaste problemas con credenciales SNMP o ves "[WARN] PySNMP missing", ejecuta:

```bash
git pull
sudo bash redaudit_install.sh
```

Deberías ver `python3-pysnmp` instalándose vía apt, o mensajes de error claros de pip si algo más falla.
