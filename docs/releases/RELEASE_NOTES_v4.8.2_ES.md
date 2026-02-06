# Notas de Lanzamiento v4.8.2

**Fecha de Lanzamiento:** 16-01-2026
**Tipo:** Hotfix

## Correcciones Críticas

### Regresión en Rango de Puertos RustScan

- **Problema**: En v4.8.0/v4.8.1, la integración de RustScan utilizaba por defecto el escaneo de los top 1000 puertos. Esto causó una regresión comparado con la implementación anterior de Masscan que escaneaba los 65.535 puertos.
- **Solución**: Se han actualizado `rustscan.py` y `hyperscan.py` para forzar explícitamente el escaneo del rango completo (`1-65535`) durante la fase HyperScan.
- **Impacto**: El descubrimiento de red ahora identificará correctamente servicios en puertos altos no estándar (ej: 8182, 8189, 55063), comunes en routers y dispositivos IoT.

## Actualización

```bash
git pull
./redaudit_install.sh  # Ejecutar de nuevo para verificar dependencias
```
