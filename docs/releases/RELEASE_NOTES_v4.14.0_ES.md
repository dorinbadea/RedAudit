[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.14.0/docs/releases/RELEASE_NOTES_v4.14.0.md)

# RedAudit v4.14.0 - UX de Consumo y Correcciones de Calidad

Este lanzamiento se centra en ofrecer una experiencia de usuario de nivel consumidor con interacciones del asistente mejoradas, menús visualmente distintos y una guía de remediación significativamente más robusta para diversos tipos de dispositivos.

## Resumen

- **Remediación Consciente del Dispositivo**: Los playbooks inteligentes ahora distinguen entre dispositivos embebidos (AVM FRITZ!), equipos de red y servidores Linux, proporcionando instrucciones de corrección adaptadas (ej. actualizaciones de firmware vs. gestores de paquetes).
- **Falsos Positivos Reducidos**: Lógica de coincidencia refinada para vulnerabilidades CVSS críticas (CVE-2024-54767) para apuntar a modelos de hardware específicos (FRITZ!Box 7530 vs 7590).
- **Pulido UX**: El asistente interactivo ahora presenta un esquema de colores profesional y flujos de credenciales más inteligentes.

## Añadido

- **Playbooks Conscientes del Dispositivo**:
  - **Dispositivos Embebidos**: Sugiere actualizaciones de firmware vía Web UI.
  - **Cisco/Red**: Sugiere actualizaciones IOS.
  - **Linux**: Mantiene comandos `apt/yum`.
- **Type Safety Mejorado**: Lógica interna endurecida contra datos de proveedor o host malformados.
- **Fallbacks Detallados**: Genera observaciones técnicas útiles a partir de banners de servicio crudos cuando falta la salida específica de herramientas.

## Corregido

- **Títulos de Playbook**: Corregido un error donde las URLs se usaban incorrectamente como títulos de playbook.
- **Credenciales del Asistente**: Añadida solicitud de configuración manual si se rechaza la carga del llavero.
- **Estilo**: Aplicada codificación de color DIM/BOLD genérica para mejor jerarquía visual en menús.

## Pruebas

- **Verificado en**: macOS 26.2 (Darwin 25.2.0)
- **Versiones de Python**: 3.9, 3.10, 3.11, 3.12, 3.13
- **Suite de Pruebas**: 1937 pruebas pasadas (100% tasa de éxito)

## Actualización

```bash
git pull origin main
sudo bash redaudit_install.sh
```
