[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.11.0/docs/releases/RELEASE_NOTES_v4.11.0.md) [![Ver en Español](https://img.shields.io/badge/Ver_en_Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.11.0/docs/releases/RELEASE_NOTES_v4.11.0_ES.md)

# Notas de la Versión RedAudit v4.11.0

## Resumen

RedAudit v4.11.0 es una actualización centrada en el rendimiento que introduce **Perfiles de Escaneo Nuclei**, mejora drásticamente la **Visibilidad de Dispositivos IoT** y expande masivamente la **Base de Datos de Fabricantes OUI**. Esta versión soluciona problemas de timeouts en redes densas permitiendo elegir entre modos `fast`, `balanced` y `full`, y corrige puntos ciegos críticos en la detección de dispositivos domésticos inteligentes como bombillas WiZ que dependen de puertos UDP específicos.

## Añadido

- **Selector de Perfiles Nuclei**: Añadido flag `--profile` para controlar intensidad y velocidad.
  - `full`: Escaneo completo con todos los templates (Por defecto).
  - `balanced`: Solo tags de alto impacto (~4x más rápido).
  - `fast`: CVEs críticos y fallos de configuración (~10x más rápido).
- **Soporte Protocolo IoT**: Añadida detección específica para **Bombillas Inteligentes WiZ** (puerto UDP 38899). Estos dispositivos ahora se identifican y etiquetan correctamente como `iot`, evitando que aparezcan como hosts "cerrados".
- **Documentación**: Añadida sección "IoT sin puertos TCP" al README, explicando cómo RedAudit detecta dispositivos visibles solo vía multicast/broadcast.

## Mejorado

- **Estabilidad Nuclei**:
  - Reducido tamaño del lote de 25 a 10 objetivos para evitar congestión.
  - Aumentado timeout de 300s a 600s para lotes grandes.
  - Los escaneos ahora devuelven resultados parciales incluso si lotes específicos fallan.
- **Motor de Identidad**: Actualizada base de datos OUI (Direcciones MAC) de ~46 entradas a **38,911 fabricantes**. La etiqueta de fabricante "Unknown" ahora debería ser extremadamente rara.
- **Verificación de Timeouts**: Timeouts de Nikto (330s), TestSSL (90s) y WhatWeb (30s) validados como adecuados para las condiciones actuales de auditoría.

## Corregido

- **Seguridad de Tipos**: Corregido error de tipos `mypy` en `nuclei.py` relacionado con la validación de listas de hallazgos.

## Pruebas

- **Automatizado**: Suite `pytest` aprobada (Core, CLI, Utils).
- **Manual**:
  - Verificado que el perfil `balanced` completa significativamente más rápido en subredes de prueba.
  - Confirmado que 8+ bombillas WiZ son visibles con metadatos de identificación.
  - Verificado que el manejo de timeouts no elimina prematuramente escaneos largos válidos.

## Actualización

Sin cambios que rompan compatibilidad. Actualizar e instalar dependencias:

```bash
git pull origin main
pip install -e .
```
