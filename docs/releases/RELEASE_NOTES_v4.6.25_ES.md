# Notas de Lanzamiento RedAudit v4.6.25

[![View in English](https://img.shields.io/badge/View_in_English-blue?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.6.25/docs/releases/RELEASE_NOTES_v4.6.25.md)

## Resumen

**RedAudit v4.6.25** es una actualizacion hotfix que asegura el nuevo motor de escaneo paralelo de Nuclei. Introduce mecanismos de seguridad de hilos para prevenir perdida de datos durante la ejecucion concurrente y extiende las capacidades de procesamiento paralelo a la interfaz CLI estandar.

## Corregido

- **Prevencion de Condiciones de Carrera**: Implementado `threading.Lock` alrededor de secciones criticas (E/S de archivos, actualizacion de estadisticas) en `nuclei.py`. Esto previene condiciones de carrera donde multiples lotes paralelos podrian intentar escribir en el archivo de salida principal simultaneamente, corrompiendo o perdiendo hallazgos.
- **Ejecucion Paralela CLI**: Corregido un descuido donde la ejecucion paralela solo estaba activa para callbacks de API. Ahora, los usuarios estandar de CLI (usando la barra de progreso Rich) tambien se benefician de la aceleracion ~4x.

## Pruebas

- Actualizado `tests/core/test_nuclei_parallel.py` para verificar no solo la velocidad, sino tambien la **integridad de datos** (asegurando que todos los hallazgos se escriben correctamente en disco sin perdidas).

## Actualizacion

```bash
git pull origin main
```
