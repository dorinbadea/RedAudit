# Notas de Version v4.19.10

**Fecha de Lanzamiento:** 2026-01-29

## Resumen

Version de hotfix que corrige un bug visual en los logs de sesion donde los prompts de countdown aparecian concatenados.

## Correcciones

### Visualizacion de Countdown en Logs de Sesion

**Problema:** Cuando el prompt de reanudacion de Nuclei mostraba su temporizador de 15 segundos, el texto aparecia repetido/concatenado en los logs de sesion (`cli.txt`) en lugar de actualizarse en el mismo lugar.

**Causa Raiz:** El metodo `TeeStream._write_lines` en `session_log.py` manejaba correctamente los frames con retorno de carro (`\r`) quedandose solo con el ultimo segmento, pero los codigos ANSI de limpieza de linea (`\x1b[2K`) no se eliminaban. Estos codigos no tienen efecto en archivos de log, causando la concatenacion visual.

**Solucion:** Se agrego el patron `ANSI_LINE_CLEAR` para eliminar los codigos de escape `\x1b[2K` y `\x1b[K` al procesar frames con retorno de carro.

## Detalles Tecnicos

### Archivos Modificados

- `redaudit/utils/session_log.py` - Agregado patron ANSI line-clear y actualizado metodo `_write_lines`
- `tests/utils/test_session_log.py` - Agregado caso de prueba para el nuevo comportamiento

### Verificacion

```bash
pytest tests/utils/test_session_log.py -v -k "test_lines_mode_strips_ansi_line_clear_codes"
```

## Notas de Actualizacion

Sin cambios incompatibles. Este es un hotfix compatible hacia atras.
