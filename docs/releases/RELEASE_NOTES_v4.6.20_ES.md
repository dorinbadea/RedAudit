# Notas de Version v4.6.20

**Fecha de Lanzamiento**: 2026-01-14

## Resumen

Esta version corrige problemas criticos de deteccion de vulnerabilidades y mejora la calidad del codigo mediante la consolidacion de funciones duplicadas.

## Nuevas Funcionalidades

### Configuracion de Timeout de Nuclei

Nuevo flag CLI `--nuclei-timeout` permite configurar el timeout de batch (defecto 300 segundos):

```bash
redaudit --target 192.168.1.0/24 --nuclei --nuclei-timeout 600
```

Util para redes Docker o entornos lentos donde el timeout por defecto causa escaneos parciales.

## Correcciones

### Deteccion de Backdoor vsftpd 2.3.4

Corregida la deteccion del infame backdoor CVE-2011-2523. La deteccion ahora combina los campos `service`, `product`, `version` y `banner` de la salida de Nmap, asegurando que la vulnerabilidad se identifique correctamente y se asigne una puntuacion de riesgo de 100.

### Consistencia de Titulos Entre Reportes

La exportacion JSONL ahora usa `descriptive_title` para ambos campos `title` y `descriptive_title`, coincidiendo con el comportamiento del reporte HTML. Esto asegura titulos consistentes en todos los formatos de salida.

## Mejoras

### Generacion Unificada de Titulos

Consolidadas las funciones duplicadas `_extract_title` de `jsonl_exporter.py` y `html_reporter.py` en una unica funcion `extract_finding_title` en `siem.py`. Esto elimina aproximadamente 170 lineas de codigo duplicado y asegura generacion consistente de titulos con la siguiente cadena de fallback:

1. Usar `descriptive_title` existente si esta definido
2. Usar `template_id` de Nuclei
3. Usar CVE IDs
4. Generar desde `parsed_observations`
5. Usar primera entrada valida de `nikto_findings`
6. Fallback a titulo basado en puerto (ej. "HTTP Service Finding on Port 80")

## Commits

- `a02e2be` - fix(siem): detectar backdoor vsftpd 2.3.4 desde campo version de puerto
- `1ee7860` - refactor(siem): unificar extract_finding_title en exportadores
- `cd3fd36` - feat(cli): anadir flag --nuclei-timeout para timeout configurable
- `b036021` - fix(siem): manejar observaciones None y anadir fallback nikto_findings

## Notas de Actualizacion

Sin cambios incompatibles. Actualizar haciendo pull de la ultima version y reinstalando:

```bash
git pull origin main
pip install -e .
```
