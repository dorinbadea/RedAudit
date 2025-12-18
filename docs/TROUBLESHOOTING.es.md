# Guía de Solución de Problemas RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](TROUBLESHOOTING.en.md)

**Audiencia:** Todos los usuarios
**Alcance:** Errores comunes, códigos de salida, problemas de dependencias.
**Fuente de verdad:** `redaudit/utils/constants.py` (Códigos de Salida)

---

## Códigos de Error y Resolución

### 1. `Permission denied` / "Se requieren privilegios de root"

**Síntoma**: El script termina inmediatamente con un error de privilegios.
**Causa**: La aplicación requiere acceso a sockets raw para `nmap` (escaneos SYN/detección de SO) y `tcpdump`.
**Resolución**:

- Siempre ejecutar con `sudo`.
- Verificar que el usuario cumple la política de sudoers.

### 2. `nmap: command not found`

**Síntoma**: El motor de escaneo falla al inicializar.
**Causa**: El binario `nmap` no está en el `$PATH` del sistema.
**Resolución**:

```bash
sudo apt update && sudo apt install nmap
```

### 3. `ModuleNotFoundError: No module named 'cryptography'`

**Síntoma**: El script falla durante las importaciones.
**Causa**: Las dependencias de Python están faltantes o instaladas en un entorno diferente.
**Resolución**:

```bash
# Ejecutar el instalador para instalar todas las dependencias
sudo bash redaudit_install.sh

# O instalar paquetes Python manualmente
sudo apt install python3-nmap python3-cryptography python3-netifaces
```

### 4. `Advertencias de Heartbeat en logs`

**Síntoma**: Ves advertencias de "Monitor de Actividad" en la salida de consola.
**Causa**: El hilo principal puede estar bloqueado por un subproceso colgado (ej: un escaneo `nikto` estancado). RedAudit monitorea la actividad del escaneo e imprime advertencias cuando no detecta salida por periodos extendidos.
**Resolución**:

- Revisar carga del sistema: `top`
- Inspeccionar logs: `tail -f ~/.redaudit/logs/redaudit_*.log`
- Terminar proceso si no responde >5 minutos.

### 5. `Decryption failed: Invalid Token`

**Síntoma**: `redaudit_decrypt.py` rechaza la contraseña.
**Causa**: Contraseña incorrecta, la clave derivada no coincide con la firma del archivo.
**Resolución**:

- Asegurar sensibilidad correcta de mayúsculas/minúsculas.
- Verificar integridad del archivo (tamaño >0). No abortar inmediatamente; los escaneos profundos en hosts filtrados pueden tomar tiempo.

### 6. "Los escaneos parecen colgarse" / Progreso lento

**Síntoma**: La herramienta se pausa 1-2 minutos en un solo host.
**Explicación**: RedAudit puede realizar **escaneos profundos / refinamiento de identidad** en hosts complejos (fingerprinting combinado TCP/UDP/SO).

- **Duración**: Estos escaneos pueden legítimamente tomar **90–150 segundos** por host.
- **Por qué**: Esencial para identificar cajas IoT, firewalls o servidores filtrados que ocultan su SO.
- **Verificar**: Buscar el marcador `[deep]` en la salida CLI.

### 6b. Reposo del sistema / apagado de pantalla durante escaneos largos (v3.5+)

**Síntoma**: Tu VM/portátil entra en reposo o se apaga la pantalla mientras RedAudit está ejecutándose.
**Explicación**: RedAudit intenta una inhibición **best-effort** del reposo/pantalla mientras el escaneo está en curso para evitar pausas involuntarias.
**Notas**:

- Depende de las herramientas disponibles en el sistema (p.ej., `systemd-inhibit` en Linux, `xset` para X11/DPMS).
- Puedes desactivarlo con `--no-prevent-sleep`.

### 7. Advertencia "Cryptography not available"

**Síntoma**: Ves una advertencia sobre `python3-cryptography` no disponible.
**Explicación**: La función de cifrado requiere `python3-cryptography`. La herramienta degrada graciosamente si falta.
**Solución**:

```bash
sudo apt install python3-cryptography
```

**Nota**: Si cryptography no está disponible, las opciones de cifrado se desactivan automáticamente. No aparecerán prompts de contraseña.

### 8. Errores en modo no interactivo

**Síntoma**: El argumento `--target` no funciona o "Error: --target is required".
**Solución**:

- Asegurar que proporcionas `--target` con un CIDR válido (ej: `--target 192.168.1.0/24`)
- Múltiples objetivos: `--target "192.168.1.0/24,10.0.0.0/24"`
- Verificar que el formato CIDR sea correcto
- Consultar `redaudit --help` para todas las opciones disponibles

**Síntoma**: El script se niega a iniciar.
**Solución**: Ejecutar el instalador nuevamente para corregir librerías de Python faltantes:

```bash
sudo bash redaudit_install.sh -y
```

### 8b. La versión/banner no se refresca tras actualizar

**Síntoma**: Actualizaste RedAudit pero el banner sigue mostrando la versión anterior.
**Causa**: La shell puede estar cacheando la ruta del ejecutable (o sigues en la misma sesión de terminal).
**Solución**:

- Reinicia el terminal (recomendado).
- Si necesitas mantener la misma sesión, ejecuta `hash -r` (zsh/bash) para limpiar la caché.
- Verifica qué binario se está ejecutando: `command -v redaudit`.

### 9. Escaneo IPv6 no funciona (v3.0)

**Síntoma**: Los objetivos IPv6 no devuelven resultados o dan errores.
**Causa**: IPv6 no habilitado en el sistema o Nmap compilado sin soporte IPv6.
**Resolución**:

- Verificar que IPv6 está habilitado: `ip -6 addr show`
- Comprobar que Nmap soporta IPv6: `nmap -6 ::1`
- Usar el flag `--ipv6` para modo solo IPv6

### 10. Errores de límite de velocidad API NVD (v3.0)

**Síntoma**: "Rate limit exceeded" o búsquedas CVE lentas.
**Causa**: Usando la API NVD sin clave (limitado a 5 peticiones/30 segundos).
**Resolución**:

- Obtener una clave API NVD gratuita en: <https://nvd.nist.gov/developers/request-an-api-key>
- Usar `--nvd-key TU_CLAVE` para límites más rápidos (50 peticiones/30 segundos)
- RedAudit cachea resultados durante 7 días para minimizar llamadas a la API

### 11. Falló la conexión del proxy (v3.0)

**Síntoma**: "Proxy connection failed" al usar `--proxy`.
**Causa**: Proxy no alcanzable o `proxychains` no instalado.
**Resolución**:

```bash
# Instalar proxychains
sudo apt install proxychains4

# Probar proxy manualmente
curl --socks5 pivot-host:1080 http://example.com

# Verificar formato del proxy
# Correcto: --proxy socks5://host:port
```

### 12. Net Discovery: Herramientas faltantes / "tool_missing" (v3.2)

**Síntoma**: Advertencias durante el Descubrimiento de Red sobre herramientas faltantes (`nbtscan`, `netdiscover`) o bloques de Red Team omitidos.
**Causa**: El descubrimiento mejorado depende de herramientas externas no incluidas en nmap estándar.
**Resolución**:

```bash
sudo apt update && sudo apt install nbtscan netdiscover fping avahi-utils snmp ldap-utils samba-common-bin
```

### 13. Net Discovery: "Permission denied" / Fallos L2 (v3.2)

**Síntoma**: Módulos de `scapy`, `bettercap` o `netdiscover` fallan o no devuelven nada.
**Causa**: Spoofing y sniffing L2 requieren privilegios de root y capacidades de inyección (`CAP_NET_RAW` a menudo no es suficiente para inyección).
**Resolución**:

- Ejecutar siempre con `sudo`.
- Verificar que no haya filtrado MAC en el switch/interfaz.
- Seleccionar interfaz explícitamente: `--net-discovery-interface eth0`.

### 14. Fallo al Generar Reporte HTML (v3.3)

**Síntoma**: "Error generating HTML report" o el archivo reporte tiene 0 bytes.
**Causa**:

- Falta el motor de plantillas `jinja2` (raro, instalado por defecto).
- Permiso denegado al escribir en directorio de salida.
**Resolución**:

```bash
# Verificar instalación
python3 -c "import jinja2; print('ok')"

# Comprobar permisos
touch ~/Documents/RedAuditReports/test_write
```

### 15. Fallo en Alerta Webhook (v3.3)

**Síntoma**: Advertencia "Failed to send webhook" en logs.
**Causa**:

- Formato de URL inválido.
- Servidor destino caído o inalcanzable (404/500).
- Red bloqueando conexiones salientes.
**Resolución**:
- Probar URL con curl: `curl -X POST -d '{"test":true}' TU_URL_WEBHOOK`
- Verificar que la URL comienza con `http://` o `https://`.

### 16. Playbooks no generados / falta carpeta `playbooks/` (v3.4)

**Síntoma**: No aparecen playbooks en `<output_dir>/playbooks/`, o el contador es 0.
**Causas comunes**:

- **Cifrado activado**: los artefactos en claro (HTML/JSONL/playbooks/manifiestos) se omiten cuando se usa `--encrypt`.
- **No hay categorías que casen**: los playbooks solo se generan cuando los hallazgos entran en categorías internas (TLS, cabeceras, CVE, web, puertos).
- **Deduplicación esperada**: solo se genera 1 playbook por host + categoría (puedes tener muchos hallazgos pero pocos playbooks).
- **Permisos**: el directorio de salida no es escribible por el usuario actual.

**Resolución**:

- Ejecuta sin cifrado si necesitas playbooks: `sudo redaudit ... --mode normal --yes`
- Confirma el directorio de salida y permisos: `ls -la <output_dir>`

RedAudit y esta guía de solución de problemas son parte de un proyecto licenciado bajo GPLv3. Consulta [LICENSE](../../LICENSE).
