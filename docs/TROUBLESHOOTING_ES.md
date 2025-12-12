# Guía de Solución de Problemas RedAudit

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](TROUBLESHOOTING.md)

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
pip3 install -r requirements.txt
# O ejecutar el instalador verificado
sudo bash redaudit_install.sh
```

### 4. `Heartbeat file stuck`

**Síntoma**: La marca de tiempo en `~/.redaudit/logs/heartbeat` es más antigua de 30 segundos.
**Causa**: El hilo principal puede estar bloqueado por un subproceso colgado (ej: un escaneo `nikto` estancado).
**Resolución**:

- Revisar carga del sistema: `top`
- Inspeccionar logs: `tail -f ~/.redaudit/logs/redaudit.log`
- Terminar proceso si no responde >5 minutos.

### 5. `Decryption failed: Invalid Token`

**Síntoma**: `redaudit_decrypt.py` rechaza la contraseña.
**Causa**: Contraseña incorrecta, la clave derivada no coincide con la firma del archivo.
**Resolución**:

- Asegurar sensibilidad correcta de mayúsculas/minúsculas.
- Verificar integridad del archivo (tamaño >0). No abortar inmediatamente; los escaneos profundos en hosts filtrados pueden tomar tiempo.

### 6. "Los escaneos parecen colgarse" / Progreso lento

**Síntoma**: La herramienta se pausa 1-2 minutos en un solo host.
**Explicación**: RedAudit v2.8.0 realiza **Escaneos de Identidad Profundos** en hosts complejos (fingerprinting combinado TCP/UDP/SO).

- **Duración**: Estos escaneos pueden legítimamente tomar **90–150 segundos** por host.
- **Por qué**: Esencial para identificar cajas IoT, firewalls o servidores filtrados que ocultan su SO.
- **Verificar**: Buscar el marcador `[deep]` en la salida CLI.

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

### 9. El escaneo IPv6 no funciona (v3.0)

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

RedAudit y esta guía de solución de problemas son parte de un proyecto licenciado bajo GPLv3. Consulta [LICENSE](../LICENSE).
