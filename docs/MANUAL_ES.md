# Manual de Usuario RedAudit v2.6

[![View in English](https://img.shields.io/badge/View%20in%20English-blue?style=flat-square)](MANUAL_EN.md)

**Versión**: 2.6
**Audiencia**: Analistas de Seguridad, Administradores de Sistemas
**Licencia**: GPLv3

## 1. Introducción

Este manual proporciona documentación exhaustiva para la operación y configuración de RedAudit. Cubre aspectos técnicos profundos del motor de escaneo, mecanismos de cifrado y gestión de reportes.

## 2. Instalación y Configuración

Asegúrese de que el sistema host cumple los siguientes requisitos:

- **SO**: Kali Linux, Debian, Ubuntu, Parrot OS.
- **Python**: v3.8+.
- **Privilegios**: Root/Sudo (obligatorio para acceso a sockets raw).

### Instalación

Ejecute el script instalador para resolver automáticamente las dependencias (nmap, python-nmap, cryptography) y configurar el alias del sistema.

```bash
git clone https://github.com/dorinbadea/RedAudit.git
cd RedAudit
sudo bash redaudit_install.sh
```

### Configuración del Shell

Después de la instalación, active el alias:

| Distribución | Shell por Defecto | Comando de Activación |
|:---|:---|:---|
| **Kali Linux** (2020.3+) | Zsh | `source ~/.zshrc` |
| **Debian / Ubuntu / Parrot** | Bash | `source ~/.bashrc` |

> **Nota**: Kali usa Zsh por defecto desde 2020. El instalador detecta tu shell automáticamente.

## 3. Configuración

RedAudit prioriza la configuración en tiempo de ejecución vía argumentos CLI sobre archivos de configuración estáticos para facilitar la automatización y ejecución stateless en entornos contenerizados.

### Control de Concurrencia

La herramienta utiliza `concurrent.futures.ThreadPoolExecutor` para paralelizar operaciones de host. El conteo de hilos por defecto se calcula como `cpu_count * 5`.

- **Alta Concurrencia**: Use `--threads 20` para redes rápidas.
- **Baja Concurrencia**: Use `--threads 2` para conexiones inestables o medidas.

## Arquitectura Modular (v2.6)

A partir de v2.6, RedAudit está organizado como un paquete Python:

| Módulo | Propósito |
|:---|:---|
| `redaudit/core/auditor.py` | Clase orquestadora principal |
| `redaudit/core/scanner.py` | Lógica de escaneo, sanitización |
| `redaudit/core/crypto.py` | Cifrado (PBKDF2, Fernet) |
| `redaudit/core/network.py` | Detección de interfaces de red |
| `redaudit/core/reporter.py` | Generación de reportes (JSON/TXT) |
| `redaudit/utils/constants.py` | Constantes de configuración nombradas |
| `redaudit/utils/i18n.py` | Internacionalización |

**Invocación alternativa:**

```bash
python -m redaudit --help
```

### Rate Limiting

Para mitigar la congestión de red o alertas IDS, se puede inyectar un retardo entre operaciones.

- **Flag**: `-r <segundos>` o `--rate-limit <segundos>`.
- **Implementación**: Inyecta llamadas `time.sleep()` dentro de los bucles de escaneo.

## 4. Subsistema de Cifrado

Cuando se habilita el cifrado (`--encrypt`), RedAudit asegura los artefactos de salida usando cifrado simétrico.

- **Algoritmo**: AES-128 en modo Fernet.
- **Derivación de Clave**: PBKDF2HMAC-SHA256.
- **Salt**: Salt aleatorio de 16 bytes generado por sesión.
- **Iteraciones**: 480,000 rondas.

El descifrado requiere la contraseña correspondiente y la utilidad `redaudit_decrypt.py`.

## 5. Fases de Escaneo

El flujo de ejecución consiste en tres fases secuenciales:

1. **Descubrimiento**: Escaneo ICMP y SYN para identificar hosts vivos.
2. **Enumeración**: Detección de versiones de servicio (`-sV`) en puertos descubiertos.
3. **Análisis Profundo**:
    - **Web**: Cabeceras, tecnologías y vulnerabilidades (si se detecta HTTP/S).
    - **Scripting**: Scripts NSE dirigidos basados en el tipo de servicio.

## 6. Monitorización (Heartbeat)

Un hilo demonio especializado monitoriza el estado del proceso principal. Actualiza un archivo `heartbeat` en el directorio de logs cada 5 segundos. Si el proceso principal se cuelga, la marca de tiempo en este archivo dejará de actualizarse, proporcionando un indicador externo de fallo.

## 7. Solución de Problemas

Consulte `docs/TROUBLESHOOTING.md` para códigos de error específicos y pasos de resolución. Los problemas comunes implican dependencias faltantes o privilegios insuficientes.

## 8. Legal y Cumplimiento

El uso de esta herramienta implica la aceptación de los términos de la licencia GPLv3. El operador asume total responsabilidad por cualquier acción realizada contra las redes objetivo.

- **Estándar**: **Fernet** (Cumple especificación).
  - **Cifrado**: AES-128 en modo CBC.
  - **Firma**: HMAC-SHA256.
  - **Validación**: Token con timestamp (TTL ignorado por defecto).
- **Derivación de Clave**:
  - **Algoritmo**: PBKDF2HMAC (SHA-256).
  - **Iteraciones**: 480,000 (supera la recomendación OWASP de 310,000).
  - **Salt**: 16 bytes aleatorios, guardados en archivo `.salt`.
- **Degradación Graceful** (v2.5): Si `python3-cryptography` no está disponible, el cifrado se desactiva automáticamente con avisos claros. No se muestran prompts de contraseña.
- **Permisos de Archivo** (v2.5): Todos los reportes (cifrados y planos) usan permisos seguros (0o600 - solo lectura/escritura del propietario).
- **Modo No Interactivo** (v2.5): El flag `--encrypt-password` permite especificar la contraseña en modo no interactivo. Si se omite, se genera una contraseña aleatoria que se muestra en la salida.

## 6. Lógica de Escaneo

1. **Descubrimiento**: Barrido ICMP Echo (`-PE`) + ARP (`-PR`) para mapear hosts vivos.
2. **Enumeración**: Escaneos Nmap paralelos basados en el modo.
3. **Deep Scan Adaptativo (Automático)**:
    - **Disparadores**: Se activa automáticamente si un host:
        - Tiene más de 8 puertos abiertos
        - Tiene servicios sospechosos (socks, proxy, vpn, tor, nagios, etc.)
        - Tiene 3 o menos puertos abiertos
        - Tiene puertos abiertos pero no se detectó información de versión
    - **Estrategia (2 Fases)**:
        1. **Fase 1**: `nmap -A -sV -Pn -p- --open --version-intensity 9` (TCP Agresivo).
            - *Chequeo*: Si encuentra MAC/SO, se detiene aquí y omite la Fase 2.
        2. **Fase 2**: `nmap -O -sSU -Pn -p- --max-retries 2` (UDP + SO de respaldo, solo si la Fase 1 no obtuvo identidad).
    - **Resultado**: Datos guardados en `host.deep_scan`, incluyendo `mac_address`, `vendor`, y flag `phase2_skipped`.

4. **Captura de Tráfico**:
    - Como parte del proceso de **Deep Scan**, si `tcpdump` está presente, captura un fragmento (50 paquetes/15s) del tráfico del host.
    - **Salida**:
        - Guarda archivos `.pcap` en el directorio de reportes.
        - Si `tshark` está instalado, incrusta un resumen de texto en `host.deep_scan.pcap_capture`.

## 7. Guía de Descifrado

Los reportes cifrados (`.json.enc`, `.txt.enc`) son ilegibles sin la contraseña y el archivo `.salt`.

**Uso:**

```bash
python3 redaudit_decrypt.py /ruta/a/reporte.json.enc
```

1. El script encuentra `reporte.salt` en el mismo directorio.
2. Pide la contraseña.
3. Deriva la clave e intenta descifrar.
4. Genera `reporte.decrypted.json` o `reporte.json` (si no hay conflicto).

## 8. Monitorización y Heartbeat

Los escaneos largos (ej: rangos de puertos completos en redes lentas) pueden parecer "cuelgues".

- **Hilo Heartbeat**: Revisa la marca de tiempo `self.last_activity` cada 60s.
- **Estados**:
  - **Activo**: Actividad < hace 60s. Sin salida.
  - **Ocupado**: Actividad < hace 300s. Log de advertencia.
  - **Silencioso**: Actividad > hace 300s.
    - Mensaje: *"Nmap sigue ejecutándose; esto es normal en hosts lentos o filtrados."*
    - **Acción**: NO abortes. Los escaneos profundos pueden tomar 8-10 minutos en hosts con firewall.
- **Logs**: Revisa `~/.redaudit/logs/` para depuración detallada.

## 9. Script de Verificación

Asegura que tu despliegue está limpio y sin corrupciones.

```bash
bash redaudit_verify.sh
```

Comprueba:

- Rutas de binarios.
- Disponibilidad de módulos Python (`cryptography`, `nmap`).
- Configuración de alias.
- Presencia de herramientas opcionales.

## 10. FAQ (Preguntas Frecuentes)

**P: ¿Por qué error "Encryption missing"?**
R: Probablemente saltaste la instalación de dependencias. Ejecuta `sudo apt install python3-cryptography`.

**P: ¿Puedo escanear sobre VPN?**
R: Sí, RedAudit detecta interfaces VPN tun0/tap0 automáticamente.

**P: ¿Es seguro para producción?**
R: Sí, si se configura responsablemente (Hilos < 5, Rate Limit > 1s). Ten siempre autorización.

**P: ¿Por qué encuentro pocos puertos?**
R: El objetivo puede estar filtrando paquetes SYN. RedAudit intentará un Deep Scan automáticamente para intentar sortear esto.

## 11. Glosario

- **Deep Scan**: Escaneo de respaldo automático con flags agresivos de Nmap para sondear hosts "silenciosos".
- **Fernet**: Primitiva de cifrado simétrico que asegura seguridad e integridad de 128 bits.
- **Heartbeat**: Hilo de monitorización en segundo plano que asegura la salud del proceso.
- **PBKDF2**: *Password-Based Key Derivation Function 2*. Hace que el crackeo de contraseñas sea lento.
- **Ports Truncated**: Optimización donde listas >50 puertos se resumen para mantener los reportes legibles.
- **Rate Limit**: Retardo artificial introducido para reducir el ruido en la red.
- **Salt**: Dato aleatorio combinado con la contraseña para crear una clave de cifrado única.

## 12. Aviso Legal

Esta herramienta es **únicamente para auditorías de seguridad autorizadas**. El uso sin consentimiento escrito del propietario de la red es ilegal bajo jurisdicciones de responsabilidad estricta. Los autores no aceptan responsabilidad por daños o uso no autorizado.

### Licencia

RedAudit se distribuye bajo la **GNU General Public License v3.0 (GPLv3)**.  
Consulta el archivo raíz [LICENSE](../LICENSE) para más detalles.
