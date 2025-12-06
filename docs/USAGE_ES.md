# Guía de Uso de RedAudit

## Instalación
RedAudit está diseñado para sistemas Kali Linux o Debian.

1. **Instalación y Actualización**:
   ```bash
   sudo bash redaudit_install.sh
   # Para modo no interactivo:
   sudo bash redaudit_install.sh -y
   ```
   Esto instala las dependencias necesarias (`nmap`, `python3-cryptography`, etc.) y crea el alias.

2. **Recargar Shell**:
   ```bash
   source ~/.bashrc  # o ~/.zshrc
   ```

3. **Ejecutar**:
   ```bash
   redaudit
   ```

## Flujo de Trabajo

### 1. Configuración
La herramienta te pedirá:
- **Red Objetivo**: Interfaces detectadas o CIDR manual.
- **Modo de Escaneo**: Normal (Discovery+Top Ports), Rápido o Completo.
- **Hilos**: Número de trabajadores concurrentes.
- **Rate Limit**: Retardo opcional (segundos) entre hosts para sigilo.
- **Cifrado**: Protección opcional con contraseña para los reportes.
- **Directorio de Salida**: Por defecto `~/RedAuditReports`.

### 2. Fases de Ejecución
- **Discovery**: Ping rápido para encontrar hosts vivos.
- **Port Scan**: Escaneo nmap específico por host.
- **Vulnerability Scan**: Revisa servicios web (http/https) contra `whatweb` / `nikto` (si es modo completo).

### 3. Reportes y Cifrado
Los reportes se guardan con fecha `redaudit_YYYYMMDD_HHMMSS`.
- **Texto Plano**: `.json` y `.txt`.
- **Cifrados**: `.json.enc`, `.txt.enc` y `.salt`.

Para descifrar resultados:
```bash
python3 redaudit_decrypt.py /ruta/a/reporte.json.enc
```
Esto generará archivos `.decrypted` (o restaurará la extensión original) tras verificar la contraseña.

### 4. Logging
Los logs de depuración se guardan en `~/.redaudit/logs/`. Revisa estos archivos si el escaneo falla o se comporta de forma inesperada.

## Rendimiento y Sigilo
**Nota sobre el Heartbeat**: Si usas un retardo alto (ej. 60s) con muchos hilos, el escaneo puede parecer "congelado". Revisa el log o el estado del heartbeat.

### Deep Scan Automático y Captura de Tráfico
RedAudit intenta automáticamente un "Deep Scan" en hosts que parecen "silenciosos" (arriba pero pocos puertos) o fiables.
- **Deep Scan**: Lanza flags agresivos de Nmap (`-A -sV -Pn --open`) y escaneo UDP (`-sSU`) para descubrir servicios ocultos.
- **Captura de Tráfico**: Si `tcpdump` está disponible, captura un **snippet de 50 paquetes** (máx 15s) del tráfico del host.
    - Guarda archivos `.pcap` en tu directorio de reportes.
    - Si `tshark` está instalado, incluye un resumen de protocolos en el reporte JSON.
    - *Defensa*: La duración de captura está estrictamente limitada para prevenir bloqueos.
