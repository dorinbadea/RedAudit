# Notas de Lanzamiento RedAudit v4.3.0

## Risk Scoring Empresarial y Optimizaciones Deep Scan

RedAudit v4.3.0 marca un hito importante en la auditoría "Smart-Check", introduciendo un motor de Risk Scoring reescrito (V2) y capacidades de escaneo significativamente más profundas para entornos contenerizados.

### 🌟 Novedades Principales

#### 1. Enterprise Risk Scoring V2

El motor de cálculo de riesgo ha sido renovado para tratar los **Hallazgos de Configuración** (de Nikto, Nuclei, Zap) como ciudadanos de primera clase junto a los CVEs.

* **Comportamiento previo**: La puntuación dependía mucho de CVSS/CVEs. Un host con cero CVEs pero un panel de admin expuesto (Hallazgo Crítico) podía recibir una puntuación baja.
* **Nuevo comportamiento**: Los hallazgos con severidad `high` o `critical` impactan directamente el Bonus de Densidad y el Multiplicador de Exposición. Un host con fallos críticos ahora puntúa correctamente en el rango 80-100 (Alto/Crítico), asegurando una priorización precisa.

#### 2. Optimización Docker y Deep Scan (H2)

Hemos optimizado la fase de "Deep Scan" para manejar mejor contenedores Docker y servicios efímeros comunes en stacks modernos:

* **Nikto Desencadenado**: Eliminadas las restricciones de tuning por defecto (`-Tuning x`) y aumentado el timeout a 5 minutos (`300s`). Esto asegura que Nikto complete chequeos en apps web complejas.
* **Nuclei Expandido**: El escáner ahora procesa hallazgos con `severity="low"`, capturando fugas de información críticas (logs expuestos, páginas de estado, .git config) anteriormente filtradas.

#### 3. HyperScan Modo SYN

Nuevo modo de escaneo de puertos basado en SYN para usuarios privilegiados:

* **Velocidad**: ~10x más rápido que escaneos connect.
* **Uso**: Seleccionado automáticamente al ejecutar como root con scapy instalado, o forzar con `--hyperscan-mode syn`.

### 🛡️ Mejoras

* **Supresión de Advertencias**: Limpiada la salida de errores de `arp-scan` y `scapy` (advertencias redundantes de "Mac address not found") para una experiencia de terminal profesional y sin ruido.
* **Visualización de Identidad**: Los reportes HTML ahora codifican por color el `identity_score` para mostrar claramente qué hosts están plenamente identificados vs. los que requieren revisión manual.
* **Gestión de PCAP**: Limpieza y organización automatizada de artefactos de captura de paquetes.

### 🐛 Correcciones

* **Validación Smart-Check**: Filtrado de falsos positivos mejorado usando validación cruzada CPE.
* **Lógica de Riesgo**: Corregida regresión donde hallazgos no-CVE resultaban en riesgo 0.

---

**Actualizar:**

```bash
git pull
sudo bash redaudit_install.sh
```
