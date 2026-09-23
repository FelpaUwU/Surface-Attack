# Escaneo light de vulnerabilidades + exposición de correos -> PDF por empresa

Escaneo **pasivo**, basado solo en información pública (DNS, WHOIS, TLS, cabeceras
HTTP de seguridad, SPF/DMARC, security.txt, archivos comúnmente expuestos). No hace
port scanning ni explotación. Opcionalmente suma, en el mismo PDF, una sección de
exposición de correos públicos vía Hunter.io Domain Search.

## Uso

En una máquina nueva puedes reconstruir el entorno así:

```
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.lock.txt
```

1. Completa `data/companies.csv` con las empresas (columnas `name,url`).
2. (Opcional, para incluir la sección de correos) define tu API key de Hunter.io:

```
$env:HUNTER_API_KEY = "tu_key_aqui"     (PowerShell)
```

3. Corre:

```
.\.venv\Scripts\python.exe main.py --input data\companies.csv --output output --workers 8
```

4. Resultado: **un solo PDF por empresa** en `output/` con dos secciones —
   análisis de vulnerabilidades y, si se proporcionó API key, exposición de
   correos públicos (Hunter.io) — más `output/_resumen.csv` (nombre, grade,
   score, PDF) para priorizar a quién contactar primero.

## Herramientas opcionales sin costo de licencia

El parámetro `--tools auto` intenta usar `amass` en modo pasivo si está
instalado. También puede activar `zap` apuntando a un daemon de OWASP ZAP con
`ZAP_API_URL`. Nuclei se ejecuta únicamente cuando se solicitan herramientas y
se incluye `--authorized-scan`; no se debe usar contra activos sin
autorización escrita.

Las rutas de ejecutables pueden definirse con `AMASS_BIN` y `NUCLEI_BIN`.
Si hay `OPENAI_API_KEY` configurada, cada PDF incluye además una explicación
no técnica (generada con IA) de los activos que descubrió Amass, pensada para
una audiencia de dirección/gerencia.
Para habilitar Nuclei hay que indicar explícitamente una o más rutas con
`--nuclei-template`; el programa nunca ejecuta todas las plantillas por defecto.
Consulta `.env.example` para ver las variables disponibles; no guardes API keys
en archivos versionados.

Ejemplo de informe comercial:

```
python main.py --input data/companies.csv --output output --tools auto `
  --provider-name "KENNERTECH" `
  --offer-name "revisión ejecutiva de exposición digital" `
  --cta-url "https://calendly.com/tu-equipo/revision" `
  --cta-email "seguridad@tuempresa.com"
```

Las herramientas ausentes quedan registradas como `unavailable` y no reducen
el puntaje. Las observaciones de herramientas externas se incorporan como
evidencia y deben revisarse antes de comunicar un riesgo a un tercero.

Si no se proporciona `HUNTER_API_KEY` (ni `--hunter-api-key`), el PDF se genera
igual, con la sección de correos marcada como "no ejecutada".

## Notas

- `--workers` controla cuántas empresas se escanean en paralelo (8-15 es razonable
  para 100 sitios; cada empresa hace únicamente requests HTTP/DNS normales, no hay
  carga agresiva contra ningún sitio).
- `--hunter-api-key`, `--hunter-limit` y `--hunter-delay` controlan la consulta a
  Hunter.io (la última evita exceder el rate limit de tu plan al correr con varios
  `--workers` en paralelo).
- `--tools`, `--authorized-scan`, `--zap-api-url`, `--tool-timeout`, `--cta-url`,
  `--cta-email`, `--provider-name`, `--offer-name` y `--nuclei-template` controlan las integraciones,
  el alcance autorizado y el llamado a la acción del informe.
- Por defecto el informe Hunter.io muestra solo cantidades agregadas. Use
  `--include-email-details` únicamente cuando exista base legal y autorización
  para compartir direcciones individuales.
- Un dominio caído/lento no detiene el batch: queda registrado en `_resumen.csv`
  con su error y el resto continúa.
- Los reportes son neutros (sin logo/CTA) por diseño; si luego quieres agregar
  branding y una llamada a la acción, se puede sumar como un bloque más en
  `pdf/report.py`.
- `generar_reportes_exposicion.py` sigue disponible como script standalone
  (genera solo el reporte de Hunter.io, vía HTML + Chrome/Edge headless), por si
  necesitas ese reporte suelto sin correr el escaneo de vulnerabilidades. La
  lógica de consulta a Hunter.io que usa `main.py` vive en `checks/hunter.py`.
