"""
Genera un reporte PDF de exposicion de correos publicos (via Hunter.io) por cada
empresa listada en un CSV de entrada.

USO:
    set HUNTER_API_KEY=tu_key_aqui          (cmd)
    $env:HUNTER_API_KEY = "tu_key_aqui"     (PowerShell)
    export HUNTER_API_KEY=tu_key_aqui       (bash)

    python generar_reportes_exposicion.py --csv empresas.csv --out reportes

CSV esperado (encabezados): nombre,url

ALCANCE DE ESTE SCRIPT:
    Solo recolecta correos ya publicos, via Hunter.io Domain Search. NO consulta
    HaveIBeenPwned. Ese cruce requiere que el titular del dominio lo verifique
    ante HIBP (o autorice expresamente por escrito la consulta), ya que implica
    tratamiento de datos personales de terceros (Ley 1581 de 2012 en Colombia).
    Este script no incluye esa integracion a proposito.
"""

import argparse
import csv
import html
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from urllib.parse import urlparse

import requests

HUNTER_DOMAIN_SEARCH_URL = "https://api.hunter.io/v2/domain-search"

BROWSER_CANDIDATES = [
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
]

CSS = """
* { box-sizing: border-box; }
body { font-family: 'Segoe UI', Arial, sans-serif; color: #1a1a2e; margin: 0; padding: 0; font-size: 12px; }
.cover { padding: 60px 50px; border-bottom: 6px solid #2b3a67; }
.cover h1 { font-size: 24px; color: #2b3a67; margin-bottom: 4px; }
.cover .subtitle { font-size: 13px; color: #555; margin-bottom: 24px; }
.meta-box { background: #f4f6fb; border: 1px solid #d8dce8; border-radius: 6px; padding: 14px 18px; font-size: 11.5px; line-height: 1.6; }
.disclaimer { margin-top: 20px; background: #fff7e6; border: 1px solid #f0c36d; border-radius: 6px; padding: 14px 18px; font-size: 11px; line-height: 1.6; }
.disclaimer b { color: #8a5a00; }
.error-box { margin-top: 20px; background: #fdeaea; border: 1px solid #e07070; border-radius: 6px; padding: 14px 18px; font-size: 12px; color: #8a1f1f; }
.section { padding: 30px 50px; }
.section h2 { font-size: 18px; color: #2b3a67; border-bottom: 2px solid #2b3a67; padding-bottom: 6px; margin-bottom: 6px; }
.domain-stats { display: flex; gap: 14px; margin: 14px 0 20px 0; }
.stat-card { flex: 1; background: #f4f6fb; border: 1px solid #d8dce8; border-radius: 6px; padding: 12px; text-align: center; }
.stat-card .num { font-size: 20px; font-weight: 700; color: #2b3a67; }
.stat-card .label { font-size: 10.5px; color: #555; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 10.5px; }
th { background: #2b3a67; color: #fff; text-align: left; padding: 7px 8px; }
td { padding: 6px 8px; border-bottom: 1px solid #e2e5ee; vertical-align: top; }
tr:nth-child(even) td { background: #f8f9fc; }
.badge { display: inline-block; padding: 2px 7px; border-radius: 10px; font-size: 9.5px; font-weight: 600; }
.badge-personal { background: #e3f0ff; color: #1257a8; }
.badge-generic { background: #eee; color: #555; }
.conf-high { color: #b00020; font-weight: 700; }
.conf-mid { color: #a86200; font-weight: 700; }
.conf-low { color: #2e7d32; font-weight: 700; }
.note { font-size: 10.5px; color: #666; margin-top: 10px; font-style: italic; }
.footer { padding: 20px 50px; font-size: 9.5px; color: #888; border-top: 1px solid #ddd; }
"""


def find_browser() -> str:
    for path in BROWSER_CANDIDATES:
        if os.path.isfile(path):
            return path
    found = shutil.which("msedge") or shutil.which("chrome") or shutil.which("google-chrome")
    if found:
        return found
    raise RuntimeError("No se encontro Microsoft Edge ni Google Chrome instalado (necesario para generar el PDF).")


def domain_from_url(url: str) -> str | None:
    u = url.strip()
    if not re.match(r"^https?://", u):
        u = "https://" + u
    try:
        host = urlparse(u).netloc
        return re.sub(r"^www\.", "", host) or None
    except Exception:
        return None


def confidence_class(confidence: int) -> str:
    if confidence >= 90:
        return "conf-high"
    if confidence >= 50:
        return "conf-mid"
    return "conf-low"


def safe_filename(name: str) -> str:
    return re.sub(r'[\\/:*?"<>|]', "_", name).strip()


def query_hunter(domain: str, api_key: str, limit: int) -> tuple[dict | None, str | None]:
    try:
        resp = requests.get(
            HUNTER_DOMAIN_SEARCH_URL,
            params={"domain": domain, "api_key": api_key, "limit": limit},
            timeout=20,
        )
        payload = resp.json()
    except Exception as exc:
        return None, str(exc)

    if "errors" in payload:
        return None, payload["errors"][0].get("details", "Error desconocido de Hunter.io")

    return payload, None


def build_error_html(company: str, domain: str, error_message: str, fecha: str) -> str:
    company = html.escape(str(company))
    domain = html.escape(str(domain))
    error_message = html.escape(str(error_message))
    fecha = html.escape(str(fecha))
    return f"""<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
<title>Reporte {company}</title><style>{CSS}</style></head>
<body>
<div class="cover">
  <h1>Reporte de Exposicion de Correos Publicos</h1>
  <div class="subtitle">{company} ({domain})</div>
  <div class="meta-box"><b>Fecha de generacion:</b> {fecha}</div>
  <div class="error-box"><b>No fue posible completar la consulta a Hunter.io para este dominio.</b><br>
  Detalle: {error_message}</div>
</div>
<div class="footer">Reporte generado automaticamente a partir de datos publicos de Hunter.io Domain Search API.</div>
</body></html>"""


def build_report_html(company: str, domain: str, payload: dict, fecha: str) -> str:
    company = html.escape(str(company))
    domain = html.escape(str(domain))
    fecha = html.escape(str(fecha))
    data = payload.get("data", {})
    meta = payload.get("meta", {})
    emails = data.get("emails", []) or []
    pattern = html.escape(str(data.get("pattern") or "(no detectado)"))
    named_count = sum(1 for e in emails if e.get("first_name"))

    rows_html = []
    has_decision_maker = False
    for e in emails:
        badge_class = "badge-personal" if e.get("type") == "personal" else "badge-generic"
        if e.get("first_name"):
            name = html.escape(f"{e.get('first_name')} {e.get('last_name') or ''}".strip())
        else:
            name = "(no identificado)"
        position = f" &mdash; {html.escape(str(e['position_raw']))}" if e.get("position_raw") else ""
        decision_tag = ""
        if e.get("decision_maker"):
            decision_tag = " <b>(Decision maker)</b>"
            has_decision_maker = True
        conf = e.get("confidence", 0)
        conf_class = confidence_class(conf)
        sources = e.get("sources") or []
        source = sources[0]["domain"] if sources else "(desconocida)"

        rows_html.append(
            f"<tr><td>{html.escape(str(e.get('value') or ''))}</td>"
            f"<td><span class='badge {badge_class}'>{html.escape(str(e.get('type') or ''))}</span></td>"
            f"<td>{name}{position}{decision_tag}</td>"
            f"<td class='{conf_class}'>{conf}%</td>"
            f"<td>{html.escape(str(source))}</td></tr>"
        )

    decision_note = ""
    if has_decision_maker:
        decision_note = (
            "<div class='note'>Se identificaron correos de personas con rol de decision, "
            "lo que eleva el riesgo de fraude dirigido (spear-phishing / Business Email Compromise).</div>"
        )

    return f"""<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
<title>Reporte {company}</title><style>{CSS}</style></head>
<body>
<div class="cover">
  <h1>Reporte de Exposicion de Correos Publicos</h1>
  <div class="subtitle">{company} ({domain})</div>
  <div class="meta-box">
    <b>Fecha de generacion:</b> {fecha}<br>
    <b>Fuente de datos:</b> Hunter.io Domain Search API<br>
    <b>Metodo:</b> Indexacion de correos ya publicados en sitios web, LinkedIn y otras fuentes publicas
  </div>
  <div class="disclaimer">
    <b>Alcance y limitaciones de este reporte:</b><br>
    - Este documento unicamente recopila direcciones de correo ya publicas en internet. No se realizo ningun acceso no autorizado a sistemas.<br>
    - <b>No se realizo verificacion de brechas de seguridad (HaveIBeenPwned)</b> sobre estos correos. Ese cruce requiere que el titular del dominio lo verifique ante HIBP o autorice expresamente la consulta por escrito, ya que implica datos personales de terceros (Ley 1581 de 2012).<br>
    - Los resultados estan limitados por el plan de Hunter.io ({meta.get('limit')} de {meta.get('results')} correos totales estimados).
  </div>
</div>
<div class="section">
  <h2>{company}</h2>
  <div class="domain-stats">
    <div class="stat-card"><div class="num">{len(emails)}</div><div class="label">Correos obtenidos</div></div>
    <div class="stat-card"><div class="num">{meta.get('results')}</div><div class="label">Total estimado por Hunter.io</div></div>
    <div class="stat-card"><div class="num">{pattern}</div><div class="label">Patron de nomenclatura</div></div>
    <div class="stat-card"><div class="num">{named_count}</div><div class="label">Personas identificables por nombre</div></div>
  </div>
  <table>
    <tr><th>Correo</th><th>Tipo</th><th>Nombre / Cargo</th><th>Confianza</th><th>Fuente principal</th></tr>
    {''.join(rows_html)}
  </table>
  {decision_note}
</div>
<div class="footer">Reporte generado automaticamente a partir de datos publicos de Hunter.io Domain Search API. Documento de uso interno / comercial preliminar &mdash; no constituye una auditoria de seguridad formal.</div>
</body></html>"""


def html_to_pdf(browser: str, html_path: str, pdf_path: str) -> None:
    subprocess.run(
        [
            browser,
            "--headless",
            "--disable-gpu",
            f"--print-to-pdf={pdf_path}",
            "--print-to-pdf-no-header",
            f"file:///{html_path}",
        ],
        capture_output=True,
        check=True,
    )
    if not os.path.isfile(pdf_path):
        raise RuntimeError(f"El navegador terminó sin crear el PDF: {pdf_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Genera reportes PDF de exposicion de correos publicos por empresa.")
    parser.add_argument("--csv", required=True, help="Ruta al CSV con columnas 'nombre' y 'url'.")
    parser.add_argument("--out", default="reportes", help="Carpeta de salida para los PDFs.")
    parser.add_argument("--api-key", default=os.environ.get("HUNTER_API_KEY"), help="API key de Hunter.io (o usa la variable de entorno HUNTER_API_KEY).")
    parser.add_argument("--limit", type=int, default=10, help="Cantidad maxima de correos por dominio (segun tu plan de Hunter.io).")
    parser.add_argument("--delay", type=float, default=2.0, help="Segundos de espera entre consultas a la API.")
    args = parser.parse_args()

    if not args.api_key:
        print("ERROR: falta la API key de Hunter.io. Pasala con --api-key o define HUNTER_API_KEY.", file=sys.stderr)
        return 1

    if not os.path.isfile(args.csv):
        print(f"ERROR: no se encontro el archivo CSV: {args.csv}", file=sys.stderr)
        return 1

    try:
        browser = find_browser()
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)

    fecha = datetime.now().strftime("%d/%m/%Y")
    resumen = []

    with open(args.csv, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    for row in rows:
        nombre = (row.get("nombre") or row.get("Nombre") or "").strip()
        url = (row.get("url") or row.get("Url") or "").strip()

        if not nombre or not url:
            print(f"AVISO: fila invalida (faltan columnas nombre/url): {row}")
            continue

        domain = domain_from_url(url)
        if not domain:
            print(f"AVISO: no se pudo extraer el dominio de: {url} (empresa: {nombre})")
            continue

        print(f"Consultando Hunter.io para '{nombre}' ({domain})...")
        payload, error_message = query_hunter(domain, args.api_key, args.limit)

        safe_name = safe_filename(nombre)
        html_path = os.path.join(out_dir, f"_tmp_{safe_name}.html")
        pdf_path = os.path.join(out_dir, f"Reporte_Exposicion_{safe_name}.pdf")

        if error_message:
            html = build_error_html(nombre, domain, error_message, fecha)
        else:
            html = build_report_html(nombre, domain, payload, fecha)

        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)

        html_to_pdf(browser, html_path, pdf_path)
        os.remove(html_path)

        if error_message:
            estado = f"ERROR: {error_message}"
        else:
            n_emails = len(payload["data"].get("emails", []))
            n_total = payload["meta"].get("results")
            estado = f"OK ({n_emails} de {n_total} correos)"

        resumen.append({"Empresa": nombre, "Dominio": domain, "Estado": estado, "PDF": pdf_path})

        time.sleep(args.delay)

    resumen_path = os.path.join(out_dir, "_resumen.csv")
    with open(resumen_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Empresa", "Dominio", "Estado", "PDF"])
        writer.writeheader()
        writer.writerows(resumen)

    print("\n=== Resumen ===")
    for r in resumen:
        print(f"{r['Empresa']:20s} {r['Dominio']:25s} {r['Estado']}")
    print(f"\nResumen guardado en: {resumen_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
