"""Orchestrator: reads a company list, runs the light passive scan on each,
writes one PDF per company plus a summary CSV to prioritize outreach.

Usage:
    .venv\\Scripts\\python.exe main.py --input data/companies.csv --output output --workers 5
"""
import argparse
import csv
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
from pathlib import Path

from checks.scanner import calculate_score, run_all_checks
from checks.hunter import run_hunter_check
from checks.ai_summary import generate_amass_summary, DEFAULT_MODEL as DEFAULT_OPENAI_MODEL
from checks.integrations import run_integrations
from checks.client_tracker import update_tracker, TrackerLayoutError
from pdf.report import build_pdf, _safe_filename


def read_companies(path):
    companies = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        fields = {k.lower().strip(): k for k in reader.fieldnames or []}
        if "name" not in fields or "url" not in fields:
            sys.exit(f"El CSV debe tener columnas 'name' y 'url'. Encontradas: {reader.fieldnames}")
        for row in reader:
            name = (row.get(fields["name"]) or "").strip()
            url = (row.get(fields["url"]) or "").strip()
            if name and url:
                companies.append((name, url))
    return companies


class HunterRateLimiter:
    """Spaces out Hunter.io calls across threads so total request rate stays
    under `delay` seconds between calls, regardless of --workers."""

    def __init__(self, delay):
        self.delay = delay
        self.lock = threading.Lock()
        self.next_allowed = 0.0

    def wait(self):
        if self.delay <= 0:
            return
        with self.lock:
            now = time.monotonic()
            start_at = max(now, self.next_allowed)
            self.next_allowed = start_at + self.delay
        sleep_for = start_at - now
        if sleep_for > 0:
            time.sleep(sleep_for)


def _grade(score):
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def scan_one(name, url, hunter_api_key, hunter_limit, hunter_limiter, openai_api_key, openai_model,
             selected_tools, authorized_scan, zap_api_url, zap_api_key, tool_timeout,
             nuclei_templates, email_detail_mode, cta_url, cta_email, provider_name, offer_name,
             hunter_cache_group=None):
    try:
        result = run_all_checks(name, url)
    except Exception as e:
        return None, f"{e.__class__.__name__}: {e}"

    try:
        if result.get("scope_valid", True):
            result["tooling"] = run_integrations(
                result["domain"], result["scanned_url"], selected_tools, authorized_scan,
                zap_api_url, zap_api_key, nuclei_templates, tool_timeout,
            )
            for tool_result in result["tooling"]:
                result["findings"].extend(tool_result.get("findings") or [])
            result["score"] = calculate_score(result["findings"])
            result["grade"] = _grade(result["score"])
        else:
            result["tooling"] = []
    except Exception as e:
        result.setdefault("errors", []).append(f"Integraciones: {e.__class__.__name__}: {e}")
        result["tooling"] = []

    result["commercial"] = {
        "cta_url": cta_url,
        "cta_email": cta_email,
        "provider_name": provider_name,
        "offer_name": offer_name,
    }

    try:
        if not result.get("scope_valid", True):
            result["hunter"] = {"enabled": False, "domain": result["domain"], "emails": [], "pattern": None,
                                 "meta": {}, "error": "Consulta omitida: destino fuera del alcance público permitido."}
        else:
            result["hunter"] = run_hunter_check(
                result["domain"], hunter_api_key, hunter_limit,
                rate_limit_wait=hunter_limiter.wait if hunter_api_key else None,
                cache_group=hunter_cache_group,
            )
            result["hunter"]["show_details"] = email_detail_mode
    except Exception as e:
        result["hunter"] = {"enabled": bool(hunter_api_key), "domain": result["domain"], "emails": [],
                             "pattern": None, "meta": {}, "error": f"{e.__class__.__name__}: {e}"}

    try:
        if result.get("scope_valid", True):
            amass_result = next((t for t in result.get("tooling") or [] if t.get("tool") == "amass"), None)
            amass_assets = amass_result.get("assets") if amass_result else []
            result["amass_summary"] = generate_amass_summary(result["name"], amass_assets, openai_api_key, openai_model)
        else:
            result["amass_summary"] = {"enabled": False, "text": None, "error": None}
    except Exception as e:
        result["amass_summary"] = {"enabled": bool(openai_api_key), "text": None, "error": f"{e.__class__.__name__}: {e}"}

    return result, None


def main():
    ap = argparse.ArgumentParser(description="Evaluación ejecutiva de exposición digital por empresa -> PDF individual")
    ap.add_argument("--input", default="data/companies.csv")
    ap.add_argument("--output", default="output")
    ap.add_argument("--workers", type=int, default=5, help="Escaneos concurrentes")
    ap.add_argument("--hunter-api-key", default=os.environ.get("HUNTER_API_KEY"),
                     help="API key de Hunter.io para incluir la sección de exposición de correos "
                          "(o usa la variable de entorno HUNTER_API_KEY). Si se omite, esa sección "
                          "del PDF se marca como no ejecutada.")
    ap.add_argument("--hunter-limit", type=int, default=10, help="Correos máximos por dominio (según tu plan de Hunter.io)")
    ap.add_argument("--hunter-delay", type=float, default=1.0, help="Segundos mínimos entre consultas a Hunter.io (across workers)")
    ap.add_argument("--openai-api-key", default=os.environ.get("OPENAI_API_KEY"),
                     help="API key de OpenAI para generar el resumen en lenguaje simple para el cliente "
                          "(o usa la variable de entorno OPENAI_API_KEY). Si se omite, esa sección del PDF "
                          "se omite.")
    ap.add_argument("--openai-model", default=DEFAULT_OPENAI_MODEL, help="Modelo de OpenAI a usar para el resumen")
    ap.add_argument("--tools", default="auto",
                    help="Integraciones separadas por coma: auto,none,amass,zap,nuclei (default: auto).")
    ap.add_argument("--authorized-scan", action="store_true",
                    help="Confirma autorización escrita para habilitar el escaneo Nuclei.")
    ap.add_argument("--zap-api-url", default=os.environ.get("ZAP_API_URL"),
                    help="URL del daemon API de OWASP ZAP, por ejemplo http://127.0.0.1:8080.")
    ap.add_argument("--zap-api-key", default=os.environ.get("ZAP_API_KEY"), help="API key de ZAP, si está configurada.")
    ap.add_argument("--tool-timeout", type=int, default=300, help="Timeout por integración externa, en segundos.")
    ap.add_argument("--nuclei-template", action="append", default=[],
                    help="Ruta a plantilla/directorio Nuclei seleccionado; se puede repetir. Requiere --authorized-scan.")
    ap.add_argument("--hunter-cache-group", default=None,
                    help="Subcarpeta de data/hunter_cache/ donde se guardan los resultados nuevos de Hunter.io "
                         "(p. ej. batch_01). Los dominios ya consultados en cualquier grupo se reutilizan sin gastar créditos.")
    ap.add_argument("--email-detail-mode", choices=["none", "obfuscated", "full"], default="none",
                    help="Nivel de detalle de los correos de Hunter.io en el PDF: 'none' (solo agregados), "
                         "'obfuscated' (primeras 3 letras + '****@dominio'), 'full' (correo completo; "
                         "requiere base legal/autorización).")
    ap.add_argument("--include-email-details", action="store_true",
                    help="Alias en desuso de --email-detail-mode full.")
    ap.add_argument("--cta-url", default=os.environ.get("CTA_URL"), help="URL de agenda o contacto para el llamado a la acción.")
    ap.add_argument("--cta-email", default=os.environ.get("CTA_EMAIL"), help="Correo comercial para el llamado a la acción.")
    ap.add_argument("--provider-name", default=os.environ.get("PROVIDER_NAME", "Equipo de ciberseguridad"),
                    help="Nombre que aparecerá como proveedor del informe.")
    ap.add_argument("--offer-name", default=os.environ.get("OFFER_NAME", "revisión ejecutiva de exposición digital"),
                    help="Nombre de la oferta comercial sugerida.")
    ap.add_argument("--tracker-xlsx", default=None,
                    help="Ruta a un Excel de seguimiento de clientes; si se indica, al terminar se marca "
                         "columna 'Informe'=SI y 'Scoring'=letra para cada dominio con reporte generado.")
    ap.add_argument("--tracker-sheet", default="Clientes Objetivos",
                    help="Nombre de la hoja dentro de --tracker-xlsx (default: 'Clientes Objetivos').")
    args = ap.parse_args()
    if args.include_email_details:
        args.email_detail_mode = "full"

    companies = read_companies(args.input)
    if not companies:
        sys.exit("No hay empresas para escanear en el CSV.")

    if args.workers < 1:
        ap.error("--workers debe ser mayor o igual a 1")
    if args.hunter_limit < 0 or args.hunter_delay < 0 or args.tool_timeout < 1:
        ap.error("--hunter-limit, --hunter-delay y --tool-timeout no pueden ser negativos")

    raw_tools = {item.strip().lower() for item in args.tools.split(",") if item.strip()}
    valid_tools = {"amass", "zap", "nuclei"}
    if "none" in raw_tools:
        selected_tools = set()
    elif "auto" in raw_tools:
        selected_tools = {"amass"}
        if args.zap_api_url:
            selected_tools.add("zap")
        if args.authorized_scan:
            selected_tools.add("nuclei")
    else:
        unknown = raw_tools - valid_tools
        if unknown:
            ap.error(f"Herramientas no reconocidas: {', '.join(sorted(unknown))}")
        selected_tools = raw_tools
    if "nuclei" in selected_tools and not args.authorized_scan:
        print("AVISO: Nuclei fue solicitado sin --authorized-scan; se registrará como no ejecutado.")

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "_resumen.csv"

    if not args.hunter_api_key:
        print("AVISO: no se proporcionó API key de Hunter.io; los PDFs incluirán la sección de "
              "correos como 'no ejecutada'. Usa --hunter-api-key o define HUNTER_API_KEY.")
    if not args.openai_api_key:
        print("AVISO: no se proporcionó API key de OpenAI; los PDFs no incluirán el resumen para dirección. "
              "Usa --openai-api-key o define OPENAI_API_KEY.")

    print(f"Escaneando {len(companies)} empresas con {args.workers} workers...")
    t0 = time.time()
    results = []
    tracker_rows = []
    hunter_limiter = HunterRateLimiter(args.hunter_delay)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(scan_one, name, url, args.hunter_api_key, args.hunter_limit, hunter_limiter,
                        args.openai_api_key, args.openai_model, selected_tools, args.authorized_scan,
                        args.zap_api_url, args.zap_api_key, args.tool_timeout, args.nuclei_template,
                        args.email_detail_mode,
                        args.cta_url, args.cta_email,
                        args.provider_name, args.offer_name, args.hunter_cache_group): (name, url)
            for name, url in companies
        }
        done = 0
        for fut in as_completed(futures):
            name, url = futures[fut]
            done += 1
            result, err = fut.result()
            if err:
                print(f"[{done}/{len(companies)}] FALLÓ {name} ({url}): {err}")
                results.append({"name": name, "url": url, "grade": "ERROR", "score": "", "pdf": "", "error": err})
                continue

            base_filename = _safe_filename(result['name'])
            filename = f"{base_filename}.pdf"
            if any(r.get("pdf") == filename for r in results):
                suffix = hashlib.sha1(result["domain"].encode("utf-8")).hexdigest()[:8]
                filename = f"{base_filename}_{suffix}.pdf"
            pdf_path = out_dir / filename
            try:
                build_pdf(result, str(pdf_path))
            except Exception as e:
                print(f"[{done}/{len(companies)}] PDF falló para {name}: {e}")
                results.append({"name": name, "url": url, "grade": result["grade"], "score": result["score"], "pdf": "", "error": f"PDF: {e}"})
                continue

            print(f"[{done}/{len(companies)}] OK {name} -> grade {result['grade']} ({result['score']}/100) -> {filename}")
            results.append({"name": name, "url": url, "grade": result["grade"], "score": result["score"], "pdf": filename, "error": ""})
            tracker_rows.append((result["domain"], result["grade"]))

    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "url", "grade", "score", "pdf", "error"])
        writer.writeheader()
        for r in sorted(results, key=lambda x: (x["grade"] != "ERROR", x["score"] if isinstance(x["score"], int) else -1)):
            writer.writerow(r)

    elapsed = time.time() - t0
    ok = sum(1 for r in results if r["pdf"])
    print(f"\nListo: {ok}/{len(companies)} PDFs generados en '{out_dir}' en {elapsed:.1f}s.")
    print(f"Resumen: {summary_path}")

    if args.tracker_xlsx:
        try:
            matched, total, backup_path = update_tracker(args.tracker_xlsx, args.tracker_sheet, tracker_rows)
            print(f"Seguimiento actualizado: {matched}/{total} dominios marcados en "
                  f"'{args.tracker_sheet}' (backup: {backup_path.name})")
            if matched < total:
                print(f"AVISO: {total - matched} dominios generados no se encontraron en la hoja de seguimiento.")
        except (TrackerLayoutError, OSError) as e:
            print(f"AVISO: no se pudo actualizar el Excel de seguimiento ({args.tracker_xlsx}): {e}")


if __name__ == "__main__":
    main()
