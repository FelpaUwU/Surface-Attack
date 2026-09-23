"""Optional local integrations for external attack-surface evidence.

The integrations are intentionally opt-in and fail closed.  A missing binary,
an unavailable daemon, or an unsupported output format is reported as a tool
status and never converted into a vulnerability finding.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import requests


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _find_binary(env_name: str, candidates: tuple[str, ...]) -> str | None:
    configured = os.environ.get(env_name)
    if configured and Path(configured).is_file():
        return configured
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    return None


def _run(args: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return completed.returncode, completed.stdout[-12000:], completed.stderr[-12000:]
    except subprocess.TimeoutExpired as exc:
        return 124, (exc.stdout or "")[-12000:], "Timeout del proceso"
    except OSError as exc:
        return 127, "", f"{exc.__class__.__name__}: {exc}"


def _read_json_or_jsonl(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    try:
        value = json.loads(text)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            return [value]
    except json.JSONDecodeError:
        pass
    rows = []
    for line in text.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


_AMASS_LINE_RE = re.compile(
    r"^(?P<left>\S.*?)\s+\((?P<left_type>\w+)\)\s+-->\s+\S+\s+-->\s+(?P<right>\S.*?)\s+\((?P<right_type>\w+)\)\s*$"
)


def _parse_amass_txt(path: Path) -> list[dict]:
    """Amass v4 dropped -json; `enum -dir` writes plain-text relation lines
    like '<name> (FQDN) --> a_record --> <ip> (IPAddress)' instead."""
    seen = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _AMASS_LINE_RE.match(line.strip())
        if not match:
            continue
        for name, kind in ((match["left"], match["left_type"]), (match["right"], match["right_type"])):
            if kind == "FQDN":
                seen.add(name.rstrip("."))
    return [{"host": name, "sources": []} for name in sorted(seen)]


def _status(tool: str, status: str, detail: str = "", evidence: dict | None = None) -> dict:
    return {
        "tool": tool,
        "status": status,
        "observed_at": _now(),
        "detail": detail,
        "evidence": evidence or {},
        "findings": [],
        "assets": [],
    }


def run_amass_passive(domain: str, timeout: int = 180) -> dict:
    binary = _find_binary("AMASS_BIN", ("amass", "amass.exe"))
    if not binary:
        return _status("amass", "unavailable", "No se encontró AMASS_BIN ni el ejecutable amass.")

    with tempfile.TemporaryDirectory(prefix="lightvuln-amass-") as temp_dir:
        code, stdout, stderr = _run([binary, "enum", "-d", domain, "-dir", temp_dir], timeout)
        if code != 0:
            return _status("amass", "error", f"AMASS terminó con código {code}: {stderr or stdout}")
        output = Path(temp_dir) / "amass.txt"
        assets = _parse_amass_txt(output) if output.exists() else []
        return _status(
            "amass",
            "ok",
            f"Descubrimiento pasivo completado: {len(assets)} activos.",
            {"mode": "passive", "asset_count": len(assets)},
        ) | {"assets": assets}


def run_zap_passive(url: str, api_url: str | None, api_key: str | None, timeout: int = 180) -> dict:
    if not api_url:
        return _status("owasp-zap", "unavailable", "Defina ZAP_API_URL para usar el daemon de ZAP en modo pasivo.")
    base = api_url.rstrip("/")
    params = {"url": url, "recurse": "true"}
    if api_key:
        params["apikey"] = api_key
    started = time.monotonic()
    try:
        spider = requests.get(f"{base}/JSON/spider/action/scan/", params=params, timeout=15)
        spider.raise_for_status()
        spider_id = spider.json().get("scan")
        while spider_id and time.monotonic() - started < timeout:
            check = requests.get(
                f"{base}/JSON/spider/view/status/", params={"scanId": spider_id, **({"apikey": api_key} if api_key else {})}, timeout=15
            )
            check.raise_for_status()
            if str(check.json().get("status")) in {"100", "complete"}:
                break
            time.sleep(1)
        alert_params = {"baseurl": url}
        if api_key:
            alert_params["apikey"] = api_key
        alerts = requests.get(f"{base}/JSON/core/view/alerts/", params=alert_params, timeout=20)
        alerts.raise_for_status()
        rows = alerts.json().get("alerts", []) or []
        findings = []
        for alert in rows:
            risk = str(alert.get("riskdesc") or alert.get("risk") or "Informational").lower()
            severity = "high" if "high" in risk else "medium" if "medium" in risk else "low" if "low" in risk else "info"
            findings.append({
                "id": f"zap-{alert.get('pluginId') or alert.get('alert')}",
                "title": alert.get("alert") or "Alerta ZAP",
                "severity": severity,
                "status": "warn" if severity in {"high", "medium", "low"} else "pass",
                "confidence": "medium",
                "source": "OWASP ZAP passive",
                "detail": alert.get("description") or alert.get("evidence") or "Alerta detectada por ZAP.",
                "evidence": {"url": alert.get("url"), "param": alert.get("param"), "solution": alert.get("solution")},
                "business_impact": "Puede aumentar la exposición de la aplicación o facilitar ataques dependiendo del contexto.",
                "recommendation": alert.get("solution") or "Validar el hallazgo y aplicar la corrección recomendada.",
            })
        return _status(
            "owasp-zap", "ok", f"ZAP pasivo completado: {len(findings)} alertas.", {"alert_count": len(findings)}
        ) | {"findings": findings}
    except (requests.RequestException, ValueError, KeyError) as exc:
        return _status("owasp-zap", "error", f"No se pudo consultar el API de ZAP: {exc}")


def run_nuclei_authorized(url: str, authorized: bool, template_paths: list[str] | None = None, timeout: int = 300) -> dict:
    if not authorized:
        return _status("nuclei", "not_run", "Nuclei requiere autorización explícita (--authorized-scan).")
    if not template_paths:
        return _status("nuclei", "not_run", "Indique al menos una plantilla o directorio con --nuclei-template; no se ejecutan todas por defecto.")
    binary = _find_binary("NUCLEI_BIN", ("nuclei", "nuclei.exe"))
    if not binary:
        return _status("nuclei", "unavailable", "No se encontró NUCLEI_BIN ni el ejecutable nuclei.")

    with tempfile.TemporaryDirectory(prefix="lightvuln-nuclei-") as temp_dir:
        output = Path(temp_dir) / "nuclei.jsonl"
        # Only the curated profiles supplied by the operator are executed.
        template_args = [item for path in template_paths for item in ("-t", path)]
        code, stdout, stderr = _run(
            [binary, "-target", url, *template_args, "-jsonl", "-output", str(output), "-no-color"], timeout
        )
        if code != 0 and not output.exists():
            return _status("nuclei", "error", f"Nuclei terminó con código {code}: {stderr or stdout}")
        rows = _read_json_or_jsonl(output) if output.exists() else []
        findings = []
        for row in rows:
            info = row.get("info") or {}
            severity = str(info.get("severity") or "info").lower()
            if severity not in {"high", "medium", "low", "info"}:
                severity = "info"
            findings.append({
                "id": f"nuclei-{row.get('template-id') or row.get('template') or 'finding'}",
                "title": info.get("name") or row.get("template-id") or "Hallazgo Nuclei",
                "severity": severity,
                "status": "fail" if severity in {"high", "medium"} else "warn" if severity == "low" else "pass",
                "confidence": "medium",
                "source": "ProjectDiscovery Nuclei",
                "detail": row.get("matched-at") or row.get("host") or "Hallazgo detectado por Nuclei; requiere validación.",
                "evidence": {"matched_at": row.get("matched-at"), "curl_command": row.get("curl-command")},
                "business_impact": "El impacto depende de que el servicio afectado esté realmente expuesto y sea explotable.",
                "recommendation": info.get("remediation") or "Reproducir de forma controlada y corregir según la referencia del template.",
            })
        return _status(
            "nuclei", "ok", f"Nuclei completado: {len(findings)} resultados; requieren revisión humana.", {"finding_count": len(findings), "exit_code": code}
        ) | {"findings": findings}


def run_integrations(domain: str, url: str, tools: set[str], authorized: bool, zap_api_url: str | None, zap_api_key: str | None, nuclei_templates: list[str] | None = None, timeout: int = 180) -> list[dict]:
    results = []
    if "amass" in tools:
        results.append(run_amass_passive(domain, timeout))
    if "zap" in tools:
        results.append(run_zap_passive(url, zap_api_url, zap_api_key, timeout))
    if "nuclei" in tools:
        results.append(run_nuclei_authorized(url, authorized, nuclei_templates, max(timeout, 300)))
    return results
