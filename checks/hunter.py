"""Hunter.io Domain Search: collects publicly-indexed email addresses for a
domain. Purely passive — same data source as the standalone
`generar_reportes_exposicion.py` script, but returns a structured dict
instead of HTML so it can be merged into the combined PDF report.

Does NOT query HaveIBeenPwned. That cross-check requires the domain owner to
verify ownership with HIBP (or authorize the query in writing), since it
involves processing third parties' personal data (Ley 1581 de 2012 in
Colombia).

Successful queries are cached to disk (one JSON file per domain, under
data/hunter_cache/) so re-running a report for the same domain never spends
another Hunter.io credit.
"""
import json
import os
import re
import threading
from pathlib import Path

import requests

HUNTER_DOMAIN_SEARCH_URL = "https://api.hunter.io/v2/domain-search"
TIMEOUT = 20
CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "hunter_cache"


def _cache_filename(domain):
    safe = re.sub(r"[^a-z0-9.-]", "_", domain.lower())
    return f"{safe}.json"


def _cache_path(domain, group):
    return (CACHE_DIR / group / _cache_filename(domain)) if group else (CACHE_DIR / _cache_filename(domain))


def _read_cache(domain, group):
    """Looks in the caller's group folder first, then any other group, so a
    domain already fetched for one batch is never fetched again for another."""
    candidates = [_cache_path(domain, group)]
    if CACHE_DIR.exists():
        candidates += sorted(CACHE_DIR.glob(f"*/{_cache_filename(domain)}"))
    for path in candidates:
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
    return None


def _write_cache(domain, result, group):
    path = _cache_path(domain, group)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f".tmp-{os.getpid()}-{threading.get_ident()}")
    tmp.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def run_hunter_check(domain, api_key, limit=10, rate_limit_wait=None, cache_group=None):
    """Returns a dict describing the Hunter.io result for `domain`.

    Shape:
        {"enabled": bool, "domain": str, "emails": [...], "pattern": str|None,
         "meta": {"limit": int, "results": int} | {}, "error": str|None,
         "from_cache": bool}

    `enabled` is False when no api_key was provided (the check was skipped,
    not attempted). `error` carries the failure reason when the query ran
    but Hunter.io returned an error or the request failed. A successful
    result (no error) is cached to disk and reused on later calls for the
    same domain, regardless of `limit`, without spending another credit.

    `rate_limit_wait`, if given, is only called right before an actual
    network request (i.e. skipped entirely on a cache hit). `cache_group` is a
    subfolder name (e.g. "batch_01") under data/hunter_cache/ where new results
    are stored.
    """
    cached = _read_cache(domain, cache_group)
    if cached is not None:
        result = dict(cached)
        result["from_cache"] = True
        return result

    if not api_key:
        return {"enabled": False, "domain": domain, "emails": [], "pattern": None, "meta": {}, "error": None,
                "from_cache": False}

    if rate_limit_wait:
        rate_limit_wait()

    try:
        resp = requests.get(
            HUNTER_DOMAIN_SEARCH_URL,
            params={"domain": domain, "api_key": api_key, "limit": limit},
            timeout=TIMEOUT,
        )
        payload = resp.json()
    except Exception as e:
        return {"enabled": True, "domain": domain, "emails": [], "pattern": None, "meta": {},
                "error": f"{e.__class__.__name__}: {e}", "from_cache": False}

    if "errors" in payload:
        return {"enabled": True, "domain": domain, "emails": [], "pattern": None, "meta": {},
                "error": payload["errors"][0].get("details", "Error desconocido de Hunter.io"),
                "from_cache": False}

    data = payload.get("data", {})
    meta = payload.get("meta", {})
    result = {
        "enabled": True,
        "domain": domain,
        "emails": data.get("emails", []) or [],
        "pattern": data.get("pattern"),
        "meta": {"limit": meta.get("limit"), "results": meta.get("results")},
        "error": None,
        "from_cache": False,
    }
    _write_cache(domain, result, cache_group)
    return result
