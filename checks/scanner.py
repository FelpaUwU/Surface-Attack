"""Light, passive OSINT scanner: DNS, WHOIS, TLS, HTTP security headers,
email-auth records and common accidental-exposure checks. No exploitation,
no port scanning, no authentication bypass — every check is a normal
public HTTP/DNS request a browser would also make.
"""
import socket
import ssl
import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import dns.resolver
import requests
import tldextract
import whois
from cryptography import x509
from cryptography.hazmat.backends import default_backend

USER_AGENT = "Mozilla/5.0 (compatible; LightVulnScan/1.0; +security-awareness-scan)"
TIMEOUT = 8

SCORE_DEDUCTION = {
    ("fail", "high"): 30,
    ("fail", "medium"): 14,
    ("fail", "low"): 6,
    ("warn", "high"): 10,
    ("warn", "medium"): 5,
    ("warn", "low"): 2,
}

CATEGORY_CAPS = {
    "web_headers": 10,
    "email_auth": 10,
    "dns_hygiene": 6,
    "governance": 5,
    "tls": 35,
    "exposure": 60,
}

FINDING_CONTEXT = {
    "spf": ("email_auth", "Sin autenticación de correo, terceros pueden intentar suplantar el dominio.", "Configurar SPF y validar los emisores autorizados."),
    "dmarc": ("email_auth", "Aumenta el riesgo de phishing y mensajes fraudulentos que parezcan venir de la empresa.", "Definir y publicar una política DMARC progresiva."),
    "http-redirect": ("tls", "El tráfico podría viajar sin protección o inducir a usuarios a una conexión insegura.", "Forzar HTTPS y revisar toda la cadena de redirecciones."),
    "tls-cert": ("tls", "Un certificado inválido o próximo a vencer puede interrumpir el servicio y generar alertas de confianza.", "Renovar y monitorizar el certificado antes de su vencimiento."),
    "tls-version": ("tls", "Protocolos antiguos pueden reducir la protección de las comunicaciones.", "Mantener únicamente protocolos TLS soportados y seguros."),
    "tls-sig": ("tls", "Una firma criptográfica débil reduce la confianza en la identidad del servicio.", "Reemitir el certificado con un algoritmo moderno."),
    "exposure-check": ("exposure", "La verificación quedó limitada porque el sitio responde igual para rutas inexistentes.", "Validar manualmente las rutas sensibles con autorización."),
    "security-txt": ("governance", "La ausencia de un canal claro puede retrasar la notificación de incidentes.", "Publicar un security.txt con un contacto operativo."),
    "whois": ("governance", "La falta de datos de registro limita la capacidad de anticipar vencimientos o cambios de control.", "Confirmar la administración y renovación del dominio."),
    "dnssec": ("dns_hygiene", "La resolución del dominio tiene una capa adicional de confianza pendiente de revisar.", "Evaluar DNSSEC según la criticidad del dominio."),
}


class TargetScopeError(ValueError):
    """The target is syntactically invalid or outside the public web scope."""


def _finding(id_, title, severity, status, detail, **extra):
    result = {"id": id_, "title": title, "severity": severity, "status": status, "detail": detail}
    context = FINDING_CONTEXT.get(id_)
    if context:
        result.setdefault("category", context[0])
        result.setdefault("business_impact", context[1])
        result.setdefault("recommendation", context[2])
    elif id_.startswith("hdr-") or id_ in {"cookie-flags", "info-disclosure", "http-headers"}:
        result.setdefault("category", "web_headers")
        result.setdefault("business_impact", "Puede aumentar la exposición del sitio, aunque su relevancia depende de la aplicación y sus controles compensatorios.")
        result.setdefault("recommendation", "Revisar la configuración web y aplicar solo las cabeceras que correspondan al servicio.")
    result.update(extra)
    return result


def _registered_from_host(host):
    ext = tldextract.extract(host)
    return ".".join(p for p in [ext.domain, ext.suffix] if p)


def _assert_public_host(host):
    host = (host or "").strip().rstrip(".")
    if not host:
        raise TargetScopeError("El destino no tiene hostname.")
    addresses = []
    try:
        addresses = [item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)]
    except socket.gaierror as exc:
        raise TargetScopeError(f"No se pudo resolver el hostname: {exc}") from exc
    for address in set(addresses):
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if not parsed.is_global:
            raise TargetScopeError(f"El destino resuelve a una IP no pública: {address}")


def _validate_url(url, allowed_registered=None, check_public=True):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TargetScopeError("Solo se permiten URLs HTTP/HTTPS con hostname.")
    if parsed.username or parsed.password:
        raise TargetScopeError("No se permiten credenciales embebidas en la URL.")
    if parsed.port not in (None, 80, 443):
        raise TargetScopeError("Solo se permiten los puertos web 80 y 443.")
    registered = _registered_from_host(parsed.hostname)
    if allowed_registered and registered != allowed_registered:
        raise TargetScopeError(f"La redirección sale del dominio autorizado: {parsed.hostname}")
    if check_public:
        _assert_public_host(parsed.hostname)
    return parsed


def _safe_get(url, allow_redirects=True, allowed_registered=None):
    current = url
    for _ in range(5):
        parsed = _validate_url(current, allowed_registered=allowed_registered)
        response = requests.get(
            current,
            timeout=TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=False,
            verify=True,
        )
        if not allow_redirects or response.status_code not in {301, 302, 303, 307, 308}:
            return response
        location = response.headers.get("Location")
        if not location:
            return response
        current = urljoin(response.url or current, location)
        if allowed_registered is None:
            allowed_registered = _registered_from_host(parsed.hostname)
    raise TargetScopeError("Se excedió el máximo de redirecciones permitidas.")


def normalize_domain(raw):
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    _validate_url(raw, check_public=False)
    ext = tldextract.extract(raw)
    registered = ".".join(p for p in [ext.domain, ext.suffix] if p)
    host = ".".join(p for p in [ext.subdomain, ext.domain, ext.suffix] if p) or registered
    return registered, host, raw


# ---------------------------------------------------------------- DNS ----

def check_dns_records(registered_domain):
    findings = []
    try:
        a_records = [r.to_text() for r in dns.resolver.resolve(registered_domain, "A", lifetime=TIMEOUT)]
        findings.append(_finding("dns-a", "Registros A", "info", "pass", ", ".join(a_records)))
    except Exception as e:
        findings.append(_finding("dns-a", "Registros A", "medium", "warn", f"Sin registro A resoluble ({e.__class__.__name__})"))

    try:
        mx_records = [r.exchange.to_text() for r in dns.resolver.resolve(registered_domain, "MX", lifetime=TIMEOUT)]
        findings.append(_finding("dns-mx", "Registros MX", "info", "pass", ", ".join(mx_records) if mx_records else "Sin MX"))
    except Exception:
        findings.append(_finding("dns-mx", "Registros MX", "info", "warn", "Sin registros MX (o dominio no recibe correo)"))

    try:
        ns_records = [r.to_text() for r in dns.resolver.resolve(registered_domain, "NS", lifetime=TIMEOUT)]
        findings.append(_finding("dns-ns", "Name servers", "info", "pass", ", ".join(ns_records)))
    except Exception as e:
        findings.append(_finding("dns-ns", "Name servers", "low", "warn", f"No se pudieron obtener NS ({e.__class__.__name__})"))

    return findings


def check_dnssec(registered_domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = TIMEOUT
        answer = resolver.resolve(registered_domain, "DNSKEY", raise_on_no_answer=False)
        if answer.rrset:
            return [_finding("dnssec", "DNSSEC", "info", "pass", "DNSSEC habilitado (DNSKEY presente)")]
        return [_finding("dnssec", "DNSSEC", "low", "warn", "DNSSEC no detectado")]
    except Exception:
        return [_finding("dnssec", "DNSSEC", "low", "warn", "DNSSEC no detectado")]


def check_email_auth(registered_domain):
    findings = []
    try:
        txt = [b"".join(r.strings).decode(errors="ignore") for r in dns.resolver.resolve(registered_domain, "TXT", lifetime=TIMEOUT)]
    except Exception:
        txt = []

    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    if spf:
        findings.append(_finding("spf", "SPF", "info", "pass", spf[0]))
    else:
        findings.append(_finding("spf", "SPF", "medium", "warn", "No se encontró registro SPF; es una oportunidad de mejora contra la suplantación de correo", confidence="high"))

    try:
        dmarc_txt = [b"".join(r.strings).decode(errors="ignore") for r in dns.resolver.resolve(f"_dmarc.{registered_domain}", "TXT", lifetime=TIMEOUT)]
        dmarc = [t for t in dmarc_txt if t.lower().startswith("v=dmarc1")]
    except Exception:
        dmarc = []
    if dmarc:
        policy = "desconocida"
        for part in dmarc[0].split(";"):
            part = part.strip()
            if part.lower().startswith("p="):
                policy = part.split("=", 1)[1]
        sev = "info" if policy in ("reject", "quarantine") else "low"
        findings.append(_finding("dmarc", "DMARC", sev, "pass" if sev == "info" else "warn", f"{dmarc[0]} (policy={policy})"))
    else:
        findings.append(_finding("dmarc", "DMARC", "medium", "warn", "No se encontró registro DMARC; es una oportunidad de mejora contra phishing y suplantación", confidence="high"))

    return findings


# ---------------------------------------------------------------- WHOIS ----

def check_whois(registered_domain):
    try:
        w = whois.whois(registered_domain)
        exp = w.expiration_date
        if isinstance(exp, list):
            exp = exp[0]
        detail_parts = []
        if w.registrar:
            detail_parts.append(f"Registrador: {w.registrar}")
        sev, status = "info", "pass"
        if exp:
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            days_left = (exp - datetime.now(timezone.utc)).days
            detail_parts.append(f"Expira: {exp.date()} ({days_left} días)")
            if days_left < 30:
                sev, status = "high", "fail"
            elif days_left < 90:
                sev, status = "medium", "warn"
        if not detail_parts:
            return [_finding("whois", "WHOIS", "low", "warn", "Datos WHOIS no disponibles (posible privacidad o WHOIS server sin respuesta)")]
        return [_finding("whois", "WHOIS / expiración de dominio", sev, status, "; ".join(detail_parts))]
    except Exception as e:
        return [_finding("whois", "WHOIS", "low", "warn", f"No se pudo consultar WHOIS ({e.__class__.__name__})")]


# ---------------------------------------------------------------- TLS ----

def check_tls(host):
    findings = []
    try:
        _assert_public_host(host)
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                proto = ssock.version()
        cert = x509.load_der_x509_certificate(der, default_backend())
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
        sev, status = "info", "pass"
        if days_left < 15:
            sev, status = "high", "fail"
        elif days_left < 30:
            sev, status = "medium", "warn"
        findings.append(_finding("tls-cert", "Certificado TLS", sev, status, f"Expira {not_after.date()} ({days_left} días) — protocolo: {proto}"))

        weak_sig = any(a in cert.signature_algorithm_oid._name.lower() for a in ["md5", "sha1"]) if cert.signature_algorithm_oid else False
        if weak_sig:
            findings.append(_finding("tls-sig", "Algoritmo de firma del certificado", "medium", "fail", cert.signature_algorithm_oid._name))

        if proto in ("TLSv1", "TLSv1.1"):
            findings.append(_finding("tls-version", "Versión de TLS", "high", "fail", f"Protocolo obsoleto en uso: {proto}"))
        else:
            findings.append(_finding("tls-version", "Versión de TLS", "info", "pass", proto))
    except ssl.SSLCertVerificationError as e:
        findings.append(_finding("tls-cert", "Certificado TLS", "high", "fail", f"Certificado inválido/no confiable: {e.verify_message if hasattr(e,'verify_message') else e}"))
    except Exception as e:
        findings.append(_finding("tls-cert", "Certificado TLS / HTTPS", "high", "fail", f"No se pudo establecer HTTPS en el puerto 443 ({e.__class__.__name__})"))
    return findings


# ---------------------------------------------------------------- HTTP ----

def _get(url, allow_redirects=True):
    parsed = urlparse(url)
    allowed_registered = _registered_from_host(parsed.hostname) if parsed.hostname else None
    return _safe_get(url, allow_redirects=allow_redirects, allowed_registered=allowed_registered)


def check_https_redirect(host):
    try:
        registered = _registered_from_host(host)
        r = _safe_get(f"http://{host}", allow_redirects=True, allowed_registered=registered)
        final = urlparse(r.url or "")
        if final.scheme == "https" and _registered_from_host(final.hostname or "") == registered:
            return [_finding("http-redirect", "Redirección HTTP -> HTTPS", "info", "pass", f"Redirige a {r.url}")]
        if final.scheme == "http":
            return [_finding("http-redirect", "Redirección HTTP -> HTTPS", "high", "fail", "El sitio sirve contenido en HTTP plano sin forzar HTTPS")]
        return [_finding("http-redirect", "Redirección HTTP -> HTTPS", "medium", "warn", "La respuesta redirige fuera del dominio autorizado o no permite confirmar HTTPS")]
    except Exception as e:
        return [_finding("http-redirect", "Redirección HTTP -> HTTPS", "low", "warn", f"No se pudo verificar ({e.__class__.__name__})")]


HEADER_CHECKS = [
    ("Strict-Transport-Security", "hsts", "medium", "Fuerza HTTPS en el navegador (protege contra downgrade/sslstrip)"),
    ("Content-Security-Policy", "csp", "medium", "Mitiga XSS e inyección de contenido"),
    ("X-Content-Type-Options", "xcto", "low", "Evita MIME-sniffing"),
    ("X-Frame-Options", "xfo", "low", "Mitiga clickjacking (si no hay CSP frame-ancestors)"),
    ("Referrer-Policy", "refpol", "low", "Controla fuga de datos vía header Referer"),
    ("Permissions-Policy", "permpol", "low", "Restringe APIs del navegador (cámara, geo, etc.)"),
]


def check_security_headers(url):
    findings = []
    try:
        r = _get(url)
        if r.status_code >= 400:
            return [_finding("http-headers", "Headers de seguridad HTTP", "info", "warn", f"La URL respondió HTTP {r.status_code}; no se evalúan ausencias de headers sobre una respuesta no representativa", confidence="high")]
        headers = {k.lower(): v for k, v in r.headers.items()}
        for header_name, hid, sev, why in HEADER_CHECKS:
            if header_name.lower() in headers:
                findings.append(_finding(f"hdr-{hid}", header_name, "info", "pass", headers[header_name.lower()][:120], confidence="high"))
            else:
                findings.append(_finding(f"hdr-{hid}", header_name, sev, "warn", f"Header ausente. {why}", confidence="high"))

        server = headers.get("server")
        powered_by = headers.get("x-powered-by")
        if server or powered_by:
            findings.append(_finding("info-disclosure", "Divulgación de información en headers", "low", "warn",
                                      f"Server: {server or '-'} | X-Powered-By: {powered_by or '-'}"))

        cookies = []
        get_all = getattr(getattr(r, "raw", None), "headers", None)
        if get_all is not None and hasattr(get_all, "getlist"):
            cookies = list(get_all.getlist("Set-Cookie"))
        if not cookies and r.headers.get("Set-Cookie"):
            cookies = [r.headers.get("Set-Cookie")]
        if cookies:
            bad_cookies = [cookie for cookie in cookies if "secure" not in cookie.lower() or "httponly" not in cookie.lower()]
            if bad_cookies:
                findings.append(_finding("cookie-flags", "Flags de cookies (Secure/HttpOnly)", "medium", "warn",
                                          f"{len(bad_cookies)} cookie(s) no tienen Secure y/o HttpOnly", confidence="high"))
            else:
                findings.append(_finding("cookie-flags", "Flags de cookies (Secure/HttpOnly)", "info", "pass", "OK", confidence="high"))
    except Exception as e:
        findings.append(_finding("http-headers", "Headers de seguridad HTTP", "medium", "warn", f"No se pudo obtener respuesta HTTP ({e.__class__.__name__})"))
    return findings


EXPOSURE_PATHS = [
    ("/.env", "env-file", "high", "Archivo .env potencialmente expuesto (credenciales/secrets)"),
    ("/.git/HEAD", "git-exposed", "high", "Repositorio .git expuesto públicamente (código fuente descargable)"),
    ("/.git/config", "git-config-exposed", "high", "Archivo .git/config expuesto"),
    ("/wp-config.php.bak", "wp-config-bak", "high", "Backup de configuración de WordPress expuesto"),
]


def check_common_exposures(url):
    findings = []
    try:
        probe = _get(url.rstrip("/") + "/__lightvulnscan_nonexistent_probe__", allow_redirects=False)
        soft_404 = probe.status_code == 200
    except Exception:
        soft_404 = False

    if soft_404:
        return [_finding("exposure-check", "Archivos sensibles expuestos", "info", "warn",
                          "El sitio devuelve 200 para rutas inexistentes (soft-404); esta verificación no es concluyente")]

    for path, hid, sev, why in EXPOSURE_PATHS:
        try:
            r = _get(url.rstrip("/") + path, allow_redirects=False)
            body = r.content[:65536]
            signatures = {
                "env-file": b"=",
                "git-exposed": b"ref: ",
                "git-config-exposed": b"[core]",
                "wp-config-bak": b"DB_",
            }
            content_type = r.headers.get("Content-Type", "").lower()
            env_like = bool(re.search(rb"(?m)^[A-Za-z_][A-Za-z0-9_]*\s*=", body)) and b"<html" not in body.lower()
            matches = {
                "env-file": env_like,
                "git-exposed": body.startswith(b"ref: "),
                "git-config-exposed": b"[core]" in body and b"repositoryformatversion" in body,
                "wp-config-bak": b"DB_" in body and (b"<?php" in body or b"define(" in body),
            }.get(hid, False)
            if r.status_code == 200 and body and "text/html" not in content_type and matches:
                findings.append(_finding(hid, path, sev, "fail", why, confidence="high", evidence={"status_code": 200, "signature": signatures[hid].decode(errors="replace")}))
        except Exception:
            continue
    if not findings:
        findings.append(_finding("exposure-check", "Archivos sensibles expuestos", "info", "pass", "No se detectaron archivos comunes expuestos"))
    return findings


def check_security_txt(url):
    for path in ["/.well-known/security.txt", "/security.txt"]:
        try:
            r = _get(url.rstrip("/") + path)
            if r.status_code == 200 and "contact" in r.text.lower():
                return [_finding("security-txt", "security.txt", "info", "pass", f"Presente en {path}")]
        except Exception:
            continue
    return [_finding("security-txt", "security.txt", "low", "warn", "No se encontró security.txt (buena práctica para reporte de vulnerabilidades)")]


# ---------------------------------------------------------------- runner ----

def run_all_checks(name, raw_url):
    registered_domain, host, url = normalize_domain(raw_url)
    findings = []
    errors = []

    try:
        _assert_public_host(host)
    except TargetScopeError as exc:
        return {
            "name": name,
            "input_url": raw_url,
            "domain": registered_domain,
            "host": host,
            "scanned_url": url,
            "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "findings": [_finding("scope", "Destino fuera de alcance", "info", "error", str(exc))],
            "errors": [f"Scope: {exc}"],
            "score": 0,
            "grade": "N/A",
            "scope_valid": False,
        }

    steps = [
        ("DNS", lambda: check_dns_records(registered_domain)),
        ("DNSSEC", lambda: check_dnssec(registered_domain)),
        ("Email auth (SPF/DMARC)", lambda: check_email_auth(registered_domain)),
        ("WHOIS", lambda: check_whois(registered_domain)),
        ("TLS", lambda: check_tls(host)),
        ("HTTP->HTTPS redirect", lambda: check_https_redirect(host)),
        ("Security headers", lambda: check_security_headers(url)),
        ("security.txt", lambda: check_security_txt(url)),
        ("Exposiciones comunes", lambda: check_common_exposures(url)),
    ]

    for label, fn in steps:
        try:
            findings.extend(fn())
        except Exception as e:
            errors.append(f"{label}: {e.__class__.__name__}: {e}")

    score = calculate_score(findings)
    score = max(0, min(100, score))

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return {
        "name": name,
        "input_url": raw_url,
        "domain": registered_domain,
        "host": host,
        "scanned_url": url,
        "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "findings": findings,
        "errors": errors,
        "score": score,
        "grade": grade,
        "scope_valid": True,
    }


def calculate_score(findings):
    """Conservative posture score; missing best practices are warnings, not breaches."""
    by_category = {}
    for finding in findings:
        amount = SCORE_DEDUCTION.get((finding.get("status"), finding.get("severity")), 0)
        category = finding.get("category", "general")
        by_category[category] = by_category.get(category, 0) + amount
    deduction = sum(min(amount, CATEGORY_CAPS.get(category, amount)) for category, amount in by_category.items())
    return max(0, min(100, 100 - deduction))
