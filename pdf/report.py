"""Renders one neutral, technical PDF per company from a scan result dict."""
import re
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
)

_ASSETS_DIR = Path(__file__).parent / "assets"

# Header/footer banners cropped directly from the company's approved Word
# template (logo already baked into the header banner at its designed size).
_HEADER_BANNER = ImageReader(str(_ASSETS_DIR / "header_banner2.png"))
_FOOTER_BANNER = ImageReader(str(_ASSETS_DIR / "footer_banner2.png"))
_HEADER_BANNER_W_PX, _HEADER_BANNER_H_PX = _HEADER_BANNER.getSize()
_FOOTER_BANNER_W_PX, _FOOTER_BANNER_H_PX = _FOOTER_BANNER.getSize()

# Natural render height (in points) of each banner when stretched to a full
# LETTER-width page, so the body's margins always clear them.
_HEADER_H = LETTER[0] * _HEADER_BANNER_H_PX / _HEADER_BANNER_W_PX
_FOOTER_H = LETTER[0] * _FOOTER_BANNER_H_PX / _FOOTER_BANNER_W_PX

PAGE_MARGIN = 18 * mm


def _draw_page_frame(canvas, doc):
    """Draws the corporate header/footer banner on every page."""
    page_w, page_h = doc.pagesize
    canvas.saveState()

    header_h = page_w * _HEADER_BANNER_H_PX / _HEADER_BANNER_W_PX
    canvas.drawImage(_HEADER_BANNER, 0, page_h - header_h, width=page_w, height=header_h, mask="auto")

    footer_h = page_w * _FOOTER_BANNER_H_PX / _FOOTER_BANNER_W_PX
    canvas.drawImage(_FOOTER_BANNER, 0, 0, width=page_w, height=footer_h, mask="auto")

    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#9CA3AF"))
    canvas.drawString(PAGE_MARGIN, footer_h + 2 * mm, "Todos los derechos reservados Kennertech")

    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.white)
    canvas.drawCentredString(page_w - 30 * mm, 22 * mm, "www.kennertech.com.co")
    canvas.drawCentredString(page_w - 30 * mm, 17 * mm, "Bogotá D.C. - 601 9178450")

    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#9CA3AF"))
    canvas.drawRightString(page_w - PAGE_MARGIN, footer_h + 2 * mm, f"Página {canvas.getPageNumber()}")

    canvas.restoreState()

GRADE_COLOR = {
    "A": colors.HexColor("#1a7f37"),
    "B": colors.HexColor("#4d9221"),
    "C": colors.HexColor("#c9a227"),
    "D": colors.HexColor("#d97316"),
    "F": colors.HexColor("#c22b2b"),
}

SEV_COLOR = {
    "high": colors.HexColor("#c22b2b"),
    "medium": colors.HexColor("#d97316"),
    "low": colors.HexColor("#c9a227"),
    "info": colors.HexColor("#4b5563"),
}

CONF_COLOR = {"high": colors.HexColor("#b00020"), "mid": colors.HexColor("#a86200"), "low": colors.HexColor("#2e7d32")}


def _xml(value):
    """Escape untrusted scanner/API/model content before ReportLab parses it."""
    return escape(str(value if value is not None else ""), {"'": "&apos;", '"': "&quot;"})


def _confidence_bucket(confidence):
    if confidence >= 90:
        return "high"
    if confidence >= 50:
        return "mid"
    return "low"


_PATTERN_TOKEN_LABELS = {
    "first": "nombre",
    "last": "apellido",
    "f": "inicial del nombre",
    "l": "inicial del apellido",
    "m": "inicial del segundo nombre",
}


def _humanize_pattern(pattern):
    """Turns a Hunter.io pattern like '{first}.{last}' into 'nombre.apellido'."""
    if not pattern:
        return None
    segments = re.findall(r"\{(\w+)\}|([^{}]+)", pattern)
    out = []
    prev_was_token = False
    for token, literal in segments:
        if token:
            if prev_was_token:
                out.append(" + ")
            out.append(_PATTERN_TOKEN_LABELS.get(token.lower(), token))
            prev_was_token = True
        else:
            out.append(literal)
            prev_was_token = False
    return "".join(out)


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("H1", parent=ss["Heading1"], fontSize=18, spaceAfter=4))
    ss.add(ParagraphStyle("H2", parent=ss["Heading2"], fontSize=13, spaceBefore=14, spaceAfter=6, textColor=colors.HexColor("#1f2937")))
    ss.add(ParagraphStyle("Meta", parent=ss["Normal"], fontSize=9, textColor=colors.HexColor("#4b5563")))
    ss.add(ParagraphStyle("GradeLetter", parent=ss["Normal"], fontSize=28, leading=34, alignment=TA_CENTER))
    ss.add(ParagraphStyle("Cell", parent=ss["Normal"], fontSize=8.5, leading=11))
    ss.add(ParagraphStyle("CellBold", parent=ss["Cell"], fontName="Helvetica-Bold"))
    ss.add(ParagraphStyle("TableHeader", parent=ss["CellBold"], textColor=colors.white))
    return ss


def _obfuscate_email(value):
    """'juan.perez@domain.com' -> 'jua****@domain.com'."""
    if not value or "@" not in value:
        return value
    local, domain = value.split("@", 1)
    return f"{local[:3]}****@{domain}"


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _obfuscate_emails_in_text(text):
    return _EMAIL_RE.sub(lambda m: _obfuscate_email(m.group(0)), str(text))


def _build_hunter_section(story, styles, hunter):
    story.append(Paragraph("Exposición de correos públicos (Hunter.io)", styles["H1"]))

    if not hunter.get("enabled"):
        story.append(Paragraph(
            "No se ejecutó esta verificación: no se proporcionó una API key de Hunter.io "
            "(variable de entorno <b>HUNTER_API_KEY</b> o argumento --hunter-api-key).",
            styles["Meta"],
        ))
        return

    if hunter.get("error"):
        story.append(Paragraph(
            f"<b>No fue posible completar la consulta a Hunter.io para este dominio.</b><br/>"
            f"Detalle: {_xml(hunter['error'])}",
            styles["Meta"],
        ))
        return

    emails = hunter["emails"]
    meta = hunter.get("meta", {})
    pattern = _humanize_pattern(hunter.get("pattern")) or "(no detectado)"
    named_count = sum(1 for e in emails if e.get("first_name"))
    has_decision_maker = any(e.get("decision_maker") for e in emails)

    story.append(Paragraph(
        "Recolección de direcciones de correo ya publicadas en internet (sitios web, LinkedIn y otras "
        "fuentes públicas indexadas por Hunter.io Domain Search). No se realizó ningún acceso no autorizado "
        "a sistemas ni verificación de brechas de seguridad (HaveIBeenPwned) — ese cruce requiere que el "
        "titular del dominio lo verifique ante HIBP o lo autorice expresamente por escrito, ya que implica "
        f"datos personales de terceros (Ley 1581 de 2012). Resultados limitados por el plan de Hunter.io "
        f"({_xml(meta.get('limit'))} de {_xml(meta.get('results'))} correos totales estimados).",
        styles["Meta"],
    ))
    story.append(Spacer(1, 4 * mm))

    stats = Table(
        [[
            Paragraph(f"<b>{meta.get('results')}</b><br/><font size=8>Total estimado</font>", styles["Normal"]),
            Paragraph(f"<b>{_xml(pattern)}</b><br/><font size=8>Patrón de nomenclatura</font>", styles["Normal"]),
            Paragraph(f"<b>{named_count}</b><br/><font size=8>Personas identificables</font>", styles["Normal"]),
        ]],
        colWidths=[55 * mm] * 3,
    )
    stats.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#d1d5db")),
        ("INNERGRID", (0, 0), (-1, -1), 0.75, colors.HexColor("#d1d5db")),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f4f6fb")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(stats)
    story.append(Spacer(1, 5 * mm))

    if not emails:
        story.append(Paragraph("No se encontraron correos públicos indexados para este dominio.", styles["Meta"]))
        return

    detail_mode = hunter.get("show_details")
    if detail_mode is True:
        detail_mode = "full"
    elif not detail_mode:
        detail_mode = "none"

    if detail_mode == "none":
        story.append(Paragraph(
            "Por protección de datos, este informe ejecutivo muestra únicamente cantidades y patrones agregados. "
            "El detalle de direcciones individuales se reserva para una revisión autorizada y con base legal definida.",
            styles["Meta"],
        ))
        return

    if detail_mode == "obfuscated":
        story.append(Paragraph(
            "Por protección de datos, las direcciones se muestran parcialmente ofuscadas "
            "(primeras 3 letras del usuario).",
            styles["Meta"],
        ))
        story.append(Spacer(1, 2 * mm))

    header = [Paragraph(h, styles["TableHeader"]) for h in ["Correo", "Tipo", "Nombre / Cargo", "Confianza", "Fuente"]]
    rows = [header]
    for e in emails:
        tipo = "Personal" if e.get("type") == "personal" else "Genérico"
        if e.get("first_name"):
            name = f"{e.get('first_name')} {e.get('last_name') or ''}".strip()
        else:
            name = "(no identificado)"
        position = f" — {e['position_raw']}" if e.get("position_raw") else ""
        decision_tag = " <b>(Decision maker)</b>" if e.get("decision_maker") else ""
        conf = e.get("confidence", 0) or 0
        conf_color = CONF_COLOR[_confidence_bucket(conf)]
        sources = e.get("sources") or []
        source = sources[0]["domain"] if sources else "(desconocida)"

        email_value = e.get("value", "")
        if detail_mode == "obfuscated":
            email_value = _obfuscate_email(email_value)

        rows.append([
            Paragraph(_xml(email_value), styles["Cell"]),
            Paragraph(tipo, styles["Cell"]),
            Paragraph(f"{_xml(name)}{_xml(position)}{decision_tag}", styles["Cell"]),
            Paragraph(f"<font color='{conf_color.hexval()}'><b>{conf}%</b></font>", styles["Cell"]),
            Paragraph(_xml(source), styles["Cell"]),
        ])

    tbl = Table(rows, colWidths=[45 * mm, 18 * mm, 62 * mm, 18 * mm, 22 * mm], repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2b3a67")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fc")]),
    ]))
    story.append(tbl)

    if has_decision_maker:
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph(
            "Se identificaron correos de personas con rol de decisión, lo que eleva el riesgo de fraude "
            "dirigido (spear-phishing / Business Email Compromise).",
            styles["Meta"],
        ))


def _safe_filename(s):
    s = re.sub(r"[^\w\-. ]", "_", s).strip().replace(" ", "_")
    return s[:120] or "empresa"


def _build_amass_summary_section(story, styles, tooling, amass_summary):
    amass_tool = next((t for t in (tooling or []) if t.get("tool") == "amass"), None)

    if amass_tool and amass_tool.get("status") == "error":
        return

    if not amass_summary or not amass_summary.get("enabled") or amass_summary.get("error"):
        return

    text = amass_summary.get("text")
    if not text:
        return

    story.append(Paragraph("Exposición externa", styles["H2"]))
    story.append(Paragraph(_xml(_obfuscate_emails_in_text(text)), styles["Normal"]))
    story.append(Spacer(1, 4 * mm))


def _build_cta_section(story, styles):
    story.append(Paragraph("Siguiente paso recomendado", styles["H2"]))
    story.append(Paragraph(
        "Comunícate con nuestro equipo de ciberseguridad o de consultoría para coordinar una sesión presencial "
        "o virtual contigo y tu equipo de sistemas y extender el análisis del informe presentado, donde veremos:",
        styles["Normal"],
    ))
    story.append(Spacer(1, 2 * mm))
    for item in (
        "Validación técnica de los hallazgos identificados.",
        "Recomendaciones técnicas y estratégicas proporcionales al nivel de riesgo identificado.",
    ):
        story.append(Paragraph(f"•&nbsp;&nbsp;{_xml(item)}", styles["Normal"]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        "<b>Datos de contacto:</b><br/>Nombre: Vanessa Vargas Fernandez"
        "<br/>Correo: negocios1@kennertech.com.co<br/>Teléfono: 310 4936250",
        styles["Normal"],
    ))
    story.append(Spacer(1, 4 * mm))


def build_pdf(result, output_path):
    styles = _styles()
    doc = SimpleDocTemplate(
        output_path, pagesize=LETTER,
        topMargin=_HEADER_H + 6 * mm,
        bottomMargin=_FOOTER_H + 6 * mm,
        leftMargin=PAGE_MARGIN, rightMargin=PAGE_MARGIN,
        title=f"Analisis de vulnerabilidades (light) - {result['name']}",
    )
    story = []

    story.append(Paragraph("Evaluación ejecutiva de exposición digital", styles["H1"]))
    story.append(Paragraph(
        f"<b>{_xml(result['name'])}</b> &nbsp;|&nbsp; {_xml(result['scanned_url'])} &nbsp;|&nbsp; Escaneado: {_xml(result['scan_date'])}",
        styles["Meta"],
    ))
    story.append(Spacer(1, 4 * mm))

    grade_color = GRADE_COLOR.get(result["grade"], colors.grey)
    summary_tbl = Table(
        [[Paragraph(f"<font color='{grade_color.hexval()}'><b>{result['grade']}</b></font>", styles["GradeLetter"]),
          Paragraph(
              f"Hallazgos de riesgo: {sum(1 for f in result['findings'] if f['status']=='fail')} &nbsp; "
              f"Atención: {sum(1 for f in result['findings'] if f['status']=='warn')} &nbsp; "
              f"OK: {sum(1 for f in result['findings'] if f['status']=='pass')}",
              styles["Normal"],
          )]],
        colWidths=[25 * mm, 140 * mm],
    )
    summary_tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#d1d5db")),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f9fafb")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_tbl)
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(
        "<b>A</b> Excelente &nbsp;·&nbsp; <b>B</b> Buena &nbsp;·&nbsp; <b>C</b> Aceptable, requiere atención "
        "&nbsp;·&nbsp; <b>D</b> Débil, riesgos relevantes &nbsp;·&nbsp; <b>F</b> Crítica, acción inmediata",
        styles["Meta"],
    ))
    story.append(Spacer(1, 6 * mm))

    for para in (
        "Este documento presenta una evaluación externa y preliminar de la exposición digital, de alcance "
        "limitado, elaborada únicamente a partir de información y señales públicamente accesibles desde "
        "Internet. La revisión considera elementos como registros DNS y WHOIS, certificados TLS, cabeceras "
        "HTTP de seguridad y registros de autenticación de correo.",

        "Durante esta evaluación no se realizaron intentos de intrusión, explotación, acceso no autorizado a "
        "sistemas, escaneo de puertos, análisis de infraestructura interna ni acciones que pudieran afectar "
        "la disponibilidad de los servicios. Los hallazgos presentados corresponden exclusivamente a "
        "información que puede ser identificada desde una perspectiva externa y mediante fuentes públicas.",

        "Podría compararse con observar una vivienda desde la calle y notar que una puerta o ventana se "
        "encuentra abierta: no ingresamos a la propiedad ni interactuamos con su interior; simplemente "
        "identificamos una posible condición visible y alertamos sobre ella.",

        "Por este motivo, los resultados deben interpretarse como una evaluación preliminar de posibles "
        "condiciones de exposición. Un análisis de seguridad más completo podría ampliar el alcance hacia "
        "otros componentes de la superficie de ataque, incluyendo aplicaciones, infraestructura de red, "
        "mecanismos de autenticación y dependencias, así como la validación de las medidas de remediación "
        "implementadas.",
    ):
        story.append(Paragraph(para, styles["Normal"]))
        story.append(Spacer(1, 3 * mm))
    story.append(Spacer(1, 1 * mm))

    order = {"fail": 0, "warn": 1, "error": 2}
    findings_sorted = sorted(
        (f for f in result["findings"] if f["status"] != "pass"),
        key=lambda f: (order.get(f["status"], 9), -{"high": 3, "medium": 2, "low": 1, "info": 0}.get(f["severity"], 0)),
    )

    story.append(Paragraph("Hallazgos relevantes y próximos pasos", styles["H2"]))
    header = [Paragraph(h, styles["TableHeader"]) for h in ["Severidad", "Check", "Detalle"]]
    rows = [header]
    for f in findings_sorted:
        sev_color = SEV_COLOR.get(f["severity"], colors.grey)
        detail_parts = [f.get("detail", "")]
        if f.get("business_impact"):
            detail_parts.append(f"Impacto para el negocio: {f['business_impact']}")
        detail = _obfuscate_emails_in_text(" ".join(str(part) for part in detail_parts if part))
        rows.append([
            Paragraph(f"<font color='{sev_color.hexval()}'><b>{_xml(f.get('severity', '')).capitalize()}</b></font>", styles["Cell"]),
            Paragraph(_xml(f.get("title")), styles["Cell"]),
            Paragraph(_xml(detail), styles["Cell"]),
        ])

    tbl = Table(rows, colWidths=[22 * mm, 48 * mm, 95 * mm], repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2b3a67")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fc")]),
    ]))
    story.append(tbl)

    if result["errors"]:
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph("Notas técnicas", styles["H2"]))
        for e in result["errors"]:
            story.append(Paragraph(f"- {_xml(e)}", styles["Meta"]))

    _build_amass_summary_section(story, styles, result.get("tooling"), result.get("amass_summary"))

    if result.get("hunter") is not None:
        _build_hunter_section(story, styles, result["hunter"])

    _build_cta_section(story, styles)

    doc.build(story, onFirstPage=_draw_page_frame, onLaterPages=_draw_page_frame)
    return output_path
