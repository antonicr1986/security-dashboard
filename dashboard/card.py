"""Tarjeta resumen en SVG para incrustar en un README (función pura, sin red).

Lleva su propio fondo para verse igual en el tema claro y en el oscuro de GitHub,
y no usa fuentes ni recursos externos: GitHub sirve los SVG como imagen estática.
"""
from xml.sax.saxutils import escape

WIDTH, HEIGHT = 840, 352
_FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif"
_BG, _TILE, _BORDER, _TRACK = "#161b22", "#0d1117", "#30363d", "#21262d"
_TEXT, _MUTED = "#e6edf3", "#8b949e"
_GREEN, _AMBER, _RED, _GREY = "#3fb950", "#d29922", "#f85149", "#6e7681"
_SEVERITY_COLORS = {"critical": _RED, "high": "#f0883e", "medium": _AMBER, "low": _MUTED}

TEXTS = {
    "es": {
        "title": "Seguridad de mis repositorios",
        "subtitle": "{repos} repos · actualizado el {date} · informe semanal automático",
        "gate_ok": "Quality gate superado",
        "gate_fail": "Quality gate no superado",
        "open": "Vulnerabilidades abiertas",
        "critical": "crítica",
        "high": "alta",
        "medium": "media",
        "low": "baja",
        "secrets": "Secretos expuestos",
        "mttr": "Resolución media",
        "days": "días",
        "accepted": "Riesgos aceptados",
        "coverage": "Cobertura de controles",
        "pinned": "Actions fijadas por SHA",
        "permissions": "Workflows con permisos mínimos",
        "sla": "Alertas resueltas en plazo (SLA)",
        "no_data": "sin datos",
    },
    "en": {
        "title": "Security across my repositories",
        "subtitle": "{repos} repos · updated on {date} · automated weekly report",
        "gate_ok": "Quality gate passed",
        "gate_fail": "Quality gate failed",
        "open": "Open vulnerabilities",
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "secrets": "Exposed secrets",
        "mttr": "Mean time to fix",
        "days": "days",
        "accepted": "Accepted risks",
        "coverage": "Security control coverage",
        "pinned": "Actions pinned to a SHA",
        "permissions": "Workflows with least privilege",
        "sla": "Alerts fixed within SLA",
        "no_data": "no data",
    },
}


def _text(x, y, content, size=13, color=_TEXT, weight="400", anchor="start"):
    return (
        f'<text x="{x}" y="{y}" font-size="{size}" fill="{color}" font-weight="{weight}" '
        f'text-anchor="{anchor}">{escape(str(content))}</text>'
    )


def _tile(x, y, width, height):
    return f'<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="10" fill="{_TILE}" stroke="{_BORDER}"/>'


def _level(pct):
    """Color de una barra: verde si va bien, ámbar si flojea, rojo si falla, gris sin datos."""
    if pct is None:
        return _GREY
    return _GREEN if pct >= 95 else _AMBER if pct >= 80 else _RED


def _bar(x, y, width, label, pct, texts):
    value = texts["no_data"] if pct is None else f"{pct} %"
    filled = 0 if pct is None else round(width * max(0, min(pct, 100)) / 100)
    parts = [
        _text(x, y, label, color=_MUTED),
        _text(x + width, y, value, weight="600", anchor="end"),
        f'<rect x="{x}" y="{y + 10}" width="{width}" height="8" rx="4" fill="{_TRACK}"/>',
    ]
    if filled:
        parts.append(f'<rect x="{x}" y="{y + 10}" width="{filled}" height="8" rx="4" fill="{_level(pct)}"/>')
    return parts


def render_card(summary, lang="es"):
    """SVG con los KPIs principales del resumen (el mismo dict que data/latest.json)."""
    texts = TEXTS[lang]
    totals = summary["totals"]
    passed = not summary["gate"]["failures"]
    gate_color = _GREEN if passed else _RED

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}" '
        f'role="img" aria-label="{escape(texts["title"])}" font-family="{_FONT}">',
        f'<rect x="0.5" y="0.5" width="{WIDTH - 1}" height="{HEIGHT - 1}" rx="14" fill="{_BG}" stroke="{_BORDER}"/>',
        _text(32, 48, texts["title"], size=21, weight="600"),
        _text(
            32,
            72,
            texts["subtitle"].format(repos=len(summary["repos"]), date=summary["generated_at"][:10]),
            color=_MUTED,
        ),
        # Estado del quality gate, arriba a la derecha
        f'<rect x="{WIDTH - 262}" y="28" width="230" height="34" rx="17" fill="{gate_color}" fill-opacity="0.15" stroke="{gate_color}"/>',
        f'<circle cx="{WIDTH - 240}" cy="45" r="5" fill="{gate_color}"/>',
        _text(WIDTH - 226, 50, texts["gate_ok" if passed else "gate_fail"], size=14, color=gate_color, weight="600"),
    ]

    # Fila de cifras: vulnerabilidades por severidad y tres contadores
    top, height = 96, 104
    parts += [_tile(32, top, 356, height), _text(52, top + 28, texts["open"], color=_MUTED)]
    for index, severity in enumerate(("critical", "high", "medium", "low")):
        count = totals["open"][severity]
        x = 52 + index * 84
        color = _SEVERITY_COLORS[severity] if count else _TEXT
        parts += [
            _text(x, top + 68, count, size=30, color=color, weight="600"),
            _text(x, top + 88, texts[severity], size=12, color=_MUTED),
        ]

    mttr = totals["mttr_days"]
    counters = [
        (texts["secrets"], totals["secrets"], "", _RED if totals["secrets"] else _TEXT),
        (texts["mttr"], "—" if mttr is None else mttr, "" if mttr is None else texts["days"], _TEXT),
        (texts["accepted"], totals.get("accepted_risks", 0), "", _TEXT),
    ]
    for index, (label, value, unit, color) in enumerate(counters):
        x = 400 + index * 139
        parts += [
            _tile(x, top, 130, height),
            _text(x + 16, top + 28, label, size=12, color=_MUTED),
            _text(x + 16, top + 68, value, size=30, color=color, weight="600"),
        ]
        if unit:
            parts.append(_text(x + 16, top + 88, unit, size=12, color=_MUTED))

    # Barras de porcentaje, en dos columnas
    bars = [
        (texts["coverage"], totals["control_coverage_pct"]),
        (texts["pinned"], totals.get("actions_pinned_pct")),
        (texts["permissions"], totals.get("workflows_with_permissions_pct")),
        (texts["sla"], totals.get("sla_pct")),
    ]
    for index, (label, pct) in enumerate(bars):
        x = 32 + (index % 2) * 396
        y = 244 + (index // 2) * 58
        parts += _bar(x, y, 380, label, pct, texts)

    parts.append("</svg>")
    return "\n".join(parts) + "\n"
