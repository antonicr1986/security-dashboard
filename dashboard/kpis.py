"""Cálculo de KPIs de seguridad a partir de alertas de GitHub.

Son funciones puras (sin red), para poder probarlas con datos de ejemplo.
"""
from dataclasses import dataclass
from datetime import datetime

SEVERITIES = ("critical", "high", "medium", "low")
SECRET_SOURCE = "secret-scanning"

# Valor de un control que el repo no puede tener por ser privado (CodeQL en un repo
# privado requiere licencia de GitHub Advanced Security). Es un riesgo aceptado:
# no cuenta en la cobertura, pero el informe lo muestra aparte.
PRIVATE = "private"

# Reglas de CodeQL sin nivel de seguridad: se aproximan con su gravedad de lint.
_FALLBACK_SEVERITY = {"error": "high", "warning": "medium", "note": "low"}

# Control -> fragmentos que delatan que el pipeline lo ejecuta.
CONTROLS = {
    "SAST": ("github/codeql-action",),
    "SCA": ("dependency-review-action", "npm audit", "--vulnerable"),
    "Secretos": ("gitleaks",),
    "Contenedores/IaC": ("trivy",),
    "DAST": ("zaproxy",),
}


@dataclass(frozen=True)
class Alert:
    source: str  # dependabot | code-scanning | secret-scanning
    severity: str  # una de SEVERITIES (los secretos usan "n/a")
    state: str  # open | fixed | dismissed
    created_at: datetime
    fixed_at: datetime | None = None


def parse_time(value):
    """Convierte '2026-11-10T20:16:25Z' en datetime con zona horaria."""
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def from_dependabot(raw):
    advisory = raw.get("security_advisory") or raw.get("security_vulnerability") or {}
    severity = (advisory.get("severity") or "low").lower()
    state = "dismissed" if raw["state"] in ("dismissed", "auto_dismissed") else raw["state"]
    return Alert(
        "dependabot",
        severity if severity in SEVERITIES else "low",
        state,
        parse_time(raw["created_at"]),
        parse_time(raw.get("fixed_at")),
    )


def from_code_scanning(raw):
    rule = raw.get("rule") or {}
    severity = rule.get("security_severity_level") or _FALLBACK_SEVERITY.get(rule.get("severity"), "low")
    return Alert(
        "code-scanning",
        severity if severity in SEVERITIES else "low",
        raw["state"],
        parse_time(raw["created_at"]),
        parse_time(raw.get("fixed_at")),
    )


def from_secret_scanning(raw):
    state = "open" if raw["state"] == "open" else "fixed"
    return Alert(
        SECRET_SOURCE, "n/a", state, parse_time(raw["created_at"]), parse_time(raw.get("resolved_at"))
    )


def open_by_severity(alerts):
    """Vulnerabilidades abiertas por severidad (los secretos se cuentan aparte)."""
    counts = dict.fromkeys(SEVERITIES, 0)
    for alert in alerts:
        if alert.state == "open" and alert.source != SECRET_SOURCE:
            counts[alert.severity] += 1
    return counts


def open_secrets(alerts):
    return sum(1 for a in alerts if a.state == "open" and a.source == SECRET_SOURCE)


def mttr_days(alerts):
    """Tiempo medio de resolución en días y nº de alertas resueltas (solo 'fixed')."""
    days = [
        (a.fixed_at - a.created_at).total_seconds() / 86400
        for a in alerts
        if a.state == "fixed" and a.fixed_at
    ]
    if not days:
        return None, 0
    return round(sum(days) / len(days), 1), len(days)


def oldest_open_days(alerts, now):
    ages = [(now - a.created_at).days for a in alerts if a.state == "open"]
    return max(ages) if ages else None


def detect_controls(workflow_texts, has_dependabot, has_codeql_analysis=False):
    """Qué controles de seguridad tiene un repo, según sus workflows y su configuración."""
    text = "\n".join(workflow_texts).lower()
    found = {name: any(p in text for p in patterns) for name, patterns in CONTROLS.items()}
    found["SCA"] = found["SCA"] or has_dependabot
    found["SAST"] = found["SAST"] or has_codeql_analysis
    return found


def evaluate_gate(open_counts, secrets, limits):
    """Quality gate: devuelve la lista de incumplimientos (vacía = aprobado)."""
    failures = []
    for severity in SEVERITIES:
        limit = limits.get(severity)
        if limit is not None and open_counts[severity] > limit:
            failures.append(f"{severity}: {open_counts[severity]} abiertas (máximo {limit})")
    limit = limits.get("secrets")
    if limit is not None and secrets > limit:
        failures.append(f"secretos: {secrets} abiertos (máximo {limit})")
    return failures
