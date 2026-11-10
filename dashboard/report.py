"""Resumen de KPIs, histórico semanal e informe en Markdown."""
from .kpis import (
    CONTROLS,
    SECRET_SOURCE,
    evaluate_gate,
    mttr_days,
    oldest_open_days,
    open_by_severity,
    open_secrets,
)

_SOURCE_NAMES = {
    "dependabot": "Dependabot",
    "code-scanning": "CodeQL",
    SECRET_SOURCE: "secret scanning",
}


def build_summary(repos, limits, now):
    alerts = [a for repo in repos for a in repo.all_alerts]
    counts = open_by_severity(alerts)
    secrets = open_secrets(alerts)
    mttr, closed = mttr_days(alerts)

    checks = [value for repo in repos for value in repo.controls.values()]
    coverage = round(100 * sum(checks) / len(checks)) if checks else 0
    by_control = {
        control: round(100 * sum(repo.controls[control] for repo in repos) / len(repos))
        for control in CONTROLS
    }

    return {
        "generated_at": now.isoformat(timespec="seconds"),
        "repos": [
            {
                "name": repo.name,
                "open": open_by_severity(repo.all_alerts),
                "secrets": open_secrets(repo.all_alerts),
                "controls": repo.controls,
                "unavailable": repo.unavailable,
            }
            for repo in repos
        ],
        "totals": {
            "open": counts,
            "secrets": secrets,
            "mttr_days": mttr,
            "closed_alerts": closed,
            "oldest_open_days": oldest_open_days(alerts, now),
            "control_coverage_pct": coverage,
            "coverage_by_control": by_control,
        },
        "gate": {"limits": limits, "failures": evaluate_gate(counts, secrets, limits)},
    }


def snapshot(summary):
    totals = summary["totals"]
    return {
        "date": summary["generated_at"][:10],
        **totals["open"],
        "secrets": totals["secrets"],
        "coverage_pct": totals["control_coverage_pct"],
    }


def update_history(history, new_snapshot, keep=52):
    """Añade la foto de hoy (sustituye la del mismo día) y conserva las últimas 'keep'."""
    kept = [item for item in history if item["date"] != new_snapshot["date"]]
    return sorted(kept + [new_snapshot], key=lambda item: item["date"])[-keep:]


def _mark(value):
    return "✅" if value else "❌"


def render_markdown(summary, history):
    totals = summary["totals"]
    counts = totals["open"]
    failures = summary["gate"]["failures"]
    mttr = f"{totals['mttr_days']} días (n={totals['closed_alerts']})" if totals["mttr_days"] is not None else "sin datos"
    oldest = f"{totals['oldest_open_days']} días" if totals["oldest_open_days"] is not None else "ninguna abierta"

    lines = [
        "# Informe de seguridad",
        "",
        f"Generado: {summary['generated_at']} · Repos analizados: {len(summary['repos'])}",
        "",
        "## Quality gate",
        "",
    ]
    if failures:
        lines += ["❌ **NO SUPERADO**", ""] + [f"- {failure}" for failure in failures]
    else:
        lines.append("✅ **SUPERADO**")
    lines += [
        "",
        "## KPIs",
        "",
        "| KPI | Valor |",
        "|---|---|",
        f"| Vulnerabilidades abiertas (crítica / alta / media / baja) | {counts['critical']} / {counts['high']} / {counts['medium']} / {counts['low']} |",
        f"| Secretos expuestos abiertos | {totals['secrets']} |",
        f"| Tiempo medio de resolución | {mttr} |",
        f"| Alerta abierta más antigua | {oldest} |",
        f"| Cobertura de controles de seguridad | {totals['control_coverage_pct']} % |",
        "",
        "## Alertas abiertas por repo",
        "",
        "| Repo | Crítica | Alta | Media | Baja | Secretos |",
        "|---|---|---|---|---|---|",
    ]
    for repo in summary["repos"]:
        o = repo["open"]
        lines.append(
            f"| {repo['name']} | {o['critical']} | {o['high']} | {o['medium']} | {o['low']} | {repo['secrets']} |"
        )

    lines += [
        "",
        "## Controles por repo",
        "",
        "| Repo | " + " | ".join(CONTROLS) + " |",
        "|---|" + "---|" * len(CONTROLS),
    ]
    for repo in summary["repos"]:
        lines.append(f"| {repo['name']} | " + " | ".join(_mark(repo["controls"][c]) for c in CONTROLS) + " |")
    lines.append(
        "| **Cobertura** | " + " | ".join(f"{totals['coverage_by_control'][c]} %" for c in CONTROLS) + " |"
    )

    unavailable = [(r["name"], r["unavailable"]) for r in summary["repos"] if r["unavailable"]]
    if unavailable:
        lines += ["", "## Datos no disponibles", "", "Fuente no habilitada en el repo o sin permiso en el token (cuenta como 0 alertas en las tablas):", ""]
        for name, sources in unavailable:
            lines.append(f"- {name}: " + ", ".join(_SOURCE_NAMES[s] for s in sources))

    lines += [
        "",
        "## Evolución semanal",
        "",
        "| Fecha | Crítica | Alta | Media | Baja | Secretos | Cobertura |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in reversed(history[-8:]):
        lines.append(
            f"| {item['date']} | {item['critical']} | {item['high']} | {item['medium']} | {item['low']} | {item['secrets']} | {item['coverage_pct']} % |"
        )
    return "\n".join(lines) + "\n"
