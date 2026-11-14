"""Resumen de KPIs, histórico semanal e informe en Markdown."""
from .kpis import (
    CONTROLS,
    DISMISS_REASONS,
    PRIVATE,
    SECRET_SOURCE,
    evaluate_gate,
    mttr_days,
    oldest_open_days,
    open_by_severity,
    open_secrets,
)

_SEVERITY_NAMES = {"critical": "crítica", "high": "alta", "medium": "media", "low": "baja"}

_SOURCE_NAMES = {
    "dependabot": "Dependabot",
    "code-scanning": "CodeQL",
    SECRET_SOURCE: "secret scanning",
}


def build_summary(repos, limits, now, accepted_details=False):
    """Resumen para el informe y para data/latest.json.

    accepted_details=False deja fuera el paquete y el comentario de los riesgos
    aceptados: el informe puede ser publico y eso seria listar vulnerabilidades
    conocidas y sin corregir. Se conserva lo que hace falta para medirlos.
    """
    alerts = [a for repo in repos for a in repo.all_alerts]
    counts = open_by_severity(alerts)
    secrets = open_secrets(alerts)
    mttr, closed = mttr_days(alerts)

    # Solo cuentan los controles exigibles (True/False). None = no aplica; PRIVATE = riesgo
    # aceptado por ser repo privado. Ninguno de los dos suma ni resta.
    checks = [value for repo in repos for value in repo.controls.values() if isinstance(value, bool)]
    coverage = round(100 * sum(checks) / len(checks)) if checks else 0
    by_control = {control: _percentage([repo.controls[control] for repo in repos]) for control in CONTROLS}

    chains = [repo.supply_chain for repo in repos if repo.supply_chain]
    actions_total = sum(c["actions_total"] for c in chains)
    actions_pinned = sum(c["actions_pinned"] for c in chains)
    workflows_total = sum(c["workflows_total"] for c in chains)
    workflows_open = sum(len(c["without_permissions"]) for c in chains)
    accepted = [risk for repo in repos for risk in repo.accepted]
    unjustified = sum(1 for risk in accepted if not risk["comment"])

    return {
        "generated_at": now.isoformat(timespec="seconds"),
        "repos": [
            {
                "name": repo.name,
                "open": open_by_severity(repo.all_alerts),
                "secrets": open_secrets(repo.all_alerts),
                "controls": repo.controls,
                "unavailable": repo.unavailable,
                "supply_chain": repo.supply_chain,
                "accepted": [_accepted_entry(risk, accepted_details) for risk in repo.accepted],
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
            "actions_pinned": actions_pinned,
            "actions_total": actions_total,
            "actions_pinned_pct": _ratio(actions_pinned, actions_total),
            "workflows_total": workflows_total,
            "workflows_with_permissions_pct": _ratio(workflows_total - workflows_open, workflows_total),
            "accepted_risks": len(accepted),
            "accepted_without_comment": unjustified,
        },
        "gate": {
            "limits": limits,
            "failures": evaluate_gate(
                counts,
                secrets,
                limits,
                extra={
                    "unpinned_actions": (actions_total - actions_pinned, "actions sin fijar por SHA"),
                    "workflows_without_permissions": (workflows_open, "workflows sin 'permissions:'"),
                    "accepted_without_comment": (unjustified, "riesgos aceptados sin justificar"),
                },
            ),
        },
    }


def _ratio(part, total):
    return round(100 * part / total) if total else None


def _accepted_entry(risk, details):
    entry = {"severity": risk["severity"], "reason": risk["reason"], "justified": bool(risk["comment"])}
    if details:
        entry["package"] = risk["package"]
        entry["comment"] = risk["comment"]
    return entry


def _percentage(values):
    applicable = [value for value in values if isinstance(value, bool)]
    return round(100 * sum(applicable) / len(applicable)) if applicable else None


def snapshot(summary):
    totals = summary["totals"]
    return {
        "date": summary["generated_at"][:10],
        **totals["open"],
        "secrets": totals["secrets"],
        "coverage_pct": totals["control_coverage_pct"],
        "actions_pinned_pct": totals["actions_pinned_pct"],
        "accepted_risks": totals["accepted_risks"],
    }


def update_history(history, new_snapshot, keep=52):
    """Añade la foto de hoy (sustituye la del mismo día) y conserva las últimas 'keep'."""
    kept = [item for item in history if item["date"] != new_snapshot["date"]]
    return sorted(kept + [new_snapshot], key=lambda item: item["date"])[-keep:]


def _mark(value):
    if value is None:
        return "N/A"
    if value == PRIVATE:
        return "🔒"
    return "✅" if value else "❌"


def _pct(value):
    return "N/A" if value is None else f"{value} %"


def _fraction(part, total):
    if not total:
        return "N/A"
    return f"{'✅' if part == total else '❌'} {part} de {total}"


def _unjustified(count):
    return f" · ⚠️ {count} sin justificar" if count else ""


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
        f"| Actions fijadas por SHA | {_pct(totals['actions_pinned_pct'])} ({totals['actions_pinned']} de {totals['actions_total']}) |",
        f"| Workflows con permisos mínimos declarados | {_pct(totals['workflows_with_permissions_pct'])} |",
        f"| Riesgos aceptados (alertas descartadas a mano) | {totals['accepted_risks']}{_unjustified(totals['accepted_without_comment'])} |",
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
        "| **Cobertura** | " + " | ".join(_pct(totals["coverage_by_control"][c]) for c in CONTROLS) + " |"
    )

    lines += [
        "",
        "## Cadena de suministro",
        "",
        "Higiene de los workflows de GitHub Actions de cada repo.",
        "",
        "| Repo | Actions fijadas por SHA | Workflows con `permissions:` |",
        "|---|---|---|",
    ]
    loose, open_workflows = [], []
    for repo in summary["repos"]:
        chain = repo["supply_chain"]
        if not chain:
            lines.append(f"| {repo['name']} | N/A | N/A |")
            continue
        with_permissions = chain["workflows_total"] - len(chain["without_permissions"])
        lines.append(
            f"| {repo['name']} | {_fraction(chain['actions_pinned'], chain['actions_total'])} "
            f"| {_fraction(with_permissions, chain['workflows_total'])} |"
        )
        loose += [f"- {repo['name']} · {item}" for item in chain["unpinned"]]
        open_workflows += [f"- {repo['name']} · {name}" for name in chain["without_permissions"]]
    if loose:
        lines += ["", "Actions sin fijar (un tag o una rama se pueden mover a otro código):", ""] + loose
    if open_workflows:
        lines += ["", "Workflows sin `permissions:` (el token usa los permisos por defecto del repo):", ""] + open_workflows

    private = [(r["name"], c) for r in summary["repos"] for c, v in r["controls"].items() if v == PRIVATE]
    dismissed = [(r["name"], risk) for r in summary["repos"] for risk in r["accepted"]]
    if private or dismissed:
        lines += ["", "## Riesgos aceptados"]
    if private:
        lines += [
            "",
            "🔒 Controles que el repo no tiene por ser privado (en repos privados requieren licencia de GitHub Advanced Security). No cuentan en la cobertura:",
            "",
        ]
        for name, control in private:
            lines.append(f"- {name}: {control}")
    if dismissed:
        lines += [
            "",
            "📝 Alertas de Dependabot descartadas a mano. No cuentan como abiertas, pero siguen sin corregir: cada una necesita un motivo y una justificación escrita.",
            "",
        ]
        for name, risk in dismissed:
            severity = _SEVERITY_NAMES[risk["severity"]]
            what = f"`{risk['package']}` ({severity})" if "package" in risk else f"1 alerta ({severity})"
            reason = DISMISS_REASONS.get(risk["reason"], risk["reason"] or "sin motivo")
            note = "✅ justificada" if risk["justified"] else "⚠️ **sin justificar**"
            comment = f" — {risk['comment']}" if risk.get("comment") else ""
            lines.append(f"- {name}: {what} · {reason} · {note}{comment}")

    unavailable = [(r["name"], r["unavailable"]) for r in summary["repos"] if r["unavailable"]]
    if unavailable:
        lines += ["", "## Datos no disponibles", "", "Fuente no habilitada en el repo o sin permiso en el token (cuenta como 0 alertas en las tablas):", ""]
        for name, sources in unavailable:
            lines.append(f"- {name}: " + ", ".join(_SOURCE_NAMES[s] for s in sources))

    lines += [
        "",
        "## Evolución semanal",
        "",
        "| Fecha | Crítica | Alta | Media | Baja | Secretos | Cobertura | Actions por SHA | Riesgos aceptados |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for item in reversed(history[-8:]):
        # Las fotos anteriores a estos KPIs no tienen las dos ultimas columnas.
        accepted_risks = item.get("accepted_risks")
        lines.append(
            f"| {item['date']} | {item['critical']} | {item['high']} | {item['medium']} | {item['low']} | {item['secrets']} | {item['coverage_pct']} % "
            f"| {_pct(item.get('actions_pinned_pct'))} | {'N/A' if accepted_risks is None else accepted_risks} |"
        )
    return "\n".join(lines) + "\n"
