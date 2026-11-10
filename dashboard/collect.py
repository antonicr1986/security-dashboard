"""Recogida de alertas y controles de un repo a través de la API de GitHub."""
from dataclasses import dataclass, field

from .kpis import (
    SECRET_SOURCE,
    detect_controls,
    from_code_scanning,
    from_dependabot,
    from_secret_scanning,
)

# Fuente -> (endpoint, conversor)
_SOURCES = {
    "dependabot": ("dependabot/alerts", from_dependabot),
    "code-scanning": ("code-scanning/alerts", from_code_scanning),
    SECRET_SOURCE: ("secret-scanning/alerts", from_secret_scanning),
}


@dataclass
class RepoData:
    name: str
    alerts: dict = field(default_factory=dict)  # fuente -> lista de Alert, o None si no disponible
    controls: dict = field(default_factory=dict)  # control -> bool

    @property
    def all_alerts(self):
        return [a for items in self.alerts.values() if items for a in items]

    @property
    def unavailable(self):
        return [source for source, items in self.alerts.items() if items is None]


def collect_repo(client, name):
    # Si el repo no se puede leer, mejor fallar que informar "0 alertas".
    if client.get_json(f"/repos/{name}") is None:
        raise RuntimeError(f"Sin acceso al repo {name}: revisa el token y sus permisos")

    alerts = {}
    for source, (endpoint, convert) in _SOURCES.items():
        raw = client.get_list(f"/repos/{name}/{endpoint}")
        alerts[source] = None if raw is None else [convert(item) for item in raw]

    workflows = client.get_list(f"/repos/{name}/contents/.github/workflows") or []
    texts = [
        client.get_file_text(item["url"].removeprefix("https://api.github.com"))
        or ""
        for item in workflows
        if item["name"].endswith((".yml", ".yaml"))
    ]
    has_dependabot = any(
        client.get_json(f"/repos/{name}/contents/.github/{file}") is not None
        for file in ("dependabot.yml", "dependabot.yaml")
    )
    setup = client.get_json(f"/repos/{name}/code-scanning/default-setup") or {}
    controls = detect_controls(texts, has_dependabot, setup.get("state") == "configured")
    return RepoData(name, alerts, controls)
