"""Punto de entrada: python -m dashboard"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from .collect import collect_repo
from .kpis import CONTROLS
from .github_api import GitHubClient
from .report import build_summary, render_markdown, snapshot, update_history


def collect_configured_repo(client, entry):
    """Un repo de config.json: "owner/repo" o {"name": ..., "not_applicable": [controles]}."""
    if isinstance(entry, str):
        entry = {"name": entry}
    repo = collect_repo(client, entry["name"])
    for control in entry.get("not_applicable", []):
        if control not in CONTROLS:
            raise ValueError(f"Control desconocido en config.json ({entry['name']}): {control}")
        repo.controls[control] = None
    return repo


def main(argv=None):
    parser = argparse.ArgumentParser(description="KPIs de seguridad de repos de GitHub")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--out", default="REPORT.md")
    parser.add_argument("--data-dir", default="data")
    parser.add_argument(
        "--fail-on-gate", action="store_true", help="Devuelve código 1 si el quality gate no se supera"
    )
    args = parser.parse_args(argv)

    token = os.environ.get("GH_TOKEN")
    if not token:
        parser.error("Falta la variable de entorno GH_TOKEN")

    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    client = GitHubClient(token)
    repos = [collect_configured_repo(client, entry) for entry in config["repos"]]
    summary = build_summary(
        repos,
        config.get("gate", {}),
        datetime.now(timezone.utc),
        accepted_details=config.get("accepted_risk_details", False),
        sla_days=config.get("sla_days"),
    )

    data_dir = Path(args.data_dir)
    data_dir.mkdir(exist_ok=True)
    history_file = data_dir / "history.json"
    history = json.loads(history_file.read_text(encoding="utf-8")) if history_file.exists() else []
    history = update_history(history, snapshot(summary))
    history_file.write_text(json.dumps(history, indent=2) + "\n", encoding="utf-8")
    (data_dir / "latest.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    markdown = render_markdown(summary, history)
    Path(args.out).write_text(markdown, encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as step_summary:
            step_summary.write(markdown)

    failures = summary["gate"]["failures"]
    print("Quality gate:", "NO SUPERADO" if failures else "superado")
    for failure in failures:
        print(" -", failure)
    return 1 if failures and args.fail_on_gate else 0


if __name__ == "__main__":
    sys.exit(main())
