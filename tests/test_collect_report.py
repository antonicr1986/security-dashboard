import base64
import unittest
from datetime import datetime, timezone

from dashboard.collect import RepoData, collect_repo
from dashboard.github_api import _NEXT
from dashboard.kpis import from_dependabot
from dashboard.report import build_summary, render_markdown, snapshot, update_history

NOW = datetime(2026, 11, 10, 6, 0, tzinfo=timezone.utc)
API = "https://api.github.com"


class FakeClient:
    """Respuestas de la API por ruta; lo que no está en el diccionario devuelve None (no disponible)."""

    def __init__(self, responses):
        self.responses = responses

    def get_json(self, path):
        return self.responses.get(path)

    def get_list(self, path):
        return self.responses.get(path)

    def get_file_text(self, path):
        data = self.responses.get(path)
        return base64.b64decode(data["content"]).decode() if data else None


def alert(severity, state="open", fixed=None):
    return from_dependabot(
        {"state": state, "created_at": "2026-11-01T00:00:00Z", "fixed_at": fixed, "security_advisory": {"severity": severity}}
    )


class CollectTests(unittest.TestCase):
    def test_collects_alerts_and_controls(self):
        workflow = base64.b64encode(b"uses: aquasecurity/trivy-action@x").decode()
        client = FakeClient(
            {
                "/repos/o/r": {"name": "r"},
                "/repos/o/r/dependabot/alerts": [
                    {"state": "open", "created_at": "2026-11-01T00:00:00Z", "security_advisory": {"severity": "high"}}
                ],
                "/repos/o/r/contents/.github/workflows": [
                    {"name": "ci.yml", "url": f"{API}/repos/o/r/contents/.github/workflows/ci.yml"}
                ],
                "/repos/o/r/contents/.github/workflows/ci.yml": {"content": workflow},
                "/repos/o/r/contents/.github/dependabot.yml": {"name": "dependabot.yml"},
            }
        )
        repo = collect_repo(client, "o/r")
        self.assertEqual(len(repo.alerts["dependabot"]), 1)
        self.assertIsNone(repo.alerts["code-scanning"])
        self.assertEqual(sorted(repo.unavailable), ["code-scanning", "secret-scanning"])
        self.assertTrue(repo.controls["Contenedores/IaC"])
        self.assertTrue(repo.controls["SCA"])
        self.assertFalse(repo.controls["DAST"])
        self.assertFalse(repo.controls["SAST"])

    def test_codeql_analysis_counts_as_sast(self):
        client = FakeClient(
            {
                "/repos/o/r": {"name": "r"},
                "/repos/o/r/code-scanning/analyses?tool_name=CodeQL&per_page=1": [{"tool": {"name": "CodeQL"}}],
            }
        )
        self.assertTrue(collect_repo(client, "o/r").controls["SAST"])

    def test_unreadable_repo_fails_instead_of_reporting_zero(self):
        with self.assertRaises(RuntimeError):
            collect_repo(FakeClient({}), "o/missing")


class ReportTests(unittest.TestCase):
    def setUp(self):
        controls = {"SAST": True, "SCA": True, "Secretos": False, "Contenedores/IaC": False, "DAST": False}
        self.repos = [
            RepoData("o/api", {"dependabot": [alert("high"), alert("low")], "code-scanning": [], "secret-scanning": None}, controls),
            RepoData("o/web", {"dependabot": [alert("critical", "fixed", "2026-11-03T00:00:00Z")]}, controls),
        ]

    def test_summary_totals_and_gate(self):
        summary = build_summary(self.repos, {"high": 0}, NOW)
        totals = summary["totals"]
        self.assertEqual(totals["open"], {"critical": 0, "high": 1, "medium": 0, "low": 1})
        self.assertEqual(totals["mttr_days"], 2.0)
        self.assertEqual(totals["control_coverage_pct"], 40)
        self.assertEqual(totals["coverage_by_control"]["SAST"], 100)
        self.assertEqual(summary["gate"]["failures"], ["high: 1 abiertas (máximo 0)"])

    def test_history_replaces_same_day_and_keeps_order(self):
        old = {"date": "2026-11-03", "critical": 0, "high": 0, "medium": 0, "low": 0, "secrets": 0, "coverage_pct": 10}
        today = {**old, "date": "2026-11-10", "coverage_pct": 40}
        history = update_history(update_history([old], today), {**today, "coverage_pct": 50})
        self.assertEqual([h["date"] for h in history], ["2026-11-03", "2026-11-10"])
        self.assertEqual(history[-1]["coverage_pct"], 50)

    def test_markdown_contains_the_main_sections(self):
        summary = build_summary(self.repos, {"high": 0}, NOW)
        markdown = render_markdown(summary, update_history([], snapshot(summary)))
        for text in ("# Informe de seguridad", "NO SUPERADO", "| o/api |", "Datos no disponibles", "Evolución semanal"):
            self.assertIn(text, markdown)


class PaginationTests(unittest.TestCase):
    def test_next_link_is_extracted(self):
        header = '<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=5>; rel="last"'
        self.assertEqual(_NEXT.search(header).group(1), "https://api.github.com/x?page=2")


if __name__ == "__main__":
    unittest.main()
