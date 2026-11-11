import base64
import unittest
from datetime import datetime, timezone

from dashboard.__main__ import collect_configured_repo
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


class NotApplicableTests(unittest.TestCase):
    def test_not_applicable_controls_are_left_out_of_coverage(self):
        api = RepoData("o/api", {"dependabot": []}, {"SAST": True, "SCA": True, "Secretos": True, "Contenedores/IaC": True, "DAST": True})
        app = RepoData("o/app", {"dependabot": []}, {"SAST": True, "SCA": False, "Secretos": True, "Contenedores/IaC": None, "DAST": None})
        summary = build_summary([api, app], {}, NOW)
        totals = summary["totals"]
        self.assertEqual(totals["coverage_by_control"]["Contenedores/IaC"], 100)  # 1 de 1 aplicable
        self.assertEqual(totals["coverage_by_control"]["SCA"], 50)
        self.assertEqual(totals["control_coverage_pct"], 88)  # 7 de 8 aplicables
        self.assertIn("| o/app | ✅ | ❌ | ✅ | N/A | N/A |", render_markdown(summary, []))

    def test_control_that_applies_to_no_repo_shows_na(self):
        app = RepoData("o/app", {}, {"SAST": True, "SCA": True, "Secretos": True, "Contenedores/IaC": None, "DAST": None})
        summary = build_summary([app], {}, NOW)
        self.assertIsNone(summary["totals"]["coverage_by_control"]["DAST"])
        self.assertIn("| **Cobertura** | 100 % | 100 % | 100 % | N/A | N/A |", render_markdown(summary, []))


class ConfigEntryTests(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient({"/repos/o/r": {"name": "r"}})

    def test_plain_string_entry_keeps_every_control(self):
        repo = collect_configured_repo(self.client, "o/r")
        self.assertNotIn(None, repo.controls.values())

    def test_not_applicable_entry_marks_controls_as_none(self):
        repo = collect_configured_repo(self.client, {"name": "o/r", "not_applicable": ["DAST"]})
        self.assertIsNone(repo.controls["DAST"])
        self.assertFalse(repo.controls["SAST"])

    def test_unknown_control_name_is_rejected(self):
        with self.assertRaises(ValueError):
            collect_configured_repo(self.client, {"name": "o/r", "not_applicable": ["Dast"]})


class PrivateRepoTests(unittest.TestCase):
    def test_private_repo_without_code_scanning_marks_sast_as_accepted_risk(self):
        repo = collect_repo(FakeClient({"/repos/o/r": {"private": True}}), "o/r")
        self.assertEqual(repo.controls["SAST"], "private")

    def test_public_repo_without_codeql_stays_red(self):
        repo = collect_repo(FakeClient({"/repos/o/r": {"private": False}}), "o/r")
        self.assertFalse(repo.controls["SAST"])

    def test_private_repo_with_codeql_is_green(self):
        client = FakeClient(
            {
                "/repos/o/r": {"private": True},
                "/repos/o/r/code-scanning/alerts": [],
                "/repos/o/r/code-scanning/analyses?tool_name=CodeQL&per_page=1": [{"tool": {"name": "CodeQL"}}],
            }
        )
        self.assertTrue(collect_repo(client, "o/r").controls["SAST"])

    def test_accepted_risk_is_shown_apart_and_left_out_of_coverage(self):
        cv = RepoData("o/cv", {}, {"SAST": "private", "SCA": True, "Secretos": True, "Contenedores/IaC": None, "DAST": True})
        summary = build_summary([cv], {}, NOW)
        self.assertEqual(summary["totals"]["control_coverage_pct"], 100)
        self.assertIsNone(summary["totals"]["coverage_by_control"]["SAST"])
        markdown = render_markdown(summary, [])
        self.assertIn("| o/cv | 🔒 | ✅ | ✅ | N/A | ✅ |", markdown)
        self.assertIn("## Riesgos aceptados", markdown)
        self.assertIn("- o/cv: SAST", markdown)
