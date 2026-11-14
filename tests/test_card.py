import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from dashboard.card import TEXTS, render_card
from dashboard.collect import RepoData
from dashboard.kpis import from_dependabot
from dashboard.report import build_summary

NOW = datetime(2026, 11, 10, 6, 0, tzinfo=timezone.utc)
CONTROLS = dict.fromkeys(("SAST", "SCA", "Secretos", "Contenedores/IaC", "DAST"), True)
SVG = "{http://www.w3.org/2000/svg}"


def summary(alerts=(), limits=None):
    raw = [
        {"state": state, "created_at": "2026-11-01T00:00:00Z", "fixed_at": fixed, "security_advisory": {"severity": severity}}
        for severity, state, fixed in alerts
    ]
    repo = RepoData("o/<r&d>", {"dependabot": [from_dependabot(item) for item in raw]}, CONTROLS)
    return build_summary([repo], limits or {}, NOW, sla_days={"high": 30})


def texts(svg):
    return [node.text for node in ET.fromstring(svg).iter(f"{SVG}text")]


class CardTests(unittest.TestCase):
    def test_card_is_valid_svg_in_every_language(self):
        for lang in TEXTS:
            root = ET.fromstring(render_card(summary(), lang))
            self.assertEqual(root.tag, f"{SVG}svg")
            self.assertIn(TEXTS[lang]["title"], texts(render_card(summary(), lang)))

    def test_shows_gate_status_and_main_figures(self):
        data = summary([("high", "open", None), ("high", "fixed", "2026-11-03T00:00:00Z")], {"high": 0})
        found = texts(render_card(data, "es"))
        self.assertIn("Quality gate no superado", found)
        self.assertNotIn("Quality gate superado", found)
        self.assertIn("2.0", found)  # resolución media en días
        self.assertIn("100 %", found)  # cobertura y SLA
        self.assertIn("1 repos · actualizado el 2026-11-10 · informe semanal automático", found)

    def test_passing_gate_and_english_labels(self):
        found = texts(render_card(summary(), "en"))
        self.assertIn("Quality gate passed", found)
        self.assertIn("Open vulnerabilities", found)

    def test_missing_values_are_shown_as_no_data_not_as_zero(self):
        found = texts(render_card(summary(), "es"))
        # Sin workflows leídos ni alertas cerradas: ni 0 % ni 100 %, "sin datos".
        self.assertEqual(found.count("sin datos"), 3)
        self.assertIn("—", found)

    def test_summary_without_the_newer_kpis_still_renders(self):
        data = summary()
        for key in ("actions_pinned_pct", "workflows_with_permissions_pct", "sla_pct", "accepted_risks"):
            del data["totals"][key]
        ET.fromstring(render_card(data, "es"))


if __name__ == "__main__":
    unittest.main()
