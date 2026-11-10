import unittest
from datetime import datetime, timezone

from dashboard.kpis import (
    detect_controls,
    evaluate_gate,
    from_code_scanning,
    from_dependabot,
    from_secret_scanning,
    mttr_days,
    oldest_open_days,
    open_by_severity,
    open_secrets,
)

NOW = datetime(2026, 11, 10, tzinfo=timezone.utc)


def dependabot(severity, state="open", created="2026-11-01T00:00:00Z", fixed=None):
    return from_dependabot(
        {"state": state, "created_at": created, "fixed_at": fixed, "security_advisory": {"severity": severity}}
    )


class ParsingTests(unittest.TestCase):
    def test_dependabot_auto_dismissed_counts_as_dismissed(self):
        alert = from_dependabot(
            {"state": "auto_dismissed", "created_at": "2026-11-01T00:00:00Z", "security_advisory": {"severity": "high"}}
        )
        self.assertEqual(alert.state, "dismissed")

    def test_code_scanning_uses_security_severity_level(self):
        alert = from_code_scanning(
            {"state": "open", "created_at": "2026-11-01T00:00:00Z", "rule": {"security_severity_level": "critical", "severity": "note"}}
        )
        self.assertEqual(alert.severity, "critical")

    def test_code_scanning_without_security_level_falls_back_to_rule_severity(self):
        alert = from_code_scanning(
            {"state": "open", "created_at": "2026-11-01T00:00:00Z", "rule": {"security_severity_level": None, "severity": "warning"}}
        )
        self.assertEqual(alert.severity, "medium")

    def test_resolved_secret_is_fixed(self):
        alert = from_secret_scanning(
            {"state": "resolved", "created_at": "2026-11-01T00:00:00Z", "resolved_at": "2026-11-02T00:00:00Z"}
        )
        self.assertEqual(alert.state, "fixed")


class KpiTests(unittest.TestCase):
    def test_open_by_severity_ignores_closed_and_secrets(self):
        alerts = [
            dependabot("high"),
            dependabot("high"),
            dependabot("low"),
            dependabot("critical", state="fixed", fixed="2026-11-02T00:00:00Z"),
            from_secret_scanning({"state": "open", "created_at": "2026-11-01T00:00:00Z"}),
        ]
        self.assertEqual(open_by_severity(alerts), {"critical": 0, "high": 2, "medium": 0, "low": 1})
        self.assertEqual(open_secrets(alerts), 1)

    def test_mttr_is_the_mean_of_fixed_alerts_only(self):
        alerts = [
            dependabot("high", "fixed", "2026-11-01T00:00:00Z", "2026-11-03T00:00:00Z"),  # 2 días
            dependabot("low", "fixed", "2026-11-01T00:00:00Z", "2026-11-05T00:00:00Z"),  # 4 días
            dependabot("low"),  # abierta: no cuenta
        ]
        self.assertEqual(mttr_days(alerts), (3.0, 2))

    def test_mttr_without_fixed_alerts(self):
        self.assertEqual(mttr_days([dependabot("low")]), (None, 0))

    def test_oldest_open_alert_age(self):
        alerts = [dependabot("low", created="2026-10-31T00:00:00Z"), dependabot("low", created="2026-11-09T00:00:00Z")]
        self.assertEqual(oldest_open_days(alerts, NOW), 10)
        self.assertIsNone(oldest_open_days([], NOW))


class ControlTests(unittest.TestCase):
    def test_detects_controls_from_workflows(self):
        texts = ["uses: github/codeql-action/init@x", "uses: zaproxy/action-baseline@x", "run: gitleaks detect"]
        found = detect_controls(texts, has_dependabot=False)
        self.assertEqual(
            found, {"SAST": True, "SCA": False, "Secretos": True, "Contenedores/IaC": False, "DAST": True}
        )

    def test_dependabot_file_and_codeql_default_setup_count(self):
        found = detect_controls([], has_dependabot=True, codeql_default_setup=True)
        self.assertTrue(found["SCA"])
        self.assertTrue(found["SAST"])


class GateTests(unittest.TestCase):
    def test_passes_when_within_limits(self):
        counts = {"critical": 0, "high": 0, "medium": 5, "low": 9}
        self.assertEqual(evaluate_gate(counts, 0, {"critical": 0, "high": 0, "secrets": 0}), [])

    def test_fails_listing_each_breach(self):
        counts = {"critical": 1, "high": 2, "medium": 0, "low": 0}
        failures = evaluate_gate(counts, 1, {"critical": 0, "high": 1, "secrets": 0})
        self.assertEqual(len(failures), 3)
        self.assertIn("critical: 1 abiertas (máximo 0)", failures)

    def test_severity_without_limit_is_not_enforced(self):
        counts = {"critical": 0, "high": 0, "medium": 50, "low": 50}
        self.assertEqual(evaluate_gate(counts, 0, {"critical": 0}), [])


if __name__ == "__main__":
    unittest.main()
