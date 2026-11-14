import unittest
from datetime import datetime, timezone

from dashboard.kpis import (
    accepted_risks,
    action_pinning,
    declares_permissions,
    detect_controls,
    evaluate_gate,
    from_code_scanning,
    from_dependabot,
    from_secret_scanning,
    mttr_days,
    oldest_open_days,
    open_by_severity,
    open_secrets,
    sla_compliance,
    update_pr_dates,
    update_pr_stats,
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


class SlaTests(unittest.TestCase):
    SLA = {"critical": 7, "high": 30}

    def test_fixed_alerts_are_measured_against_their_severity_deadline(self):
        alerts = [
            dependabot("critical", "fixed", "2026-11-01T00:00:00Z", "2026-11-08T00:00:00Z"),  # 7 días: justo en plazo
            dependabot("critical", "fixed", "2026-11-01T00:00:00Z", "2026-11-08T00:00:01Z"),  # fuera por 1 segundo
            dependabot("high", "fixed", "2026-10-01T00:00:00Z", "2026-10-20T00:00:00Z"),
        ]
        result = sla_compliance(alerts, self.SLA, NOW)
        self.assertEqual(result["critical"], {"within": 1, "total": 2, "overdue_open": 0})
        self.assertEqual(result["high"], {"within": 1, "total": 1, "overdue_open": 0})

    def test_open_alert_only_counts_once_it_is_overdue(self):
        alerts = [
            dependabot("critical", created="2026-11-01T00:00:00Z"),  # 9 días abierta: fuera de plazo
            dependabot("critical", created="2026-11-05T00:00:00Z"),  # 5 días: aún en plazo, no cuenta
        ]
        self.assertEqual(sla_compliance(alerts, self.SLA, NOW)["critical"], {"within": 0, "total": 1, "overdue_open": 1})

    def test_dismissed_secrets_and_severities_without_deadline_are_left_out(self):
        alerts = [
            dependabot("critical", "dismissed"),
            dependabot("low", "fixed", "2026-01-01T00:00:00Z", "2026-11-01T00:00:00Z"),  # sin plazo para "low"
            from_secret_scanning({"state": "open", "created_at": "2026-01-01T00:00:00Z"}),
        ]
        result = sla_compliance(alerts, self.SLA, NOW)
        self.assertNotIn("low", result)
        self.assertEqual(sum(entry["total"] for entry in result.values()), 0)


class UpdatePrTests(unittest.TestCase):
    def test_only_dependabot_pull_requests_count(self):
        raw = [
            {"created_at": "2026-11-01T00:00:00Z", "user": {"login": "dependabot[bot]"}},
            {"created_at": "2026-11-02T00:00:00Z", "user": {"login": "antonicr1986"}},
            {"created_at": "2026-11-03T00:00:00Z", "user": None},
        ]
        self.assertEqual(update_pr_dates(raw), [datetime(2026, 11, 1, tzinfo=timezone.utc)])

    def test_stats_count_open_oldest_and_stale(self):
        opened = [datetime(2026, 9, 1, tzinfo=timezone.utc), datetime(2026, 10, 11, tzinfo=timezone.utc), datetime(2026, 11, 9, tzinfo=timezone.utc)]
        # 70, 30 y 1 días: solo la primera supera el plazo de 30 (30 justos aún está en plazo)
        self.assertEqual(update_pr_stats(opened, NOW, 30), {"open": 3, "oldest_days": 70, "stale": 1})

    def test_stats_without_pull_requests(self):
        self.assertEqual(update_pr_stats([], NOW, 30), {"open": 0, "oldest_days": None, "stale": 0})


class ControlTests(unittest.TestCase):
    def test_detects_controls_from_workflows(self):
        texts = ["uses: github/codeql-action/init@x", "uses: zaproxy/action-baseline@x", "run: gitleaks detect"]
        found = detect_controls(texts, has_dependabot=False)
        self.assertEqual(
            found, {"SAST": True, "SCA": False, "Secretos": True, "Contenedores/IaC": False, "DAST": True}
        )

    def test_dependabot_file_and_codeql_analysis_count(self):
        found = detect_controls([], has_dependabot=True, has_codeql_analysis=True)
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

    def test_extra_counters_are_enforced_only_with_a_limit(self):
        counts = dict.fromkeys(("critical", "high", "medium", "low"), 0)
        extra = {"unpinned_actions": (2, "actions sin fijar por SHA")}
        self.assertEqual(evaluate_gate(counts, 0, {}, extra), [])
        self.assertEqual(
            evaluate_gate(counts, 0, {"unpinned_actions": 0}, extra), ["actions sin fijar por SHA: 2 (máximo 0)"]
        )


SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"


class SupplyChainTests(unittest.TestCase):
    def test_only_a_full_commit_sha_counts_as_pinned(self):
        workflow = f"""
        steps:
          - uses: actions/checkout@{SHA} # v7.0.1
          - uses: actions/setup-node@v7
          - name: Build
            uses: docker/build-push-action@main
          - uses: actions/cache@3d3c42e   # SHA corto: no vale
        """
        pinned, total, unpinned = action_pinning(workflow)
        self.assertEqual((pinned, total), (1, 4))
        self.assertEqual(unpinned, ["actions/setup-node@v7", "docker/build-push-action@main", "actions/cache@3d3c42e"])

    def test_local_actions_are_ignored_and_docker_needs_a_digest(self):
        workflow = f"""
          - uses: ./.github/actions/setup
          - uses: docker://alpine:3.20
          - uses: docker://alpine@sha256:{'a' * 64}
          # - uses: actions/checkout@v1   (comentado: no cuenta)
        """
        self.assertEqual(action_pinning(workflow), (1, 2, ["docker://alpine:3.20"]))

    def test_workflow_without_actions(self):
        self.assertEqual(action_pinning("steps:\n  - run: echo hola"), (0, 0, []))

    def test_permissions_must_be_declared_at_workflow_level(self):
        self.assertTrue(declares_permissions("name: CI\npermissions:\n  contents: read\njobs: {}"))
        self.assertTrue(declares_permissions("permissions: {}\njobs: {}"))
        # Solo dentro de un job: los demas jobs siguen con los permisos por defecto.
        self.assertFalse(declares_permissions("jobs:\n  build:\n    permissions:\n      contents: read"))


class AcceptedRiskTests(unittest.TestCase):
    def test_only_manually_dismissed_alerts_are_accepted_risks(self):
        raw = [
            {"state": "open", "security_advisory": {"severity": "high"}},
            {"state": "auto_dismissed", "security_advisory": {"severity": "low"}},
            {
                "state": "dismissed",
                "dismissed_reason": "not_used",
                "dismissed_comment": " Solo desarrollo ",
                "dependency": {"package": {"name": "minimatch"}},
                "security_advisory": {"severity": "medium"},
            },
            {"state": "dismissed", "dismissed_reason": "tolerable_risk", "dismissed_comment": None},
        ]
        self.assertEqual(
            accepted_risks(raw),
            [
                {"package": "minimatch", "severity": "medium", "reason": "not_used", "comment": "Solo desarrollo"},
                {"package": "?", "severity": "low", "reason": "tolerable_risk", "comment": ""},
            ],
        )


if __name__ == "__main__":
    unittest.main()
