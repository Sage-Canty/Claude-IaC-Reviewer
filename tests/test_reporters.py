"""tests/test_reporters.py — Reporter unit tests."""

import json
from src.reporters.console import ConsoleReporter
from src.reporters.json_reporter import JSONReporter

FINDINGS = [
    {"severity": "critical", "resource": "aws_iam_role_policy.admin", "file": "main.tf",
     "rule": "IAM_WILDCARD", "title": "Wildcard IAM action", "description": "Allows all actions.",
     "recommendation": "Scope to specific actions."},
    {"severity": "high", "resource": "aws_s3_bucket.data", "file": "storage.tf",
     "rule": "S3_NO_ENCRYPTION", "title": "Missing S3 encryption", "description": "Unencrypted at rest.",
     "recommendation": "Add server-side encryption configuration."},
]


class TestConsoleReporter:
    def test_no_findings(self, capsys):
        ConsoleReporter().report([])
        assert "No security issues found" in capsys.readouterr().out

    def test_shows_findings(self, capsys):
        ConsoleReporter().report(FINDINGS)
        out = capsys.readouterr().out
        assert "IAM_WILDCARD" in out
        assert "S3_NO_ENCRYPTION" in out

    def test_summary_counts(self, capsys):
        ConsoleReporter().report(FINDINGS)
        out = capsys.readouterr().out
        assert "CRITICAL" in out and "HIGH" in out

    def test_groups_by_file(self, capsys):
        ConsoleReporter().report(FINDINGS)
        out = capsys.readouterr().out
        assert "main.tf" in out and "storage.tf" in out


class TestJSONReporter:
    def test_valid_json(self, capsys):
        JSONReporter().report(FINDINGS)
        json.loads(capsys.readouterr().out)

    def test_correct_counts(self, capsys):
        JSONReporter().report(FINDINGS)
        parsed = json.loads(capsys.readouterr().out)
        assert parsed["total_findings"] == 2
        assert parsed["summary"]["critical"] == 1

    def test_has_timestamp(self, capsys):
        JSONReporter().report([])
        parsed = json.loads(capsys.readouterr().out)
        assert "generated_at" in parsed
