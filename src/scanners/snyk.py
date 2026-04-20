"""
src/scanners/snyk.py

Snyk IaC scanner — runs `snyk iac test` and parses findings into
the same format used by the rest of the pipeline.
"""

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


class SnykScanner:
    """
    Runs Snyk IaC static analysis on Terraform files and returns
    normalized findings.

    Requires the Snyk CLI to be installed and authenticated:
        npm install -g snyk
        snyk auth <token>

    Or set SNYK_TOKEN environment variable (used in CI).
    """

    def __init__(self):
        self.available = shutil.which("snyk") is not None

    def scan(self, path: str) -> list[dict[str, Any]]:
        """
        Run `snyk iac test` on the given path and return normalized findings.
        Returns empty list if Snyk is not available or scan fails.
        """
        if not self.available:
            logger.warning("Snyk CLI not found — skipping Snyk IaC scan. "
                           "Install with: npm install -g snyk")
            return []

        try:
            result = subprocess.run(
                ["snyk", "iac", "test", path, "--json", "--severity-threshold=low"],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Snyk scan timed out after 120s")
            return []
        except Exception as e:
            logger.warning("Snyk scan failed: %s", e)
            return []

        # Snyk exits 1 when issues are found — that's expected, not an error
        if result.returncode not in (0, 1):
            logger.warning("Snyk exited with code %d: %s",
                           result.returncode, result.stderr[:200])
            return []

        if not result.stdout.strip():
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse Snyk output: %s", e)
            return []

        return self._normalize(data)

    def _normalize(self, data: Any) -> list[dict[str, Any]]:
        """
        Convert Snyk JSON output to the pipeline's finding format.

        Snyk returns either a single result object or a list of result
        objects (one per file). Handles both.
        """
        findings = []

        results = data if isinstance(data, list) else [data]

        for result in results:
            if not isinstance(result, dict):
                continue

            target_file = result.get("targetFile", result.get("path", "unknown"))
            infrastructureAsCodeIssues = result.get("infrastructureAsCodeIssues", [])

            for issue in infrastructureAsCodeIssues:
                severity = SEVERITY_MAP.get(
                    issue.get("severity", "low").lower(), "low"
                )
                findings.append({
                    "severity": severity,
                    "resource": issue.get("resource", "unknown"),
                    "file": Path(target_file).name,
                    "rule": issue.get("id", "SNYK_IAC"),
                    "title": issue.get("title", "Snyk IaC finding"),
                    "description": issue.get("msg", ""),
                    "recommendation": issue.get("resolve", "See Snyk documentation."),
                    "source": "snyk",
                    "references": issue.get("references", []),
                })

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(
            key=lambda f: severity_order.get(f.get("severity", "low").lower(), 3)
        )

        return findings
