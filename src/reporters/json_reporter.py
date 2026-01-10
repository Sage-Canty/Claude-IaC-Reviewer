"""
src/reporters/json_reporter.py

JSON output for CI/CD integration.
"""

import json
from datetime import datetime, timezone
from typing import Any


class JSONReporter:
    def report(self, findings: list[dict[str, Any]], files: dict[str, str] = None) -> None:
        counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "info").lower()
            counts[sev] = counts.get(sev, 0) + 1

        print(json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "files_analyzed": list(files.keys()) if files else [],
            "total_findings": len(findings),
            "summary": {s: counts.get(s, 0) for s in ["critical", "high", "medium", "low", "info"]},
            "findings": findings,
        }, indent=2))
