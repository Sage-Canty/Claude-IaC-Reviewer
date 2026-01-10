"""
src/reporters/console.py

Human-readable console output for security findings.
"""

from typing import Any

SEVERITY_ICONS = {
    "critical": "🔴 CRITICAL",
    "high":     "🟠 HIGH    ",
    "medium":   "🟡 MEDIUM  ",
    "low":      "🔵 LOW     ",
    "info":     "⚪ INFO    ",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ConsoleReporter:
    def report(self, findings: list[dict[str, Any]], files: dict[str, str] = None) -> None:
        if not findings:
            print("\n✅ No security issues found.\n")
            return

        by_file: dict[str, list] = {}
        for f in findings:
            by_file.setdefault(f.get("file", "unknown"), []).append(f)

        counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "info").lower()
            counts[sev] = counts.get(sev, 0) + 1

        print(f"\n{'='*65}")
        print(f"  Terraform Security Review — {len(findings)} finding(s)")
        print(f"{'='*65}\n")

        for file_path, file_findings in sorted(by_file.items()):
            print(f"  📄 {file_path}")
            print(f"  {'─'*60}")
            for finding in sorted(file_findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info").lower(), 4)):
                sev = finding.get("severity", "info").lower()
                icon = SEVERITY_ICONS.get(sev, "⚪ INFO    ")
                print(f"\n  {icon}  [{finding.get('rule', '')}]")
                print(f"  Resource:  {finding.get('resource', 'unknown')}")
                print(f"  Issue:     {finding.get('title', '')}")
                if finding.get("description"):
                    print(f"  Detail:    {finding['description'][:120]}")
                if finding.get("recommendation"):
                    print(f"  Fix:       {finding['recommendation'].split(chr(10))[0]}")
            print()

        print(f"{'='*65}")
        print("  Summary:")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if counts.get(sev, 0) > 0:
                print(f"    {SEVERITY_ICONS[sev]}  {counts[sev]}")
        print(f"{'='*65}\n")
