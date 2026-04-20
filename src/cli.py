#!/usr/bin/env python3
"""
terraform-security-review — AI-powered IaC security reviewer.

Two-layer pipeline: Checkov + Snyk IaC static analysis feeds Claude
for synthesis, deduplication, and remediation.

Usage:
    python -m src.cli review --path ./terraform
    python -m src.cli review --file main.tf --output json
    python -m src.cli review --path . --severity high
    python -m src.cli review --path . --no-snyk   # skip Snyk scan
"""

import argparse
import os
import sys
from pathlib import Path

from src.parsers.terraform import TerraformParser
from src.analyzers.claude import ClaudeAnalyzer
from src.scanners.snyk import SnykScanner
from src.reporters.console import ConsoleReporter
from src.reporters.json_reporter import JSONReporter


def cmd_review(args):
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    parser = TerraformParser()

    if args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        files = {str(path): path.read_text()}
        scan_path = str(path)
    elif args.path:
        path = Path(args.path)
        if not path.exists():
            print(f"Error: path not found: {args.path}", file=sys.stderr)
            sys.exit(1)
        files = parser.collect_files(path)
        scan_path = str(path)
    else:
        print("Error: specify --file or --path", file=sys.stderr)
        sys.exit(1)

    if not files:
        print("No Terraform files found", file=sys.stderr)
        sys.exit(1)

    # --- Snyk IaC scan (first layer) ---
    snyk_findings = []
    if not args.no_snyk:
        snyk = SnykScanner()
        if snyk.available:
            print("Running Snyk IaC scan...", file=sys.stderr)
            snyk_findings = snyk.scan(scan_path)
            if snyk_findings:
                print(
                    f"Snyk found {len(snyk_findings)} issue(s) — passing to Claude for synthesis",
                    file=sys.stderr,
                )
            else:
                print("Snyk: no issues found", file=sys.stderr)
        else:
            print(
                "Snyk CLI not found — running Claude-only analysis. "
                "Install Snyk with: npm install -g snyk",
                file=sys.stderr,
            )

    # --- Claude synthesis (second layer) ---
    analyzer = ClaudeAnalyzer(api_key=api_key, model=args.model)
    findings = analyzer.analyze(
        files,
        snyk_findings=snyk_findings,
    )

    if args.severity:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        min_level = order.get(args.severity.lower(), 4)
        findings = [
            f for f in findings
            if order.get(f.get("severity", "info").lower(), 4) <= min_level
        ]

    reporter = JSONReporter() if args.output == "json" else ConsoleReporter()
    reporter.report(findings, files=files)

    critical_high = [
        f for f in findings
        if f.get("severity", "").lower() in ("critical", "high")
    ]
    if critical_high and not args.no_fail:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="AI-powered Terraform security reviewer"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    review = subparsers.add_parser("review")
    review.add_argument("--file")
    review.add_argument("--path")
    review.add_argument("--output", default="text", choices=["text", "json"])
    review.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"])
    review.add_argument("--model", default="claude-sonnet-4-20250514")
    review.add_argument("--no-fail", action="store_true")
    review.add_argument(
        "--no-snyk",
        action="store_true",
        help="Skip Snyk IaC scan and run Claude-only analysis",
    )
    review.set_defaults(func=cmd_review)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
