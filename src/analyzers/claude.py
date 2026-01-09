"""
src/analyzers/claude.py

Claude-powered Terraform security analyzer.
"""

import json
import logging
import time
from typing import Any

import anthropic
from src.parsers.terraform import TerraformParser

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a senior DevSecOps engineer reviewing Terraform code for security issues.

For each finding respond with a JSON array. Each item must have:
- "severity": "critical", "high", "medium", "low", or "info"
- "resource": terraform resource identifier
- "file": filename
- "rule": short rule id (e.g. S3_PUBLIC_ACCESS)
- "title": one-line description
- "description": 2-3 sentence explanation
- "recommendation": concrete fix

Focus on: IAM wildcards, S3 public access, open security groups, missing encryption, hardcoded secrets, public databases.

Respond with ONLY a valid JSON array. No preamble. Empty array if no issues found.
"""


class ClaudeAnalyzer:
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self.parser = TerraformParser()

    def analyze(self, files: dict[str, str]) -> list[dict[str, Any]]:
        chunks = self.parser.chunk_for_analysis(files)
        all_findings = []
        seen: set[tuple[str, str]] = set()

        for i, chunk in enumerate(chunks, 1):
            findings = self._analyze_chunk(chunk["files"])
            for f in findings:
                key = (f.get("resource", ""), f.get("rule", ""))
                if key not in seen:
                    seen.add(key)
                    all_findings.append(f)
            if i < len(chunks):
                time.sleep(1)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "info").lower(), 4))
        return all_findings

    def _analyze_chunk(self, files: dict[str, str]) -> list[dict[str, Any]]:
        sections = [f"### File: {p}\n\n```hcl\n{c}\n```" for p, c in files.items()]
        user_msg = "Review these Terraform files for security issues:\n\n" + "\n\n".join(sections)

        try:
            resp = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_msg}],
            )
        except anthropic.RateLimitError:
            logger.warning("Rate limited, retrying in 30s...")
            time.sleep(30)
            resp = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_msg}],
            )
        except anthropic.APIError as e:
            logger.error("Claude API error: %s", e)
            return []

        raw = resp.content[0].text.strip()
        if raw.startswith("```"):
            lines = raw.split("\n")
            raw = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        try:
            result = json.loads(raw)
            return result if isinstance(result, list) else []
        except json.JSONDecodeError as e:
            logger.error("Failed to parse response as JSON: %s", e)
            return []
