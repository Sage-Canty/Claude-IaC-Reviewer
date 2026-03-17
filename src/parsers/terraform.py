"""
src/parsers/terraform.py

Collects and preprocesses Terraform files for analysis.
"""

import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MAX_CHUNK_SIZE = 80_000

SECURITY_SENSITIVE_RESOURCES = {
    "aws_iam_role",
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_user",
    "aws_security_group",
    "aws_s3_bucket",
    "aws_s3_bucket_policy",
    "aws_s3_bucket_public_access_block",
    "aws_kms_key",
    "aws_rds_instance",
    "aws_db_instance",
    "aws_lambda_function",
    "aws_ecs_task_definition",
}


class TerraformParser:
    def collect_files(self, root: Path) -> dict[str, str]:
        files = {}
        for tf_file in sorted(root.rglob("*.tf")):
            parts = tf_file.parts
            if any(p in parts for p in [".terraform", "test", "tests", "fixtures"]):
                continue
            if tf_file.name.endswith("_test.tf"):
                continue
            try:
                content = tf_file.read_text(encoding="utf-8")
                rel_path = str(tf_file.relative_to(root))
                files[rel_path] = content
            except (OSError, UnicodeDecodeError) as e:
                logger.warning("Could not read %s: %s", tf_file, e)
        return files

    def chunk_for_analysis(self, files: dict[str, str]) -> list[dict[str, Any]]:
        chunks = []
        current_chunk: dict[str, Any] = {"files": {}, "size": 0}

        def file_priority(item: tuple[str, str]) -> int:
            path, content = item
            for rt in SECURITY_SENSITIVE_RESOURCES:
                if rt in content:
                    return 0
            return 1

        for path, content in sorted(files.items(), key=file_priority):
            file_size = len(content)
            if file_size > MAX_CHUNK_SIZE:
                if current_chunk["files"]:
                    chunks.append(current_chunk)
                    current_chunk = {"files": {}, "size": 0}
                chunks.append({"files": {path: content[:MAX_CHUNK_SIZE]}, "size": MAX_CHUNK_SIZE})
                continue
            if current_chunk["size"] + file_size > MAX_CHUNK_SIZE and current_chunk["files"]:
                chunks.append(current_chunk)
                current_chunk = {"files": {}, "size": 0}
            current_chunk["files"][path] = content
            current_chunk["size"] += file_size

        if current_chunk["files"]:
            chunks.append(current_chunk)
        return chunks


    def extract_resources(self, content: str) -> list[dict[str, Any]]:
        """Extract resource blocks from Terraform content."""
        import re as _re
        resources = []
        pattern = _re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', _re.MULTILINE)
        for match in pattern.finditer(content):
            resource_type = match.group(1)
            resource_name = match.group(2)
            start = match.start()
            brace_depth = 0
            end = start
            for i, char in enumerate(content[start:], start=start):
                if char == "{":
                    brace_depth += 1
                elif char == "}":
                    brace_depth -= 1
                    if brace_depth == 0:
                        end = i + 1
                        break
            resources.append({
                "type": resource_type,
                "name": resource_name,
                "content": content[start:end],
                "is_security_sensitive": resource_type in SECURITY_SENSITIVE_RESOURCES,
            })
        return resources


# Note: files exceeding MAX_CHUNK_SIZE are truncated.
# This affects very large monolithic terraform files (>80k chars).
# Split large files into modules to get complete analysis coverage.
