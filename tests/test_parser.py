"""tests/test_parser.py — Terraform parser unit tests."""

import pytest
from pathlib import Path
from src.parsers.terraform import TerraformParser

SAMPLE_INSECURE = '''
resource "aws_iam_role_policy" "admin" {
  name = "admin"
  role = "test"
  policy = jsonencode({ Statement = [{ Action = ["*"], Resource = ["*"] }] })
}
resource "aws_security_group" "open" {
  name = "open"
  ingress { from_port = 0; to_port = 65535; protocol = "tcp"; cidr_blocks = ["0.0.0.0/0"] }
}
'''

SAMPLE_SECURE = '''
resource "aws_s3_bucket" "secure" { bucket = "my-bucket" }
resource "aws_s3_bucket_public_access_block" "secure" {
  bucket = aws_s3_bucket.secure.id
  block_public_acls = true
}
'''


class TestTerraformParser:
    def test_collect_files_empty_dir(self, tmp_path):
        assert TerraformParser().collect_files(tmp_path) == {}

    def test_collect_files_finds_tf_files(self, tmp_path):
        (tmp_path / "main.tf").write_text(SAMPLE_SECURE)
        (tmp_path / "vars.tf").write_text('variable "x" {}')
        result = TerraformParser().collect_files(tmp_path)
        assert "main.tf" in result and "vars.tf" in result

    def test_skips_terraform_dir(self, tmp_path):
        (tmp_path / "main.tf").write_text(SAMPLE_SECURE)
        td = tmp_path / ".terraform"
        td.mkdir()
        (td / "cached.tf").write_text("# cache")
        result = TerraformParser().collect_files(tmp_path)
        assert len(result) == 1

    def test_collect_files_recursive(self, tmp_path):
        (tmp_path / "main.tf").write_text(SAMPLE_SECURE)
        mod = tmp_path / "modules" / "vpc"
        mod.mkdir(parents=True)
        (mod / "main.tf").write_text('resource "aws_vpc" "m" { cidr_block = "10.0.0.0/16" }')
        assert len(TerraformParser().collect_files(tmp_path)) == 2

    def test_extract_resources(self):
        resources = TerraformParser().extract_resources(SAMPLE_INSECURE)
        types = [r["type"] for r in resources]
        assert "aws_iam_role_policy" in types
        assert "aws_security_group" in types

    def test_security_sensitive_flagged(self):
        resources = TerraformParser().extract_resources(SAMPLE_INSECURE)
        iam = next(r for r in resources if r["type"] == "aws_iam_role_policy")
        assert iam["is_security_sensitive"] is True

    def test_chunk_single_chunk(self):
        files = {"a.tf": SAMPLE_SECURE, "b.tf": SAMPLE_INSECURE}
        chunks = TerraformParser().chunk_for_analysis(files)
        assert len(chunks) == 1
        assert "a.tf" in chunks[0]["files"]

    def test_chunk_prioritizes_sensitive(self):
        files = {"vars.tf": 'variable "x" {}', "iam.tf": SAMPLE_INSECURE}
        chunks = TerraformParser().chunk_for_analysis(files)
        assert "iam.tf" in list(chunks[0]["files"].keys())
