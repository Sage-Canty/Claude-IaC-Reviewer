# terraform-security-review

AI-powered security reviewer for Terraform configurations. Uses Claude to analyze IaC for misconfigurations, overly permissive IAM, missing encryption, exposed resources, and hardcoded secrets — with actionable remediation for each finding.

Runs as a CLI tool locally or as a GitHub Actions step that posts findings directly to pull requests.

---

## Example output

```
=================================================================
  Terraform Security Review — 5 findings
=================================================================

  📄 main.tf
  ──────────────────────────────────────────────────────────────

  🔴 CRITICAL  [IAM_WILDCARD_ACTION]
  Resource:  aws_iam_role_policy.admin
  Issue:     IAM policy allows wildcard action on all resources
  Detail:    Action: * grants every AWS API call including
             destructive operations.
  Fix:       Replace * with specific required actions.

  🔴 CRITICAL  [RDS_HARDCODED_PASSWORD]
  Resource:  aws_db_instance.insecure
  Issue:     Hardcoded password in RDS configuration
```

---

## Usage

```bash
export ANTHROPIC_API_KEY=your-key-here

python -m src.cli review --path ./terraform
python -m src.cli review --file main.tf
python -m src.cli review --path . --severity high
python -m src.cli review --path . --output json
python -m src.cli review --path . --no-fail
```

---

## GitHub Actions

Posts findings as PR comments on any PR touching `.tf` files.
Requires `ANTHROPIC_API_KEY` secret in repository settings.

---

## What it checks

| Category | Examples |
|---|---|
| IAM | Wildcard actions, AdministratorAccess attachments, broad trust policies |
| S3 | Public access, missing encryption, no versioning |
| Security groups | 0.0.0.0/0 ingress, all-port rules |
| Encryption | Missing KMS on RDS, EBS, DynamoDB |
| Secrets | Hardcoded passwords, API keys in configs |
| Networking | Publicly accessible databases, default VPC usage |

---

## Development

```bash
make install
make test
make review-bad   # requires ANTHROPIC_API_KEY
make review-good
```

---

## How it works

1. Collects `.tf` files, skipping `.terraform` dirs
2. Prioritizes security-sensitive resources (IAM, S3, SGs) in first API call
3. Chunks large configs to stay within context limits
4. Sends to Claude with structured security review prompt
5. Parses JSON findings, deduplicates, sorts by severity

Static analysis only — does not execute Terraform or resolve variables.
