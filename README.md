# Claude-IaC-Reviewer

IaC misconfigurations — public S3 buckets, overpermissioned IAM, unencrypted RDS — are the easiest class of cloud security failures to prevent and the most common to miss. They slip through because static analysis runs after the fact, findings land in a separate report nobody reads, and the feedback loop between "I wrote this Terraform" and "this will cause a security incident" is too long.

This tool closes that loop. It runs Checkov static analysis and Snyk IaC scanning as a first pass, then sends findings to Claude for synthesis — structured, severity-ranked, with actionable remediation for each issue. Runs locally or as a GitHub Actions step that posts findings directly to the PR before merge.

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

Posts findings as PR comments on any PR touching `.tf` files — so the engineer who wrote the config sees the findings before it merges, not after it deploys.

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

## How it works

1. Collects `.tf` files, skipping `.terraform` dirs
2. Runs Checkov static analysis and Snyk IaC scan as first pass
3. Prioritizes security-sensitive resources (IAM, S3, SGs) in first API call
4. Chunks large configs to stay within context limits
5. Sends findings to Claude for synthesis — structured, deduplicated, severity-ranked
6. Parses JSON output, sorts by severity, generates remediation for each finding

Static analysis only — does not execute Terraform or resolve variables.

---

## Development

```bash
make install
make test
make review-bad   # requires ANTHROPIC_API_KEY
make review-good
```

---

## Limitations

- Analyzes static config only — does not resolve variable references at runtime
- Very large repos may require multiple API calls
- Complementary to Checkov and Snyk, not a replacement — the value is in synthesis and PR integration
