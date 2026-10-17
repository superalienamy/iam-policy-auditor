# AWS IAM & CloudTrail Auditor

Two small Python tools for spotting risky AWS configuration and activity:

- `audit_iam.py` scans IAM policies for wildcard actions, wildcard resources,
  `NotAction`/`NotResource`, and `Principal: "*"`, then scores each statement.
- `audit_cloudtrail.py` scans CloudTrail logs for risky activity such as root
  usage, console logins without MFA, brute-force logins, audit-trail tampering,
  privilege escalation, and repeated `AccessDenied` errors.

Both are dependency-free (standard library only), produce text, JSON or
Markdown reports, and exit with code 1 on any high/critical finding so they can
gate a CI pipeline. `boto3` is needed only for the optional `--live` mode.

Requires Python 3.9+.

## Project layout

```
audit_iam.py              IAM policy auditor
audit_cloudtrail.py       CloudTrail log analyzer
sample_policies/          example IAM policies (one safe, several risky)
sample_logs/              example CloudTrail log with planted findings
tests/                    pytest suite
```

## IAM policy auditor

```bash
python audit_iam.py sample_policies/
python audit_iam.py sample_policies/ --min-severity high
python audit_iam.py sample_policies/ --format json
python audit_iam.py sample_policies/ --format markdown > report.md
```

To audit a real account:

```bash
aws iam get-account-authorization-details > auth-details.json
python audit_iam.py auth-details.json --min-severity medium
```

### Scoring

| Signal | Points |
|---|---|
| `Action: "*"` | 10 |
| Service-wide wildcard (`s3:*`) | 6 (+3 for sensitive services: iam, sts, kms, organizations, cloudtrail, lambda, secretsmanager) |
| Partial wildcard (`s3:Get*`) | 2 (+3 sensitive) |
| `Allow` + `NotAction` | 8 |
| `Allow` + `NotResource` | 4 |
| `Resource: "*"` | 3 |
| Wildcard inside a resource ARN | 1 |
| `Principal: "*"` | 8 |
| `Condition` block present | score x 0.75 |

Severity: low (<4), medium (4-7), high (8-11), critical (12+).

## CloudTrail analyzer

Offline mode works on log files you already have, so no AWS credentials are
needed:

```bash
python audit_cloudtrail.py sample_logs/
python audit_cloudtrail.py sample_logs/ --min-severity high --format json
python audit_cloudtrail.py logs/ --format markdown > cloudtrail-report.md
```

To analyze your own trail, copy its logs down and point the script at them
(`.json` and `.json.gz` are both read):

```bash
aws s3 sync s3://YOUR-TRAIL-BUCKET/AWSLogs/ ./logs/
python audit_cloudtrail.py logs/
```

It also accepts the output of `aws cloudtrail lookup-events`. For live queries
(management events, last 90 days), install `boto3` and run:

```bash
python audit_cloudtrail.py --live --hours 24 --region us-east-1
```

### Detection rules

| Rule | Severity | Trigger |
|---|---|---|
| `root-account-usage` | high | Any non-service activity by the root user |
| `console-login-no-mfa` | medium (critical for root) | Successful console login with `MFAUsed: No` |
| `console-login-brute-force` | high | 5+ failed console logins from one IP (`--login-fail-threshold`) |
| `defense-evasion` | critical / high | `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `DeleteFlowLogs`, `DeleteDetector`, `StopConfigurationRecorder` |
| `admin-policy-attached` | critical | A policy grant whose parameters include `AdministratorAccess` |
| `privilege-change` | medium | `CreateAccessKey`, `AttachUserPolicy`, `PutRolePolicy`, `CreatePolicyVersion`, and similar |
| `data-exposure-risk` | medium / high | Bucket ACL/policy changes, removing public access blocks, scheduling KMS key deletion |
| `repeated-access-denied` | medium (high at 4x) | 5+ `AccessDenied`/`UnauthorizedOperation` errors from one principal (`--denied-threshold`) |

## Tests

```bash
pip install pytest
pytest
```

## Ideas for extending it

- Add a GitHub Actions workflow that runs `pytest` and audits policies on each push.
- Cross-reference the two tools: for each wildcard permission found in IAM,
  report whether CloudTrail shows it was ever used.
- Add rules for unusual source IPs or regions, or for use of long-lived access keys.
- Query the same data at scale with Athena SQL over the CloudTrail S3 bucket.
