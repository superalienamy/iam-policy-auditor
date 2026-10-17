# IAM Policy Auditor

A small, dependency-free Python tool that scans AWS IAM policies for wildcard
actions, wildcard resources, `NotAction`/`NotResource`, and `Principal: "*"`,
then scores each statement and reports it by severity.

## Quick start

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

Requires Python 3.9+ and nothing else.

## Scoring

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
The script exits with code 1 if any high or critical finding exists, so it can
gate a CI pipeline.

## Next steps (to grow the project)

- Add unit tests with `pytest` for `score_action` and `audit_statement`.
- Add a GitHub Actions workflow that runs the audit on policies in a repo.
- Add a second script that queries CloudTrail logs (Athena SQL or `boto3`
  `lookup_events`) to flag risky access such as console logins without MFA,
  `AccessDenied` spikes, or use of the root account.
- Cross-reference findings with CloudTrail to show which wildcard permissions
  are actually used.
