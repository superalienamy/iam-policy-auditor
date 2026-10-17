#!/usr/bin/env python3
"""Audit AWS IAM policies for wildcard actions/resources, score them, and report.

Accepts:
  * a single policy document (JSON file)
  * a directory of policy JSON files
  * the output of `aws iam get-account-authorization-details`

Usage:
  python audit_iam.py sample_policies/
  python audit_iam.py policies.json --format json --min-severity high
  python audit_iam.py auth-details.json --format markdown > report.md
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

# Services where a wildcard is especially dangerous (privilege escalation,
# data access, or loss of audit trail).
SENSITIVE_SERVICES = {"iam", "sts", "kms", "organizations", "cloudtrail", "lambda", "secretsmanager"}

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


@dataclass
class Finding:
    source: str          # file or policy name
    statement: str       # Sid or index
    score: int
    severity: str
    reasons: list[str] = field(default_factory=list)


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def severity_for(score: int) -> str:
    if score >= 12:
        return "critical"
    if score >= 8:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def score_action(action: str) -> tuple[int, str | None]:
    """Score a single action string like 's3:*' or '*'."""
    if action in ("*", "*:*"):
        return 10, "action '*' grants every API call"
    service, _, name = action.partition(":")
    service = service.lower()
    bonus = 3 if service in SENSITIVE_SERVICES else 0
    if name == "*":
        return 6 + bonus, f"service-wide wildcard '{action}'"
    if "*" in name or "?" in name:
        return 2 + bonus, f"partial wildcard '{action}'"
    return 0, None


def audit_statement(stmt: dict, label: str, source: str) -> Finding | None:
    if stmt.get("Effect") != "Allow":
        return None

    score, reasons = 0, []

    # Actions
    if "NotAction" in stmt:
        score += 8
        reasons.append("Allow + NotAction allows everything except the listed actions")
    action_scores = []
    for action in as_list(stmt.get("Action")):
        s, why = score_action(str(action))
        if why:
            action_scores.append(s)
            reasons.append(why)
    if action_scores:
        score += max(action_scores) + min(len(action_scores) - 1, 3)  # small bump for many wildcards

    # Resources
    resources = [str(r) for r in as_list(stmt.get("Resource"))]
    if "NotResource" in stmt:
        score += 4
        reasons.append("Allow + NotResource applies to everything except the listed resources")
    if "*" in resources:
        score += 3
        reasons.append("Resource '*' applies to all resources")
    elif any("*" in r for r in resources):
        score += 1
        reasons.append("wildcard inside resource ARN")

    # Principals (resource-based policies)
    principal = stmt.get("Principal")
    if principal == "*" or (isinstance(principal, dict) and "*" in as_list(principal.get("AWS"))):
        score += 8
        reasons.append("Principal '*' allows any AWS account/anonymous callers")

    if not reasons:
        return None

    # Conditions narrow the blast radius; dampen the score a bit.
    if stmt.get("Condition"):
        score = max(1, int(score * 0.75))
        reasons.append("has Condition block (score reduced 25%)")

    return Finding(source, label, score, severity_for(score), reasons)


def audit_policy_document(doc: dict, source: str) -> list[Finding]:
    findings = []
    for i, stmt in enumerate(as_list(doc.get("Statement"))):
        label = stmt.get("Sid") or f"#{i}"
        f = audit_statement(stmt, label, source)
        if f:
            findings.append(f)
    return findings


def audit_json(data, source: str) -> list[Finding]:
    """Dispatch on the shape of the JSON."""
    findings: list[Finding] = []
    if isinstance(data, list):
        for i, item in enumerate(data):
            findings += audit_json(item, f"{source}[{i}]")
    elif isinstance(data, dict):
        if "Statement" in data:
            findings += audit_policy_document(data, source)
        elif "PolicyDocument" in data:  # inline policy
            name = data.get("PolicyName", "inline")
            findings += audit_policy_document(data["PolicyDocument"], f"{source}:{name}")
        elif any(k in data for k in ("Policies", "RoleDetailList", "UserDetailList", "GroupDetailList")):
            findings += audit_auth_details(data, source)
    return findings


def audit_auth_details(data: dict, source: str) -> list[Finding]:
    findings = []
    for pol in data.get("Policies", []):  # managed policies
        for ver in pol.get("PolicyVersionList", []):
            if ver.get("IsDefaultVersion"):
                findings += audit_policy_document(ver["Document"], f"managed:{pol['PolicyName']}")
    for key, prefix in (("RoleDetailList", "role"), ("UserDetailList", "user"), ("GroupDetailList", "group")):
        for ent in data.get(key, []):
            name = ent.get(f"{prefix.capitalize()}Name", "?")
            for inline in ent.get(f"{prefix.capitalize()}PolicyList", []):
                findings += audit_policy_document(
                    inline["PolicyDocument"], f"{prefix}:{name}:{inline['PolicyName']}"
                )
    return findings


def load_findings(path: Path) -> list[Finding]:
    files = sorted(path.rglob("*.json")) if path.is_dir() else [path]
    findings = []
    for f in files:
        try:
            findings += audit_json(json.loads(f.read_text()), f.name)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"warning: skipped {f}: {exc}", file=sys.stderr)
    return findings


def render_text(findings: list[Finding]) -> str:
    if not findings:
        return "No risky statements found."
    lines = []
    for f in findings:
        lines.append(f"[{f.severity.upper():8}] score={f.score:<3} {f.source} / {f.statement}")
        lines += [f"             - {r}" for r in f.reasons]
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER[::-1]}
    lines.append("\nSummary: " + ", ".join(f"{n} {s}" for s, n in counts.items()))
    return "\n".join(lines)


def render_markdown(findings: list[Finding]) -> str:
    out = ["# IAM Policy Audit", "", "| Severity | Score | Source | Statement | Reasons |", "|---|---|---|---|---|"]
    for f in findings:
        out.append(f"| {f.severity} | {f.score} | {f.source} | {f.statement} | {'; '.join(f.reasons)} |")
    return "\n".join(out)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("path", type=Path, help="policy JSON file or directory")
    p.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    p.add_argument("--min-severity", choices=SEVERITY_ORDER, default="low")
    args = p.parse_args()

    findings = load_findings(args.path)
    floor = SEVERITY_ORDER.index(args.min_severity)
    findings = [f for f in findings if SEVERITY_ORDER.index(f.severity) >= floor]
    findings.sort(key=lambda f: f.score, reverse=True)

    if args.format == "json":
        print(json.dumps([asdict(f) for f in findings], indent=2))
    elif args.format == "markdown":
        print(render_markdown(findings))
    else:
        print(render_text(findings))

    # Non-zero exit if anything high/critical, handy for CI.
    return 1 if any(f.severity in ("high", "critical") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
