#!/usr/bin/env python3
"""Flag risky activity in AWS CloudTrail logs.

Detection rules
  * root account usage
  * console logins without MFA (critical for root)
  * brute-force pattern: many failed console logins from one IP
  * defense evasion: StopLogging, DeleteTrail, UpdateTrail, ...
  * privilege escalation: access keys, policy attachments, admin policy grants
  * data exposure: bucket ACL/policy changes, public access block removal, KMS key disabling
  * repeated AccessDenied / UnauthorizedOperation from one principal (probing)

Input (offline, no AWS credentials needed):
  * a CloudTrail log file (.json or .json.gz) or a directory of them, such as
    files copied from your trail's S3 bucket (`aws s3 sync`)
  * the output of `aws cloudtrail lookup-events`

Live mode (needs boto3 and credentials; management events from the last 90 days):
  python audit_cloudtrail.py --live --hours 24

Usage:
  python audit_cloudtrail.py sample_logs/
  python audit_cloudtrail.py logs/ --format json --min-severity high
  python audit_cloudtrail.py logs/ --format markdown > report.md
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

DEFENSE_EVASION = {
    "StopLogging": "critical",
    "DeleteTrail": "critical",
    "UpdateTrail": "high",
    "PutEventSelectors": "high",
    "DeleteFlowLogs": "high",
    "DeleteDetector": "high",           # GuardDuty
    "StopConfigurationRecorder": "high",
}

PRIVILEGE_ESCALATION = {
    "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile",
    "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
    "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
    "CreatePolicyVersion", "SetDefaultPolicyVersion", "AddUserToGroup",
    "UpdateAssumeRolePolicy",
}

DATA_EXPOSURE = {
    "PutBucketAcl": "medium",
    "PutBucketPolicy": "medium",
    "DeleteBucketPolicy": "medium",
    "DeletePublicAccessBlock": "high",
    "DeleteBucketPublicAccessBlock": "high",
    "PutBucketPublicAccessBlock": "medium",
    "ScheduleKeyDeletion": "high",
    "DisableKey": "medium",
}


@dataclass
class Alert:
    severity: str
    rule: str
    time: str
    principal: str
    source_ip: str
    event: str
    detail: str


def principal_of(ev: dict) -> str:
    ui = ev.get("userIdentity") or {}
    return ui.get("arn") or ui.get("userName") or ui.get("principalId") or ui.get("type") or "unknown"


def make_alert(ev: dict, severity: str, rule: str, detail: str) -> Alert:
    return Alert(
        severity, rule, ev.get("eventTime", ""), principal_of(ev),
        ev.get("sourceIPAddress", ""), ev.get("eventName", ""), detail,
    )


def is_denied(code: str | None) -> bool:
    return bool(code) and ("AccessDenied" in code or "UnauthorizedOperation" in code)


def check_event(ev: dict) -> list[Alert]:
    """Rules that can be decided from a single event."""
    alerts: list[Alert] = []
    name = ev.get("eventName", "")
    ui = ev.get("userIdentity") or {}
    is_root = ui.get("type") == "Root"
    handled_root = False

    if name == "ConsoleLogin":
        outcome = (ev.get("responseElements") or {}).get("ConsoleLogin")
        mfa = (ev.get("additionalEventData") or {}).get("MFAUsed")
        if outcome == "Success" and mfa == "No":
            alerts.append(make_alert(
                ev, "critical" if is_root else "medium", "console-login-no-mfa",
                "Console login succeeded without MFA" + (" (root account)" if is_root else ""),
            ))
            handled_root = is_root

    if is_root and not handled_root and ev.get("eventType") != "AwsServiceEvent":
        alerts.append(make_alert(ev, "high", "root-account-usage", f"Root account performed {name}"))

    if name in DEFENSE_EVASION:
        alerts.append(make_alert(
            ev, DEFENSE_EVASION[name], "defense-evasion",
            f"{name} can disable or weaken audit/detection coverage",
        ))

    if name in PRIVILEGE_ESCALATION:
        params = json.dumps(ev.get("requestParameters") or {})
        if "AdministratorAccess" in params:
            alerts.append(make_alert(
                ev, "critical", "admin-policy-attached", f"{name} granted AdministratorAccess",
            ))
        else:
            alerts.append(make_alert(
                ev, "medium", "privilege-change", f"{name} changes credentials or permissions",
            ))

    if name in DATA_EXPOSURE:
        alerts.append(make_alert(
            ev, DATA_EXPOSURE[name], "data-exposure-risk", f"{name} may expose or destroy data",
        ))

    return alerts


def analyze(events: list[dict], denied_threshold: int = 5, login_fail_threshold: int = 5) -> list[Alert]:
    alerts: list[Alert] = []
    failed_logins: dict[str, list[dict]] = defaultdict(list)   # keyed by source IP
    denied: dict[str, list[dict]] = defaultdict(list)          # keyed by principal

    for ev in events:
        alerts += check_event(ev)

        if ev.get("eventName") == "ConsoleLogin":
            outcome = (ev.get("responseElements") or {}).get("ConsoleLogin")
            if outcome == "Failure":
                failed_logins[ev.get("sourceIPAddress", "unknown")].append(ev)

        if is_denied(ev.get("errorCode")):
            denied[principal_of(ev)].append(ev)

    for ip, evs in failed_logins.items():
        if len(evs) >= login_fail_threshold:
            alerts.append(make_alert(
                evs[0], "high", "console-login-brute-force",
                f"{len(evs)} failed console logins from {ip}",
            ))

    for who, evs in denied.items():
        n = len(evs)
        if n >= denied_threshold:
            sev = "high" if n >= denied_threshold * 4 else "medium"
            alerts.append(make_alert(
                evs[0], sev, "repeated-access-denied", f"{n} AccessDenied/Unauthorized errors by {who}",
            ))

    alerts.sort(key=lambda a: (-SEVERITY_ORDER.index(a.severity), a.time))
    return alerts


# --- loading ---------------------------------------------------------------

def read_json(path: Path):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as fh:
        return json.load(fh)


def extract_events(data) -> list[dict]:
    """Handle CloudTrail log files, lookup-events output, or a bare list of events."""
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict) and "Records" in data:
        items = data["Records"]
    elif isinstance(data, dict) and "Events" in data:
        items = []
        for e in data["Events"]:
            raw = e.get("CloudTrailEvent") if isinstance(e, dict) else None
            items.append(json.loads(raw) if isinstance(raw, str) else e)
    else:
        items = []
    return [e for e in items if isinstance(e, dict)]


def load_events(path: Path) -> list[dict]:
    if path.is_dir():
        files = sorted(set(path.rglob("*.json")) | set(path.rglob("*.json.gz")))
    else:
        files = [path]
    events: list[dict] = []
    for f in files:
        try:
            events += extract_events(read_json(f))
        except (json.JSONDecodeError, OSError, EOFError) as exc:
            print(f"warning: skipped {f}: {exc}", file=sys.stderr)
    return events


def fetch_live(hours: int, region: str | None) -> list[dict]:
    try:
        import boto3
    except ImportError:
        sys.exit("boto3 is required for --live (pip install boto3)")
    client = boto3.client("cloudtrail", region_name=region)
    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    events = []
    for page in client.get_paginator("lookup_events").paginate(StartTime=start):
        for e in page["Events"]:
            events.append(json.loads(e["CloudTrailEvent"]))
    return events


# --- reporting -------------------------------------------------------------

def render_text(alerts: list[Alert]) -> str:
    if not alerts:
        return "No risky activity found."
    lines = []
    for a in alerts:
        lines.append(f"[{a.severity.upper():8}] {a.rule}  {a.time}  {a.principal}  {a.source_ip}")
        lines.append(f"             - {a.detail}")
    counts = {s: sum(1 for a in alerts if a.severity == s) for s in SEVERITY_ORDER[::-1]}
    lines.append("\nSummary: " + ", ".join(f"{n} {s}" for s, n in counts.items()))
    return "\n".join(lines)


def render_markdown(alerts: list[Alert]) -> str:
    out = ["# CloudTrail Audit", "", "| Severity | Rule | Time | Principal | Source IP | Detail |", "|---|---|---|---|---|---|"]
    for a in alerts:
        out.append(f"| {a.severity} | {a.rule} | {a.time} | {a.principal} | {a.source_ip} | {a.detail} |")
    return "\n".join(out)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("path", nargs="?", type=Path, help="log file or directory (.json / .json.gz)")
    p.add_argument("--live", action="store_true", help="query CloudTrail directly with boto3")
    p.add_argument("--hours", type=int, default=24, help="look-back window for --live (default 24)")
    p.add_argument("--region", help="AWS region for --live")
    p.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    p.add_argument("--min-severity", choices=SEVERITY_ORDER, default="low")
    p.add_argument("--denied-threshold", type=int, default=5, help="AccessDenied count that triggers an alert")
    p.add_argument("--login-fail-threshold", type=int, default=5, help="failed logins per IP that trigger an alert")
    args = p.parse_args()

    if args.live:
        events = fetch_live(args.hours, args.region)
    elif args.path:
        events = load_events(args.path)
    else:
        p.error("provide a log path or use --live")

    alerts = analyze(events, args.denied_threshold, args.login_fail_threshold)
    floor = SEVERITY_ORDER.index(args.min_severity)
    alerts = [a for a in alerts if SEVERITY_ORDER.index(a.severity) >= floor]

    if args.format == "json":
        print(json.dumps([asdict(a) for a in alerts], indent=2))
    elif args.format == "markdown":
        print(render_markdown(alerts))
    else:
        print(render_text(alerts))

    return 1 if any(a.severity in ("high", "critical") for a in alerts) else 0


if __name__ == "__main__":
    sys.exit(main())
