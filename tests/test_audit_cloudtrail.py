import gzip
import json
import subprocess
import sys
from pathlib import Path

import audit_cloudtrail as ct

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "sample_logs" / "cloudtrail_sample.json"


def ev(name="ListBuckets", user_type="IAMUser", arn="arn:aws:iam::1:user/u", ip="198.51.100.1", **kw):
    base = {
        "eventTime": "2026-10-10T00:00:00Z",
        "eventName": name,
        "sourceIPAddress": ip,
        "userIdentity": {"type": user_type, "arn": arn},
    }
    base.update(kw)
    return base


def rules(alerts):
    return [a.rule for a in alerts]


# --- single-event rules ----------------------------------------------------

def test_benign_event_no_alert():
    assert ct.analyze([ev("GetObject")]) == []


def test_root_usage_is_high():
    alerts = ct.analyze([ev("ListBuckets", user_type="Root", arn="arn:aws:iam::1:root")])
    assert rules(alerts) == ["root-account-usage"]
    assert alerts[0].severity == "high"


def test_root_aws_service_event_ignored():
    alerts = ct.analyze([ev("RotateKey", user_type="Root", eventType="AwsServiceEvent")])
    assert alerts == []


def test_console_login_without_mfa():
    login = dict(responseElements={"ConsoleLogin": "Success"}, additionalEventData={"MFAUsed": "No"})
    user = ct.analyze([ev("ConsoleLogin", **login)])
    assert rules(user) == ["console-login-no-mfa"] and user[0].severity == "medium"

    root = ct.analyze([ev("ConsoleLogin", user_type="Root", **login)])
    assert rules(root) == ["console-login-no-mfa"]       # no duplicate root-usage alert
    assert root[0].severity == "critical"


def test_console_login_with_mfa_is_fine():
    e = ev("ConsoleLogin", responseElements={"ConsoleLogin": "Success"}, additionalEventData={"MFAUsed": "Yes"})
    assert ct.analyze([e]) == []


def test_defense_evasion_severities():
    assert ct.analyze([ev("StopLogging")])[0].severity == "critical"
    assert ct.analyze([ev("UpdateTrail")])[0].severity == "high"


def test_admin_policy_attachment_is_critical():
    e = ev("AttachUserPolicy", requestParameters={"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})
    alerts = ct.analyze([e])
    assert rules(alerts) == ["admin-policy-attached"]
    assert alerts[0].severity == "critical"


def test_ordinary_privilege_change_is_medium():
    e = ev("CreateAccessKey", requestParameters={"userName": "u"})
    alerts = ct.analyze([e])
    assert rules(alerts) == ["privilege-change"] and alerts[0].severity == "medium"


def test_data_exposure_rule():
    assert ct.analyze([ev("DeleteBucketPublicAccessBlock")])[0].severity == "high"


# --- aggregate rules -------------------------------------------------------

def failed_login(ip="203.0.113.9"):
    return ev("ConsoleLogin", ip=ip, responseElements={"ConsoleLogin": "Failure"})


def test_brute_force_threshold():
    assert ct.analyze([failed_login() for _ in range(4)]) == []
    alerts = ct.analyze([failed_login() for _ in range(5)])
    assert rules(alerts) == ["console-login-brute-force"]
    assert "5 failed" in alerts[0].detail


def test_brute_force_is_per_ip():
    events = [failed_login("203.0.113.1") for _ in range(3)] + [failed_login("203.0.113.2") for _ in range(3)]
    assert ct.analyze(events) == []


def test_login_threshold_is_configurable():
    assert rules(ct.analyze([failed_login(), failed_login()], login_fail_threshold=2)) == ["console-login-brute-force"]


def denied(arn="arn:aws:iam::1:user/u", code="AccessDenied"):
    return ev("ListUsers", arn=arn, errorCode=code)


def test_access_denied_medium_then_high():
    assert ct.analyze([denied() for _ in range(4)]) == []
    assert ct.analyze([denied() for _ in range(5)])[0].severity == "medium"
    assert ct.analyze([denied() for _ in range(20)])[0].severity == "high"


def test_access_denied_counts_unauthorized_operation_and_per_principal():
    mixed = [denied(code="Client.UnauthorizedOperation") for _ in range(3)] + [denied() for _ in range(2)]
    assert rules(ct.analyze(mixed)) == ["repeated-access-denied"]
    split = [denied(arn="a") for _ in range(3)] + [denied(arn="b") for _ in range(3)]
    assert ct.analyze(split) == []


def test_alerts_sorted_most_severe_first():
    alerts = ct.analyze([ev("CreateAccessKey"), ev("StopLogging")])
    assert [a.severity for a in alerts] == ["critical", "medium"]


# --- loading ---------------------------------------------------------------

def test_extract_events_shapes():
    one = ev("GetObject")
    assert ct.extract_events({"Records": [one]}) == [one]
    assert ct.extract_events([one]) == [one]
    wrapped = {"Events": [{"CloudTrailEvent": json.dumps(one)}]}
    assert ct.extract_events(wrapped) == [one]
    assert ct.extract_events({"nope": 1}) == []


def test_load_gzip_and_directory(tmp_path, capsys):
    with gzip.open(tmp_path / "a.json.gz", "wt") as fh:
        json.dump({"Records": [ev("StopLogging")]}, fh)
    (tmp_path / "b.json").write_text(json.dumps({"Records": [ev("GetObject")]}))
    (tmp_path / "bad.json").write_text("{oops")
    events = ct.load_events(tmp_path)
    assert sorted(e["eventName"] for e in events) == ["GetObject", "StopLogging"]
    assert "skipped" in capsys.readouterr().err


# --- sample log + CLI ------------------------------------------------------

def test_sample_log_expected_alerts():
    alerts = ct.analyze(ct.load_events(SAMPLE))
    found = sorted((a.rule, a.severity) for a in alerts)
    assert found == sorted([
        ("console-login-no-mfa", "critical"),
        ("console-login-no-mfa", "medium"),
        ("console-login-brute-force", "high"),
        ("admin-policy-attached", "critical"),
        ("defense-evasion", "critical"),
        ("repeated-access-denied", "medium"),
        ("data-exposure-risk", "medium"),
    ])


def run_cli(*args):
    return subprocess.run(
        [sys.executable, str(ROOT / "audit_cloudtrail.py"), *args], capture_output=True, text=True
    )


def test_cli_text_and_exit_code():
    r = run_cli(str(SAMPLE))
    assert r.returncode == 1
    assert "CRITICAL" in r.stdout and "Summary:" in r.stdout


def test_cli_json_min_severity():
    r = run_cli(str(SAMPLE), "--format", "json", "--min-severity", "critical")
    data = json.loads(r.stdout)
    assert data and all(a["severity"] == "critical" for a in data)


def test_cli_clean_log_exits_zero(tmp_path):
    f = tmp_path / "clean.json"
    f.write_text(json.dumps({"Records": [ev("GetObject")]}))
    r = run_cli(str(f))
    assert r.returncode == 0
    assert "No risky activity found." in r.stdout


def test_cli_requires_path_or_live():
    r = run_cli()
    assert r.returncode == 2
