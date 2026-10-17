import json
import subprocess
import sys
from pathlib import Path

import pytest

import audit_iam
from audit_iam import (
    audit_json,
    audit_policy_document,
    audit_statement,
    as_list,
    score_action,
    severity_for,
)

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "sample_policies"


# --- helpers ---------------------------------------------------------------

def stmt(**kw):
    base = {"Effect": "Allow"}
    base.update(kw)
    return base


# --- as_list / severity_for -------------------------------------------------

def test_as_list():
    assert as_list(None) == []
    assert as_list("a") == ["a"]
    assert as_list(["a", "b"]) == ["a", "b"]


@pytest.mark.parametrize(
    "score,expected",
    [(0, "low"), (3, "low"), (4, "medium"), (7, "medium"),
     (8, "high"), (11, "high"), (12, "critical"), (50, "critical")],
)
def test_severity_boundaries(score, expected):
    assert severity_for(score) == expected


# --- score_action ----------------------------------------------------------

def test_full_wildcard_action():
    assert score_action("*")[0] == 10
    assert score_action("*:*")[0] == 10


def test_service_wildcard_normal_vs_sensitive():
    assert score_action("s3:*")[0] == 6
    assert score_action("iam:*")[0] == 9
    assert score_action("IAM:*")[0] == 9  # service match is case-insensitive


def test_partial_wildcard():
    assert score_action("s3:Get*")[0] == 2
    assert score_action("kms:Dec*")[0] == 5
    assert score_action("s3:Get?bject")[0] == 2


def test_exact_action_scores_zero():
    assert score_action("s3:GetObject") == (0, None)


# --- audit_statement -------------------------------------------------------

def test_deny_statements_are_ignored():
    assert audit_statement(stmt(Effect="Deny", Action="*", Resource="*"), "x", "f") is None


def test_clean_statement_returns_none():
    s = stmt(Action="s3:GetObject", Resource="arn:aws:s3:::b/key")
    assert audit_statement(s, "x", "f") is None


def test_admin_star_is_critical():
    f = audit_statement(stmt(Action="*", Resource="*"), "x", "f")
    assert f.score == 13
    assert f.severity == "critical"


def test_resource_star_alone_is_low():
    f = audit_statement(stmt(Action="s3:GetObject", Resource="*"), "x", "f")
    assert f.score == 3
    assert f.severity == "low"


def test_wildcard_inside_arn():
    f = audit_statement(stmt(Action="s3:GetObject", Resource="arn:aws:s3:::b/*"), "x", "f")
    assert f.score == 1
    assert "wildcard inside resource ARN" in f.reasons


def test_not_action_flagged():
    f = audit_statement(stmt(NotAction="iam:*", Resource="arn:aws:s3:::b"), "x", "f")
    assert f is not None
    assert any("NotAction" in r for r in f.reasons)


def test_not_resource_flagged():
    f = audit_statement(stmt(Action="s3:GetObject", NotResource="arn:aws:s3:::b"), "x", "f")
    assert any("NotResource" in r for r in f.reasons)


def test_principal_star_string_and_dict():
    for principal in ("*", {"AWS": "*"}, {"AWS": ["*"]}):
        f = audit_statement(
            stmt(Principal=principal, Action="s3:GetObject", Resource="arn:aws:s3:::b/key"),
            "x", "f",
        )
        assert f is not None and f.score == 8, principal


def test_condition_reduces_score():
    plain = audit_statement(stmt(Action="ec2:*", Resource="*"), "x", "f")
    cond = audit_statement(
        stmt(Action="ec2:*", Resource="*", Condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}}),
        "x", "f",
    )
    assert cond.score < plain.score
    assert cond.score == int(plain.score * 0.75)


def test_multiple_wildcards_add_small_bump():
    one = audit_statement(stmt(Action=["s3:Get*"], Resource="arn:aws:s3:::b/key"), "x", "f")
    two = audit_statement(stmt(Action=["s3:Get*", "s3:List*"], Resource="arn:aws:s3:::b/key"), "x", "f")
    assert two.score == one.score + 1


# --- document / dispatch ---------------------------------------------------

def test_single_statement_object_not_in_list():
    doc = {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
    assert len(audit_policy_document(doc, "f")) == 1


def test_label_uses_sid_or_index():
    doc = {"Statement": [
        {"Effect": "Allow", "Action": "*", "Resource": "*"},
        {"Sid": "Named", "Effect": "Allow", "Action": "*", "Resource": "*"},
    ]}
    labels = [f.statement for f in audit_policy_document(doc, "f")]
    assert labels == ["#0", "Named"]


def test_inline_policy_shape():
    data = {"PolicyName": "p", "PolicyDocument": {"Statement": [
        {"Effect": "Allow", "Action": "*", "Resource": "*"}]}}
    findings = audit_json(data, "file.json")
    assert findings[0].source == "file.json:p"


def test_list_of_policies():
    doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    findings = audit_json([doc, doc], "f.json")
    assert [f.source for f in findings] == ["f.json[0]", "f.json[1]"]


def test_auth_details_shape():
    admin = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    data = {
        "Policies": [{
            "PolicyName": "Managed",
            "PolicyVersionList": [
                {"IsDefaultVersion": False, "Document": admin},   # old version: ignored
                {"IsDefaultVersion": True, "Document": admin},
            ],
        }],
        "RoleDetailList": [{
            "RoleName": "r1",
            "RolePolicyList": [{"PolicyName": "inline1", "PolicyDocument": admin}],
        }],
        "UserDetailList": [{
            "UserName": "u1",
            "UserPolicyList": [{"PolicyName": "inline2", "PolicyDocument": admin}],
        }],
    }
    sources = sorted(f.source for f in audit_json(data, "auth.json"))
    assert sources == ["managed:Managed", "role:r1:inline1", "user:u1:inline2"]


def test_unknown_json_shape_yields_nothing():
    assert audit_json({"hello": "world"}, "f") == []


# --- loading and CLI -------------------------------------------------------

def test_load_findings_skips_bad_json(tmp_path, capsys):
    (tmp_path / "bad.json").write_text("{not json")
    (tmp_path / "good.json").write_text(json.dumps(
        {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
    findings = audit_iam.load_findings(tmp_path)
    assert len(findings) == 1
    assert "skipped" in capsys.readouterr().err


def run_cli(*args):
    return subprocess.run(
        [sys.executable, str(ROOT / "audit_iam.py"), *args],
        capture_output=True, text=True,
    )


def test_cli_exit_code_nonzero_on_high_findings():
    r = run_cli(str(SAMPLES))
    assert r.returncode == 1
    assert "CRITICAL" in r.stdout


def test_cli_exit_code_zero_when_clean():
    r = run_cli(str(SAMPLES / "least_privilege.json"))
    assert r.returncode == 0
    assert "No risky statements found." in r.stdout


def test_cli_json_output_and_min_severity():
    r = run_cli(str(SAMPLES), "--format", "json", "--min-severity", "high")
    data = json.loads(r.stdout)
    assert data and all(f["severity"] in ("high", "critical") for f in data)
    scores = [f["score"] for f in data]
    assert scores == sorted(scores, reverse=True)


def test_cli_markdown_output():
    r = run_cli(str(SAMPLES), "--format", "markdown")
    assert r.stdout.startswith("# IAM Policy Audit")
