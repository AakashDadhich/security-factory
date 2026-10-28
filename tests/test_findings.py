import copy
import json

import pytest
from jsonschema import Draft202012Validator

from factory import findings
from factory.findings import FindingsError


def sample(**overrides) -> dict:
    fields = {
        "stage": "sast-semgrep",
        "tool": "semgrep",
        "source": "scanner",
        "rule_id": "python.sql-injection",
        "title": "SQL injection",
        "severity": "high",
        "location": {"path": "app/db.py", "start_line": 12, "end_line": 14},
        "cwe": ["CWE-89"],
        "description": "User input reaches a SQL query.",
        "remediation": "Use parameterised queries.",
    }
    fields.update(overrides)
    return findings.make_finding(**fields)


def manifest(**overrides) -> dict:
    data = {
        "run_id": "40746602330-1",
        "mode": "check",
        "platform": "web",
        "iteration": 0,
        "issue": None,
        "repo": "AakashDadhich/factory-test-web",
        "commit_sha": "7d528a4" + "0" * 33,
        "factory_ref": "v0.1.0",
        "asvs_level": 2,
        "stages": [{"name": "secrets", "status": "success"}, {"name": "sast-semgrep", "status": "pending"}],
        "tool_versions": {"gitleaks": "8.30.1", "semgrep": "1.0.0"},
    }
    data.update(overrides)
    return data


@pytest.mark.parametrize(
    "name", ["finding.schema.json", "findings.schema.json", "run-manifest.schema.json"]
)
def test_schemas_are_valid_2020_12(name):
    schema = json.loads((findings.SCHEMA_DIR / name).read_text())
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator.check_schema(schema)


def test_finding_schema_requires_exactly_the_contract_fields():
    schema = json.loads((findings.SCHEMA_DIR / "finding.schema.json").read_text())
    assert set(schema["required"]) == {
        "id", "stage", "tool", "source", "rule_id", "title", "severity",
        "location", "cwe", "description", "remediation", "fingerprint",
    }
    assert schema["additionalProperties"] is False


def test_make_finding_fills_id_and_fingerprint():
    f = sample()
    assert len(f["fingerprint"]) == 64
    assert f["id"] == f"sast-semgrep:{f['fingerprint']}"
    findings.validate([f])


def test_make_finding_defaults_optional_text_fields():
    f = findings.make_finding(
        stage="secrets",
        tool="gitleaks",
        source="scanner",
        rule_id="aws-access-token",
        title="AWS key",
        severity="high",
        location={"path": "config.py", "start_line": 3},
    )
    assert f["cwe"] == []
    assert f["description"] == ""
    assert f["remediation"] == ""
    assert f["location"] == {"path": "config.py", "start_line": 3, "end_line": 3}


def test_make_finding_accepts_url_location():
    f = sample(stage="dast-zap", tool="zap", rule_id="10021", location={"url": "http://localhost:3000/login?x=1", "method": "post"})
    assert f["location"] == {"url": "http://localhost:3000/login?x=1", "method": "POST"}


def test_make_finding_rejects_missing_fields():
    with pytest.raises(FindingsError, match="missing severity"):
        findings.make_finding(stage="s", tool="t", source="scanner", rule_id="r", title="x", location={"path": "a", "start_line": 1})


def test_make_finding_rejects_unknown_fields():
    with pytest.raises(FindingsError, match="unknown fields: colour"):
        sample(colour="red")


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"severity": "urgent"}, "severity"),
        ({"source": "human"}, "source"),
        ({"cwe": ["89"]}, "cwe"),
        ({"stage": "Bad Stage"}, "stage"),
        ({"location": {"path": "a.py", "start_line": 0, "end_line": 0}}, "location"),
    ],
)
def test_make_finding_rejects_bad_values(overrides, message):
    with pytest.raises(FindingsError, match=message):
        sample(**overrides)


def test_fingerprint_is_stable_and_normalised():
    a = findings.fingerprint("semgrep", "r1", {"path": "./app/db.py", "start_line": 12, "end_line": 12})
    b = findings.fingerprint("semgrep", "r1", {"path": "app/db.py", "start_line": 12, "end_line": 20})
    c = findings.fingerprint("semgrep", "r1", {"path": "app\\db.py", "start_line": 12})
    assert a == b == c
    assert a == findings.fingerprint("semgrep", "r1", {"path": "app/db.py", "start_line": 12})


@pytest.mark.parametrize(
    "tool, rule_id, location",
    [
        ("codeql", "r1", {"path": "app/db.py", "start_line": 12}),
        ("semgrep", "r2", {"path": "app/db.py", "start_line": 12}),
        ("semgrep", "r1", {"path": "app/other.py", "start_line": 12}),
        ("semgrep", "r1", {"path": "app/db.py", "start_line": 13}),
    ],
)
def test_fingerprint_changes_with_each_input(tool, rule_id, location):
    base = findings.fingerprint("semgrep", "r1", {"path": "app/db.py", "start_line": 12})
    assert findings.fingerprint(tool, rule_id, location) != base


def test_url_fingerprint_uses_path_and_method_only():
    a = findings.fingerprint("zap", "10021", {"url": "http://localhost:3000/login?a=1", "method": "GET"})
    b = findings.fingerprint("zap", "10021", {"url": "http://127.0.0.1:8080/login", "method": "get"})
    c = findings.fingerprint("zap", "10021", {"url": "http://localhost:3000/login", "method": "POST"})
    assert a == b
    assert a != c


def test_validate_rejects_tampered_fingerprint():
    f = sample()
    f["location"]["start_line"] = 99
    with pytest.raises(FindingsError, match="fingerprint does not match"):
        findings.validate([f])


def test_validate_rejects_wrong_id():
    f = sample()
    f["id"] = "other-stage:" + f["fingerprint"]
    with pytest.raises(FindingsError, match="id must be"):
        findings.validate([f])


def test_validate_rejects_duplicates():
    f = sample()
    with pytest.raises(FindingsError, match="duplicate id"):
        findings.validate([f, copy.deepcopy(f)])


def test_validate_rejects_non_array():
    with pytest.raises(FindingsError, match="<root>"):
        findings.validate({"not": "a list"})


def test_write_then_load_round_trip(tmp_path):
    items = [sample(), sample(rule_id="python.xss", cwe=["CWE-79"])]
    path = tmp_path / "out" / "sast-semgrep" / "findings.json"
    findings.write(path, items)
    assert findings.load(path) == items
    assert path.read_text().endswith("\n")


def test_write_refuses_invalid(tmp_path):
    bad = sample()
    bad["severity"] = "nope"
    with pytest.raises(FindingsError):
        findings.write(tmp_path / "findings.json", [bad])
    assert not (tmp_path / "findings.json").exists()


def test_load_rejects_bad_json(tmp_path):
    path = tmp_path / "findings.json"
    path.write_text("{oops")
    with pytest.raises(FindingsError, match="not valid JSON"):
        findings.load(path)


def test_empty_findings_are_valid(tmp_path):
    path = tmp_path / "findings.json"
    findings.write(path, [])
    assert findings.load(path) == []


def test_run_manifest_valid():
    assert list(findings.validator("run-manifest.schema.json").iter_errors(manifest())) == []
    assert list(findings.validator("run-manifest.schema.json").iter_errors(manifest(issue=7))) == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"mode": "deploy"},
        {"platform": "android"},
        {"iteration": 3},
        {"iteration": -1},
        {"issue": "7"},
        {"repo": "no-slash"},
        {"commit_sha": "abc"},
        {"asvs_level": 4},
        {"stages": [{"name": "secrets", "status": "done"}]},
        {"tool_versions": {"gitleaks": 8}},
    ],
)
def test_run_manifest_rejects_bad_values(overrides):
    assert list(findings.validator("run-manifest.schema.json").iter_errors(manifest(**overrides)))


def test_run_manifest_requires_every_field():
    data = manifest()
    del data["tool_versions"]
    assert list(findings.validator("run-manifest.schema.json").iter_errors(data))
