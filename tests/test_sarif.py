import json
import subprocess
import sys
from pathlib import Path

import pytest

from factory import findings, sarif
from factory.findings import FindingsError

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def by_rule(items: list) -> dict:
    return {f["rule_id"]: f for f in items}


@pytest.mark.parametrize(
    "score, severity",
    [
        (10.0, "critical"),
        (9.0, "critical"),
        (8.9, "high"),
        (8.1, "high"),
        (7.0, "high"),
        (6.9, "medium"),
        (4.0, "medium"),
        (3.9, "low"),
        (0.1, "low"),
        (0.0, "info"),
    ],
)
def test_severity_from_score(score, severity):
    assert sarif.severity_from_score(score) == severity


@pytest.mark.parametrize(
    "tags, expected",
    [
        (["external/cwe/cwe-089"], ["CWE-89"]),
        (["CWE-89: Improper Neutralization of Special Elements"], ["CWE-89"]),
        (["cwe-79", "external/cwe/cwe-079", "security"], ["CWE-79"]),
        (["external/cwe/cwe-798", "external/cwe/cwe-259"], ["CWE-259", "CWE-798"]),
        (["OWASP-A03:2021 - Injection", "security", 7], []),
        (["CWE-0"], []),
    ],
)
def test_cwes_from_tags(tags, expected):
    assert sarif.cwes_from_tags(tags) == expected


def test_codeql_uses_security_severity():
    items = by_rule(sarif.sarif_to_findings(FIXTURES / "codeql.sarif", "sast-codeql", "codeql"))
    assert items["js/sql-injection"]["severity"] == "high"
    assert items["js/reflected-xss"]["severity"] == "medium"
    assert items["js/hardcoded-credentials"]["severity"] == "critical"
    assert items["js/insecure-randomness"]["severity"] == "low"
    assert items["js/unused-local-variable"]["severity"] == "low"


def test_codeql_reads_rules_from_extensions():
    items = by_rule(sarif.sarif_to_findings(FIXTURES / "codeql.sarif", "sast-codeql", "codeql"))
    sqli = items["js/sql-injection"]
    assert sqli["title"] == "Database query built from user-controlled sources"
    assert sqli["cwe"] == ["CWE-89", "CWE-90", "CWE-943"]
    assert sqli["remediation"] == "Use a parameterised query or prepared statement."
    assert sqli["location"] == {"path": "src/routes/users.js", "start_line": 27, "end_line": 27}
    assert items["js/reflected-xss"]["location"]["end_line"] == 17
    assert items["js/hardcoded-credentials"]["cwe"] == ["CWE-259", "CWE-321", "CWE-798"]
    assert items["js/unused-local-variable"]["cwe"] == []


def test_codeql_skips_pass_results():
    items = sarif.sarif_to_findings(FIXTURES / "codeql.sarif", "sast-codeql", "codeql")
    assert len(items) == 5
    assert all(f["description"] != "No issue." for f in items)


def test_semgrep_uses_level_and_dedupes_same_line():
    items = sarif.sarif_to_findings(FIXTURES / "semgrep.sarif", "sast-semgrep", "semgrep")
    assert len(items) == 3
    rules = by_rule(items)
    sqli = rules["python.lang.security.audit.formatted-sql-query.formatted-sql-query"]
    assert sqli["severity"] == "high"
    assert sqli["cwe"] == ["CWE-89"]
    assert rules["python.flask.security.audit.debug-enabled.debug-enabled"]["severity"] == "medium"
    assert rules["python.flask.security.audit.debug-enabled.debug-enabled"]["location"]["path"] == "app/main.py"
    assert rules["python.flask.security.audit.debug-enabled.debug-enabled"]["cwe"] == ["CWE-489"]
    assert rules["generic.style.todo"]["severity"] == "low"


def test_gitleaks_defaults_to_warning_level():
    items = by_rule(sarif.sarif_to_findings(FIXTURES / "gitleaks.sarif", "secrets", "gitleaks"))
    assert set(items) == {"aws-access-token", "generic-api-key"}
    aws = items["aws-access-token"]
    assert aws["severity"] == "medium"
    assert aws["source"] == "scanner"
    assert aws["location"] == {"path": "config/settings.py", "start_line": 3, "end_line": 3}
    assert aws["title"].startswith("Identified a pattern that may indicate AWS credentials")
    assert aws["description"] == "aws-access-token has detected secret for file config/settings.py."
    assert "REDACTED" not in json.dumps(aws)


@pytest.mark.parametrize(
    "fixture, stage, tool",
    [
        ("semgrep.sarif", "sast-semgrep", "semgrep"),
        ("gitleaks.sarif", "secrets", "gitleaks"),
        ("codeql.sarif", "sast-codeql", "codeql"),
    ],
)
def test_fixtures_convert_to_valid_findings_with_stable_fingerprints(fixture, stage, tool):
    first = sarif.sarif_to_findings(FIXTURES / fixture, stage, tool)
    second = sarif.sarif_to_findings(FIXTURES / fixture, stage, tool)
    findings.validate(first)
    assert [f["fingerprint"] for f in first] == [f["fingerprint"] for f in second]
    assert all(f["stage"] == stage and f["tool"] == tool for f in first)
    assert all(f["id"] == f"{stage}:{f['fingerprint']}" for f in first)


def write_sarif(tmp_path: Path, runs) -> Path:
    path = tmp_path / "in.sarif"
    path.write_text(json.dumps({"version": "2.1.0", "runs": runs}))
    return path


def test_result_level_overrides_rule_default(tmp_path):
    path = write_sarif(tmp_path, [{
        "tool": {"driver": {"name": "t", "rules": [{"id": "r", "defaultConfiguration": {"level": "note"}}]}},
        "results": [{"ruleId": "r", "level": "error", "message": {"text": "m"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}]}],
    }])
    assert sarif.sarif_to_findings(path, "s", "t")[0]["severity"] == "high"


def test_result_security_severity_overrides_rule(tmp_path):
    path = write_sarif(tmp_path, [{
        "tool": {"driver": {"name": "t", "rules": [{"id": "r", "properties": {"security-severity": "2.0"}}]}},
        "results": [{"ruleId": "r", "ruleIndex": 0, "properties": {"security-severity": "9.1"}, "message": {"text": "m"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}]}],
    }])
    assert sarif.sarif_to_findings(path, "s", "t")[0]["severity"] == "critical"


def test_bad_security_severity_falls_back_to_level(tmp_path):
    path = write_sarif(tmp_path, [{
        "tool": {"driver": {"name": "t", "rules": [{"id": "r", "properties": {"security-severity": "high"}}]}},
        "results": [{"ruleId": "r", "level": "note", "message": {"text": "m"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}]}],
    }])
    assert sarif.sarif_to_findings(path, "s", "t")[0]["severity"] == "low"


def test_level_none_maps_to_info_and_missing_location_is_kept(tmp_path):
    path = write_sarif(tmp_path, [{
        "tool": {"driver": {"name": "t"}},
        "results": [{"ruleId": "r", "level": "none", "message": {"text": "first line\nsecond"}}],
    }])
    [f] = sarif.sarif_to_findings(path, "s", "t")
    assert f["severity"] == "info"
    assert f["title"] == "first line"
    assert f["location"] == {"path": ".", "start_line": None, "end_line": None}


def test_dedupe_keeps_highest_severity(tmp_path):
    loc = [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 5}}}]
    path = write_sarif(tmp_path, [{
        "tool": {"driver": {"name": "t"}},
        "results": [
            {"ruleId": "r", "level": "note", "message": {"text": "m"}, "locations": loc},
            {"ruleId": "r", "level": "error", "message": {"text": "m"}, "locations": loc},
        ],
    }])
    [f] = sarif.sarif_to_findings(path, "s", "t")
    assert f["severity"] == "high"


def test_multiple_runs_are_merged(tmp_path):
    def run(uri):
        return {"tool": {"driver": {"name": "t"}},
                "results": [{"ruleId": "r", "message": {"text": "m"},
                             "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 1}}}]}]}
    path = write_sarif(tmp_path, [run("a.py"), run("b.py")])
    assert {f["location"]["path"] for f in sarif.sarif_to_findings(path, "s", "t")} == {"a.py", "b.py"}


def test_rejects_non_sarif(tmp_path):
    path = tmp_path / "x.sarif"
    path.write_text("[]")
    with pytest.raises(FindingsError, match="not a SARIF log"):
        sarif.sarif_to_findings(path, "s", "t")
    path.write_text("{")
    with pytest.raises(FindingsError, match="not valid JSON"):
        sarif.sarif_to_findings(path, "s", "t")


def test_main_writes_out_file(tmp_path):
    out = tmp_path / "out" / "secrets" / "findings.json"
    assert sarif.main([str(FIXTURES / "gitleaks.sarif"), "--stage", "secrets", "--tool", "gitleaks", "--out", str(out)]) == 0
    assert len(findings.load(out)) == 2


def test_main_reports_missing_file(tmp_path, capsys):
    assert sarif.main([str(tmp_path / "nope.sarif"), "--stage", "s", "--tool", "t"]) == 1
    assert "error:" in capsys.readouterr().err


def run_cli() -> str:
    proc = subprocess.run(
        [sys.executable, "-m", "factory.sarif", "tests/fixtures/codeql.sarif", "--stage", "sast-codeql", "--tool", "codeql"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    return proc.stdout


def test_cli_codeql_output_validates_and_is_stable():
    first = run_cli()
    second = run_cli()
    assert first == second
    items = findings.validate(json.loads(first))
    assert by_rule(items)["js/sql-injection"]["severity"] == "high"
