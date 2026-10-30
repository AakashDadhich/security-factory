import json

import pytest
import yaml

from factory import acceptance
from factory.acceptance import AcceptanceError, evaluate, load_expected, matches, render_table


def finding(**over):
    base = {
        "id": "f1",
        "stage": "sast-semgrep",
        "stages": ["sast-semgrep"],
        "tool": "semgrep",
        "source": "scanner",
        "rule_id": "javascript.express.sqli",
        "title": "t",
        "severity": "high",
        "location": {"path": "src/app.ts", "start_line": 10, "end_line": 10},
        "cwe": ["CWE-89"],
        "fingerprint": "a" * 64,
        "suppressed": False,
    }
    base.update(over)
    return base


def exp(**over):
    base = {"id": "sqli", "stages": ["sast-semgrep"], "rule_id": None, "cwe": ["CWE-89"], "path": None, "min_severity": "high", "optional": False}
    base.update(over)
    return base


def write_expected(tmp_path, data):
    path = tmp_path / "expected.yml"
    path.write_text(yaml.safe_dump(data))
    return path


def test_cwe_match():
    assert matches(exp(), finding())


def test_cwe_mismatch():
    assert not matches(exp(), finding(cwe=["CWE-79"]))


def test_rule_id_regex_matches_without_cwe():
    assert matches(exp(cwe=None, rule_id=r"sqli$"), finding(cwe=[]))
    assert not matches(exp(cwe=None, rule_id=r"^xss"), finding(cwe=[]))


def test_rule_id_or_cwe_either_is_enough():
    assert matches(exp(rule_id="nomatch"), finding())
    assert matches(exp(cwe=["CWE-1"], rule_id="sqli"), finding())


def test_stage_must_be_one_of_the_merged_stages():
    merged = finding(stage="sast-semgrep", stages=["sast-codeql", "sast-semgrep"])
    assert matches(exp(stages=["sast-codeql"]), merged)
    assert not matches(exp(stages=["secrets"]), merged)


def test_stage_alternatives():
    assert matches(exp(stages=["sast-codeql", "sast-semgrep"]), finding())


def test_finding_without_stages_list_uses_stage():
    f = finding()
    del f["stages"]
    assert matches(exp(), f)


@pytest.mark.parametrize(("severity", "ok"), [("critical", True), ("high", True), ("medium", False), ("low", False), ("info", False)])
def test_severity_floor(severity, ok):
    assert matches(exp(min_severity="high"), finding(severity=severity)) is ok


def test_low_floor_accepts_everything_above():
    assert matches(exp(min_severity="low"), finding(severity="medium"))
    assert not matches(exp(min_severity="low"), finding(severity="info"))


def test_suppressed_findings_do_not_count():
    assert not matches(exp(), finding(suppressed=True))


def test_path_regex():
    assert matches(exp(path=r"^src/"), finding())
    assert not matches(exp(path=r"^lib/"), finding())


def test_path_regex_uses_url_for_dast_findings():
    dast = finding(stage="dast-web", stages=["dast-web"], location={"url": "/health", "method": "GET"}, cwe=["CWE-693"])
    assert matches(exp(stages=["dast-web"], cwe=["CWE-693"], path="health", min_severity="low"), dast)


def test_evaluate_all_matched_and_gate_failed():
    result = evaluate([exp()], [finding()], {"status": "fail"})
    assert result["ok"]
    row = result["rows"][0]
    assert row["status"] == "matched"
    assert row["caught_by"] == "sast-semgrep"
    assert "javascript.express.sqli" in row["finding"]


def test_evaluate_gate_pass_is_a_failure():
    result = evaluate([exp()], [finding()], {"status": "pass"})
    assert not result["ok"]
    assert not result["gate_failed_as_required"]


def test_evaluate_missing_required_fails():
    result = evaluate([exp()], [], {"status": "fail"})
    assert not result["ok"]
    assert result["rows"][0]["status"] == "missed"


def test_evaluate_missing_optional_is_ok():
    result = evaluate([exp(optional=True)], [], {"status": "fail"})
    assert result["ok"]
    assert result["rows"][0]["status"] == "optional-missed"


def test_evaluate_optional_found_is_matched():
    result = evaluate([exp(optional=True)], [finding()], {"status": "fail"})
    assert result["rows"][0]["status"] == "matched"


def test_evaluate_picks_most_severe_hit():
    report = [finding(severity="high", fingerprint="b" * 64), finding(severity="critical", fingerprint="a" * 64)]
    result = evaluate([exp()], report, {"status": "fail"})
    assert "(critical)" in result["rows"][0]["finding"]


def test_evaluate_stage_failure_does_not_satisfy_expectation():
    check = finding(stage="gate", stages=["gate"], tool="factory", source="check", rule_id="stage-failed", cwe=[], severity="critical")
    result = evaluate([exp(stages=["sast-semgrep"], cwe=None, rule_id="sqli")], [check], {"status": "fail"})
    assert not result["ok"]


def test_render_table_marks_pass_and_fail():
    ok = render_table(evaluate([exp()], [finding()], {"status": "fail"}))
    assert "| sqli | sast-semgrep | no | matched | sast-semgrep |" in ok
    assert "**PASS**" in ok
    bad = render_table(evaluate([exp()], [], {"status": "pass"}))
    assert "**FAIL**" in bad
    assert "MISMATCH" in bad


def test_render_table_escapes_pipes():
    f = finding(location={"path": "a|b.ts", "start_line": 1, "end_line": 1})
    assert "a\\|b.ts" in render_table(evaluate([exp()], [f], {"status": "fail"}))


def test_load_expected_reads_list_and_mapping(tmp_path):
    entry = {"id": "x", "stage": "secrets", "rule_id": "generic", "min_severity": "high"}
    for data in ([entry], {"expectations": [entry]}):
        loaded = load_expected(write_expected(tmp_path, data))
        assert loaded[0]["stages"] == ["secrets"]
        assert loaded[0]["optional"] is False


def test_load_expected_accepts_stage_list_and_cwe_string(tmp_path):
    loaded = load_expected(write_expected(tmp_path, [{"id": "x", "stage": ["a", "b"], "cwe": "CWE-79", "min_severity": "low", "optional": True}]))
    assert loaded[0]["stages"] == ["a", "b"]
    assert loaded[0]["cwe"] == ["CWE-79"]
    assert loaded[0]["optional"] is True


@pytest.mark.parametrize(
    "entry",
    [
        {"stage": "s", "cwe": "CWE-1", "min_severity": "low"},
        {"id": "x", "cwe": "CWE-1", "min_severity": "low"},
        {"id": "x", "stage": "s", "min_severity": "low"},
        {"id": "x", "stage": "s", "cwe": "CWE-1"},
        {"id": "x", "stage": "s", "cwe": "CWE-1", "min_severity": "severe"},
        {"id": "x", "stage": "s", "rule_id": "(", "min_severity": "low"},
        {"id": "x", "stage": "s", "cwe": "CWE-1", "min_severity": "low", "optional": "yes"},
        {"id": "x", "stage": [], "cwe": "CWE-1", "min_severity": "low"},
        {"id": "x", "stage": "s", "cwe": [1], "min_severity": "low"},
        "text",
    ],
)
def test_load_expected_rejects_bad_entries(tmp_path, entry):
    with pytest.raises(AcceptanceError):
        load_expected(write_expected(tmp_path, [entry]))


def test_load_expected_rejects_duplicate_ids(tmp_path):
    entry = {"id": "x", "stage": "s", "cwe": "CWE-1", "min_severity": "low"}
    with pytest.raises(AcceptanceError, match="duplicate"):
        load_expected(write_expected(tmp_path, [entry, entry]))


def test_load_expected_rejects_empty_and_missing(tmp_path):
    with pytest.raises(AcceptanceError):
        load_expected(write_expected(tmp_path, []))
    with pytest.raises(AcceptanceError):
        load_expected(tmp_path / "nope.yml")


def write_gate(tmp_path, report, gate_result):
    d = tmp_path / "gate"
    d.mkdir()
    (d / "report.json").write_text(json.dumps(report))
    (d / "gate-result.json").write_text(json.dumps(gate_result))
    return d


def test_main_pass_writes_outputs(tmp_path, capsys):
    gate = write_gate(tmp_path, [finding()], {"status": "fail"})
    expected = write_expected(tmp_path, [{"id": "sqli", "stage": "sast-semgrep", "cwe": "CWE-89", "min_severity": "high"}])
    out = tmp_path / "out"
    code = acceptance.main(["--repo", "o/r", "--expected", str(expected), "--artifacts", str(gate), "--out", str(out)])
    assert code == 0
    assert "**PASS**" in capsys.readouterr().out
    assert json.loads((out / "acceptance.json").read_text())["ok"] is True
    assert "matched" in (out / "acceptance.md").read_text()


def test_main_mismatch_exits_nonzero(tmp_path):
    gate = write_gate(tmp_path, [], {"status": "fail"})
    expected = write_expected(tmp_path, [{"id": "sqli", "stage": "sast-semgrep", "cwe": "CWE-89", "min_severity": "high"}])
    assert acceptance.main(["--repo", "o/r", "--expected", str(expected), "--artifacts", str(gate)]) == 1


def test_main_bad_artifact_exits_nonzero(tmp_path, capsys):
    expected = write_expected(tmp_path, [{"id": "sqli", "stage": "s", "cwe": "CWE-89", "min_severity": "high"}])
    empty = tmp_path / "empty"
    empty.mkdir()
    assert acceptance.main(["--repo", "o/r", "--expected", str(expected), "--artifacts", str(empty)]) == 1
    assert "gate artifact unusable" in capsys.readouterr().err


def test_main_downloads_with_gh_when_given_a_run_id(tmp_path, monkeypatch):
    expected = write_expected(tmp_path, [{"id": "sqli", "stage": "sast-semgrep", "cwe": "CWE-89", "min_severity": "high"}])
    calls = []

    def fake_download(repo, run_id, dest):
        calls.append((repo, run_id))
        (tmp_path / dest).mkdir(exist_ok=True)
        (tmp_path / dest / "report.json").write_text(json.dumps([finding()]))
        (tmp_path / dest / "gate-result.json").write_text(json.dumps({"status": "fail"}))

    monkeypatch.setattr(acceptance, "download_gate", fake_download)
    assert acceptance.main(["--repo", "o/r", "--run-id", "42", "--expected", str(expected)]) == 0
    assert calls == [("o/r", "42")]


def test_main_requires_run_id_or_artifacts(tmp_path):
    expected = write_expected(tmp_path, [{"id": "x", "stage": "s", "cwe": "CWE-1", "min_severity": "low"}])
    with pytest.raises(SystemExit):
        acceptance.main(["--repo", "o/r", "--expected", str(expected)])
