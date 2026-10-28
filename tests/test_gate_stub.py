import json

import pytest

from factory import findings, gate


def finding(severity, line=1, stage="passthrough"):
    return findings.make_finding(
        stage=stage, tool="test", source="scanner", rule_id=f"r-{severity}",
        title=f"{severity} thing", severity=severity, location={"path": "a.ts", "start_line": line},
    )


def artifacts(tmp_path, stages):
    root = tmp_path / "artifacts"
    for stage, items in stages.items():
        findings.write(root / stage / "findings.json", items)
    (root / "setup").mkdir(parents=True, exist_ok=True)
    (root / "setup" / "run-manifest.json").write_text("{}")
    return root


NEEDS_OK = {"setup": {"result": "success"}, "passthrough": {"result": "success"}, "hello-ai": {"result": "skipped"}}


def test_count_starts_every_severity_at_zero():
    assert gate.count([]) == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    assert gate.count([finding("medium", 1), finding("medium", 2), finding("info")]) == {
        "critical": 0, "high": 0, "medium": 2, "low": 0, "info": 1,
    }


def test_empty_findings_pass_with_all_zero_table(tmp_path, monkeypatch, capsys):
    summary_file = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
    root = artifacts(tmp_path, {"passthrough": []})
    assert gate.main(["--artifacts", str(root), "--needs", json.dumps(NEEDS_OK)]) == 0
    text = summary_file.read_text()
    assert "**PASS**" in text
    for severity in findings.SEVERITIES:
        assert f"| {severity} | 0 |" in text
    assert "| passthrough | 0 |" in text
    assert "| hello-ai | skipped |" in text
    assert capsys.readouterr().out == text


@pytest.mark.parametrize("severity, exit_code", [("critical", 1), ("high", 1), ("medium", 0), ("low", 0), ("info", 0)])
def test_exit_code_blocks_only_on_critical_or_high(tmp_path, monkeypatch, severity, exit_code):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    root = artifacts(tmp_path, {"passthrough": [finding(severity)]})
    assert gate.main(["--artifacts", str(root), "--needs", json.dumps(NEEDS_OK)]) == exit_code


def test_counts_merge_across_stages(tmp_path):
    root = artifacts(tmp_path, {
        "passthrough": [finding("low"), finding("high", 2)],
        "secrets": [finding("high", stage="secrets"), finding("critical", 3, stage="secrets")],
    })
    by_stage, errors = gate.collect(root)
    result = gate.evaluate(by_stage, errors, NEEDS_OK)
    assert result["counts"] == {"critical": 1, "high": 2, "medium": 0, "low": 1, "info": 0}
    assert not result["passed"]
    assert result["reasons"] == ["3 critical or high finding(s)"]


@pytest.mark.parametrize("result", ["failure", "cancelled"])
def test_failed_needed_job_fails_gate(tmp_path, monkeypatch, result):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    root = artifacts(tmp_path, {"passthrough": []})
    needs = NEEDS_OK | {"hello-ai": {"result": result}}
    assert gate.main(["--artifacts", str(root), "--needs", json.dumps(needs)]) == 1
    by_stage, errors = gate.collect(root)
    assert gate.evaluate(by_stage, errors, needs)["reasons"] == [f"job `hello-ai` {result}"]


def test_invalid_findings_file_fails_gate(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    root = artifacts(tmp_path, {"passthrough": []})
    (root / "passthrough" / "findings.json").write_text('[{"severity": "high"}]')
    assert gate.main(["--artifacts", str(root)]) == 1
    _, errors = gate.collect(root)
    assert len(errors) == 1 and errors[0].startswith("passthrough/findings.json")


def test_no_artifacts_and_no_needs_passes(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    assert gate.main(["--artifacts", str(tmp_path / "nothing")]) == 0


def test_bad_needs_json_exits_1(tmp_path, capsys):
    assert gate.main(["--artifacts", str(tmp_path), "--needs", "{"]) == 1
    assert "--needs" in capsys.readouterr().err
