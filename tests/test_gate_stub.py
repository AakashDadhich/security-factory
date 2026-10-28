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


def run_gate(root, needs=NEEDS_OK, optional=("hello-ai",)):
    args = ["--artifacts", str(root), "--needs", json.dumps(needs)]
    for name in optional:
        args += ["--optional", name]
    return gate.main(args)


def test_count_starts_every_severity_at_zero():
    assert gate.count([]) == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    assert gate.count([finding("medium", 1), finding("medium", 2), finding("info")]) == {
        "critical": 0, "high": 0, "medium": 2, "low": 0, "info": 1,
    }


def test_empty_findings_pass_with_all_zero_table(tmp_path, monkeypatch, capsys):
    summary_file = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
    root = artifacts(tmp_path, {"passthrough": []})
    assert run_gate(root) == 0
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
    assert run_gate(root) == exit_code


def test_counts_merge_across_stages(tmp_path):
    root = artifacts(tmp_path, {
        "passthrough": [finding("low"), finding("high", 2)],
        "secrets": [finding("high", stage="secrets"), finding("critical", 3, stage="secrets")],
    })
    by_stage, errors = gate.collect(root)
    needs = NEEDS_OK | {"secrets": {"result": "success"}}
    result = gate.evaluate(by_stage, errors, needs, {"hello-ai"})
    assert result["counts"] == {"critical": 1, "high": 2, "medium": 0, "low": 1, "info": 0}
    assert not result["passed"]
    assert result["reasons"] == ["3 critical or high finding(s)"]


@pytest.mark.parametrize("result", ["failure", "cancelled"])
def test_failed_needed_job_fails_gate(tmp_path, monkeypatch, result):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    root = artifacts(tmp_path, {"passthrough": []})
    needs = NEEDS_OK | {"hello-ai": {"result": result}}
    assert run_gate(root, needs) == 1
    by_stage, errors = gate.collect(root)
    assert gate.evaluate(by_stage, errors, needs, {"hello-ai"})["reasons"] == [f"job `hello-ai` {result}"]


def test_invalid_findings_file_fails_gate(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    root = artifacts(tmp_path, {"passthrough": []})
    (root / "passthrough" / "findings.json").write_text('[{"severity": "high"}]')
    assert run_gate(root) == 1
    _, errors = gate.collect(root)
    assert len(errors) == 1 and errors[0].startswith("passthrough/findings.json")


def test_skipped_job_fails_unless_optional(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    root = artifacts(tmp_path, {"passthrough": []})
    assert run_gate(root, optional=()) == 1
    by_stage, errors = gate.collect(root)
    assert gate.evaluate(by_stage, errors, NEEDS_OK)["reasons"] == ["job `hello-ai` skipped"]


@pytest.mark.parametrize("job", [{"result": "neutral"}, {}, None])
def test_unknown_or_missing_result_fails(tmp_path, job):
    root = artifacts(tmp_path, {"passthrough": []})
    by_stage, errors = gate.collect(root)
    result = gate.evaluate(by_stage, errors, NEEDS_OK | {"passthrough": job}, {"hello-ai"})
    assert not result["passed"]
    assert result["reasons"][0].startswith("job `passthrough` ")


def test_successful_stage_without_findings_fails(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    root = artifacts(tmp_path, {})
    assert run_gate(root) == 1
    by_stage, errors = gate.collect(root)
    assert gate.evaluate(by_stage, errors, NEEDS_OK, {"hello-ai"})["reasons"] == [
        "job `passthrough` succeeded but left no findings.json",
    ]


def test_empty_needs_and_no_artifacts_fail(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    assert run_gate(tmp_path / "nothing", needs={}) == 1


@pytest.mark.parametrize("needs, message", [("{", "not valid JSON"), ("[]", "JSON object")])
def test_bad_needs_exits_1(tmp_path, capsys, needs, message):
    assert gate.main(["--artifacts", str(tmp_path), "--needs", needs]) == 1
    assert message in capsys.readouterr().err


def test_needs_is_required(tmp_path):
    with pytest.raises(SystemExit):
        gate.main(["--artifacts", str(tmp_path)])
