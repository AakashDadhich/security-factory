import json
import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from factory import findings, sarif
from factory.stages import sast_eslint as stage

FIXTURES = Path(__file__).parent / "fixtures" / "eslint"
ROOT = Path(__file__).resolve().parents[1]
TOOLING = ROOT / "tools" / "eslint"


def converted() -> list:
    items = sarif.sarif_to_findings(FIXTURES / "eslint.sarif", stage.STAGE, stage.TOOL)
    return stage.apply_severity(stage.relativise(items, Path("/work/app")), stage.load_escalations())


def by_line(items: list) -> dict:
    return {(f["rule_id"], f["location"]["start_line"]): f for f in items}


def test_escalated_rule_becomes_high():
    assert by_line(converted())[("security/detect-eval-with-expression", 2)]["severity"] == "high"


def test_other_errors_become_medium():
    assert by_line(converted())[("security/detect-object-injection", 7)]["severity"] == "medium"


def test_warnings_keep_their_level():
    assert by_line(converted())[("security/detect-object-injection", 9)]["severity"] == "medium"


def test_escalation_ignores_rules_not_listed():
    items = sarif.sarif_to_findings(FIXTURES / "eslint.sarif", stage.STAGE, stage.TOOL)
    result = stage.apply_severity(items, set())
    assert {f["severity"] for f in result} == {"medium"}


def test_paths_become_relative_to_the_source_root():
    paths = {f["location"]["path"] for f in converted()}
    assert paths == {"src/run.js", "src/util.js"}


def test_findings_have_stage_and_tool():
    for f in converted():
        assert (f["stage"], f["tool"], f["source"]) == ("sast-eslint", "eslint", "scanner")


def test_fingerprints_are_stable():
    assert [f["fingerprint"] for f in converted()] == [f["fingerprint"] for f in converted()]


def test_shipped_escalation_list_includes_eval():
    assert "security/detect-eval-with-expression" in stage.load_escalations()


def test_bad_escalation_file_is_rejected(tmp_path):
    bad = tmp_path / "severity.yml"
    bad.write_text("escalate: nope\n")
    with pytest.raises(stage.StageError, match="escalate"):
        stage.load_escalations(bad)


def test_command_uses_factory_config_and_ignores_project_config(tmp_path):
    cmd = stage.eslint_command(tmp_path / "t", tmp_path / "r.sarif")
    assert cmd[cmd.index("--config") + 1] == str(tmp_path / "t" / "eslint.config.mjs")
    assert "--no-config-lookup" in cmd
    assert cmd[-1] == "."


def test_run_eslint_accepts_exit_1_when_report_written(tmp_path):
    report = tmp_path / "out" / "eslint.sarif"

    def runner(cmd, cwd):
        report.write_text("{}")
        return SimpleNamespace(returncode=1)

    stage.run_eslint(tmp_path, report, TOOLING, runner=runner)


def test_run_eslint_rejects_fatal_exit(tmp_path):
    with pytest.raises(stage.StageError, match="exit code 2"):
        stage.run_eslint(tmp_path, tmp_path / "r.sarif", TOOLING, runner=lambda cmd, cwd: SimpleNamespace(returncode=2))


def test_run_eslint_rejects_missing_report(tmp_path):
    with pytest.raises(stage.StageError, match="wrote no report"):
        stage.run_eslint(tmp_path, tmp_path / "r.sarif", TOOLING, runner=lambda cmd, cwd: SimpleNamespace(returncode=0))


def test_run_eslint_reports_missing_binary(tmp_path):
    def runner(cmd, cwd):
        raise FileNotFoundError(cmd[0])

    with pytest.raises(stage.StageError, match="npm ci"):
        stage.run_eslint(tmp_path, tmp_path / "r.sarif", TOOLING, runner=runner)


def test_npm_ci_failure_is_reported(tmp_path):
    with pytest.raises(stage.StageError, match="npm ci failed"):
        stage.npm_ci(tmp_path, runner=lambda cmd, cwd: SimpleNamespace(returncode=1))


def test_npm_ci_missing_npm(tmp_path):
    def runner(cmd, cwd):
        raise FileNotFoundError("npm")

    with pytest.raises(stage.StageError, match="npm not found"):
        stage.npm_ci(tmp_path, runner=runner)


def test_tooling_pins_are_exact_versions():
    pkg = json.loads((TOOLING / "package.json").read_text())
    expected = {"eslint", "typescript-eslint", "eslint-plugin-security", "eslint-plugin-no-unsanitized", "@microsoft/eslint-formatter-sarif"}
    assert expected <= set(pkg["devDependencies"])
    for name, version in pkg["devDependencies"].items():
        assert version[0].isdigit(), f"{name} is not pinned exactly: {version}"


def test_main_reports_stage_errors(tmp_path, capsys):
    assert stage.main(["--src", str(tmp_path), "--out", str(tmp_path / "o"), "--tooling", str(tmp_path), "--skip-install"]) == 1
    assert "error:" in capsys.readouterr().err


@pytest.mark.skipif(
    not (TOOLING / "node_modules" / ".bin" / "eslint").exists() and not os.environ.get("FACTORY_REQUIRE_ESLINT"),
    reason="eslint tooling not installed",
)
def test_integration_eval_fixture_yields_one_high_finding(tmp_path):
    src = tmp_path / "project"
    src.mkdir()
    shutil.copy(FIXTURES / "eval.js", src / "eval.js")
    shutil.copy(FIXTURES / "clean.js", src / "clean.js")
    out = tmp_path / "out"
    result = stage.run(src, out, install=False)
    high = [f for f in result if f["severity"] == "high"]
    assert len(high) == 1
    assert high[0]["rule_id"] == "security/detect-eval-with-expression"
    assert high[0]["location"]["path"] == "eval.js"
    assert findings.load(out / "findings.json") == result
    keep = os.environ.get("FACTORY_ESLINT_IT_OUT")
    if keep:
        shutil.copytree(out, keep, dirs_exist_ok=True)
