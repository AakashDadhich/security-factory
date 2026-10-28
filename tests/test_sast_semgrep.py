import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from factory import findings
from factory.stages import sast_semgrep as stage

FIXTURES = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).resolve().parents[1]


def community(tmp_path: Path, *names: str) -> Path:
    root = tmp_path / "rules"
    for name in names:
        (root / name).mkdir(parents=True)
    return root


def test_web_selects_javascript_typescript_and_custom_web(tmp_path):
    root = tmp_path / "rules"
    configs = stage.select_configs("web", root)
    assert configs == [str(root / "javascript"), str(root / "typescript"), str(ROOT / "semgrep-rules" / "custom/web")]


@pytest.mark.parametrize("platform", ["macos", "ios"])
def test_apple_platforms_select_swift_and_custom_swift(tmp_path, platform):
    root = tmp_path / "rules"
    configs = stage.select_configs(platform, root)
    assert configs == [str(root / "swift"), str(ROOT / "semgrep-rules" / "custom/swift")]


def test_unknown_platform_is_rejected(tmp_path):
    with pytest.raises(stage.StageError, match="no Semgrep rule sets for platform 'android'"):
        stage.select_configs("android", tmp_path)


def test_every_configured_custom_directory_exists_and_has_rules():
    rulesets = stage.load_rulesets()
    for paths in rulesets["custom"].values():
        for rel in paths:
            directory = ROOT / "semgrep-rules" / rel
            assert list(directory.glob("*.yaml")), rel


def test_every_custom_rule_has_a_test_file():
    for rule_file in (ROOT / "semgrep-rules" / "custom").glob("*/*.yaml"):
        siblings = [p for p in rule_file.parent.glob(rule_file.stem + ".*") if p != rule_file]
        assert siblings, f"{rule_file.name} has no test file"
        ids = [r["id"] for r in yaml.safe_load(rule_file.read_text())["rules"]]
        text = siblings[0].read_text()
        for rule_id in ids:
            assert f"ruleid: {rule_id}" in text and f"ok: {rule_id}" in text, rule_id


def test_load_rulesets_requires_both_sections(tmp_path):
    bad = tmp_path / "rulesets.yml"
    bad.write_text("community: {}\n")
    with pytest.raises(stage.StageError, match="'community' and 'custom'"):
        stage.load_rulesets(bad)


def test_command_turns_metrics_off_and_excludes_build_dirs():
    cmd = stage.semgrep_command(["/r/javascript", "/c/web"], "src", "out/semgrep.sarif")
    assert cmd[:2] == ["semgrep", "scan"]
    assert "--metrics=off" in cmd and "--disable-version-check" in cmd and "--sarif" in cmd
    assert cmd[cmd.index("--output") + 1] == "out/semgrep.sarif"
    assert [cmd[i + 1] for i, a in enumerate(cmd) if a == "--config"] == ["/r/javascript", "/c/web"]
    excluded = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--exclude"]
    assert excluded == ["node_modules", "dist", "build", "Pods", ".build", ".factory"]
    assert cmd[-1] == "src"


def test_run_semgrep_requires_rule_directories(tmp_path):
    with pytest.raises(stage.StageError, match="rule directory not found"):
        stage.run_semgrep([str(tmp_path / "missing")], ".", tmp_path / "o" / "semgrep.sarif", runner=lambda c: None)


def test_run_semgrep_reports_missing_binary(tmp_path):
    def runner(cmd):
        raise FileNotFoundError

    with pytest.raises(stage.StageError, match="semgrep not found"):
        stage.run_semgrep([str(tmp_path)], ".", tmp_path / "semgrep.sarif", runner=runner)


def test_run_semgrep_fails_on_nonzero_exit(tmp_path):
    with pytest.raises(stage.StageError, match="exit code 2"):
        stage.run_semgrep([str(tmp_path)], ".", tmp_path / "semgrep.sarif", runner=lambda c: SimpleNamespace(returncode=2))


def test_run_semgrep_fails_without_report(tmp_path):
    with pytest.raises(stage.StageError, match="wrote no report"):
        stage.run_semgrep([str(tmp_path)], ".", tmp_path / "semgrep.sarif", runner=lambda c: SimpleNamespace(returncode=0))


def test_run_converts_sarif_to_valid_findings(tmp_path, monkeypatch):
    root = community(tmp_path, "javascript", "typescript")

    def fake_run(cmd, **kwargs):
        report = Path(cmd[cmd.index("--output") + 1])
        report.write_text((FIXTURES / "semgrep.sarif").read_text())
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    out = tmp_path / "out"
    result = stage.run("web", ".", out, community_root=root)
    assert result
    assert {f["stage"] for f in result} == {"sast-semgrep"}
    assert {f["tool"] for f in result} == {"semgrep"}
    assert findings.validate(json.loads((out / "findings.json").read_text()))
    assert (out / "semgrep.sarif").is_file()


def test_main_returns_one_on_stage_error(tmp_path, capsys):
    code = stage.main(["--platform", "android", "--out", str(tmp_path)])
    assert code == 1
    assert "no Semgrep rule sets" in capsys.readouterr().err
