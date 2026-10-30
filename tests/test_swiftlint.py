import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from factory import findings, sarif
from factory.stages import swiftlint as stage

FIXTURES = Path(__file__).parent / "fixtures" / "swiftlint"
CONFIG = Path(__file__).resolve().parents[1] / "tools" / "swiftlint" / ".swiftlint.yml"


def converted() -> list:
    items = sarif.sarif_to_findings(FIXTURES / "swiftlint.sarif", stage.STAGE, stage.TOOL)
    return stage.apply_severity(stage.sast_eslint.relativise(items, Path("/work/app")), stage.custom_rule_ids())


def by_rule(items: list) -> dict:
    return {f["rule_id"]: f for f in items}


def test_custom_security_rules_are_high():
    result = by_rule(converted())
    assert result["print_of_secret"]["severity"] == "high"
    assert result["userdefaults_secret_key"]["severity"] == "high"


def test_default_rules_are_low_whatever_their_level():
    result = by_rule(converted())
    assert result["force_cast"]["severity"] == "low"
    assert result["identifier_name"]["severity"] == "low"


def test_paths_are_relative_and_findings_carry_stage_and_tool():
    for f in converted():
        assert f["location"]["path"].startswith("Sources/")
        assert (f["stage"], f["tool"], f["source"]) == ("sast-swiftlint", "swiftlint", "scanner")


def test_fingerprints_are_stable():
    assert [f["fingerprint"] for f in converted()] == [f["fingerprint"] for f in converted()]


def test_shipped_config_defines_the_security_rules_as_errors():
    config = yaml.safe_load(CONFIG.read_text())
    assert set(config["custom_rules"]) == {"print_of_secret", "userdefaults_secret_key"}
    assert all(rule["severity"] == "error" for rule in config["custom_rules"].values())


def test_config_excludes_the_factory_checkout_and_build_output():
    excluded = yaml.safe_load(CONFIG.read_text())["excluded"]
    assert {".factory", "build", "Pods"} <= set(excluded)


def test_bad_config_is_refused(tmp_path):
    bad = tmp_path / "c.yml"
    bad.write_text("disabled_rules: []\n")
    with pytest.raises(stage.StageError, match="custom_rules"):
        stage.custom_rule_ids(bad)


def regex(rule: str) -> re.Pattern:
    return re.compile(yaml.safe_load(CONFIG.read_text())["custom_rules"][rule]["regex"])


@pytest.mark.parametrize(
    "line",
    [
        "print(token)",
        "print(user.password)",
        'print("login with \\(password)")',
        "debugPrint(apiKey)",
        "NSLog(secret)",
        "print(api_key)",
        "print(refreshToken)",
    ],
)
def test_print_of_secret_matches_leaks(line):
    assert regex("print_of_secret").search(line)


@pytest.mark.parametrize("line", ["print(count)", "print(username)", "let token = fetch()", "printer(token)", "print(\"done\")"])
def test_print_of_secret_ignores_other_lines(line):
    assert not regex("print_of_secret").search(line)


@pytest.mark.parametrize(
    "line",
    [
        'UserDefaults.standard.set(value, forKey: "authToken")',
        'UserDefaults.standard.setValue(pw, forKey: "user_password")',
        'UserDefaults.standard["apiKey"] = key',
    ],
)
def test_userdefaults_rule_matches_secret_keys(line):
    assert regex("userdefaults_secret_key").search(line)


@pytest.mark.parametrize(
    "line",
    [
        'UserDefaults.standard.set(true, forKey: "hasOnboarded")',
        'Keychain.set(value, forKey: "authToken")',
        'UserDefaults.standard["theme"] = "dark"',
    ],
)
def test_userdefaults_rule_ignores_harmless_lines(line):
    assert not regex("userdefaults_secret_key").search(line)


def test_rendered_config_excludes_absolute_project_paths(tmp_path):
    src = tmp_path / "proj"
    src.mkdir()
    rendered = stage.render_config(CONFIG, src, tmp_path / "out" / "swiftlint.yml")
    data = yaml.safe_load(rendered.read_text())
    assert str(src.resolve() / ".factory") in data["excluded"]
    assert all(Path(p).is_absolute() for p in data["excluded"])
    assert set(data["custom_rules"]) == set(yaml.safe_load(CONFIG.read_text())["custom_rules"])


def test_run_passes_the_rendered_config_to_swiftlint(tmp_path):
    runner = fake_runner(0, (FIXTURES / "swiftlint.sarif").read_text())
    stage.run(tmp_path, tmp_path / "out", runner=runner)
    cmd = runner.calls[0][0]
    assert cmd[cmd.index("--config") + 1] == str((tmp_path / "out" / "swiftlint.yml").resolve())


def test_command_uses_the_factory_config_and_the_sarif_reporter():
    cmd = stage.swiftlint_command(CONFIG)
    assert cmd[:2] == ["swiftlint", "lint"]
    assert cmd[cmd.index("--config") + 1] == str(CONFIG)
    assert cmd[cmd.index("--reporter") + 1] == "sarif"


def fake_runner(code: int, sarif_text: str | None):
    calls = []

    def runner(cmd, cwd=None, stdout=None):
        calls.append((cmd, cwd))
        if sarif_text is not None:
            stdout.write(sarif_text)
        return SimpleNamespace(returncode=code)

    runner.calls = calls
    return runner


@pytest.mark.parametrize("code", [0, 2])
def test_exit_codes_for_clean_and_violations_are_accepted(tmp_path, code):
    text = (FIXTURES / "swiftlint.sarif").read_text()
    runner = fake_runner(code, text)
    result = stage.run("/work/app", tmp_path, runner=runner)
    assert len(result) == 4
    assert json.loads((tmp_path / "findings.json").read_text()) == result
    findings.validate(result)
    assert runner.calls[0][1] == Path("/work/app")


def test_other_exit_codes_fail_the_stage(tmp_path):
    with pytest.raises(stage.StageError, match="exit code 1"):
        stage.run(".", tmp_path, runner=fake_runner(1, ""))


def test_missing_binary_fails_with_install_hint(tmp_path):
    def runner(cmd, cwd=None, stdout=None):
        raise FileNotFoundError

    with pytest.raises(stage.StageError, match="factory.tools install swiftlint"):
        stage.run(".", tmp_path, runner=runner)


def test_main_reports_errors(tmp_path, capsys):
    assert stage.main(["--src", str(tmp_path), "--out", str(tmp_path / "o"), "--swiftlint", "/nonexistent/swiftlint"]) == 1
    assert "error:" in capsys.readouterr().err
