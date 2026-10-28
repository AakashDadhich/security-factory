import json
import math
import os
import re
import secrets
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from factory import findings
from factory.stages import secrets as stage

FIXTURES = Path(__file__).parent / "fixtures"


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        check=True, capture_output=True,
    )


def make_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text)
    git(repo, "add", "-f", ".")
    git(repo, "commit", "-q", "-m", "init")
    return repo


@pytest.mark.parametrize("path", [".env", "config/.env.local", ".env.production", "a/b/.env"])
def test_env_matcher_matches_env_files(path):
    assert stage.is_env_file(path)


@pytest.mark.parametrize("path", [".env.example", "web/.env.example", "env.ts", "src/env.ts", ".envrc", "my.env", ".env/x"])
def test_env_matcher_ignores_other_files(path):
    assert not stage.is_env_file(path)


def test_exit_zero_means_no_leaks():
    assert stage.leaks_from_exit(0) is False


def test_leaks_exit_code_means_findings_not_failure():
    assert stage.leaks_from_exit(stage.LEAKS_EXIT) is True


@pytest.mark.parametrize("code", [1, 2, 126, 127, -9])
def test_other_exit_codes_fail_the_stage(code):
    with pytest.raises(stage.StageError, match=str(code)):
        stage.leaks_from_exit(code)


def test_command_scans_history_with_redaction_and_factory_config(tmp_path):
    cmd = stage.gitleaks_command("repo", tmp_path / "g.sarif")
    assert cmd[:3] == ["gitleaks", "git", "repo"]
    assert "--redact=100" in cmd
    assert cmd[cmd.index("--report-format") + 1] == "sarif"
    assert cmd[cmd.index("--exit-code") + 1] == str(stage.LEAKS_EXIT)
    assert Path(cmd[cmd.index("--config") + 1]) == stage.CONFIG
    assert "useDefault = true" in stage.CONFIG.read_text()


def test_run_gitleaks_fails_when_no_report_written(tmp_path):
    with pytest.raises(stage.StageError, match="no report"):
        stage.run_gitleaks(".", tmp_path / "g.sarif", runner=lambda cmd: SimpleNamespace(returncode=0))


def test_run_gitleaks_reports_missing_binary(tmp_path):
    def runner(cmd):
        raise FileNotFoundError(cmd[0])
    with pytest.raises(stage.StageError, match="not found"):
        stage.run_gitleaks(".", tmp_path / "g.sarif", runner=runner)


def test_secret_findings_are_all_high(tmp_path):
    items = stage.secret_findings(FIXTURES / "gitleaks.sarif")
    assert len(items) == 2
    assert {f["severity"] for f in items} == {"high"}
    assert {f["stage"] for f in items} == {"secrets"}
    assert {f["tool"] for f in items} == {"gitleaks"}
    assert all(f["cwe"] == ["CWE-798"] and f["remediation"] for f in items)
    findings.validate(items)


def test_env_file_findings_skip_example(tmp_path):
    repo = make_repo(tmp_path, {".env": "DEBUG=1\n", "config/.env.local": "X=1\n", ".env.example": "X=fake\n", "env.ts": "x\n"})
    items = stage.env_file_findings(stage.tracked_files(repo))
    assert [f["location"]["path"] for f in items] == [".env", "config/.env.local"]
    assert all(f["source"] == "check" and f["rule_id"] == "committed-env-file" and f["severity"] == "high" for f in items)


def test_untracked_env_file_is_not_flagged(tmp_path):
    repo = make_repo(tmp_path, {"README.md": "hi\n"})
    (repo / ".env").write_text("DEBUG=1\n")
    assert stage.env_file_findings(stage.tracked_files(repo)) == []


def fake_gitleaks(tmp_path: Path, exit_code: int, report: Path | None) -> Path:
    script = tmp_path / "fake-gitleaks"
    copy = f'cp "{report}" "$report"' if report else ":"
    script.write_text(
        "#!/bin/sh\n"
        'while [ $# -gt 0 ]; do if [ "$1" = --report-path ]; then report="$2"; fi; shift; done\n'
        f"{copy}\nexit {exit_code}\n"
    )
    script.chmod(0o755)
    return script


def test_main_with_leaks_writes_findings_and_succeeds(tmp_path):
    repo = make_repo(tmp_path, {".env": "DEBUG=1\n"})
    binary = fake_gitleaks(tmp_path, stage.LEAKS_EXIT, FIXTURES / "gitleaks.sarif")
    out = tmp_path / "out"
    assert stage.main(["--repo", str(repo), "--out", str(out), "--gitleaks", str(binary)]) == 0
    items = findings.load(out / "findings.json")
    assert len(items) == 3
    assert (out / "gitleaks.sarif").is_file()


def test_main_with_gitleaks_error_fails(tmp_path, capsys):
    repo = make_repo(tmp_path, {"README.md": "hi\n"})
    binary = fake_gitleaks(tmp_path, 1, None)
    assert stage.main(["--repo", str(repo), "--out", str(tmp_path / "out"), "--gitleaks", str(binary)]) == 1
    assert "exit code 1" in capsys.readouterr().err
    assert not (tmp_path / "out" / "findings.json").exists()


def entropy(s: str) -> float:
    return -sum(s.count(c) / len(s) * math.log2(s.count(c) / len(s)) for c in set(s))


def fake_api_key() -> str:
    # Gitleaks' generic-api-key rule needs entropy above 3.5 and drops secrets
    # containing a stopword, so avoid low-entropy draws and runs of letters.
    while True:
        key = secrets.token_hex(16)
        if entropy(key) >= 3.7 and not re.search(r"[a-f]{3}", key):
            return key


@pytest.mark.skipif(
    shutil.which("gitleaks") is None and not os.environ.get("FACTORY_REQUIRE_GITLEAKS"),
    reason="gitleaks is not installed",
)
def test_integration_real_gitleaks_finds_secret_and_env_file(tmp_path):
    key = fake_api_key()
    repo = make_repo(tmp_path, {"config.py": f'api_key = "{key}"\n', ".env": "DEBUG=true\n"})
    out = Path(os.environ.get("FACTORY_SECRETS_IT_OUT") or tmp_path / "out")
    assert stage.main(["--repo", str(repo), "--out", str(out)]) == 0

    items = findings.load(out / "findings.json")
    print(json.dumps([{k: f[k] for k in ("source", "rule_id", "severity", "location")} for f in items], indent=2))
    assert len(items) == 2
    assert {(f["source"], f["rule_id"]) for f in items} == {("scanner", "generic-api-key"), ("check", "committed-env-file")}
    assert {f["severity"] for f in items} == {"high"}

    report = (out / "gitleaks.sarif").read_text()
    assert key not in report
    assert "REDACTED" in report
