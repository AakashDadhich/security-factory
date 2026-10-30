import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from factory.stages import apple_build as stage

SPEC = "name: Notes\ntargets:\n  Notes:\n    type: application\n    platform: macOS\n"
CONFIG = "platform: macos\napple:\n  project_spec: project.yml\n  scheme: Notes\n"


def test_xcodebuild_command_is_a_release_ad_hoc_signed_build():
    cmd = stage.xcodebuild_command("Notes.xcodeproj", "Notes", "/tmp/dd")
    assert cmd[0] == "xcodebuild" and cmd[-1] == "build"
    assert cmd[cmd.index("-scheme") + 1] == "Notes"
    assert cmd[cmd.index("-configuration") + 1] == "Release"
    assert cmd[cmd.index("-derivedDataPath") + 1] == "/tmp/dd"
    assert "CODE_SIGN_IDENTITY=-" in cmd
    assert "CODE_SIGN_STYLE=Manual" in cmd
    assert "-onlyUsePackageVersionsFromResolvedFile" not in cmd


def test_xcodebuild_command_can_pin_package_versions():
    assert "-onlyUsePackageVersionsFromResolvedFile" in stage.xcodebuild_command("a.xcodeproj", "A", "dd", pinned=True)


def test_ditto_command_keeps_the_parent_folder():
    assert stage.ditto_command("A.app", "A.app.zip") == ["ditto", "-c", "-k", "--keepParent", "A.app", "A.app.zip"]


def test_xcodegen_command_names_the_spec():
    assert stage.xcodegen_command("project.yml") == ["xcodegen", "generate", "--spec", "project.yml"]


def test_project_name_comes_from_the_spec(tmp_path):
    (tmp_path / "project.yml").write_text(SPEC)
    assert stage.project_name(tmp_path / "project.yml") == "Notes"


def test_project_name_requires_a_name(tmp_path):
    (tmp_path / "project.yml").write_text("targets: {}\n")
    with pytest.raises(stage.StageError, match="no 'name'"):
        stage.project_name(tmp_path / "project.yml")


def test_pin_packages_copies_the_resolved_file_into_the_workspace(tmp_path):
    project = tmp_path / "Notes.xcodeproj"
    project.mkdir()
    (tmp_path / "Package.resolved").write_text('{"pins": []}')
    assert stage.pin_packages(tmp_path, project) is True
    assert (project / stage.RESOLVED).read_text() == '{"pins": []}'


def test_pin_packages_does_nothing_without_a_resolved_file(tmp_path):
    assert stage.pin_packages(tmp_path, tmp_path / "Notes.xcodeproj") is False
    assert not (tmp_path / "Notes.xcodeproj").exists()


class FakeMac:
    def __init__(self, src: Path, fail: str | None = None, apps: tuple[str, ...] = ("Notes.app",)):
        self.src, self.fail, self.apps, self.calls = src, fail, apps, []

    def __call__(self, cmd, cwd=None):
        self.calls.append((cmd, cwd))
        if cmd[0] == self.fail:
            return SimpleNamespace(returncode=65)
        if cmd[0] == "xcodegen":
            (self.src / "Notes.xcodeproj").mkdir(exist_ok=True)
        if cmd[0] == "xcodebuild":
            products = Path(cmd[cmd.index("-derivedDataPath") + 1]) / "Build" / "Products" / "Release"
            for app in self.apps:
                (products / app).mkdir(parents=True, exist_ok=True)
        if cmd[0] == "ditto":
            Path(cmd[-1]).write_bytes(b"PK")
        return SimpleNamespace(returncode=0)


@pytest.fixture
def project(tmp_path):
    src = tmp_path / "proj"
    src.mkdir()
    (src / "project.yml").write_text(SPEC)
    (src / ".factory.yml").write_text(CONFIG)
    (src / "Package.resolved").write_text("{}")
    return src


def test_script_holds_the_same_build_command_so_codeql_can_trace_only_xcodebuild(project, tmp_path):
    spec, scheme = stage.settings(project, project / ".factory.yml")
    runner = FakeMac(project)
    generated = stage.generate(project, spec, runner=runner)
    script = stage.write_script(project, generated, scheme, project / "build" / "codeql", tmp_path / "x.sh")
    lines = script.read_text().splitlines()
    assert lines[0] == "#!/bin/bash" and "set -euo pipefail" in lines
    assert lines[-1].startswith("exec xcodebuild -project Notes.xcodeproj -scheme Notes -configuration Release")
    assert "CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual build" in lines[-1]
    assert "-onlyUsePackageVersionsFromResolvedFile" in lines[-1]
    assert script.stat().st_mode & 0o111
    assert [c[0][0] for c in runner.calls] == ["xcodegen"]


def test_zip_runs_ditto_with_a_bare_app_name_from_the_products_folder(project, tmp_path):
    runner = FakeMac(project)
    stage.run(project, project / ".factory.yml", tmp_path / "out", runner=runner)
    cmd, cwd = runner.calls[2]
    assert cmd[-2] == "Notes.app" and cwd.name == "Release"


def test_run_generates_builds_and_zips_in_order(project, tmp_path):
    runner = FakeMac(project)
    archive = stage.run(project, project / ".factory.yml", tmp_path / "out", runner=runner)
    assert [c[0][0] for c in runner.calls] == ["xcodegen", "xcodebuild", "ditto"]
    assert archive == tmp_path / "out" / "Notes.app.zip" and archive.is_file()
    assert json.loads((tmp_path / "out" / "findings.json").read_text()) == []
    assert "-onlyUsePackageVersionsFromResolvedFile" in runner.calls[1][0]
    assert runner.calls[1][1] == project


def test_a_failed_build_stops_before_packaging(project, tmp_path):
    runner = FakeMac(project, fail="xcodebuild")
    with pytest.raises(stage.StageError, match="xcodebuild failed with exit code 65"):
        stage.run(project, project / ".factory.yml", tmp_path / "out", runner=runner)
    assert "ditto" not in [c[0][0] for c in runner.calls]
    assert not (tmp_path / "out" / "findings.json").exists()


def test_exactly_one_app_is_expected(project, tmp_path):
    runner = FakeMac(project, apps=("A.app", "B.app"))
    with pytest.raises(stage.StageError, match="exactly one .app"):
        stage.run(project, project / ".factory.yml", tmp_path / "out", runner=runner)


def test_missing_tool_names_the_binary(project, tmp_path):
    def runner(cmd, cwd=None):
        raise FileNotFoundError

    with pytest.raises(stage.StageError, match="xcodegen not found"):
        stage.run(project, project / ".factory.yml", tmp_path / "out", runner=runner)


def test_config_without_an_apple_section_is_refused(tmp_path):
    cfg = tmp_path / ".factory.yml"
    cfg.write_text("platform: web\nweb: {port: 1, health_path: /h, dockerfile: Dockerfile}\n")
    with pytest.raises(stage.StageError, match="no 'apple' section"):
        stage.settings(tmp_path, cfg)


def test_main_reports_errors(tmp_path, capsys):
    assert stage.main(["run", "--src", str(tmp_path), "--config", str(tmp_path / "missing.yml")]) == 1
    assert "error:" in capsys.readouterr().err
