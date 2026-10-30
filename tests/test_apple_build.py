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
    assert "CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO" in cmd
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
    assert "CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO build" in lines[-1]
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


IOS_CONFIG = "platform: ios\napple:\n  project_spec: project.yml\n  scheme: Notes\n"


def test_ios_xcodebuild_command_builds_unsigned_for_devices():
    cmd = stage.xcodebuild_command("Notes.xcodeproj", "Notes", "/tmp/dd", platform="ios")
    assert cmd[cmd.index("-sdk") + 1] == "iphoneos"
    assert cmd[cmd.index("-destination") + 1] == "generic/platform=iOS"
    assert cmd[cmd.index("-configuration") + 1] == "Release"
    assert "CODE_SIGNING_ALLOWED=NO" in cmd and cmd[-1] == "build"
    assert not any(a.startswith("CODE_SIGN_IDENTITY") for a in cmd)


def test_macos_command_has_no_sdk_or_destination():
    cmd = stage.xcodebuild_command("a.xcodeproj", "A", "dd")
    assert "-sdk" not in cmd and "-destination" not in cmd and "CODE_SIGNING_ALLOWED=NO" not in cmd


def test_ios_products_folder_is_release_iphoneos():
    assert stage.products_dir("ios") == "Release-iphoneos" and stage.products_dir("macos") == "Release"


def make_ios_app(root: Path, name: str = "Notes.app") -> Path:
    app = root / name
    (app / "Frameworks").mkdir(parents=True)
    (app / "Notes").write_bytes(b"\xcf\xfa\xed\xfe")
    (app / "Notes").chmod(0o755)
    (app / "Info.plist").write_text("<plist/>")
    (app / "Frameworks" / "link").symlink_to("../Info.plist")
    return app


def test_package_ipa_puts_the_app_under_payload(tmp_path):
    import zipfile

    archive = stage.package_ipa(make_ios_app(tmp_path / "products"), tmp_path / "out")
    assert archive == tmp_path / "out" / "app.ipa"
    with zipfile.ZipFile(archive) as zf:
        names = zf.namelist()
        assert names[0] == "Payload/"
        assert "Payload/Notes.app/Info.plist" in names and "Payload/Notes.app/Notes" in names
        assert "Payload/Notes.app/Frameworks/" in names
        assert all(n.startswith("Payload/") for n in names)
        assert zf.testzip() is None


def test_package_ipa_keeps_the_executable_bit_and_symlinks(tmp_path):
    import stat
    import zipfile

    archive = stage.package_ipa(make_ios_app(tmp_path / "products"), tmp_path / "out")
    with zipfile.ZipFile(archive) as zf:
        binary = zf.getinfo("Payload/Notes.app/Notes")
        assert (binary.external_attr >> 16) & 0o111
        link = zf.getinfo("Payload/Notes.app/Frameworks/link")
        assert stat.S_ISLNK(link.external_attr >> 16)
        assert zf.read(link).decode() == "../Info.plist"


def test_package_ipa_is_reproducible(tmp_path):
    app = make_ios_app(tmp_path / "products")
    first = stage.package_ipa(app, tmp_path / "a").read_bytes()
    second = stage.package_ipa(app, tmp_path / "b").read_bytes()
    assert first == second


class FakePhone(FakeMac):
    def __call__(self, cmd, cwd=None):
        if cmd[0] == "xcodebuild":
            self.calls.append((cmd, cwd))
            products = Path(cmd[cmd.index("-derivedDataPath") + 1]) / "Build" / "Products" / "Release-iphoneos"
            make_ios_app(products)
            return SimpleNamespace(returncode=0)
        return super().__call__(cmd, cwd)


def test_ios_run_builds_for_iphoneos_and_writes_app_ipa_without_ditto(project, tmp_path):
    (project / ".factory.yml").write_text(IOS_CONFIG)
    runner = FakePhone(project)
    archive = stage.run(project, project / ".factory.yml", tmp_path / "out", runner=runner)
    assert [c[0][0] for c in runner.calls] == ["xcodegen", "xcodebuild"]
    assert "-sdk" in runner.calls[1][0]
    assert archive == tmp_path / "out" / "app.ipa" and archive.is_file()
    assert json.loads((tmp_path / "out" / "findings.json").read_text()) == []


def test_ios_script_holds_the_iphoneos_command(project, tmp_path):
    (project / ".factory.yml").write_text(IOS_CONFIG)
    spec, scheme = stage.settings(project, project / ".factory.yml")
    runner = FakePhone(project)
    generated = stage.generate(project, spec, runner=runner)
    script = stage.write_script(project, generated, scheme, project / "build" / "codeql", tmp_path / "x.sh", "ios")
    last = script.read_text().splitlines()[-1]
    assert "-sdk iphoneos" in last and "-destination generic/platform=iOS" in last and "CODE_SIGNING_ALLOWED=NO" in last


def test_config_platform_must_be_apple(tmp_path):
    cfg = tmp_path / ".factory.yml"
    cfg.write_text("platform: web\nweb:\n  port: 3000\n  health_path: /health\n  dockerfile: Dockerfile\n")
    with pytest.raises(stage.StageError, match="not an Apple platform"):
        stage.config_platform(cfg)
    cfg.write_text(IOS_CONFIG)
    assert stage.config_platform(cfg) == "ios"
