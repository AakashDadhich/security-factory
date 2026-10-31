import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from factory import findings
from factory.apple import inspect as ins
from factory.stages import apple_checks as stage

FIXTURES = Path(__file__).parent / "fixtures" / "apple"


def fx(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def make_app(root: Path, platform: str, info: str = "info-clean.plist", privacy: str | None = "privacy-valid.xcprivacy") -> Path:
    app = root / "Demo.app"
    base = app / "Contents" if platform == "macos" else app
    res = app / "Contents" / "Resources" if platform == "macos" else app
    res.mkdir(parents=True)
    (base / "Info.plist").write_bytes(fx(info))
    if privacy:
        (res / "PrivacyInfo.xcprivacy").write_bytes(fx(privacy))
    return app


def fake_runner(entitlements: str, codesign: str):
    def runner(cmd, **kwargs):
        if "--entitlements" in cmd:
            return SimpleNamespace(returncode=0, stdout=fx(entitlements), stderr=b"")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=fx(codesign))
    return runner


def check(tmp_path, platform="macos", entitlements="entitlements-good.xml", codesign="codesign-runtime.txt", src_files=None, **app_kwargs):
    app = make_app(tmp_path / "bundle", platform, **app_kwargs)
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    for name, text in (src_files or {}).items():
        (src / name).parent.mkdir(parents=True, exist_ok=True)
        (src / name).write_text(text)
    return stage.run(app, platform, src, tmp_path / "out", fake_runner(entitlements, codesign))


def rules(items) -> dict:
    return {f["rule_id"]: f for f in items}


def test_parse_entitlements_reads_xml_and_tolerates_a_header_and_empty_output():
    assert ins.parse_entitlements(fx("entitlements-good.xml")) == {"com.apple.security.app-sandbox": True}
    assert ins.parse_entitlements(b"\x00\x00junk" + fx("entitlements-good.xml")) == {"com.apple.security.app-sandbox": True}
    assert ins.parse_entitlements(b"  \n") == {}


def test_parse_plist_rejects_garbage_and_non_dictionaries():
    with pytest.raises(ins.InspectError):
        ins.parse_plist(fx("privacy-invalid.xcprivacy"))
    with pytest.raises(ins.InspectError):
        ins.parse_plist(b'<?xml version="1.0"?><plist version="1.0"><array/></plist>')


def test_parse_code_flags_finds_the_runtime_flag():
    assert ins.parse_code_flags(fx("codesign-runtime.txt").decode())["runtime"] is True
    assert ins.parse_code_flags(fx("codesign-no-runtime.txt").decode())["runtime"] is False
    assert ins.parse_code_flags("flags=0x10000()")["runtime"] is True
    with pytest.raises(ins.InspectError):
        ins.parse_code_flags("nothing useful")


def test_ats_settings():
    assert ins.ats_settings(ins.parse_plist(fx("info-clean.plist"))) == {"arbitrary_loads": False, "web_content": False, "insecure_http_domains": []}
    assert ins.ats_settings(ins.parse_plist(fx("info-ats-arbitrary.plist")))["arbitrary_loads"] is True
    exc = ins.ats_settings(ins.parse_plist(fx("info-ats-exceptions.plist")))
    assert exc["web_content"] is True and exc["insecure_http_domains"] == ["legacy.example.com"]


def test_declared_api_types_validates_shape():
    assert ins.declared_api_types(ins.parse_plist(fx("privacy-valid.xcprivacy"))) == {"NSPrivacyAccessedAPICategoryUserDefaults"}
    assert ins.declared_api_types({}) == set()
    with pytest.raises(ins.InspectError):
        ins.declared_api_types({"NSPrivacyAccessedAPITypes": {"a": 1}})
    with pytest.raises(ins.InspectError):
        ins.declared_api_types({"NSPrivacyAccessedAPITypes": [{"x": 1}]})


def test_wrappers_report_codesign_failures_and_missing_binary():
    bad = lambda cmd, **kw: SimpleNamespace(returncode=1, stdout=b"", stderr=b"code object is not signed")
    with pytest.raises(ins.InspectError, match="not signed"):
        ins.read_entitlements("x.app", bad)
    with pytest.raises(ins.InspectError, match="not signed"):
        ins.read_code_flags("x.app", bad)
    def missing(cmd, **kw):
        raise FileNotFoundError(cmd[0])
    with pytest.raises(ins.InspectError, match="codesign not found"):
        ins.read_code_flags("x.app", missing)


def test_wrapper_commands():
    seen = []
    def runner(cmd, **kw):
        seen.append(cmd)
        return SimpleNamespace(returncode=0, stdout=b"", stderr=fx("codesign-runtime.txt"))
    ins.read_entitlements("a.app", runner)
    ins.read_code_flags("a.app", runner)
    assert seen[0][:3] == ["codesign", "-d", "--entitlements"]
    assert seen[1] == ["codesign", "-dv", "--verbose=4", "a.app"]


def test_clean_macos_app_has_no_findings(tmp_path):
    assert check(tmp_path) == []
    assert findings.load(tmp_path / "out" / "findings.json") == []


def test_macos_missing_runtime_and_sandbox_are_high(tmp_path):
    result = rules(check(tmp_path, entitlements="entitlements-no-sandbox.xml", codesign="codesign-no-runtime.txt"))
    assert result["macos-hardened-runtime-missing"]["severity"] == "high"
    assert result["macos-app-sandbox-disabled"]["severity"] == "high"


def test_sandbox_explicitly_false_is_high(tmp_path):
    assert "macos-app-sandbox-disabled" in rules(check(tmp_path, entitlements="entitlements-sandbox-false.xml"))


def test_ios_skips_the_macos_only_rules(tmp_path):
    src = ios_project(tmp_path, "entitlements-no-sandbox.xml")
    assert run_ios(tmp_path, src / "project.yml") == []


@pytest.mark.parametrize("platform", ["macos", "ios"])
def test_risky_entitlements_on_both_platforms(tmp_path, platform):
    if platform == "ios":
        result = rules(run_ios(tmp_path, ios_project(tmp_path, "entitlements-task-allow.xml") / "project.yml"))
    else:
        result = rules(check(tmp_path, platform, entitlements="entitlements-task-allow.xml"))
    for rule in ("get-task-allow-release", "entitlement-cs-disable-library-validation", "entitlement-cs-allow-unsigned-executable-memory", "entitlement-cs-allow-dyld-environment-variables"):
        assert result[rule]["severity"] == "high"
    temp = result["entitlement-temporary-exception-files-absolute-path-read-only"]
    assert temp["severity"] == "medium"


def test_ats_rules_and_severities(tmp_path):
    assert rules(check(tmp_path, info="info-ats-arbitrary.plist"))["ats-allows-arbitrary-loads"]["severity"] == "high"
    result = rules(check(tmp_path / "b", info="info-ats-exceptions.plist"))
    assert result["ats-allows-arbitrary-loads-in-web-content"]["severity"] == "medium"
    assert result["ats-exception-allows-insecure-http"]["severity"] == "medium"
    assert "legacy.example.com" in result["ats-exception-allows-insecure-http"]["description"]
    assert "secure.example.com" not in result["ats-exception-allows-insecure-http"]["description"]


def test_missing_privacy_manifest_is_high(tmp_path):
    result = rules(check(tmp_path, privacy=None))
    assert result["privacy-manifest-missing"]["severity"] == "high"
    assert result["privacy-manifest-missing"]["location"]["path"] == "Demo.app/Contents/Resources/PrivacyInfo.xcprivacy"


def test_manifest_in_source_is_used_when_the_bundle_has_none(tmp_path):
    result = check(tmp_path, privacy=None, src_files={"Sources/PrivacyInfo.xcprivacy": fx("privacy-valid.xcprivacy").decode()})
    assert result == []


def test_invalid_privacy_manifest_is_high(tmp_path):
    result = rules(check(tmp_path, privacy="privacy-invalid.xcprivacy"))
    assert result["privacy-manifest-invalid"]["severity"] == "high"


def test_undeclared_required_reason_api_is_medium_with_a_source_line(tmp_path):
    src = {"Sources/Store.swift": "import Foundation\n\nlet d = UserDefaults.standard\n", "Sources/Disk.swift": "let k = URLResourceKey.volumeAvailableCapacityKey\n"}
    result = rules(check(tmp_path, privacy="privacy-missing-declaration.xcprivacy", src_files=src))
    ud = result["privacy-required-reason-user-defaults"]
    assert ud["severity"] == "medium"
    assert ud["location"] == {"path": "Sources/Store.swift", "start_line": 3, "end_line": 3}
    assert "privacy-required-reason-disk-space" in result


def test_declared_required_reason_api_is_not_reported(tmp_path):
    assert check(tmp_path, src_files={"Sources/Store.swift": "let d = UserDefaults.standard\n"}) == []


def test_commented_out_apis_and_skipped_folders_are_ignored(tmp_path):
    src = {"Sources/A.swift": "// UserDefaults.standard\n", "build/B.swift": "let x = UserDefaults.standard\n", ".factory/C.swift": "let x = ProcessInfo.processInfo.systemUptime\n"}
    assert check(tmp_path, src_files=src) == []


@pytest.mark.parametrize("text,sample", [
    ("UserDefaults.standard", "user-defaults"),
    ("let a = NSFileModificationDate", "file-timestamp"),
    ("var s = stat()", "file-timestamp"),
    ("ProcessInfo.processInfo.systemUptime", "system-boot-time"),
    ("statfs(path, &buf)", "disk-space"),
    ("UITextInputMode.activeInputModes", "active-keyboards"),
    ("@AppStorage(\"x\") var x = 1", "user-defaults"),
])
def test_each_required_reason_category_is_detected(tmp_path, text, sample):
    result = rules(check(tmp_path, privacy="privacy-missing-declaration.xcprivacy", src_files={"A.swift": text + "\n"}))
    assert f"privacy-required-reason-{sample}" in result


def test_unrelated_names_do_not_match_required_reason_patterns(tmp_path):
    src = {"A.swift": "let status = 1\nlet statement = 2\nlet systemSizeClass = 3\n"}
    assert check(tmp_path, src_files=src) == []


def test_every_api_category_has_rule_label_and_valid_regexes():
    source, categories = stage.load_apis()
    assert source.startswith("https://developer.apple.com/")
    assert len({c["rule"] for c in categories}) == len(categories) == 5
    assert all(c["type"].startswith("NSPrivacyAccessedAPICategory") and c["compiled"] for c in categories)


def test_keychain_accessible_always_is_high_per_occurrence(tmp_path):
    src = {"K.swift": "let a = kSecAttrAccessibleAlways\nlet b = kSecAttrAccessibleAlwaysThisDeviceOnly\nlet c = kSecAttrAccessibleWhenUnlocked\n"}
    items = check(tmp_path, src_files=src)
    result = rules(items)
    assert result["keychain-accessible-always"]["location"]["start_line"] == 1
    assert result["keychain-accessible-always-this-device-only"]["location"]["start_line"] == 2
    assert {f["severity"] for f in items} == {"high"}
    assert len(items) == 2


def test_findings_match_the_contract(tmp_path):
    items = check(tmp_path, entitlements="entitlements-task-allow.xml", info="info-ats-arbitrary.plist", privacy=None)
    for f in items:
        assert (f["stage"], f["source"]) == ("apple-checks", "check")
    findings.validate(items)


def test_unsigned_app_fails_the_stage(tmp_path):
    app = make_app(tmp_path / "b", "macos")
    bad = lambda cmd, **kw: SimpleNamespace(returncode=1, stdout=b"", stderr=b"not signed")
    with pytest.raises(stage.StageError, match="not signed"):
        stage.run(app, "macos", tmp_path, tmp_path / "out", bad)


def test_bad_inputs_fail_the_stage(tmp_path):
    with pytest.raises(stage.StageError, match="unknown platform"):
        stage.run(tmp_path, "tvos", tmp_path, tmp_path / "out")
    with pytest.raises(stage.StageError, match="not an app bundle"):
        stage.run(tmp_path / "nope.app", "macos", tmp_path, tmp_path / "out")


def test_cli_returns_one_on_stage_error(tmp_path, capsys):
    assert stage.main(["--app", str(tmp_path / "nope.app"), "--platform", "macos", "--out", str(tmp_path / "o")]) == 1
    assert "error:" in capsys.readouterr().err


CODESIGN = shutil.which("codesign")
REQUIRE = bool(os.environ.get("FACTORY_REQUIRE_CODESIGN"))


@pytest.mark.skipif(not CODESIGN and not REQUIRE, reason="codesign is only on macOS")
def test_integration_real_codesign_reads_flags_and_entitlements(tmp_path):
    assert CODESIGN, "FACTORY_REQUIRE_CODESIGN is set but codesign is missing"
    binary = tmp_path / "tiny"
    shutil.copy(shutil.which("true") or "/usr/bin/true", binary)
    ent = tmp_path / "ent.plist"
    ent.write_bytes(fx("entitlements-task-allow.xml"))
    subprocess.run(["codesign", "--force", "--sign", "-", "--options", "runtime", "--entitlements", str(ent), str(binary)], check=True, capture_output=True)
    flags = ins.read_code_flags(binary)
    assert flags["runtime"] is True and "adhoc" in flags["names"]
    got = ins.read_entitlements(binary)
    assert got["com.apple.security.get-task-allow"] is True
    assert got["com.apple.security.app-sandbox"] is True

    plain = tmp_path / "plain"
    shutil.copy(shutil.which("true") or "/usr/bin/true", plain)
    subprocess.run(["codesign", "--force", "--sign", "-", str(plain)], check=True, capture_output=True)
    assert ins.read_code_flags(plain)["runtime"] is False
    assert ins.read_entitlements(plain) == {}


def no_codesign(cmd, **kwargs):
    raise AssertionError("codesign must not run for an unsigned iOS build")


def ios_project(tmp_path, entitlements: str | None, spec_text: str | None = None) -> Path:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    setting = "CODE_SIGN_ENTITLEMENTS: App.entitlements" if entitlements else "FOO: bar"
    default = f"name: Demo\ntargets:\n  Demo:\n    type: application\n    platform: iOS\n    settings:\n      base:\n        {setting}\n"
    (src / "project.yml").write_text(spec_text or default)
    if entitlements:
        (src / "App.entitlements").write_bytes(fx(entitlements))
    return src


def run_ios(tmp_path, spec: Path | None):
    app = make_app(tmp_path / "bundle", "ios")
    return stage.run(app, "ios", tmp_path / "src", tmp_path / "out", no_codesign, project_spec=spec)


def test_ios_never_calls_codesign_and_is_clean_without_entitlements(tmp_path):
    src = ios_project(tmp_path, None)
    assert run_ios(tmp_path, src / "project.yml") == []


def test_ios_without_a_spec_reads_no_entitlements(tmp_path):
    ios_project(tmp_path, None)
    assert run_ios(tmp_path, None) == []


def test_ios_reads_entitlements_from_the_file_the_spec_names(tmp_path):
    src = ios_project(tmp_path, "entitlements-task-allow.xml")
    result = rules(run_ios(tmp_path, src / "project.yml"))
    assert result["get-task-allow-release"]["severity"] == "high"
    assert "entitlement-cs-disable-library-validation" in result


def test_ios_entitlements_file_may_be_declared_with_the_entitlements_key(tmp_path):
    spec = "name: Demo\ntargets:\n  Demo:\n    type: application\n    platform: iOS\n    entitlements:\n      path: App.entitlements\n"
    src = ios_project(tmp_path, "entitlements-task-allow.xml", spec)
    assert "get-task-allow-release" in rules(run_ios(tmp_path, src / "project.yml"))


def test_ios_style_get_task_allow_key_is_flagged(tmp_path):
    src = ios_project(tmp_path, "entitlements-task-allow.xml")
    (src / "App.entitlements").write_text('<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>get-task-allow</key><true/></dict></plist>')
    result = rules(run_ios(tmp_path, src / "project.yml"))
    assert "get-task-allow-release" in result


def test_spec_entitlement_paths_skip_non_application_targets(tmp_path):
    spec = tmp_path / "project.yml"
    spec.write_text("name: X\ntargets:\n  Lib:\n    type: framework\n    settings:\n      base:\n        CODE_SIGN_ENTITLEMENTS: lib.entitlements\n  App:\n    type: application\n    settings:\n      base:\n        CODE_SIGN_ENTITLEMENTS: sub/app.entitlements\n")
    assert stage.spec_entitlement_paths(spec) == [tmp_path / "sub" / "app.entitlements"]


def test_missing_entitlements_file_fails_the_stage(tmp_path):
    src = ios_project(tmp_path, "entitlements-good.xml")
    (src / "App.entitlements").unlink()
    with pytest.raises(stage.StageError, match="cannot read"):
        run_ios(tmp_path, src / "project.yml")


def test_bad_spec_fails_the_stage(tmp_path):
    spec = tmp_path / "project.yml"
    spec.write_text("a: [unclosed\n")
    with pytest.raises(stage.StageError, match="XcodeGen spec"):
        stage.spec_entitlement_paths(spec)


def test_ios_still_runs_ats_privacy_and_keychain_checks_on_unsigned_apps(tmp_path):
    app = make_app(tmp_path / "bundle", "ios", info="info-ats-arbitrary.plist", privacy=None)
    src = tmp_path / "src"
    src.mkdir()
    result = rules(stage.run(app, "ios", src, tmp_path / "out", no_codesign))
    assert "ats-allows-arbitrary-loads" in result and "privacy-manifest-missing" in result
