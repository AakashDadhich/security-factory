import json
from pathlib import Path

import yaml

from factory import stage_matrix

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github" / "workflows" / "factory.yml"
MACOS_JOBS = ("apple-build", "sast-swiftlint", "codeql-swift-analyze")
STAGE_JOBS = ("apple-build", "sast-swiftlint", "sast-codeql-swift")


def jobs() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]


def names(platform: str, mode: str = "check") -> list[str]:
    return [s.name for s in stage_matrix.expected(platform, mode)]


def test_macos_check_mode_expects_the_six_stages_and_the_ai_ones():
    assert set(names("macos")) == {"threat-model", "review", "secrets", "sast-semgrep", "sast-swiftlint", "sast-codeql-swift", "deps-sbom", "apple-build", "apple-checks"}


def test_macos_does_not_expect_web_only_stages():
    assert not {"sast-codeql", "sast-eslint", "dast-web"} & set(names("macos"))


def test_web_does_not_expect_macos_stages():
    assert not set(STAGE_JOBS) & set(names("web"))
    assert not set(STAGE_JOBS) & set(names("web", "spec"))


def test_web_only_jobs_are_not_applicable_to_macos_by_not_being_expected():
    assert {s.name for s in stage_matrix.STAGES if "macos" not in s.platforms} == {"sast-codeql", "sast-eslint", "dast-web", "mobsf"}


def test_macos_jobs_run_on_macos_15_with_least_privilege():
    j = jobs()
    for name in MACOS_JOBS:
        assert j[name]["runs-on"] == "macos-15"
        assert j[name]["permissions"] == ({"contents": "read", "security-events": "write"} if name == "codeql-swift-analyze" else {"contents": "read"})


def test_only_three_jobs_use_macos_runners_in_the_reusable_workflow():
    assert {n for n, job in jobs().items() if job["runs-on"] == "macos-15"} == set(MACOS_JOBS)


def test_macos_jobs_only_run_for_macos_projects():
    for name in set(MACOS_JOBS) | set(STAGE_JOBS):
        assert "needs.setup.outputs.platform == 'macos'" in jobs()[name]["if"]


def test_gate_waits_for_the_macos_jobs_and_the_manifest_lists_them():
    j = jobs()
    assert set(MACOS_JOBS) | set(STAGE_JOBS) <= set(j["gate"]["needs"])
    step = next(s for s in j["setup"]["steps"] if s.get("name") == "write run manifest")
    for name in STAGE_JOBS:
        assert f"--stage {name}" in step["run"]


def test_macos_jobs_wait_for_the_pushed_commit_and_the_review():
    for name in set(MACOS_JOBS) | set(STAGE_JOBS):
        assert {"setup", "codegen-commit", "review"} <= set(jobs()[name]["needs"])


def test_codeql_swift_uses_a_manual_build_and_the_same_builder():
    steps = jobs()["codeql-swift-analyze"]["steps"]
    init = next(s for s in steps if "codeql-action/init" in s.get("uses", ""))
    assert init["with"]["languages"] == "swift" and init["with"]["build-mode"] == "manual"
    run_steps = [s.get("run", "") for s in steps]
    assert any("factory.stages.apple_build script" in r for r in run_steps)
    uses = [s.get("uses", "") for s in steps]
    build = next(i for i, s in enumerate(steps) if "xcodebuild-codeql.sh" in s.get("run", "") and "apple_build" not in s["run"])
    assert steps.index(init) < build
    assert not any("python" in steps[i].get("run", "") for i in range(steps.index(init) + 1, build))
    assert any("codeql-action/analyze" in u for u in uses)


def test_apple_build_job_uploads_the_zip_artifact():
    steps = jobs()["apple-build"]["steps"]
    upload = next(s for s in steps if "upload-artifact" in s.get("uses", ""))
    assert upload["with"]["name"] == "apple-build" and upload["with"]["path"] == "out/apple-build/"


def test_apple_checks_run_inside_apple_build_after_the_build_and_upload_their_own_artifact():
    steps = jobs()["apple-build"]["steps"]
    build = next(i for i, s in enumerate(steps) if "apple_build run" in s.get("run", ""))
    checks = next(i for i, s in enumerate(steps) if "factory.stages.apple_checks" in s.get("run", ""))
    assert checks > build
    uploads = {s["with"]["name"]: s["with"]["path"] for s in steps if "upload-artifact" in s.get("uses", "")}
    assert uploads == {"apple-build": "out/apple-build/", "apple-checks": "out/apple-checks/"}
    assert "apple-checks" not in jobs()


def test_apple_checks_is_a_macos_only_matrix_stage_and_in_the_manifest():
    assert "apple-checks" in names("macos") and "apple-checks" not in names("web")
    step = next(s for s in jobs()["setup"]["steps"] if s.get("name") == "write run manifest")
    assert "--stage apple-checks" in step["run"]


def test_app_private_key_and_claude_token_stay_out_of_the_macos_jobs():
    for name in MACOS_JOBS:
        text = json.dumps(jobs()[name])
        assert "FACTORY_APP_PRIVATE_KEY" not in text and "CLAUDE_CODE_OAUTH_TOKEN" not in text



def test_codeql_swift_findings_are_converted_on_linux_after_the_traced_job():
    j = jobs()
    stage = j["sast-codeql-swift"]
    assert stage["runs-on"] == "ubuntu-24.04" and "codeql-swift-analyze" in stage["needs"]
    assert stage["permissions"] == {"contents": "read"}
    assert "factory.sarif" in json.dumps(stage)
    assert "factory.sarif" not in json.dumps(j["codeql-swift-analyze"])
    uploads = [s["with"]["name"] for s in j["codeql-swift-analyze"]["steps"] if "upload-artifact" in s.get("uses", "")]
    assert uploads == ["codeql-swift-analyze"]
    assert any("findings.json" in s.get("run", "") for s in j["codeql-swift-analyze"]["steps"])
