import json
from pathlib import Path

import yaml

from factory import stage_matrix

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github" / "workflows" / "factory.yml"
APPLE_JOBS = ("apple-build", "sast-swiftlint", "codeql-swift-analyze", "sast-codeql-swift")


def jobs() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]


def names(platform: str, mode: str = "check") -> set[str]:
    return {s.name for s in stage_matrix.expected(platform, mode)}


def test_ios_check_mode_expects_the_scanners_the_apple_stages_mobsf_and_the_ai_ones():
    assert names("ios") == {
        "threat-model", "review", "secrets", "sast-semgrep", "sast-swiftlint", "sast-codeql-swift",
        "deps-sbom", "apple-build", "apple-checks", "mobsf",
    }


def test_ios_does_not_expect_web_only_stages():
    assert not {"sast-codeql", "sast-eslint", "dast-web"} & names("ios")


def test_mobsf_is_ios_only():
    assert "mobsf" not in names("macos") and "mobsf" not in names("web")


def test_ios_spec_mode_also_expects_mobsf():
    assert "mobsf" in names("ios", "spec")


def test_apple_jobs_run_for_macos_and_ios_only():
    for name in APPLE_JOBS:
        condition = jobs()[name]["if"]
        assert "platform == 'macos'" in condition and "platform == 'ios'" in condition
        assert "platform == 'web'" not in condition


def test_mobsf_job_is_linux_least_privilege_and_waits_for_the_build():
    job = jobs()["mobsf"]
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["permissions"] == {"contents": "read"}
    assert {"setup", "codegen-commit", "review", "apple-build"} <= set(job["needs"])
    assert "platform == 'ios'" in job["if"] and "macos" not in job["if"]


def test_mobsf_job_has_no_secrets_and_does_not_echo_the_key():
    text = json.dumps(jobs()["mobsf"])
    assert "secrets." not in text
    assert "MOBSF_API_KEY" not in text


def test_mobsf_job_downloads_the_ipa_installs_the_image_and_uploads_its_artifact():
    steps = jobs()["mobsf"]["steps"]
    download = next(s for s in steps if "download-artifact" in s.get("uses", ""))
    assert download["with"] == {"name": "apple-build", "path": "in/apple-build"}
    assert any("factory.tools install mobsf" in s.get("run", "") for s in steps)
    assert any("--ipa in/apple-build/app.ipa" in s.get("run", "") for s in steps)
    upload = next(s for s in steps if "upload-artifact" in s.get("uses", ""))
    assert upload["with"]["name"] == "mobsf" and upload["with"]["path"] == "out/mobsf/"


def test_gate_waits_for_mobsf_and_the_manifest_lists_it():
    assert "mobsf" in jobs()["gate"]["needs"]
    step = next(s for s in jobs()["setup"]["steps"] if s.get("name") == "write run manifest")
    assert "--stage mobsf" in step["run"]


def test_apple_checks_get_the_config_so_ios_can_read_entitlements_from_the_project():
    step = next(s for s in jobs()["apple-build"]["steps"] if "factory.stages.apple_checks" in s.get("run", ""))
    assert "--config" in step["run"]
