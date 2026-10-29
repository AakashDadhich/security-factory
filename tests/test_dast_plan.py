import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from factory import findings
from factory.dast import harness
from factory.dast import plan
from factory.stages import dast_web as stage

ACTIVE_FIXTURE = Path(__file__).parent / "fixtures" / "zap" / "report-active.json"
WEB_CONFIG = "platform: web\nweb:\n  port: 3000\n  health_path: /health\n  dockerfile: Dockerfile\n  openapi: openapi.yaml\n"


def jobs(openapi: bool, port: int = 3000) -> list[dict]:
    return yaml.safe_load(plan.render("full", port, openapi=openapi))["jobs"]


def test_full_plan_with_openapi_has_jobs_in_order():
    assert [j["type"] for j in jobs(True)] == [
        "openapi", "spider", "passiveScan-wait", "activeScan", "passiveScan-wait", "export", "report", "report",
    ]


def test_full_plan_without_openapi_has_no_import_job():
    assert [j["type"] for j in jobs(False)] == [
        "spider", "passiveScan-wait", "activeScan", "passiveScan-wait", "export", "report", "report",
    ]


def test_openapi_job_overrides_target_and_reads_the_mounted_spec():
    job = jobs(True, 8080)[0]
    assert job["parameters"]["targetUrl"] == "http://app:8080"
    assert job["parameters"]["apiFile"] == plan.SPEC_MOUNT


def test_active_scan_is_time_boxed():
    job = next(j for j in jobs(False) if j["type"] == "activeScan")
    assert job["parameters"]["maxRuleDurationInMins"] == 2
    assert job["parameters"]["maxScanDurationInMins"] == 15


def test_rendered_plan_has_no_placeholders():
    for openapi in (True, False):
        text = plan.render("full", 3000, openapi=openapi)
        assert "{{" not in text


def test_rendering_is_deterministic():
    assert plan.render("full", 3000, openapi=True) == plan.render("full", 3000, openapi=True)


def test_openapi_is_rejected_for_baseline():
    with pytest.raises(plan.PlanError):
        plan.render("baseline", 3000, openapi=True)


@pytest.mark.parametrize("url", [
    "http://example.com",
    "http://example.com:3000",
    "https://app:3000",
    "http://app.evil.com:3000",
    "http://app:3000@example.com",
    "http://app:9999",
    "http://app:3000/admin",
    "http://localhost:3000",
])
def test_guard_rejects_hosts_other_than_the_app_alias(url):
    with pytest.raises(plan.PlanError):
        plan.assert_safe_target(url, 3000)


def test_guard_accepts_the_app_alias():
    plan.assert_safe_target("http://app:3000", 3000)
    plan.assert_safe_target("http://app:3000/", 3000)


def test_command_guard_requires_the_isolated_network():
    plan.assert_safe_command(["docker", "run", "--network", harness.NETWORK, "img"])
    with pytest.raises(plan.PlanError):
        plan.assert_safe_command(["docker", "run", "--network", "host", "img"])
    with pytest.raises(plan.PlanError):
        plan.assert_safe_command(["docker", "run", "img"])


def test_spec_path_must_stay_inside_the_project(tmp_path):
    (tmp_path / "openapi.yaml").write_text("openapi: 3.1.0\n")
    assert plan.resolve_spec("openapi.yaml", tmp_path) == (tmp_path / "openapi.yaml").resolve()
    with pytest.raises(plan.PlanError):
        plan.resolve_spec("../outside.yaml", tmp_path)
    with pytest.raises(plan.PlanError):
        plan.resolve_spec("missing.yaml", tmp_path)


def test_zap_cmd_mounts_spec_read_only():
    cmd = stage.zap_cmd("zap@sha256:abc", Path("/w"), "full.yaml", Path("/p/openapi.yaml"))
    assert f"/p/openapi.yaml:{plan.SPEC_MOUNT}:ro" in cmd
    assert plan.SPEC_MOUNT not in stage.zap_cmd("zap@sha256:abc", Path("/w"), "full.yaml")


def test_active_scan_report_maps_risk_codes():
    results = stage.convert(json.loads(ACTIVE_FIXTURE.read_text()))
    findings.validate(results)
    severity = {f["rule_id"]: f["severity"] for f in results}
    assert severity == {"40018": "high", "40012": "medium", "90022": "low"}
    sqli = next(f for f in results if f["rule_id"] == "40018")
    assert sqli["cwe"] == ["CWE-89"]
    assert sqli["location"]["url"].startswith("http://app:3000/api/greeting")


def test_run_full_mounts_spec_and_renders_import_job(tmp_path):
    (tmp_path / "openapi.yaml").write_text("openapi: 3.1.0\n")
    config = tmp_path / ".factory.yml"
    config.write_text(WEB_CONFIG)
    seen = {}

    def fake_zap(cmd):
        work = Path(next(c for c in cmd if c.endswith(":/zap/wrk:rw")).split(":")[0])
        seen["plan"] = yaml.safe_load((work / "full.yaml").read_text())
        seen["cmd"] = cmd
        (work / "zap-report.json").write_text(ACTIVE_FIXTURE.read_text())
        (work / "zap-report.html").write_text("<html></html>")
        return SimpleNamespace(returncode=0)

    results = stage.run("full", tmp_path / "out", config, "zap@sha256:abc", runner=fake_zap, project_dir=tmp_path)
    assert len(results) == 3
    assert seen["plan"]["jobs"][0]["type"] == "openapi"
    assert any(c.endswith(f"{plan.SPEC_MOUNT}:ro") for c in seen["cmd"])


def test_run_full_without_openapi_skips_import_and_mount(tmp_path):
    config = tmp_path / ".factory.yml"
    config.write_text(WEB_CONFIG.replace("  openapi: openapi.yaml\n", ""))
    seen = {}

    def fake_zap(cmd):
        work = Path(next(c for c in cmd if c.endswith(":/zap/wrk:rw")).split(":")[0])
        seen["plan"] = yaml.safe_load((work / "full.yaml").read_text())
        seen["cmd"] = cmd
        (work / "zap-report.json").write_text(ACTIVE_FIXTURE.read_text())
        return SimpleNamespace(returncode=0)

    stage.run("full", tmp_path / "out", config, "zap@sha256:abc", runner=fake_zap, project_dir=tmp_path)
    assert seen["plan"]["jobs"][0]["type"] == "spider"
    assert not any(plan.SPEC_MOUNT in c for c in seen["cmd"])


def test_run_fails_when_configured_spec_is_missing(tmp_path):
    config = tmp_path / ".factory.yml"
    config.write_text(WEB_CONFIG)
    with pytest.raises(stage.StageError):
        stage.run("full", tmp_path / "out", config, "zap@sha256:abc", runner=lambda cmd: SimpleNamespace(returncode=0), project_dir=tmp_path)


def test_stage_defaults_to_the_full_plan():
    import inspect

    assert 'default="full"' in inspect.getsource(stage.main)
