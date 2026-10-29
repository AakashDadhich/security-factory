import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from factory import findings, stage_matrix, tools
from factory.dast import harness
from factory.dast import plan as dast_plan
from factory.findings import FindingsError
from factory.stages import dast_web as stage

FIXTURE = Path(__file__).parent / "fixtures" / "zap" / "report.json"
WEB_CONFIG = "platform: web\nweb:\n  port: 3000\n  health_path: /health\n  dockerfile: Dockerfile\n"


def converted() -> list[dict]:
    return stage.convert(json.loads(FIXTURE.read_text()))


def by_rule(rule: str) -> list[dict]:
    return [f for f in converted() if f["rule_id"] == rule]


def test_conversion_validates_against_schema():
    findings.validate(converted())


def test_risk_codes_map_to_severities():
    assert by_rule("10105")[0]["severity"] == "high"
    assert by_rule("10020")[0]["severity"] == "medium"
    assert by_rule("10096")[0]["severity"] == "low"
    assert by_rule("10049")[0]["severity"] == "info"


def test_cwe_comes_from_cweid_and_negative_is_dropped():
    assert by_rule("10020")[0]["cwe"] == ["CWE-1021"]
    assert by_rule("10105")[0]["cwe"] == []


def test_location_is_url_and_uppercased_method():
    assert by_rule("10105")[0]["location"] == {"url": "http://app:3000/admin", "method": "POST"}


def test_query_string_does_not_change_fingerprint():
    assert len(by_rule("10049")) == 2
    paths = sorted(f["location"]["url"].split("?")[0] for f in by_rule("10049"))
    assert paths == ["http://app:3000/", "http://app:3000/health"]


def test_fingerprint_ignores_host_and_query():
    a = findings.fingerprint("zap", "10020", {"url": "http://app:3000/page?a=1", "method": "GET"})
    b = findings.fingerprint("zap", "10020", {"url": "http://other:80/page", "method": "GET"})
    assert a == b
    assert a == by_rule("10020")[0]["fingerprint"]


def test_alert_without_instances_uses_site_name():
    assert by_rule("10096")[0]["location"]["url"] == "http://app:3000"


def test_html_is_stripped_from_text():
    assert by_rule("10020")[0]["description"] == "The response does not protect against clickjacking."


def test_unknown_riskcode_is_rejected():
    report = {"site": [{"@name": "http://app", "alerts": [{"pluginid": "1", "name": "x", "riskcode": "9"}]}]}
    with pytest.raises(FindingsError):
        stage.convert(report)


def test_non_zap_report_is_rejected():
    with pytest.raises(FindingsError):
        stage.convert({"runs": []})


def test_plan_targets_the_app_alias_and_port():
    plan = dast_plan.render("baseline", 8080)
    assert "http://app:8080" in plan
    assert "{{TARGET}}" not in plan


def test_unknown_plan_is_rejected():
    with pytest.raises(dast_plan.PlanError):
        dast_plan.render("nope", 3000)


def test_baseline_plan_has_expected_jobs():
    import yaml

    plan = yaml.safe_load(dast_plan.render("baseline", 3000))
    types = [j["type"] for j in plan["jobs"]]
    assert types == ["spider", "passiveScan-wait", "report", "report"]
    assert plan["jobs"][0]["parameters"]["maxDuration"] == 2
    assert {j["parameters"]["template"] for j in plan["jobs"] if j["type"] == "report"} == {"traditional-json", "traditional-html"}


def test_zap_runs_on_the_isolated_network():
    cmd = stage.zap_cmd("zap@sha256:abc", Path("/w"), "baseline.yaml")
    assert cmd[cmd.index("--network") + 1] == harness.NETWORK
    assert cmd[-4:] == ["-cmd", "-silent", "-autorun", "/zap/wrk/baseline.yaml"]


def test_run_writes_findings_and_reports(tmp_path):
    config = tmp_path / ".factory.yml"
    config.write_text(WEB_CONFIG)
    out = tmp_path / "out"

    def fake_zap(cmd):
        work = Path(cmd[cmd.index("-v") + 1].split(":")[0])
        (work / "zap-report.json").write_text(FIXTURE.read_text())
        (work / "zap-report.html").write_text("<html></html>")
        return SimpleNamespace(returncode=0)

    results = stage.run("baseline", out, config, "zap@sha256:abc", runner=fake_zap)
    assert len(results) == len(findings.load(out / "findings.json"))
    assert (out / "zap-report.html").is_file()
    assert (out / "zap-report.json").is_file()
    assert not (out / "zap-work").exists()


def test_run_fails_when_zap_writes_no_report(tmp_path):
    config = tmp_path / ".factory.yml"
    config.write_text(WEB_CONFIG)
    with pytest.raises(stage.StageError):
        stage.run("baseline", tmp_path / "out", config, "zap@sha256:abc", runner=lambda cmd: SimpleNamespace(returncode=2))


def test_run_refuses_non_web_platform(tmp_path):
    config = tmp_path / ".factory.yml"
    config.write_text("platform: ios\napple:\n  project_spec: project.yml\n  scheme: App\n")
    with pytest.raises(stage.StageError):
        stage.run("baseline", tmp_path / "out", config, "zap@sha256:abc", runner=lambda cmd: SimpleNamespace(returncode=0))


def test_lock_pins_zap_and_curl_by_digest():
    lock = tools.load_lock()
    for name in ("zap", "curl"):
        assert lock[name].kind == "container"
        assert "@sha256:" in lock[name].image


def test_stage_matrix_includes_dast_web_for_web_only():
    assert "dast-web" in [s.name for s in stage_matrix.expected("web", "check")]
    assert "dast-web" not in [s.name for s in stage_matrix.expected("ios", "check")]


def test_network_is_internal():
    assert harness.network_create_cmd() == ["docker", "network", "create", "--internal", "factory-dast"]


def test_app_container_is_locked_down():
    cmd = harness.run_cmd("42", {"PORT": "3000"})
    joined = " ".join(cmd)
    assert "--read-only" in cmd
    assert "--cap-drop ALL" in joined
    assert "--security-opt no-new-privileges" in joined
    assert "--tmpfs /tmp" in joined
    assert "--network factory-dast" in joined
    assert "--network-alias app" in joined
    assert cmd[-1] == "factory-app:42"
    assert "-e PORT=3000" in joined
    assert "--privileged" not in cmd and "-p" not in cmd and "--publish" not in cmd


def test_build_command_tags_with_run_id():
    assert harness.build_cmd("7", "ctx/Dockerfile", "ctx") == ["docker", "build", "-t", "factory-app:7", "-f", "ctx/Dockerfile", "ctx"]


def test_health_command_polls_from_curl_on_the_network():
    cmd = harness.health_cmd("curl@sha256:abc", 3000, "/health")
    assert cmd[:5] == ["docker", "run", "--rm", "--network", "factory-dast"]
    assert "curl@sha256:abc" in cmd
    assert cmd[-1] == "http://app:3000/health"


def test_down_removes_container_network_and_image():
    flat = [" ".join(c) for c in harness.down_cmds("9")]
    assert any("rm --force factory-app-9" in c for c in flat)
    assert any("network rm factory-dast" in c for c in flat)


def test_env_example_parsing(tmp_path):
    path = tmp_path / ".env.example"
    path.write_text("# comment\nPORT=3000\nexport NAME=\"fake value\"\n\nBAD LINE\nEMPTY=\n")
    assert harness.read_env_example(path) == {"PORT": "3000", "NAME": "fake value", "EMPTY": ""}


def test_missing_env_example_gives_no_env(tmp_path):
    assert harness.read_env_example(tmp_path / ".env.example") == {}


def make_runner(codes: list[str]):
    calls = []

    def runner(cmd):
        calls.append(cmd)
        code = codes[min(len(calls) - 1, len(codes) - 1)]
        return SimpleNamespace(returncode=0, stdout=code)

    return runner, calls


def test_wait_healthy_returns_once_200(monkeypatch):
    runner, calls = make_runner(["000", "000", "200"])
    harness.wait_healthy("curl@sha256:a", 3000, "/health", "1", runner=runner, sleep=lambda s: None)
    assert len(calls) == 3


def test_wait_healthy_times_out_and_dumps_logs(monkeypatch):
    runner, _ = make_runner(["503"])
    logged = []
    monkeypatch.setattr(harness, "_run", lambda cmd, **kw: logged.append(cmd) or SimpleNamespace(returncode=0))
    now = iter(range(0, 1000, 10))
    with pytest.raises(harness.HarnessError):
        harness.wait_healthy("curl@sha256:a", 3000, "/health", "1", timeout=30, runner=runner, sleep=lambda s: None, clock=lambda: next(now))
    assert ["docker", "logs", "factory-app-1"] in logged


def test_up_refuses_non_web(tmp_path):
    config = tmp_path / ".factory.yml"
    config.write_text("platform: ios\napple:\n  project_spec: project.yml\n  scheme: App\n")
    with pytest.raises(harness.HarnessError):
        harness.up(config, "1", tmp_path)
