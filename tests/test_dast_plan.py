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


SITES_FIXTURE = Path(__file__).parent / "fixtures" / "zap" / "sites-tree.yaml"


def _fake_zap_with(tree: bool):
    def fake_zap(cmd):
        work = Path(next(c for c in cmd if c.endswith(":/zap/wrk:rw")).split(":")[0])
        (work / "zap-report.json").write_text(ACTIVE_FIXTURE.read_text())
        if tree:
            (work / "sites-tree.yaml").write_text(SITES_FIXTURE.read_text())
        return SimpleNamespace(returncode=0)

    return fake_zap


def _no_openapi_config(tmp_path):
    config = tmp_path / ".factory.yml"
    config.write_text(WEB_CONFIG.replace("  openapi: openapi.yaml\n", ""))
    return config


def test_site_paths_come_from_the_sites_tree():
    paths = stage.site_paths(yaml.safe_load(SITES_FIXTURE.read_text()))
    assert "/health" in paths
    assert "/api/greeting" in paths
    assert paths == sorted(set(paths))


def test_site_paths_ignores_malformed_trees():
    assert stage.site_paths(None) == []
    assert stage.site_paths([{"node": "x", "children": "bad"}, "oops"]) == []


def test_run_writes_sites_json_from_the_exported_tree(tmp_path):
    out = tmp_path / "out"
    stage.run("full", out, _no_openapi_config(tmp_path), "zap@sha256:abc", runner=_fake_zap_with(True), project_dir=tmp_path)
    sites = json.loads((out / "sites.json").read_text())
    assert "/health" in sites["paths"] and "/api/greeting" in sites["paths"]
    assert (out / "sites-tree.yaml").is_file()


def test_run_without_exported_tree_writes_no_sites_json(tmp_path):
    out = tmp_path / "out"
    stage.run("full", out, _no_openapi_config(tmp_path), "zap@sha256:abc", runner=_fake_zap_with(False), project_dir=tmp_path)
    assert not (out / "sites.json").exists()


AUTH_JSON = {
    "type": "json",
    "login_url": "/login",
    "username_field": "username",
    "password_field": "password",
    "username_env": "TEST_USERNAME",
    "password_env": "TEST_PASSWORD",
    "logged_in_regex": '"ok":true',
    "logged_out_regex": "login required",
}
AUTH_FORM = {**AUTH_JSON, "type": "form", "login_url": "/session/new"}
CREDS = ("zap-test", "zap-pw-7f3a9c2e41d8")
SNAPSHOT_DIR = Path(__file__).parent / "snapshots"
AUTH_ENV_EXAMPLE = "TEST_USERNAME=zap-test\nTEST_PASSWORD=zap-pw-7f3a9c2e41d8\n"


def auth_plan(auth=AUTH_JSON, creds=CREDS, port=3000, openapi=True):
    return plan.render("full", port, openapi=openapi, auth=auth, credentials=creds)


def test_json_auth_plan_matches_snapshot():
    assert auth_plan() == (SNAPSHOT_DIR / "dast-full-auth-json.yaml").read_text()


def test_auth_is_omitted_when_not_configured():
    text = plan.render("full", 3000, openapi=True)
    assert "authentication" not in text and "users:" not in text and "user:" not in text
    assert text == plan.render("full", 3000, openapi=True, auth=None, credentials=CREDS)


def test_auth_context_and_scan_users():
    doc = yaml.safe_load(auth_plan())
    context = doc["env"]["contexts"][0]
    assert context["authentication"]["method"] == "json"
    assert context["authentication"]["parameters"]["loginRequestUrl"] == "http://app:3000/login"
    assert context["authentication"]["parameters"]["loginRequestBody"] == '{"username":"{%username%}","password":"{%password%}"}'
    assert context["authentication"]["verification"] == {"method": "response", "loggedInRegex": '"ok":true', "loggedOutRegex": "login required"}
    assert context["sessionManagement"] == {"method": "cookie"}
    assert context["users"] == [{"name": "test-user", "credentials": {"username": CREDS[0], "password": CREDS[1]}}]
    by_type = {j["type"]: j for j in doc["jobs"] if j["type"] in ("spider", "activeScan")}
    assert by_type["spider"]["parameters"]["user"] == "test-user"
    assert by_type["activeScan"]["parameters"]["user"] == "test-user"
    assert by_type["activeScan"]["parameters"]["maxScanDurationInMins"] == 15


def test_form_auth_uses_a_urlencoded_body():
    doc = yaml.safe_load(auth_plan(AUTH_FORM))
    parameters = doc["env"]["contexts"][0]["authentication"]["parameters"]
    assert doc["env"]["contexts"][0]["authentication"]["method"] == "form"
    assert parameters["loginRequestBody"] == "username={%username%}&password={%password%}"
    assert parameters["loginRequestUrl"] == "http://app:3000/session/new"


def test_only_one_regex_is_needed():
    auth = {k: v for k, v in AUTH_JSON.items() if k != "logged_out_regex"}
    verification = yaml.safe_load(auth_plan(auth))["env"]["contexts"][0]["authentication"]["verification"]
    assert verification == {"method": "response", "loggedInRegex": '"ok":true'}


def test_credentials_with_yaml_special_characters_stay_one_value():
    doc = yaml.safe_load(auth_plan(creds=("a: b", 'p"w\n#x')))
    assert doc["env"]["contexts"][0]["users"][0]["credentials"] == {"username": "a: b", "password": 'p"w\n#x'}


@pytest.mark.parametrize("login_url", ["//evil.test/login", "http://evil.test/login", "@evil.test/x", "login"])
def test_login_url_must_stay_on_the_app(login_url):
    with pytest.raises(plan.PlanError):
        auth_plan({**AUTH_JSON, "login_url": login_url})


def test_auth_needs_credentials_and_a_known_type():
    with pytest.raises(plan.PlanError):
        plan.render("full", 3000, auth=AUTH_JSON)
    with pytest.raises(plan.PlanError):
        auth_plan(creds=("", "x"))
    with pytest.raises(plan.PlanError):
        auth_plan({**AUTH_JSON, "type": "basic"})


def test_auth_is_rejected_for_baseline():
    with pytest.raises(plan.PlanError):
        plan.render("baseline", 3000, auth=AUTH_JSON, credentials=CREDS)


def test_harness_seeds_the_test_user_only_with_auth(tmp_path):
    (tmp_path / ".env.example").write_text(AUTH_ENV_EXAMPLE + "PORT=3000\n")
    web = {"port": 3000, "health_path": "/health", "dockerfile": "Dockerfile"}
    assert "SEED_TEST_USER" not in harness.app_env(web, tmp_path)
    env = harness.app_env({**web, "auth": AUTH_JSON}, tmp_path)
    assert env["SEED_TEST_USER"] == "1"
    assert env["TEST_USERNAME"] == "zap-test" and env["PORT"] == "3000"
    assert "-e SEED_TEST_USER=1" in " ".join(harness.run_cmd("5", env))


def test_harness_refuses_auth_without_env_values(tmp_path):
    (tmp_path / ".env.example").write_text("TEST_USERNAME=zap-test\nTEST_PASSWORD=\n")
    web = {"port": 3000, "health_path": "/health", "dockerfile": "Dockerfile", "auth": AUTH_JSON}
    with pytest.raises(harness.HarnessError, match="TEST_PASSWORD"):
        harness.app_env(web, tmp_path)
    with pytest.raises(harness.HarnessError):
        harness.app_env(web, tmp_path / "missing")


def _auth_config(tmp_path):
    config = tmp_path / ".factory.yml"
    web = yaml.safe_load(WEB_CONFIG)
    web["web"].pop("openapi")
    web["web"]["auth"] = AUTH_JSON
    config.write_text(yaml.safe_dump(web))
    return config


def test_run_renders_the_auth_plan_and_removes_it_afterwards(tmp_path):
    (tmp_path / ".env.example").write_text(AUTH_ENV_EXAMPLE)
    seen = {}

    def fake_zap(cmd):
        work = Path(next(c for c in cmd if c.endswith(":/zap/wrk:rw")).split(":")[0])
        seen["plan"] = yaml.safe_load((work / "full.yaml").read_text())
        (work / "zap-report.json").write_text(ACTIVE_FIXTURE.read_text())
        return SimpleNamespace(returncode=0)

    out = tmp_path / "out"
    stage.run("full", out, _auth_config(tmp_path), "zap@sha256:abc", runner=fake_zap, project_dir=tmp_path)
    assert seen["plan"]["env"]["contexts"][0]["users"][0]["credentials"]["password"] == CREDS[1]
    assert not any(CREDS[1] in p.read_text() for p in out.rglob("*") if p.is_file() and p.suffix in (".yaml", ".json"))


def test_run_without_env_credentials_fails_before_zap(tmp_path):
    called = []
    with pytest.raises(stage.StageError, match="TEST_USERNAME"):
        stage.run("full", tmp_path / "out", _auth_config(tmp_path), "zap@sha256:abc", runner=lambda cmd: called.append(cmd), project_dir=tmp_path)
    assert called == []
