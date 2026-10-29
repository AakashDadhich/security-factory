import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from factory import findings, manifest, stage_matrix, tools
from factory.stages import plan, threat_model
from factory.threatmodel import pytm_runner
from factory.threatmodel.pytm_runner import ModelRejected

REPO = Path(__file__).resolve().parent.parent
FAKE = REPO / "tests" / "fixtures" / "fake"
TM_FIXTURES = REPO / "tests" / "fixtures" / "threat-model"
WORKFLOW = REPO / ".github" / "workflows" / "factory.yml"
GOOD_TM = (TM_FIXTURES / "tm_notes.py").read_text()
IMPORT_OS_TM = (TM_FIXTURES / "tm_import_os.py").read_text()
EXPECTED_NAMES = {"Internet", "Server", "User", "Web app", "Notes DB", "Sign-in request", "Create note request",
                  "Store note", "Read notes", "Notes response"}


def stride_reply() -> dict:
    return json.loads((FAKE / "threat-model-stride.json").read_text())


@pytest.fixture
def fake_pytm(tmp_path) -> Path:
    wrapper = tmp_path / "fake-python"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{TM_FIXTURES / "fake_pytm.py"}" "$@"\n')
    wrapper.chmod(0o755)
    return wrapper


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("FACTORY_MODEL_ADAPTER", "fake")
    monkeypatch.setenv("FACTORY_FAKE_RESPONSES", str(FAKE))
    root = tmp_path / "project"
    root.mkdir()
    plan_reply = json.loads((FAKE / "plan.json").read_text())
    stride_only = plan.finalize(plan_reply, None) | {"personal_data": False, "high_risk_features": []}
    (root / "plan.json").write_text(json.dumps(stride_only))
    return root


def responses(tmp_path, monkeypatch, files: dict) -> None:
    folder = tmp_path / "responses"
    folder.mkdir(exist_ok=True)
    for name, value in files.items():
        (folder / name).write_text(json.dumps(value))
    monkeypatch.setenv("FACTORY_FAKE_RESPONSES", str(folder))


def run_stage(project, python, out_name="out", previous="security"):
    out = project / out_name
    code = threat_model.main([
        "--plan", str(project / "plan.json"), "--out", str(out), "--previous", str(project / previous),
        "--pytm-python", str(python), "--workdir", str(project), "--sandbox", "none",
    ])
    return code, out


def test_allowed_model_passes_ast_validation():
    assert pytm_runner.validate_source(GOOD_TM) == []


def test_import_os_is_rejected():
    errors = pytm_runner.validate_source(IMPORT_OS_TM)
    assert any("import of 'os' is not allowed" in e for e in errors)


@pytest.mark.parametrize(("snippet", "message"), [
    ("import subprocess", "import of 'subprocess'"),
    ("from os import path", "import from 'os'"),
    ("from . import x", "import from 'None'"),
    ("import pytm as p", "'import pytm as p'"),
    ("from pytm import *", "'from pytm import *'"),
    ("from pytm import load", "'from pytm import load'"),
    ("from pytm import tm as m\nm.os.system('id')", "'from pytm import tm'"),
    ("from pytm import Threat", "'from pytm import Threat'"),
    ("import pytm\npytm.tm.os.system('id')", "pytm may only be used as pytm.<class>"),
    ("import pytm\nmod = pytm", "pytm may only be used as pytm.<class>"),
    ("tm.process.os", "attribute 'os'"),
    ("x = tm._threats", "attribute '_threats'"),
    ("x = TM.process.__globals__", "attribute '__globals__'"),
    ("x = (y for y in ()).gi_frame.f_globals['__builtins__']", "attribute 'gi_frame'"),
    ("x = (y for y in ()).gi_frame.f_globals['__builtins__']", "only integer subscripts"),
    ("x = (y for y in ())", "GeneratorExp is not allowed"),
    ("x = [y for y in ()]", "ListComp is not allowed"),
    ("f = lambda: 1", "Lambda is not allowed"),
    ("def f():\n    pass", "FunctionDef is not allowed"),
    ("class C:\n    pass", "ClassDef is not allowed"),
    ("x = f'{tm}'", "JoinedStr is not allowed"),
    ("x = '{0}'.format(tm)", "attribute 'format'"),
    ("x = type(tm)", "'type' is not allowed"),
    ("data = open('/etc/passwd').read()", "'open' is not allowed"),
    ("exec('1')", "'exec' is not allowed"),
    ("eval('1')", "'eval' is not allowed"),
    ("__import__('os')", "'__import__' is not allowed"),
    ("getattr(tm, 'x')", "'getattr' is not allowed"),
    ("x = ().__class__.__base__", "attribute '__class__'"),
    ("__builtins__", "'__builtins__' is not allowed"),
    ("import sys\nsys.argv += ['--report', '/etc/passwd']", "import of 'sys' is not allowed"),
    ("tm.process.argv", "attribute 'argv'"),
    ("tm.threatsFile = '/etc/passwd'", "attribute 'threatsFile'"),
    ("TM('x', threatsFile='/etc/passwd')", "keyword 'threatsFile'"),
    ("TM('x', **{'threatsFile': '/etc/passwd'})", "** unpacking"),
    ("Server('Worker', **extra)", "** unpacking"),
    ("Server('Worker', condition='True')", "keyword 'condition'"),
    ("Server('Worker', anything=1)", "keyword 'anything'"),
    ("print(tm.report('/etc/passwd'))", "attribute 'report'"),
    ("def broken(:\n    pass", "syntax error"),
])
def test_ast_rejects_unsafe_code(snippet, message):
    errors = pytm_runner.validate_source(GOOD_TM + "\n" + snippet + "\n")
    assert any(message in e for e in errors), errors


def test_pytm_classes_can_be_used_through_the_module():
    source = (GOOD_TM + "\nimport pytm\nextra = pytm.Server('Worker', inBoundary=server_zone)\n"
              "extra.controls.isHardened = True\ndb.type = pytm.DatastoreType.SQL\nfirst = [web, db][0]\n")
    assert pytm_runner.validate_source(source) == []


def test_model_must_declare_boundaries_flows_and_process_call():
    errors = pytm_runner.validate_source("from pytm import TM, Actor\ntm = TM('x')\nActor('User')\n")
    text = "\n".join(errors)
    for name in ("Boundary", "Datastore", "Dataflow", "Server, Process", "tm.process()"):
        assert name in text


def test_check_and_run_writes_outputs_after_ast_passes(tmp_path, fake_pytm, capsys):
    out = tmp_path / "out"
    out.mkdir()
    model = pytm_runner.check_and_run(GOOD_TM, out, fake_pytm)
    assert (out / "tm.py").read_text() == GOOD_TM
    assert (out / "dfd.dot").read_text().startswith("digraph")
    assert set(pytm_runner.element_names(model)) == EXPECTED_NAMES
    assert json.loads((out / "elements.json").read_text()) == model
    log = capsys.readouterr().out
    assert log.index("AST validation passed") < log.index("running pytm")


def test_rejected_source_is_never_executed(tmp_path, fake_pytm, monkeypatch):
    calls = []
    monkeypatch.setattr(pytm_runner, "execute", lambda *a, **k: calls.append(a))
    with pytest.raises(ModelRejected, match="AST validation failed"):
        pytm_runner.check_and_run(IMPORT_OS_TM, tmp_path, fake_pytm)
    assert calls == []
    assert not (tmp_path / "tm.py").exists()


def test_pytm_runs_without_secrets_in_env(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "sk-secret")
    monkeypatch.setenv("GITHUB_TOKEN", "ghs-secret")
    script = tmp_path / "tm.py"
    script.write_text("import os, json\nprint(json.dumps(sorted(os.environ)))\n")
    keys = json.loads(pytm_runner.execute(Path(sys.executable), script, [], 30))
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in keys and "GITHUB_TOKEN" not in keys
    assert set(keys) <= {"PATH", "LANG", "LC_ALL", "HOME", "LC_CTYPE", "__CF_USER_TEXT_ENCODING"}


def fake_venv(tmp_path) -> Path:
    site = tmp_path / "venv" / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (tmp_path / "venv" / "bin").mkdir()
    return tmp_path / "venv" / "bin" / "python"


def test_sandbox_command_isolates_pytm(tmp_path):
    python = fake_venv(tmp_path)
    cmd = pytm_runner.sandbox_command("img@sha256:abc", python, pytm_runner.HARNESS, tmp_path, ["tm.py", "--dfd"], "n1")
    joined = " ".join(cmd)
    for flag in ("--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges", "--rm"):
        assert flag in joined
    assert f"{tmp_path.resolve()}:/work:rw" in cmd
    assert f"{tmp_path / 'venv' / 'lib' / 'python3.12' / 'site-packages'}:/usr/local/lib/python3.12/site-packages:ro" in cmd
    assert f"{pytm_runner.HARNESS}:/factory/pytm_harness.py:ro" in cmd
    assert cmd[-5:] == ["python", "-I", "/factory/pytm_harness.py", "tm.py", "--dfd"]
    assert cmd[cmd.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
    assert not any(a.startswith("-e") and "TOKEN" in a for a in cmd)
    assert [cmd[i + 1] for i, a in enumerate(cmd) if a == "-e"] == ["HOME=/work"]


def test_sandbox_needs_exactly_one_site_packages(tmp_path):
    python = fake_venv(tmp_path)
    (tmp_path / "venv" / "lib" / "python3.13" / "site-packages").mkdir(parents=True)
    with pytest.raises(pytm_runner.RunnerError, match="found 2"):
        pytm_runner.site_packages(python)


def test_sandbox_is_the_default_and_pinned_by_digest():
    image = pytm_runner.sandbox_image("docker")
    assert image.startswith("docker.io/library/python@sha256:")
    assert pytm_runner.sandbox_image("none") is None
    for module in (pytm_runner, threat_model):
        parser_text = Path(module.__file__).read_text()
        assert 'choices=("docker", "none"), default="docker"' in parser_text


def test_sandbox_timeout_removes_the_container(tmp_path, monkeypatch):
    python = fake_venv(tmp_path)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(cmd, 1)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(pytm_runner.subprocess, "run", fake_run)
    with pytest.raises(ModelRejected, match="timed out"):
        pytm_runner.execute(python, pytm_runner.HARNESS, ["tm.py"], 1, tmp_path, "img@sha256:abc")
    name = calls[0][calls[0].index("--name") + 1]
    assert calls[1] == ["docker", "rm", "-f", name]


def test_pytm_timeout_is_a_model_error(tmp_path):
    script = tmp_path / "tm.py"
    script.write_text("import time\ntime.sleep(10)\n")
    with pytest.raises(ModelRejected, match="timed out after 1 s"):
        pytm_runner.execute(Path(sys.executable), script, [], 1)


@pytest.mark.parametrize(("change", "message"), [
    (lambda raw: raw["flows"][0].update(sink="Ghost"), "sink 'Ghost', which is not an element"),
    (lambda raw: raw["flows"][0].update(name="User"), "names must be unique"),
    (lambda raw: raw.update(boundaries=[]), "no boundaries"),
])
def test_incomplete_pytm_output_is_rejected(change, message):
    raw = json.loads((TM_FIXTURES / "pytm.json").read_text())
    change(raw)
    with pytest.raises(ModelRejected, match=message):
        pytm_runner.normalise(raw)


def test_ast_error_is_fed_back_once(project, tmp_path, monkeypatch, fake_pytm):
    responses(tmp_path, monkeypatch, {
        "threat-model-pytm.json": {"tm_py": IMPORT_OS_TM},
        "threat-model-pytm-retry.json": {"tm_py": GOOD_TM},
        "threat-model-stride.json": stride_reply(),
    })
    code, out = run_stage(project, fake_pytm)
    assert code == 0
    assert "import of 'os' is not allowed" in (out / "error.txt").read_text()
    assert (out / "tm.rejected.py").read_text() == IMPORT_OS_TM
    assert (out / "tm.py").read_text() == GOOD_TM


def test_run_error_is_fed_back_once(project, tmp_path, monkeypatch, fake_pytm):
    responses(tmp_path, monkeypatch, {
        "threat-model-pytm.json": {"tm_py": GOOD_TM + "\n# FAKE_PYTM_FAIL\n"},
        "threat-model-pytm-retry.json": {"tm_py": GOOD_TM},
        "threat-model-stride.json": stride_reply(),
    })
    code, out = run_stage(project, fake_pytm)
    assert code == 0
    assert "exited 1" in (out / "error.txt").read_text()


def test_second_rejection_fails_the_stage(project, tmp_path, monkeypatch, fake_pytm):
    responses(tmp_path, monkeypatch, {
        "threat-model-pytm.json": {"tm_py": IMPORT_OS_TM},
        "threat-model-pytm-retry.json": {"tm_py": GOOD_TM + "\n# FAKE_PYTM_FAIL\n"},
    })
    code, out = run_stage(project, fake_pytm)
    assert code == pytm_runner.EXIT_REJECTED
    assert not (out / "tm.py").exists()
    assert not (out / "threats.json").exists()


def test_missing_pytm_interpreter_is_an_error(project, tmp_path):
    code, _ = run_stage(project, tmp_path / "no-python")
    assert code == 1


def test_full_run_writes_valid_threats_and_info_findings(project, fake_pytm):
    code, out = run_stage(project, fake_pytm)
    assert code == 0
    for name in ("tm.py", "dfd.dot", "elements.json", "threats.json", "findings.json"):
        assert (out / name).is_file(), name
    doc = json.loads((out / "threats.json").read_text())
    assert not list(findings.validator("threats.schema.json").iter_errors(doc))
    assert doc["model_version"] == hashlib.sha256((out / "tm.py").read_bytes()).hexdigest()
    assert [t["id"] for t in doc["threats"]] == ["TM-001", "TM-002", "TM-003", "TM-004"]
    assert {"spoofing", "tampering", "information-disclosure"} <= {t["category"] for t in doc["threats"]}
    for threat in doc["threats"]:
        assert threat["framework"] == "stride"
        assert threat["mitigations"] and all(m["asvs_refs"] for m in threat["mitigations"])
    assert doc["threats"][0]["severity"] == "critical"
    assert doc["threats"][0]["mitigations"][1]["id"] == "TM-001-M2"

    emitted = findings.load(out / "findings.json")
    assert len(emitted) == 4
    assert {f["severity"] for f in emitted} == {"info"}
    assert {f["source"] for f in emitted} == {"ai-threat-model"}
    assert [f["rule_id"] for f in emitted] == ["TM-001", "TM-002", "TM-003", "TM-004"]
    assert emitted[0]["title"] == "Spoofing: Credential stuffing against sign-in"
    assert "V6.3.1" in emitted[0]["remediation"]


def test_stable_ids_across_an_update(project, tmp_path, monkeypatch, fake_pytm):
    code, first = run_stage(project, fake_pytm, "first")
    assert code == 0
    security = project / "security"
    security.mkdir()
    shutil.copy(first / "tm.py", security / "tm.py")
    shutil.copy(first / "threats.json", security / "threats.json")

    old = stride_reply()["threats"]
    kept_by_id = old[2] | {"previous_id": "TM-003", "title": "Another user's notes returned"}
    kept_by_title = old[1] | {"title": "  note CREATED for another user "}
    new = {"previous_id": None, "category": "denial-of-service", "element": "Notes DB", "title": "Notes table filled",
           "description": "A user creates notes until the disk is full.", "likelihood": "medium", "impact": "medium",
           "mitigations": [{"text": "Cap notes per user.", "asvs_refs": ["V2.4.1"]}], "status": "open"}
    reused_wrong_element = old[0] | {"previous_id": "TM-001", "element": "Web app"}
    responses(tmp_path, monkeypatch, {
        "threat-model-pytm.json": {"tm_py": GOOD_TM},
        "threat-model-stride.json": {"threats": [kept_by_id, new, kept_by_title, reused_wrong_element]},
    })
    code, second = run_stage(project, fake_pytm, "second")
    assert code == 0
    doc = json.loads((second / "threats.json").read_text())
    assert [t["id"] for t in doc["threats"]] == ["TM-003", "TM-005", "TM-002", "TM-006"]
    assert doc["threats"][0]["title"] == "Another user's notes returned"
    assert sorted(t["id"] for t in doc["removed"]) == ["TM-001", "TM-004"]
    assert [f["rule_id"] for f in findings.load(second / "findings.json")] == ["TM-003", "TM-005", "TM-002", "TM-006"]
    first_fp = {f["rule_id"]: f["fingerprint"] for f in findings.load(first / "findings.json")}
    second_fp = {f["rule_id"]: f["fingerprint"] for f in findings.load(second / "findings.json")}
    assert first_fp["TM-003"] == second_fp["TM-003"]


def test_removed_ids_are_never_reused():
    previous = threat_model.merge(stride_reply()["threats"], None, "0" * 64)
    after_drop = threat_model.merge(stride_reply()["threats"][:1], previous, "0" * 64)
    after_new = threat_model.merge(stride_reply()["threats"][:1] + [stride_reply()["threats"][3] | {"title": "New"}],
                                   after_drop, "0" * 64)
    assert [t["id"] for t in after_new["threats"]] == ["TM-001", "TM-005"]
    assert [t["id"] for t in after_new["removed"]] == ["TM-002", "TM-003", "TM-004"]


def test_other_frameworks_are_carried_over():
    other = {"id": "TM-009", "framework": "linddun", "category": "linking", "element": "Notes DB", "title": "Link notes",
             "description": "d", "likelihood": "low", "impact": "low", "severity": "low",
             "mitigations": [{"id": "TM-009-M1", "text": "t", "asvs_refs": ["V14.1.1"]}], "status": "open"}
    doc = threat_model.merge(stride_reply()["threats"][:1], {"threats": [other], "removed": []}, "0" * 64)
    assert doc["threats"][0] == other
    assert doc["threats"][1]["id"] == "TM-010"


def test_mitigated_threats_are_not_findings_and_need_evidence():
    reply = stride_reply()
    reply["threats"][0]["status"] = "mitigated"
    schema = threat_model.stride_reply_schema(sorted(EXPECTED_NAMES), threat_model.asvs_ids())
    validator = Draft202012Validator(schema)
    assert any("evidence" in e.message for e in validator.iter_errors(reply))
    reply["threats"][0]["evidence"] = "src/auth.ts"
    assert not list(validator.iter_errors(reply))
    doc = threat_model.merge(reply["threats"], None, "0" * 64)
    assert [f["rule_id"] for f in threat_model.threat_findings(doc)] == ["TM-002", "TM-003", "TM-004"]


def test_reply_schema_pins_elements_and_asvs_ids():
    schema = threat_model.stride_reply_schema(sorted(EXPECTED_NAMES), threat_model.asvs_ids())
    validator = Draft202012Validator(schema)
    assert not list(validator.iter_errors(stride_reply()))
    for change in ({"element": "Ghost"}, {"category": "phishing"}, {"severity": "high"}, {"id": "TM-1"},
                   {"mitigations": [{"text": "t", "asvs_refs": ["V99.9.9"]}]}, {"mitigations": [{"text": "t", "asvs_refs": []}]},
                   {"title": "# Heading"}, {"title": "x" * 401}, {"mitigations": [{"text": "- bullet", "asvs_refs": ["V8.2.2"]}]},
                   {"mitigations": [{"text": "1. step", "asvs_refs": ["V8.2.2"]}]},
                   {"mitigations": [{"text": "Use <!-- hidden -->", "asvs_refs": ["V8.2.2"]}]}):
        bad = stride_reply()
        bad["threats"][0] |= change
        assert list(validator.iter_errors(bad)), change


@pytest.mark.parametrize(("likelihood", "impact", "severity"), [
    ("high", "high", "critical"), ("high", "medium", "high"), ("medium", "high", "high"), ("medium", "medium", "medium"),
    ("high", "low", "medium"), ("medium", "low", "low"), ("low", "low", "low"),
])
def test_severity_matrix(likelihood, impact, severity):
    assert threat_model.severity(likelihood, impact) == severity


def test_invalid_previous_threats_fail_the_stage(project, fake_pytm):
    security = project / "security"
    security.mkdir()
    (security / "threats.json").write_text(json.dumps({"threats": []}))
    code, _ = run_stage(project, fake_pytm)
    assert code == 1


def test_threats_feed_the_rules_renderer(project, fake_pytm):
    from factory import rules
    code, out = run_stage(project, fake_pytm)
    assert code == 0
    loaded = rules.load_threats(out / "threats.json")
    assert len(loaded) == 4


def workflow_jobs() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]


def test_threat_model_job_is_wired_with_least_privilege():
    jobs = workflow_jobs()
    job = jobs["threat-model"]
    assert set(job["needs"]) >= {"plan"}
    assert job["permissions"] == {"contents": "read"}
    text = json.dumps(job)
    assert "FACTORY_APP_PRIVATE_KEY" not in text and "create-github-app-token" not in text
    assert "python -m factory.tools install claude-code pytm pytm-sandbox" in text
    assert "--sandbox none" not in text
    assert "threat-model" in jobs["gate"]["needs"]
    setup_steps = json.dumps(jobs["setup"]["steps"])
    assert "--stage threat-model" in setup_steps


def test_threat_model_is_not_a_fix_mode_stage():
    for mode in stage_matrix.MODES:
        names = [s.name for s in stage_matrix.expected("web", mode)]
        assert ("threat-model" in names) == (mode in ("spec", "change", "check"))


def test_real_pytm_tool_resolves_to_its_venv():
    assert tools.load_lock()["pytm"].kind == "venv"
    assert tools.venv_python("pytm") == Path.home() / ".factory" / "venvs" / "pytm" / "bin" / "python"


def test_integration_real_pytm_runs_the_fixture_model(tmp_path):
    python = tools.venv_python("pytm")
    if not python.is_file():
        if os.environ.get("FACTORY_REQUIRE_PYTM"):
            pytest.fail(f"pytm is required but {python} is missing")
        pytest.skip("pytm venv not installed")
    model = pytm_runner.check_and_run(GOOD_TM, tmp_path, python)
    assert set(pytm_runner.element_names(model)) == EXPECTED_NAMES
    types = {e["name"]: e["type"] for e in model["elements"]}
    assert types == {"User": "Actor", "Web app": "Server", "Notes DB": "Datastore"}
    flows = {f["name"]: (f["source"], f["sink"]) for f in model["flows"]}
    assert flows["Store note"] == ("Web app", "Notes DB")
    assert "Note text" in next(f for f in model["flows"] if f["name"] == "Create note request")["data"]
    assert "digraph" in (tmp_path / "dfd.dot").read_text()
    print(json.dumps(model, indent=2))


def test_integration_harness_resets_a_custom_threats_file(tmp_path):
    python = tools.venv_python("pytm")
    if not python.is_file():
        if os.environ.get("FACTORY_REQUIRE_PYTM"):
            pytest.fail(f"pytm is required but {python} is missing")
        pytest.skip("pytm venv not installed")
    bundled = subprocess.run(
        [str(python), "-I", "-c", "import os, pytm; print(os.path.join(os.path.dirname(pytm.__file__), 'threatlib', 'threats.json'))"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    threats = json.loads(Path(bundled).read_text())
    threats.append(threats[0] | {"SID": "FACTORYTEST", "target": ["Server"], "condition": "True"})
    custom = tmp_path / "custom-threats.json"
    custom.write_text(json.dumps(threats))
    model = tmp_path / "tm.py"
    model.write_text(GOOD_TM.replace('tm.isOrdered = True', f'tm.isOrdered = True\ntm.threatsFile = "{custom}"'))
    raw = tmp_path / "pytm.json"
    pytm_runner.execute(python, pytm_runner.HARNESS, [str(model), "--json", str(raw)], 60, tmp_path)
    found = {f.get("threat_id") for f in json.loads(raw.read_text())["findings"]}
    assert found and "FACTORYTEST" not in found


def require_sandbox():
    python = tools.venv_python("pytm")
    ready = python.is_file() and shutil.which("docker")
    if not ready:
        if os.environ.get("FACTORY_REQUIRE_PYTM"):
            pytest.fail(f"pytm and docker are required ({python}, docker on PATH: {bool(shutil.which('docker'))})")
        pytest.skip("pytm venv or docker not available")
    return python, pytm_runner.sandbox_image("docker")


def test_integration_sandboxed_pytm_runs_the_fixture_model(tmp_path):
    python, image = require_sandbox()
    model = pytm_runner.check_and_run(GOOD_TM, tmp_path, python, image=image)
    assert set(pytm_runner.element_names(model)) == EXPECTED_NAMES
    assert "digraph" in (tmp_path / "dfd.dot").read_text()


def test_integration_sandbox_has_no_network_processes_or_tokens(tmp_path, monkeypatch):
    python, image = require_sandbox()
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "sk-secret")
    probe = tmp_path / "probe.py"
    probe.write_text(
        "import json, os, socket\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 53), timeout=3)\n"
        "    net = True\n"
        "except OSError:\n"
        "    net = False\n"
        "pids = [p for p in os.listdir('/proc') if p.isdigit()]\n"
        "try:\n"
        "    open('/usr/local/lib/probe-write', 'w')\n"
        "    writable = True\n"
        "except OSError:\n"
        "    writable = False\n"
        "print(json.dumps({'net': net, 'pids': len(pids), 'uid': os.getuid(), 'env': sorted(os.environ),\n"
        "                  'writable': writable, 'pytm': __import__('pytm').__name__}))\n"
    )
    seen = json.loads(pytm_runner.execute(python, probe, [], 60, tmp_path, image))
    print(seen)
    assert seen["net"] is False
    assert seen["pids"] <= 3
    assert seen["uid"] != 0
    assert seen["writable"] is False
    assert seen["pytm"] == "pytm"
    assert not any("TOKEN" in k for k in seen["env"])
