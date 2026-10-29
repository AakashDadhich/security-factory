import copy
import json
from pathlib import Path

import pytest
import yaml

from factory import authorize, findings, gate, manifest, plan_comment, stage_matrix
from factory.stages import plan

REPO = Path(__file__).resolve().parent.parent
FAKE = REPO / "tests" / "fixtures" / "fake"
WORKFLOW = REPO / ".github" / "workflows" / "factory.yml"
STUB = REPO / "templates" / "project" / ".github" / "workflows" / "factory.yml"
CONFIG = """\
platform: web
asvs_level: {level}
web:
  port: 3000
  health_path: /health
  dockerfile: Dockerfile
"""
ISSUE = {"title": "Add a notes feature", "body": "Signed-in users can save private text notes."}
MODEL_STATUS_FUNCS = ("always()", "failure()", "cancelled()")


def canned() -> dict:
    return json.loads((FAKE / "plan.json").read_text())


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("FACTORY_MODEL_ADAPTER", "fake")
    monkeypatch.setenv("FACTORY_FAKE_RESPONSES", str(FAKE))
    (tmp_path / ".factory.yml").write_text(CONFIG.format(level="null"))
    issue = tmp_path / "issue.json"
    issue.write_text(json.dumps(ISSUE))
    return tmp_path


def run_plan(project, out_name="out"):
    out = project / out_name
    code = plan.main(["--issue-file", str(project / "issue.json"), "--config", str(project / ".factory.yml"),
                      "--out", str(out), "--workdir", str(project)])
    return code, out


def with_responses(tmp_path, monkeypatch, files: dict):
    responses = tmp_path / "responses"
    responses.mkdir()
    for name, value in files.items():
        text = value if isinstance(value, str) else json.dumps(value)
        (responses / name).write_text(text)
    monkeypatch.setenv("FACTORY_FAKE_RESPONSES", str(responses))


def test_fake_run_writes_valid_plan_and_empty_findings(project):
    code, out = run_plan(project)
    assert code == 0
    result = json.loads((out / "plan.json").read_text())
    assert not list(findings.validator("plan.schema.json").iter_errors(result))
    assert result["personal_data"] is True
    assert result["asvs_level"] == 2
    assert result["high_risk_features"] == ["F1"]
    assert findings.load(out / "findings.json") == []
    assert json.loads((out / "reply.json.meta.json").read_text())["attempts"] == 1


def test_reply_schema_leaves_derived_fields_to_the_factory():
    reply = plan.reply_schema(plan.plan_schema())
    for name in plan.DERIVED:
        assert name not in reply["properties"]
        assert name not in reply["required"]
    assert reply["additionalProperties"] is False
    assert set(plan.plan_schema()["required"]) - set(reply["required"]) == set(plan.DERIVED)


@pytest.mark.parametrize(("risk", "payments", "configured", "level"), [
    ("low", False, None, 2),
    ("medium", False, None, 2),
    ("high", False, None, 3),
    ("low", True, None, 3),
    ("high", True, 1, 1),
    ("low", False, 3, 3),
    ("high", False, 2, 2),
])
def test_asvs_level_rule(risk, payments, configured, level):
    reply = canned() | {"risk_rating": risk, "takes_payments": payments}
    assert plan.finalize(reply, configured)["asvs_level"] == level


def test_explicit_config_level_wins_in_a_full_run(project, tmp_path, monkeypatch):
    (project / ".factory.yml").write_text(CONFIG.format(level=1))
    with_responses(tmp_path, monkeypatch, {"plan.json": canned() | {"risk_rating": "high"}})
    code, out = run_plan(project)
    assert code == 0
    assert json.loads((out / "plan.json").read_text())["asvs_level"] == 1


def test_high_risk_raises_level_in_a_full_run(project, tmp_path, monkeypatch):
    with_responses(tmp_path, monkeypatch, {"plan.json": canned() | {"risk_rating": "high"}})
    code, out = run_plan(project)
    assert code == 0
    assert json.loads((out / "plan.json").read_text())["asvs_level"] == 3


@pytest.mark.parametrize(("stores", "classes", "expected"), [
    (True, ["public"], True),
    (False, ["personal"], True),
    (False, ["internal", "sensitive"], True),
    (False, ["credentials", "payment", "public"], False),
    (False, [], False),
])
def test_personal_data_flag(stores, classes, expected):
    reply = canned() | {
        "stores_personal_data": stores,
        "data_handled": [{"name": f"d{i}", "classification": c} for i, c in enumerate(classes)],
    }
    assert plan.finalize(reply, None)["personal_data"] is expected


def test_schema_invalid_reply_is_retried(project, tmp_path, monkeypatch):
    broken = canned()
    del broken["abuse_cases"]
    with_responses(tmp_path, monkeypatch, {"plan.1.json": broken, "plan.2.json": canned()})
    code, out = run_plan(project)
    assert code == 0
    meta = json.loads((out / "reply.json.meta.json").read_text())
    assert meta["attempts"] == 2 and meta["valid"] is True
    assert (out / "plan.json").exists()


def test_model_cannot_set_derived_fields(project, tmp_path, monkeypatch):
    with_responses(tmp_path, monkeypatch, {"plan.1.json": canned() | {"asvs_level": 1}, "plan.2.json": canned()})
    code, out = run_plan(project)
    assert code == 0
    assert json.loads((out / "reply.json.meta.json").read_text())["attempts"] == 2
    assert json.loads((out / "plan.json").read_text())["asvs_level"] == 2


def test_reply_invalid_twice_fails_without_plan(project, tmp_path, monkeypatch):
    with_responses(tmp_path, monkeypatch, {"plan.json": "not json"})
    code, out = run_plan(project)
    assert code == 2
    assert not (out / "plan.json").exists()
    assert not (out / "findings.json").exists()
    assert (out / "reply.json.rejected.txt").exists()


def test_abuse_cases_must_cover_known_features(project, tmp_path, monkeypatch, capsys):
    reply = canned()
    reply["abuse_cases"] = [reply["abuse_cases"][0] | {"feature_id": "F9"}]
    with_responses(tmp_path, monkeypatch, {"plan.json": reply})
    code, out = run_plan(project)
    assert code == plan.EXIT_INCONSISTENT
    err = capsys.readouterr().err
    assert "unknown features: F9" in err
    assert "without an abuse case: F1, F2" in err
    assert not (out / "plan.json").exists()


def test_duplicate_ids_are_rejected():
    reply = canned()
    reply["requirements"].append(copy.deepcopy(reply["requirements"][0]))
    assert plan.consistency_errors(plan.finalize(reply, None)) == ["duplicate requirements ids: R1"]


@pytest.mark.parametrize("issue", [{"title": "x"}, ["x"], {"title": " ", "body": ""}])
def test_bad_issue_file_fails_before_the_model(project, monkeypatch, issue):
    monkeypatch.setenv("FACTORY_FAKE_RESPONSES", str(project / "nowhere"))
    (project / "issue.json").write_text(json.dumps(issue))
    code, out = run_plan(project)
    assert code == 1
    assert not (out / "reply.json.meta.json").exists()


def test_missing_canned_reply_is_an_adapter_error(project, monkeypatch):
    monkeypatch.setenv("FACTORY_FAKE_RESPONSES", str(project / "nowhere"))
    code, _ = run_plan(project)
    assert code == 1


@pytest.mark.parametrize(("mode", "actor", "allowed", "ok"), [
    ("spec", "AakashDadhich", "AakashDadhich", True),
    ("change", "aakashdadhich", " someone , AakashDadhich ", True),
    ("spec", "mallory", "AakashDadhich", False),
    ("spec", "", "AakashDadhich", False),
    ("spec", "AakashDadhich", "", False),
    ("spec", "Aakash", "AakashDadhich", False),
    ("check", "mallory", "", True),
    ("fix", "mallory", "", True),
])
def test_authorize(mode, actor, allowed, ok):
    assert authorize.authorized(mode, actor, allowed) is ok
    assert authorize.main(["--mode", mode, "--actor", actor, "--allowed", allowed]) == (0 if ok else 1)


def test_mocked_unauthorized_issues_event_is_refused(tmp_path, capsys):
    event = {"action": "labeled", "label": {"name": "factory:spec"}, "sender": {"login": "mallory"}, "issue": {"number": 7}}
    path = tmp_path / "event.json"
    path.write_text(json.dumps(event))
    loaded = json.loads(path.read_text())
    assert authorize.main(["--mode", "spec", "--actor", loaded["sender"]["login"], "--allowed", "AakashDadhich"]) == 1
    assert "mallory is not in FACTORY_ALLOWED_ACTORS" in capsys.readouterr().err


def workflow_jobs() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]


def needs_of(job: dict) -> list[str]:
    needs = job.get("needs", [])
    return [needs] if isinstance(needs, str) else list(needs)


def ancestors(jobs: dict, name: str) -> set[str]:
    seen: set[str] = set()
    stack = needs_of(jobs[name])
    while stack:
        n = stack.pop()
        if n not in seen:
            seen.add(n)
            stack += needs_of(jobs[n])
    return seen


def calls_model(job: dict) -> bool:
    runs = " ".join(str(step.get("run", "")) for step in job.get("steps", []))
    return any(marker in runs for marker in ("factory.adapter", "factory.stages.plan", "install claude-code"))


def test_model_jobs_are_skipped_when_authorize_fails():
    jobs = workflow_jobs()
    model_jobs = [n for n, j in jobs.items() if calls_model(j)]
    assert {"plan", "hello-ai"} <= set(model_jobs)
    for name in model_jobs:
        chain = ancestors(jobs, name)
        assert "authorize" in chain, name
        for link in ({name} | chain) - {"authorize"}:
            condition = str(jobs[link].get("if", ""))
            assert not any(f in condition for f in MODEL_STATUS_FUNCS), f"{link} would run after a failed authorize"


def test_authorize_is_first_and_reads_event_text_through_env():
    jobs = workflow_jobs()
    auth = jobs["authorize"]
    assert "needs" not in auth
    assert jobs["setup"]["needs"] == "authorize"
    step = auth["steps"][-1]
    assert "${{" not in step["run"]
    assert step["env"]["SENDER"] == "${{ github.event.sender.login }}"
    assert step["env"]["ALLOWED"] == "${{ vars.FACTORY_ALLOWED_ACTORS }}"
    assert "needs.authorize.result == 'success'" in jobs["gate"]["if"]
    assert "authorize" in jobs["gate"]["needs"] and "plan" in jobs["gate"]["needs"]


def test_plan_jobs_have_least_privilege():
    jobs = workflow_jobs()
    assert jobs["plan"]["permissions"] == {"contents": "read", "issues": "read"}
    assert jobs["plan-comment"]["permissions"] == {"contents": "read", "issues": "write"}
    assert not calls_model(jobs["plan-comment"])
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in json.dumps(jobs["plan-comment"])
    for job in jobs.values():
        for step in job.get("steps", []):
            assert "${{" not in str(step.get("run", ""))


def test_stub_maps_labels_to_modes():
    stub = yaml.safe_load(STUB.read_text())
    triggers = stub[True]
    assert triggers["issues"] == {"types": ["labeled"]}
    job = stub["jobs"]["factory"]
    assert "factory:spec" in job["if"] and "factory:change" in job["if"]
    assert job["permissions"]["issues"] == "write"
    mode = job["with"]["mode"]
    assert "'factory:spec' && 'spec'" in mode and "'change'" in mode and "'check'" in mode
    assert "github.event.issue.number" in job["with"]["issue"]


def test_plan_is_a_spec_and_change_stage_only():
    for mode, present in (("spec", True), ("change", True), ("check", False), ("fix", False)):
        assert ("plan" in [s.name for s in stage_matrix.expected("web", mode)]) is present


def test_manifest_records_the_issue():
    cfg = {"platform": "web", "web": {"port": 3000, "health_path": "/health", "dockerfile": "Dockerfile"}}
    env = {"GITHUB_RUN_ID": "1", "GITHUB_REPOSITORY": "o/r", "GITHUB_SHA": "a" * 40}
    assert manifest.create(cfg, mode="spec", factory_ref="main", stages=[], env=env, issue=7)["issue"] == 7
    assert manifest.create(cfg, mode="check", factory_ref="main", stages=[], env=env, issue=0)["issue"] is None


def test_gate_ignores_authorize_and_fails_when_plan_is_skipped_in_spec_mode():
    rows = gate.stage_rows(stage_matrix.expected("web", "spec"), {"authorize": {"result": "success"}, "plan": {"result": "skipped"}}, {}, {})
    by_name = {r["stage"]: r for r in rows}
    assert "authorize" not in by_name
    assert by_name["plan"]["status"] == "missing"
    rows = gate.stage_rows(stage_matrix.expected("web", "check"), {"plan": {"result": "skipped"}}, {}, {})
    assert {r["stage"]: r for r in rows}["plan"]["status"] == "skipped"


def test_comment_renders_plan_deterministically():
    result = plan.finalize(canned(), None)
    text = plan_comment.render(result, "https://github.com/o/r/actions/runs/1")
    assert text == plan_comment.render(result, "https://github.com/o/r/actions/runs/1")
    assert text.startswith(plan_comment.MARKER)
    assert "| medium | 2 | yes | no |" in text
    assert "**F1** Sign in (risk high, high risk)" in text
    assert "### Abuse cases" in text and "### Open questions" in text
    assert "[this run](https://github.com/o/r/actions/runs/1)" in text


def test_comment_neutralises_model_text():
    reply = canned() | {"summary": "Hi @owner see https://evil.example/x and www.evil.example <img src=x> [l](u) # h"}
    text = plan_comment.render(plan.finalize(reply, None))
    summary = text.splitlines()[3]
    assert "@owner" not in summary and "@​owner" in summary
    assert "https://" not in summary and "www.evil" not in summary
    assert "<img" not in summary and "\\<img" in summary
    assert "\\[l\\]\\(u\\)" in summary and "\\#" in summary


def test_comment_truncates_long_text_and_long_lists():
    reply = canned()
    reply["out_of_scope"] = [f"item {i}" for i in range(20)]
    reply["open_questions"] = ["x" * 1500]
    text = plan_comment.render(plan.finalize(reply, None))
    assert "...and 5 more in `plan.json`" in text
    question = next(line for line in text.splitlines() if line.startswith("- xxx"))
    assert len(question) <= plan_comment.TEXT_LIMIT + 2


def test_comment_main_rejects_invalid_plan_and_bad_url(tmp_path):
    good = tmp_path / "plan.json"
    good.write_text(json.dumps(plan.finalize(canned(), None)))
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(canned()))
    out = tmp_path / "comment.md"
    assert plan_comment.main(["--plan", str(bad), "--out", str(out)]) == 1
    assert plan_comment.main(["--plan", str(good), "--out", str(out), "--run-url", "https://evil.example/x"]) == 1
    assert plan_comment.main(["--plan", str(good), "--out", str(out), "--run-url", "https://github.com/o/r/actions/runs/1"]) == 0
    assert out.read_text().startswith(plan_comment.MARKER)
