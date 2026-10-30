import copy
import json
import shutil
import sys
from pathlib import Path

import pytest
import yaml

from factory import fixloop, plan_comment, sbomnote, stage_matrix
from factory.stages import plan, threat_model
from factory.threatmodel import diff as threat_diff

REPO = Path(__file__).resolve().parent.parent
FAKE = REPO / "tests" / "fixtures" / "fake"
TM_FIXTURES = REPO / "tests" / "fixtures" / "threat-model"
WORKFLOW = REPO / ".github" / "workflows" / "factory.yml"
CONFIG = """\
platform: web
asvs_level: {level}
web:
  port: 3000
  health_path: /health
  dockerfile: Dockerfile
"""
ISSUE = {"title": "Rate-limit the notes endpoints", "body": "Limit how often one user can call the notes API."}


def canned() -> dict:
    return json.loads((FAKE / "plan.json").read_text())


def current_plan(level: int = 2) -> dict:
    return plan.finalize(canned(), None) | {"asvs_level": level}


def change_reply(**overrides) -> dict:
    reply = canned()
    reply.update({"changed_features": ["F2"], "touched_elements": ["Web app"]})
    reply.update(overrides)
    return reply


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("FACTORY_MODEL_ADAPTER", "fake")
    root = tmp_path / "project"
    (root / "security").mkdir(parents=True)
    (root / ".factory.yml").write_text(CONFIG.format(level="null"))
    (root / "issue.json").write_text(json.dumps(ISSUE))
    (root / "security" / "plan.json").write_text(json.dumps(current_plan()))
    return root


def set_reply(tmp_path, monkeypatch, reply: dict) -> None:
    responses = tmp_path / "responses"
    responses.mkdir(exist_ok=True)
    (responses / "plan.json").write_text(json.dumps(reply))
    monkeypatch.setenv("FACTORY_FAKE_RESPONSES", str(responses))


def run_change(project, tmp_path, monkeypatch, reply=None, record=None, current=None):
    set_reply(tmp_path, monkeypatch, reply or change_reply())
    out = project / "out"
    args = ["--issue-file", str(project / "issue.json"), "--config", str(project / ".factory.yml"),
            "--out", str(out), "--workdir", str(project),
            "--current-plan", str(current or project / "security" / "plan.json")]
    if record is not None:
        args += ["--record", str(record)]
    return plan.main(args), out


def result(out: Path) -> dict:
    return json.loads((out / "plan.json").read_text())


def test_change_run_writes_a_plan_with_change_fields(project, tmp_path, monkeypatch):
    code, out = run_change(project, tmp_path, monkeypatch)
    assert code == 0
    updated = result(out)
    assert updated["changed_features"] == ["F2"]
    assert updated["touched_elements"] == ["Web app"]
    assert [f["id"] for f in updated["features"]] == ["F1", "F2"]


@pytest.mark.parametrize(("configured", "previous", "expected"), [
    ("null", 3, 3),
    (1, 3, 3),
    (2, 3, 3),
    (3, 2, 3),
    ("null", 1, 2),
    ("null", 2, 2),
])
def test_asvs_level_never_decreases(project, tmp_path, monkeypatch, configured, previous, expected):
    (project / ".factory.yml").write_text(CONFIG.format(level=configured))
    (project / "security" / "plan.json").write_text(json.dumps(current_plan(previous)))
    code, out = run_change(project, tmp_path, monkeypatch)
    assert code == 0
    assert result(out)["asvs_level"] == expected


def test_a_riskier_change_can_raise_the_asvs_level(project, tmp_path, monkeypatch):
    reply = change_reply(takes_payments=True)
    code, out = run_change(project, tmp_path, monkeypatch, reply)
    assert code == 0
    assert result(out)["asvs_level"] == 3


def test_asvs_level_function_keeps_the_previous_level():
    base = canned()
    assert plan.asvs_level(base, None, 3) == 3
    assert plan.asvs_level(base, 1, 2) == 2
    assert plan.asvs_level(base, None, None) == 2


def test_dropping_an_existing_feature_is_refused(project, tmp_path, monkeypatch, capsys):
    reply = change_reply(changed_features=["F2"])
    reply["features"] = [f for f in reply["features"] if f["id"] != "F1"]
    reply["abuse_cases"] = [a for a in reply["abuse_cases"] if a["feature_id"] != "F1"]
    code, _ = run_change(project, tmp_path, monkeypatch, reply)
    assert code == plan.EXIT_INCONSISTENT
    assert "feature F1 was dropped" in capsys.readouterr().err


def test_dropping_an_existing_requirement_is_refused(project, tmp_path, monkeypatch, capsys):
    reply = change_reply()
    reply["requirements"] = [r for r in reply["requirements"] if r["id"] != "R2"]
    code, _ = run_change(project, tmp_path, monkeypatch, reply)
    assert code == plan.EXIT_INCONSISTENT
    assert "requirement R2 was dropped" in capsys.readouterr().err


def test_features_that_differ_are_listed_as_changed_even_if_not_declared(project, tmp_path, monkeypatch):
    reply = change_reply(changed_features=["F2"])
    reply["features"][0]["description"] = "Users sign in with a passkey."
    code, out = run_change(project, tmp_path, monkeypatch, reply)
    assert code == 0
    assert result(out)["changed_features"] == ["F1", "F2"]


def test_unchanged_features_keep_their_ids_and_text(project, tmp_path, monkeypatch):
    reply = change_reply()
    reply["features"].append({"id": "F3", "name": "Rate limit", "description": "Limit calls per user.", "risk": "low"})
    reply["abuse_cases"].append({"feature_id": "F3", "attacker_goal": "Flood the API.", "steps": "Send many requests.", "mitigation": "Per-user limit."})
    code, out = run_change(project, tmp_path, monkeypatch, reply)
    assert code == 0
    updated = result(out)
    before = {f["id"]: f for f in canned()["features"]}
    assert all(f == before[f["id"]] for f in updated["features"] if f["id"] in before)
    assert updated["changed_features"] == ["F2", "F3"]


def test_changed_features_naming_an_unknown_feature_is_refused(project, tmp_path, monkeypatch, capsys):
    code, _ = run_change(project, tmp_path, monkeypatch, change_reply(changed_features=["F9"]))
    assert code == plan.EXIT_INCONSISTENT
    assert "unknown features: F9" in capsys.readouterr().err


def test_a_change_without_touched_elements_is_rejected_by_the_reply_schema(project, tmp_path, monkeypatch):
    code, _ = run_change(project, tmp_path, monkeypatch, change_reply(touched_elements=[]))
    assert code != 0


def test_a_change_without_a_current_plan_fails(project, tmp_path, monkeypatch, capsys):
    code, _ = run_change(project, tmp_path, monkeypatch, current=project / "security" / "missing.json")
    assert code == 1
    assert "current plan" in capsys.readouterr().err


def test_record_flag_needs_a_current_plan(project):
    with pytest.raises(SystemExit):
        plan.main(["--issue-file", str(project / "issue.json"), "--record", str(project)])


def test_reply_schemas_differ_by_mode():
    schema = plan.plan_schema()
    spec = plan.reply_schema(schema)
    change = plan.reply_schema(schema, change=True)
    assert "changed_features" not in spec["properties"] and "touched_elements" not in spec["properties"]
    assert {"changed_features", "touched_elements"} <= set(change["required"])
    assert change["properties"]["touched_elements"]["minItems"] == 1


def test_spec_mode_stays_valid_without_the_change_fields():
    assert plan.finalize(canned(), None)
    assert "changed_features" not in plan.plan_schema()["required"]


def make_record(root: Path, failed: int = 5) -> Path:
    (root / "latest").mkdir(parents=True)
    (root / "runs").mkdir()
    (root / "latest" / "findings.json").write_text(json.dumps([
        {"rule_id": "js/sql-injection", "title": "SQL injection", "severity": "high", "stages": ["sast-codeql"],
         "location": {"path": "src/a.ts", "start_line": 3}, "description": "x" * 5000},
    ]))
    for n in range(failed):
        (root / "runs" / f"20261001T00000{n}Z-{100 + n}.json").write_text(json.dumps(
            {"run_id": str(100 + n), "mode": "check", "ref": "refs/heads/x", "status": "fail", "counts": {"high": n}, "iteration": 0, "issue": None}))
    (root / "runs" / "20261001T000099Z-999.json").write_text(json.dumps({"run_id": "999", "status": "pass", "mode": "check"}))
    return root


def test_record_context_keeps_the_last_three_failed_runs(tmp_path):
    context = plan.record_context(make_record(tmp_path / "record"))
    assert [r["run_id"] for r in context["failed_runs"]] == ["102", "103", "104"]
    assert all(r["status"] == "fail" for r in context["failed_runs"])
    finding = context["latest_findings"][0]
    assert finding["rule_id"] == "js/sql-injection" and "description" not in finding


@pytest.mark.parametrize("missing", [None, "absent"])
def test_record_context_without_a_record_is_empty(tmp_path, missing):
    folder = None if missing is None else tmp_path / missing
    assert plan.record_context(folder) == {"latest_findings": [], "failed_runs": []}


def test_record_context_ignores_broken_files(tmp_path):
    record = make_record(tmp_path / "record", failed=1)
    (record / "latest" / "findings.json").write_text("{not json")
    (record / "runs" / "20261001T000050Z-50.json").write_text("{not json")
    context = plan.record_context(record)
    assert context["latest_findings"] == []
    assert [r["run_id"] for r in context["failed_runs"]] == ["100"]


def test_record_inputs_reach_the_change_prompt(project, tmp_path, monkeypatch):
    record = make_record(tmp_path / "record")
    seen = {}
    real = plan.adapter.run_stage

    def spy(**kwargs):
        seen.update(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(plan.adapter, "run_stage", spy)
    code, out = run_change(project, tmp_path, monkeypatch, record=record)
    assert code == 0
    assert seen["prompt_path"] == plan.CHANGE_PROMPT
    assert [p.name for p in seen["inputs"]] == ["issue.json", "plan.json", "record.json"]
    passed = json.loads(seen["inputs"][2].read_text())
    assert [r["run_id"] for r in passed["failed_runs"]] == ["102", "103", "104"]
    assert passed["latest_findings"][0]["rule_id"] == "js/sql-injection"
    assert json.loads(seen["inputs"][1].read_text())["asvs_level"] == 2


def test_spec_mode_still_uses_the_plain_prompt_and_only_the_issue(project, tmp_path, monkeypatch):
    seen = {}
    real = plan.adapter.run_stage

    def spy(**kwargs):
        seen.update(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(plan.adapter, "run_stage", spy)
    set_reply(tmp_path, monkeypatch, canned())
    code = plan.main(["--issue-file", str(project / "issue.json"), "--config", str(project / ".factory.yml"),
                      "--out", str(project / "spec-out"), "--workdir", str(project)])
    assert code == 0
    assert seen["prompt_path"] == plan.PROMPT
    assert [p.name for p in seen["inputs"]] == ["issue.json"]


def test_change_prompt_names_every_input_and_output_field():
    text = plan.CHANGE_PROMPT.read_text()
    for needle in ("issue.json", "current-plan.json", "record.json", "latest_findings", "failed_runs",
                   "changed_features", "touched_elements"):
        assert needle in text
    assert "—" not in text


def test_plan_comment_shows_the_change(project):
    final = current_plan() | {"changed_features": ["F2"], "touched_elements": ["Web app"]}
    text = plan_comment.render(final)
    assert "**Changed features:** F2" in text
    assert "**Touched elements:** Web app" in text
    assert "Changed features" not in plan_comment.render(current_plan())


def expected_names(platform: str, mode: str) -> list[str]:
    return [s.name for s in stage_matrix.expected(platform, mode)]


@pytest.mark.parametrize("platform", stage_matrix.PLATFORMS)
def test_change_mode_expects_every_stage_that_spec_mode_expects(platform):
    assert expected_names(platform, "change") == expected_names(platform, "spec")


@pytest.mark.parametrize("platform", stage_matrix.PLATFORMS)
def test_change_mode_has_no_targeted_reruns(platform):
    change = set(expected_names(platform, "change"))
    check_and_fix = set(expected_names(platform, "check")) | set(expected_names(platform, "fix"))
    assert check_and_fix <= change
    for stage in stage_matrix.expected(platform, "change"):
        assert not stage.skippable


def jobs() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]


def needs(job: dict) -> set[str]:
    value = job.get("needs", [])
    return {value} if isinstance(value, str) else set(value)


def ancestors(name: str, all_jobs: dict) -> set[str]:
    seen, todo = set(), [name]
    while todo:
        for parent in needs(all_jobs[todo.pop()]):
            if parent not in seen:
                seen.add(parent)
                todo.append(parent)
    return seen


def test_change_mode_job_chain_runs_in_the_documented_order():
    j = jobs()
    chain = ["authorize", "plan", "threat-model", "codegen-ai", "codegen-commit", "review"]
    for earlier, later in zip(chain, chain[1:]):
        assert earlier in ancestors(later, j), f"{later} must run after {earlier}"
    scanners = [s.name for s in stage_matrix.expected("web", "change") if s.name not in chain]
    assert scanners
    for scanner in scanners:
        assert "review" in ancestors(scanner, j), f"{scanner} must wait for review"
        assert scanner in needs(j["gate"])
    assert "gate" in needs(j["next-step"]) and "gate" in needs(j["record"])


def test_every_expected_change_stage_is_a_workflow_job_the_gate_waits_for():
    j = jobs()
    for stage in stage_matrix.expected("web", "change"):
        assert stage.name in j
        assert stage.name in needs(j["gate"]) or stage.name in ancestors("gate", j)


def test_plan_job_reads_the_record_and_current_plan_in_change_mode():
    steps = {s["name"]: s for s in jobs()["plan"]["steps"] if "name" in s}
    assert steps["read the project record"]["if"] == "inputs.mode == 'change'"
    run = steps["plan stage"]["run"]
    assert "--current-plan security/plan.json" in run and "--record in/record" in run
    assert "FACTORY_APP_PRIVATE_KEY" not in json.dumps(jobs()["plan"])


def test_plan_job_has_no_write_permission():
    assert jobs()["plan"]["permissions"] == {"contents": "read", "issues": "read"}


def test_next_step_adds_the_threat_diff_to_the_pass_comment():
    steps = {s["name"]: s for s in jobs()["next-step"]["steps"] if "name" in s}
    assert steps["threat model diff"]["if"] == "steps.decide.outputs.action == 'done'"
    assert "factory.threatmodel.diff" in steps["threat model diff"]["run"]
    assert "--extra out/next-step/threat-diff.md" in steps["comment on the issue"]["run"]


def test_record_job_comments_the_sbom_diff_only_after_a_default_branch_pass():
    record = jobs()["record"]
    assert record["permissions"] == {"contents": "read", "issues": "write", "pull-requests": "read"}
    steps = {s["name"]: s for s in record["steps"] if "name" in s}
    condition = steps["comment the dependency changes on the merged issue"]["if"]
    assert "github.event_name == 'push'" in condition and "needs.gate.result == 'success'" in condition


def threat(threat_id, element, title="Title", framework="stride", category="tampering", severity="high", status="open"):
    return {
        "id": threat_id, "framework": framework, "category": category, "element": element, "title": title,
        "description": "d", "likelihood": "high", "impact": "medium", "severity": severity,
        "mitigations": [{"id": f"{threat_id}-M1", "text": "Do it", "asvs_refs": ["V8.2.1"]}], "status": status,
    }


def test_diff_lists_added_changed_and_removed():
    old = {"threats": [threat("TM-001", "A"), threat("TM-002", "B"), threat("TM-003", "C")], "removed": []}
    changed = threat("TM-002", "B", severity="critical")
    changed["mitigations"][0]["text"] = "Do it better"
    new = {"threats": [threat("TM-001", "A"), changed, threat("TM-004", "D")], "removed": []}
    result = threat_diff.diff_threats(old, new)
    assert [t["id"] for t in result["added"]] == ["TM-004"]
    assert [t["id"] for t in result["removed"]] == ["TM-003"]
    assert [t["id"] for t in result["changed"]] == ["TM-002"]
    assert result["changed"][0]["fields"] == ["severity", "mitigations"]
    assert result["changed"][0]["was_severity"] == "high"


def test_diff_without_an_earlier_model_adds_everything():
    new = {"threats": [threat("TM-001", "A")], "removed": []}
    assert [t["id"] for t in threat_diff.diff_threats(None, new)["added"]] == ["TM-001"]


def test_diff_of_identical_models_is_empty_and_renders_none():
    doc = {"threats": [threat("TM-001", "A")], "removed": []}
    result = threat_diff.diff_threats(doc, copy.deepcopy(doc))
    assert result == {"added": [], "changed": [], "removed": []}
    text = threat_diff.render_markdown(result)
    assert "**Added:** none" in text and "**Changed:** none" in text and "**Removed:** none" in text


def test_diff_markdown_escapes_model_text_and_truncates_long_lists():
    many = [threat(f"TM-{n:03d}", "A", title="[x](http://evil.example) @bob") for n in range(1, 31)]
    text = threat_diff.render_markdown(threat_diff.diff_threats(None, {"threats": many, "removed": []}))
    assert "**Added (30):**" in text
    assert "...and 15 more" in text
    assert "http://evil" not in text and "@bob" not in text


def test_diff_cli_writes_files_and_handles_a_missing_base(tmp_path, capsys):
    head = tmp_path / "head.json"
    head.write_text(json.dumps({"threats": [threat("TM-001", "A")], "removed": []}))
    code = threat_diff.main(["--base", str(tmp_path / "none.json"), "--head", str(head),
                             "--out-json", str(tmp_path / "d.json"), "--out-md", str(tmp_path / "d.md")])
    assert code == 0
    assert json.loads((tmp_path / "d.json").read_text())["added"][0]["id"] == "TM-001"
    assert "### Threat model changes" in (tmp_path / "d.md").read_text()
    assert "1 added, 0 changed, 0 removed" in capsys.readouterr().out


def test_diff_cli_rejects_a_bad_head(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("[]")
    assert threat_diff.main(["--head", str(bad)]) == 1
    assert threat_diff.main(["--head", str(tmp_path / "gone.json")]) == 1


def test_pass_comment_includes_the_extra_section_before_the_report():
    text = fixloop.render_comment("done", 12, "# Report\nall good", "https://github.com/o/r/actions/runs/1",
                                  "### Threat model changes\n\n**Added (1):**")
    assert text.index("### Threat model changes") < text.index("# Report")
    assert "ready to merge" in text


def test_stop_comment_without_an_extra_section_is_unchanged():
    assert "Threat model changes" not in fixloop.render_comment("stop", 12, "# Report")


def test_comment_cli_reads_the_extra_file(tmp_path):
    report, extra, out = tmp_path / "r.md", tmp_path / "e.md", tmp_path / "c.md"
    report.write_text("report")
    extra.write_text("### Threat model changes")
    assert fixloop.main(["comment", "--kind", "done", "--issue", "4", "--report", str(report), "--extra", str(extra), "--out", str(out)]) == 0
    assert "### Threat model changes" in out.read_text()
    assert fixloop.main(["comment", "--kind", "done", "--issue", "4", "--report", str(report), "--extra", str(tmp_path / "none.md"), "--out", str(out)]) == 0
    assert "Threat model changes" not in out.read_text()


def test_sbom_note_finds_the_factory_branch_issue():
    pulls = [{"head": {"ref": "feature/x"}}, {"head": {"ref": "factory/17"}}]
    assert sbomnote.issue_for_pulls(pulls) == 17
    assert sbomnote.issue_for_pulls([{"head": {"ref": "factory/17/extra"}}]) is None
    assert sbomnote.issue_for_pulls([{"head": {"ref": "factory/0"}}, {"head": None}, "x"]) is None
    assert sbomnote.issue_for_pulls([]) is None


def test_sbom_note_renders_added_removed_and_changed():
    diff = {
        "added": [{"name": "express-rate-limit", "version": "8.1.0"}],
        "removed": [{"name": "left-pad", "version": "1.3.0"}],
        "changed": [{"name": "helmet", "old_versions": ["8.2.0"], "new_versions": ["8.3.0"]}],
    }
    text = sbomnote.render(diff, 17, "abcdef1234567890")
    assert text.startswith(sbomnote.MARKER)
    assert "express-rate-limit 8.1.0" in text and "left-pad 1.3.0" in text and "helmet: 8.2.0 to 8.3.0" in text


def test_sbom_note_with_no_changes_says_so():
    assert "No dependency changes." in sbomnote.render({"added": [], "removed": [], "changed": []}, 3)


def test_sbom_note_cli(tmp_path):
    pulls, diff, out, output = tmp_path / "p.json", tmp_path / "d.json", tmp_path / "c.md", tmp_path / "gh"
    pulls.write_text(json.dumps([{"head": {"ref": "factory/9"}}]))
    diff.write_text(json.dumps({"added": [], "removed": [], "changed": []}))
    assert sbomnote.main(["--pulls", str(pulls), "--diff", str(diff), "--out", str(out), "--github-output", str(output)]) == 0
    assert output.read_text() == "issue=9\n" and out.exists()
    pulls.write_text(json.dumps([{"head": {"ref": "dependabot/npm"}}]))
    out.unlink()
    output.unlink()
    assert sbomnote.main(["--pulls", str(pulls), "--diff", str(diff), "--out", str(out), "--github-output", str(output)]) == 0
    assert output.read_text() == "issue=\n" and not out.exists()
    diff.unlink()
    pulls.write_text(json.dumps([{"head": {"ref": "factory/9"}}]))
    assert sbomnote.main(["--pulls", str(pulls), "--diff", str(diff), "--out", str(out), "--github-output", str(output)]) == 0
    assert not out.exists()


def test_sbom_note_cli_rejects_unreadable_input(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{")
    assert sbomnote.main(["--pulls", str(bad), "--diff", str(bad), "--out", str(tmp_path / "c.md")]) == 1


def test_merge_keeps_threats_the_predicate_protects_and_numbers_after_the_old_ones():
    previous = {"model_version": "v", "threats": [threat("TM-001", "A"), threat("TM-002", "B", title="Old")], "removed": [threat("TM-007", "Z")]}
    reply = [{
        "previous_id": "TM-002", "category": "tampering", "element": "B", "title": "Old", "description": "new text",
        "likelihood": "low", "impact": "low", "mitigations": [{"text": "Do more", "asvs_refs": ["V8.2.1"]}], "status": "open",
    }, {
        "previous_id": None, "category": "spoofing", "element": "B", "title": "Brand new", "description": "d",
        "likelihood": "high", "impact": "high", "mitigations": [{"text": "Check", "asvs_refs": ["V8.2.1"]}], "status": "open",
    }]
    doc = threat_model.merge(reply, previous, "v2", keep=lambda t: t["element"] != "B")
    ids = {t["id"]: t for t in doc["threats"]}
    assert set(ids) == {"TM-001", "TM-002", "TM-008"}
    assert ids["TM-001"] == previous["threats"][0]
    assert ids["TM-002"]["description"] == "new text"


def test_merge_moves_a_protected_looking_threat_on_a_vanished_element_to_removed():
    previous = {"model_version": "v", "threats": [threat("TM-001", "Gone"), threat("TM-002", "B")], "removed": []}
    reply = [{
        "previous_id": "TM-002", "category": "tampering", "element": "B", "title": "Title", "description": "d",
        "likelihood": "high", "impact": "medium", "mitigations": [{"text": "Do it", "asvs_refs": ["V8.2.1"]}], "status": "open",
    }]
    names = ["B"]
    doc = threat_model.merge(reply, previous, "v2", keep=lambda t: t["element"] not in ["B"] and t["element"] in names)
    assert [t["id"] for t in doc["threats"]] == ["TM-002"]
    assert [t["id"] for t in doc["removed"]] == ["TM-001"]


def test_focus_elements_filters_to_known_names():
    focus, ignored = threat_model.focus_elements({"touched_elements": ["Notes DB", "Ghost"]}, ["Web app", "Notes DB"])
    assert focus == ["Notes DB"] and ignored == ["Ghost"]
    assert threat_model.focus_elements(None, ["A"]) == ([], [])
    assert threat_model.focus_elements({}, ["A"]) == ([], [])


@pytest.fixture
def fake_pytm(tmp_path) -> Path:
    wrapper = tmp_path / "fake-python"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{TM_FIXTURES / "fake_pytm.py"}" "$@"\n')
    wrapper.chmod(0o755)
    return wrapper


@pytest.fixture
def tm_project(tmp_path, monkeypatch):
    monkeypatch.setenv("FACTORY_MODEL_ADAPTER", "fake")
    responses = tmp_path / "tm-responses"
    responses.mkdir()
    for name in ("threat-model-pytm.json", "threat-model-stride.json", "threat-model-linddun.json",
                 "threat-model-attack-tree-f1.json"):
        shutil.copy(FAKE / name, responses / name)
    monkeypatch.setenv("FACTORY_FAKE_RESPONSES", str(responses))
    root = tmp_path / "tm-project"
    root.mkdir()
    reply = canned()
    for feature in reply["features"]:
        feature["risk"] = "high" if feature["id"] == "F1" else "low"
    (root / "plan.json").write_text(json.dumps(plan.finalize(reply, None)))
    return root, responses


def run_threat_model(root, python, out_name):
    out = root / out_name
    code = threat_model.main(["--plan", str(root / "plan.json"), "--out", str(out), "--previous", str(root / "security"),
                              "--pytm-python", str(python), "--workdir", str(root), "--sandbox", "none"])
    return code, out


def seed_security(root, python):
    code, first = run_threat_model(root, python, "first")
    assert code == 0
    (root / "security").mkdir()
    for name in ("tm.py", "threats.json"):
        shutil.copy(first / name, root / "security" / name)
    return json.loads((first / "threats.json").read_text())


def set_touched(root, elements):
    doc = json.loads((root / "plan.json").read_text())
    doc.update({"changed_features": ["F2"], "touched_elements": elements})
    (root / "plan.json").write_text(json.dumps(doc))


def test_change_run_focuses_stride_and_keeps_untouched_threats(tm_project, fake_pytm):
    root, responses = tm_project
    before = seed_security(root, fake_pytm)
    set_touched(root, ["Notes DB"])
    stride = json.loads((FAKE / "threat-model-stride.json").read_text())
    new = copy.deepcopy(stride["threats"][0])
    new.update({"element": "Notes DB", "category": "denial-of-service", "title": "Notes API flooded"})
    (responses / "threat-model-stride.json").write_text(json.dumps({"threats": [new]}))
    code, out = run_threat_model(root, fake_pytm, "second")
    assert code == 0
    after = json.loads((out / "threats.json").read_text())
    old_by_id = {t["id"]: t for t in before["threats"]}
    new_by_id = {t["id"]: t for t in after["threats"]}
    assert set(old_by_id) <= set(new_by_id)
    for threat_id, old in old_by_id.items():
        if old["framework"] == "stride":
            assert new_by_id[threat_id] == old
    added = [t for t in after["threats"] if t["id"] not in old_by_id]
    assert [(t["element"], t["category"]) for t in added] == [("Notes DB", "denial-of-service")]
    assert added[0]["id"] == f"TM-{max(int(i[3:]) for i in old_by_id) + 1:03d}"
    passes = json.loads((out / "passes.json").read_text())
    assert passes["stride"]["focus"] == ["Notes DB"] and passes["stride"]["ignored"] == []
    assert json.loads((out / "touched.json").read_text()) == {"elements": ["Notes DB"]}
    schema = json.loads((out / "stride-reply.schema.json").read_text())
    assert schema["properties"]["threats"]["items"]["properties"]["element"]["enum"] == ["Notes DB"]
    summary = threat_diff.diff_threats(before, after)
    assert [t["element"] for t in summary["added"]] == ["Notes DB"]
    assert summary["removed"] == []


def test_change_run_keeps_old_ids_when_a_touched_threat_is_updated(tm_project, fake_pytm):
    root, responses = tm_project
    before = seed_security(root, fake_pytm)
    set_touched(root, ["Sign-in request"])
    stride = json.loads((FAKE / "threat-model-stride.json").read_text())
    update = copy.deepcopy(stride["threats"][0])
    update["description"] = "Now rate limited, but lockout is still missing."
    update["likelihood"] = "low"
    (responses / "threat-model-stride.json").write_text(json.dumps({"threats": [update]}))
    code, out = run_threat_model(root, fake_pytm, "second")
    assert code == 0
    after = json.loads((out / "threats.json").read_text())
    old = next(t for t in before["threats"] if t["element"] == "Sign-in request" and t["framework"] == "stride")
    new = next(t for t in after["threats"] if t["id"] == old["id"])
    assert new["description"].startswith("Now rate limited") and new["likelihood"] == "low"
    summary = threat_diff.diff_threats(before, after)
    assert [t["id"] for t in summary["changed"]] == [old["id"]]
    assert summary["added"] == []


def test_touched_elements_missing_from_the_model_fall_back_to_the_full_pass(tm_project, fake_pytm):
    root, _ = tm_project
    before = seed_security(root, fake_pytm)
    set_touched(root, ["No such element"])
    code, out = run_threat_model(root, fake_pytm, "second")
    assert code == 0
    after = json.loads((out / "threats.json").read_text())
    assert {t["id"] for t in before["threats"]} == {t["id"] for t in after["threats"]}
    assert not (out / "touched.json").exists()


def test_spec_mode_ignores_touched_elements_without_a_previous_model(tm_project, fake_pytm):
    root, _ = tm_project
    set_touched(root, ["Notes DB"])
    code, out = run_threat_model(root, fake_pytm, "first")
    assert code == 0
    assert not (out / "touched.json").exists()
    assert len([t for t in json.loads((out / "threats.json").read_text())["threats"] if t["framework"] == "stride"]) == 4
