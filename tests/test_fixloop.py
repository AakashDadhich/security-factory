import json
from pathlib import Path

import pytest
import yaml

from factory import authorize, fixloop, manifest
from factory.fixloop import FixLoopError

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "factory.yml"
STUB = REPO / "templates" / "project" / ".github" / "workflows" / "factory.yml"


DECISIONS = [
    ("spec", "fail", 0, "dispatch"),
    ("spec", "fail", 1, "dispatch"),
    ("spec", "fail", 2, "stop"),
    ("spec", "pass", 0, "done"),
    ("change", "fail", 0, "dispatch"),
    ("change", "fail", 2, "stop"),
    ("change", "pass", 0, "done"),
    ("fix", "fail", 1, "dispatch"),
    ("fix", "fail", 2, "stop"),
    ("fix", "pass", 1, "done"),
    ("fix", "pass", 2, "done"),
    ("check", "fail", 0, "none"),
    ("check", "pass", 0, "none"),
    ("check", "fail", 2, "none"),
    ("spec", "none", 0, "none"),
    ("fix", "none", 1, "none"),
    ("spec", "skipped", 0, "none"),
    ("bogus", "fail", 0, "none"),
]


@pytest.mark.parametrize(("mode", "status", "iteration", "expected"), DECISIONS)
def test_decision_table(mode, status, iteration, expected):
    assert fixloop.decide(mode, status, iteration) == expected
    assert expected in fixloop.ACTIONS


@pytest.mark.parametrize(("result", "status"), [("success", "pass"), ("failure", "fail"), ("skipped", "none"), ("cancelled", "none"), ("", "none")])
def test_gate_job_result_maps_to_a_status(result, status):
    assert fixloop.gate_status_of(result) == status


def test_a_run_that_fixes_forever_is_impossible():
    steps, iteration = 0, 0
    while fixloop.decide("fix" if iteration else "spec", "fail", iteration) == "dispatch":
        iteration += 1
        steps += 1
    assert steps == 2 and iteration == 2


def test_valid_fix_inputs_parse_to_integers():
    assert fixloop.parse_fix_inputs("3", "1", "40952075813") == {"issue": 3, "iteration": 1, "findings_run_id": 40952075813}
    assert fixloop.parse_fix_inputs(7, 2, 9)["iteration"] == 2


@pytest.mark.parametrize(("issue", "iteration", "run_id", "needle"), [
    ("3", "3", "5", "iteration"),
    ("3", "0", "5", "iteration"),
    ("3", "-1", "5", "iteration"),
    ("3", "1.5", "5", "iteration"),
    ("3", "", "5", "iteration"),
    ("abc", "1", "5", "issue"),
    ("0", "1", "5", "issue"),
    ("-2", "1", "5", "issue"),
    ("3.5", "1", "5", "issue"),
    ("3; rm -rf /", "1", "5", "issue"),
    ("$(id)", "1", "5", "issue"),
    ("", "1", "5", "issue"),
    ("3", "1", "-5", "findings_run_id"),
    ("3", "1", "0", "findings_run_id"),
    ("3", "1", "abc", "findings_run_id"),
    ("3", "1", "1" * 16, "findings_run_id"),
    ("3", "1", "", "findings_run_id"),
    ("3", "1", "1e3", "findings_run_id"),
    (True, "1", "5", "issue"),
])
def test_bad_fix_inputs_are_rejected(issue, iteration, run_id, needle):
    with pytest.raises(FixLoopError, match=needle):
        fixloop.parse_fix_inputs(issue, iteration, run_id)


def authorize_args(mode, issue, iteration, run_id):
    return ["--mode", mode, "--issue", issue, "--iteration", iteration, "--findings-run-id", run_id]


def test_authorize_validates_the_payload_in_fix_mode(capsys):
    assert authorize.main(authorize_args("fix", "3", "1", "12345")) == 0
    for args in (("fix", "3", "3", "12345"), ("fix", "x", "1", "12345"), ("fix", "3", "1", "-4")):
        assert authorize.main(authorize_args(*args)) == 1
    assert "must be" in capsys.readouterr().err


def test_authorize_does_not_validate_payload_fields_outside_fix_mode():
    assert authorize.main(authorize_args("check", "0", "0", "0")) == 0
    assert authorize.main(["--mode", "check"]) == 0


def test_dispatch_body_moves_to_the_next_iteration():
    assert fixloop.dispatch_body(3, 0, 777) == {
        "event_type": "factory-fix", "client_payload": {"issue": 3, "iteration": 1, "findings_run_id": 777}}
    assert fixloop.dispatch_body(3, 1, 778)["client_payload"]["iteration"] == 2


@pytest.mark.parametrize("iteration", [2, 3, -1])
def test_dispatch_body_refuses_past_the_cap(iteration):
    with pytest.raises(FixLoopError):
        fixloop.dispatch_body(3, iteration, 5)


def test_dispatch_body_rejects_bad_ids():
    with pytest.raises(FixLoopError):
        fixloop.dispatch_body(-3, 0, 5)
    with pytest.raises(FixLoopError):
        fixloop.dispatch_body(3, 0, "abc")


class FakeRun:
    def __init__(self, code=0, err=""):
        self.calls, self.code, self.err = [], code, err

    def __call__(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        return type("R", (), {"returncode": self.code, "stderr": self.err})()


def test_send_dispatch_posts_json_to_the_dispatches_endpoint():
    run = FakeRun()
    body = fixloop.dispatch_body(3, 0, 777)
    fixloop.send_dispatch("AakashDadhich/factory-test-web", body, run=run)
    (cmd, kwargs), = run.calls
    assert cmd == ["gh", "api", "--method", "POST", "repos/AakashDadhich/factory-test-web/dispatches", "--input", "-"]
    assert json.loads(kwargs["input"]) == body


def test_send_dispatch_reports_failures_and_bad_repos():
    with pytest.raises(FixLoopError, match="Resource not accessible"):
        fixloop.send_dispatch("o/r", {}, run=FakeRun(1, "Resource not accessible"))
    with pytest.raises(FixLoopError, match="owner/name"):
        fixloop.send_dispatch("o/r; echo", {}, run=FakeRun())


def gate_dir(tmp_path, *, status="fail", mode="spec", iteration=0, issue=3, report=None, blocking=None):
    report = report if report is not None else [
        {"id": "a", "fingerprint": "fp-low", "severity": "low", "rule_id": "r3", "title": "Low thing", "tool": "semgrep", "stages": ["sast-semgrep"]},
        {"id": "b", "fingerprint": "fp-crit", "severity": "critical", "rule_id": "r1", "title": "Critical " + "x" * 400, "tool": "codeql",
         "stages": ["sast-codeql"], "location": {"path": "src/a.ts", "start_line": 3}, "cwe": ["CWE-89"], "description": "d" * 2000,
         "remediation": "Use bound parameters."},
        {"id": "c", "fingerprint": "fp-high", "severity": "high", "rule_id": "r2", "title": "High thing", "tool": "review", "stages": ["review"]},
    ]
    blocking = blocking if blocking is not None else ["fp-high", "fp-crit"]
    gate = tmp_path / "gate"
    gate.mkdir()
    (gate / "gate-result.json").write_text(json.dumps({"status": status, "mode": mode, "iteration": iteration, "blocking_fingerprints": blocking}))
    (gate / "report.json").write_text(json.dumps(report))
    setup = tmp_path / "setup"
    setup.mkdir()
    (setup / "run-manifest.json").write_text(json.dumps({"issue": issue, "iteration": iteration}))
    return gate, setup


def test_blocking_findings_keeps_only_blocking_ones_most_severe_first(tmp_path):
    gate, setup = gate_dir(tmp_path)
    items = fixloop.blocking_findings(gate, setup, 3, 1)
    assert [i["fingerprint"] for i in items] == ["fp-crit", "fp-high"]
    assert items[0]["location"] == {"path": "src/a.ts", "start_line": 3} and items[0]["cwe"] == ["CWE-89"]
    assert len(items[0]["title"]) <= 300 and len(items[0]["description"]) <= 1500
    assert items[0]["remediation"] == "Use bound parameters."


def test_blocking_findings_are_capped(tmp_path):
    report = [{"id": str(n), "fingerprint": f"fp{n}", "severity": "high", "rule_id": "r", "title": "t"} for n in range(60)]
    gate, setup = gate_dir(tmp_path, report=report, blocking=[f"fp{n}" for n in range(60)])
    assert len(fixloop.blocking_findings(gate, setup, 3, 1)) == fixloop.MAX_FINDINGS


@pytest.mark.parametrize(("kwargs", "needle"), [
    ({"status": "pass"}, "did not fail"),
    ({"mode": "check"}, "not a loop mode"),
    ({"issue": 9}, "issue 9"),
    ({"iteration": 1}, "iteration 1, expected 0"),
    ({"blocking": []}, "no blocking findings"),
    ({"blocking": ["unknown"]}, "no blocking findings"),
])
def test_blocking_findings_check_the_referenced_run(tmp_path, kwargs, needle):
    gate, setup = gate_dir(tmp_path, **kwargs)
    with pytest.raises(FixLoopError, match=needle):
        fixloop.blocking_findings(gate, setup, 3, 1)


def test_blocking_findings_reject_missing_files(tmp_path):
    with pytest.raises(FixLoopError):
        fixloop.blocking_findings(tmp_path / "none", tmp_path / "none", 3, 1)


def test_blocking_cli_writes_the_file(tmp_path):
    gate, setup = gate_dir(tmp_path, iteration=1)
    out = tmp_path / "out" / "blocking.json"
    args = ["blocking", "--gate", str(gate), "--setup", str(setup), "--issue", "3", "--iteration", "2", "--out", str(out)]
    assert fixloop.main(args) == 0
    assert [i["fingerprint"] for i in json.loads(out.read_text())] == ["fp-crit", "fp-high"]
    assert fixloop.main([*args[:-4], "--iteration", "3", "--out", str(out)]) == 1
    assert fixloop.main([*args[:6], "x", *args[7:]]) == 1


def test_stop_comment_has_the_required_heading_and_report():
    text = fixloop.render_comment("stop", 3, "## Factory gate\n\n**FAIL**\n", "https://example.com/run/1")
    assert "## Factory stopped after 2 fix attempts" in text
    assert "**FAIL**" in text and "factory/3" in text and text.startswith(fixloop.MARKER)


def test_done_comment_says_the_branch_is_ready():
    text = fixloop.render_comment("done", 3, "## Factory gate\n\n**PASS**\n")
    assert "Gate passed. Branch `factory/3` is ready to merge." in text and "**PASS**" in text


def test_comment_defangs_mentions_and_links_and_stays_under_the_limit():
    report = "ping @victim see https://evil.example/x www.evil.example\n" + "line\n" * 40000
    text = fixloop.render_comment("stop", 3, report)
    assert "@victim" not in text and "https://evil" not in text and "www.evil" not in text
    assert "@​victim" in text
    assert len(text) < 65536 and "report truncated" in text


def test_unknown_comment_kind_is_an_error():
    with pytest.raises(FixLoopError):
        fixloop.render_comment("maybe", 3, "")


def test_comment_cli_writes_the_comment(tmp_path):
    report = tmp_path / "report.md"
    report.write_text("## Factory gate\n")
    out = tmp_path / "c" / "comment.md"
    assert fixloop.main(["comment", "--kind", "done", "--issue", "4", "--report", str(report), "--out", str(out)]) == 0
    assert "factory/4" in out.read_text()
    assert fixloop.main(["comment", "--kind", "done", "--issue", "x", "--report", str(report), "--out", str(out)]) == 1


def test_decide_cli_writes_the_action_output(tmp_path, capsys):
    output = tmp_path / "out.txt"
    assert fixloop.main(["decide", "--mode", "spec", "--gate-result", "failure", "--iteration", "0", "--github-output", str(output)]) == 0
    assert output.read_text() == "action=dispatch\n"
    assert fixloop.main(["decide", "--mode", "fix", "--gate-result", "failure", "--iteration", "2", "--github-output", str(output)]) == 0
    assert output.read_text().splitlines()[-1] == "action=stop"
    assert "-> stop" in capsys.readouterr().out


def test_manifest_records_the_iteration():
    cfg = {"platform": "web", "web": {"port": 3000, "health_path": "/health", "dockerfile": "Dockerfile"}}
    env = {"GITHUB_RUN_ID": "1", "GITHUB_REPOSITORY": "o/r", "GITHUB_SHA": "a" * 40}
    assert manifest.create(cfg, mode="fix", factory_ref="main", stages=[], env=env, issue=7, iteration=2)["iteration"] == 2
    with pytest.raises(manifest.ManifestError):
        manifest.create(cfg, mode="fix", factory_ref="main", stages=[], env=env, issue=7, iteration=3)


def jobs():
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]


def test_next_step_runs_after_the_gate_without_ai_and_holds_the_key_only_for_the_dispatch():
    job = jobs()["next-step"]
    assert job["needs"] == "gate" and "always()" in job["if"]
    assert job["permissions"] == {"contents": "read", "issues": "write"}
    text = json.dumps(job)
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in text and "factory.adapter" not in text and "install claude-code" not in text
    mint = next(s for s in job["steps"] if s.get("id") == "app-token")
    assert mint["if"] == "steps.decide.outputs.action == 'dispatch'"
    assert mint["with"]["permission-contents"] == "write"
    holders = [s for s in job["steps"] if "FACTORY_APP_PRIVATE_KEY" in json.dumps(s)]
    assert holders == [mint]
    for step in job["steps"]:
        assert "${{" not in step.get("run", "")


def test_next_step_actions_match_the_decisions():
    steps = {s.get("name"): s for s in jobs()["next-step"]["steps"]}
    assert "'stop'" in steps["ask for a human"]["if"] and "factory:needs-human" in steps["ask for a human"]["run"]
    assert "'dispatch'" in steps["start the next fix run"]["if"]
    assert "'stop'" in steps["comment on the issue"]["if"] and "'done'" in steps["comment on the issue"]["if"]
    assert steps["start the next fix run"]["env"]["RUN_ID"] == "${{ github.run_id }}"


def test_fix_mode_workflow_wiring():
    wf = yaml.safe_load(WORKFLOW.read_text())
    inputs = wf[True]["workflow_call"]["inputs"]
    assert inputs["iteration"]["type"] == "number" and inputs["findings-run-id"]["type"] == "number"
    assert wf["concurrency"]["cancel-in-progress"] is False
    group = wf["concurrency"]["group"]
    assert "factory-issue-{0}" in group and "'fix'" in group and "'spec'" in group and "'change'" in group
    j = jobs()
    assert j["plan"]["if"] == "inputs.mode == 'spec' || inputs.mode == 'change'"
    assert j["threat-model"]["if"] == "inputs.mode == 'spec' || inputs.mode == 'change'"
    assert j["fix-input"]["permissions"] == {"contents": "read", "actions": "read"}
    commit_if = j["codegen-commit"]["if"]
    assert "inputs.mode == 'fix'" in commit_if and "!cancelled()" in commit_if and "needs.codegen-ai.result == 'success'" in commit_if
    assert "inputs.mode == 'fix'" in j["review"]["if"]
    for name in ("secrets", "sast-semgrep", "deps-sbom"):
        assert "inputs.mode != 'fix'" in j[name]["if"], name
    assert "inputs.mode != 'fix'" in j["gate"]["if"]


def test_authorize_passes_fix_inputs_through_env_only():
    step = jobs()["authorize"]["steps"][-1]
    assert step["env"]["ITERATION"] == "${{ inputs.iteration }}"
    assert step["env"]["FINDINGS_RUN_ID"] == "${{ inputs.findings-run-id }}"
    assert step["env"]["ISSUE"] == "${{ inputs.issue }}"
    assert "${{" not in step["run"]


def test_fix_stage_gets_only_the_findings_artifact_and_no_token():
    job = jobs()["codegen-ai"]
    assert job["permissions"] == {"contents": "read"}
    fix = next(s for s in job["steps"] if s.get("id") == "fix")
    assert fix["if"] == "inputs.mode == 'fix'"
    assert "--fix-findings in/fix-input/blocking.json" in fix["run"]
    assert "--plan" not in fix["run"] and "GH_TOKEN" not in json.dumps(fix)
    downloads = [s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/download-artifact")]
    by_name = {s["with"]["name"]: s["if"] for s in downloads}
    assert by_name == {"plan": "inputs.mode != 'fix'", "threat-model": "inputs.mode != 'fix'", "fix-input": "inputs.mode == 'fix'"}


def test_stub_maps_repository_dispatch_to_fix_mode():
    stub = yaml.safe_load(STUB.read_text())
    assert stub[True]["repository_dispatch"] == {"types": ["factory-fix"]}
    job = stub["jobs"]["factory"]
    assert job["permissions"]["actions"] == "read"
    assert job["with"]["mode"].startswith("${{ github.event_name == 'repository_dispatch' && 'fix'")
    assert "client_payload.issue" in job["with"]["issue"]
    assert "client_payload.iteration" in job["with"]["iteration"]
    assert "client_payload.findings_run_id" in job["with"]["findings-run-id"]
