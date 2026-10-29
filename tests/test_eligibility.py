import itertools
import json
from pathlib import Path

import pytest
import yaml

from factory import eligibility, gate, stage_matrix
from test_gate import WEB_STAGES, needs_for, result_of, run_gate, setup_run

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "factory.yml"
STUB = REPO / "templates" / "project" / ".github" / "workflows" / "factory.yml"
SCANNERS = [s for s in WEB_STAGES if s not in ("threat-model", "review")]


def decide(**overrides):
    args = {"mode": "check", "event": "push", "head_is_fork": False, "on_default_branch": True, "has_secret": True}
    return eligibility.decide(**(args | overrides))


@pytest.mark.parametrize(("args", "run_ai", "reason"), [
    ({"event": "pull_request"}, True, ""),
    ({"event": "pull_request", "on_default_branch": False}, True, ""),
    ({"event": "pull_request", "head_is_fork": True}, False, "fork-pr"),
    ({"event": "pull_request", "head_is_fork": True, "has_secret": False}, False, "fork-pr"),
    ({"event": "pull_request", "has_secret": False}, False, "no-secret"),
    ({"event": "push"}, True, ""),
    ({"event": "push", "on_default_branch": False}, False, "work-in-progress-push"),
    ({"event": "push", "on_default_branch": False, "has_secret": False}, False, "work-in-progress-push"),
    ({"event": "push", "has_secret": False}, False, "no-secret"),
    ({"event": "workflow_dispatch"}, True, ""),
    ({"event": "workflow_dispatch", "on_default_branch": False}, False, "work-in-progress-push"),
    ({"event": "schedule"}, False, "work-in-progress-push"),
])
def test_truth_table(args, run_ai, reason):
    assert decide(**args) == eligibility.Decision(run_ai, reason)


def test_every_reason_is_reachable_and_nothing_else_is():
    seen = set()
    for event, fork, default, secret in itertools.product(
            ("pull_request", "push", "workflow_dispatch", "other"), (False, True), (False, True), (False, True)):
        d = decide(event=event, head_is_fork=fork, on_default_branch=default, has_secret=secret)
        assert d.run_ai == (d.reason == "")
        seen.add(d.reason)
    assert seen == {"", *eligibility.REASONS}


@pytest.mark.parametrize("mode", ["spec", "change", "fix"])
def test_non_check_modes_are_not_gated_here(mode):
    assert decide(mode=mode, event="issues", on_default_branch=False, has_secret=False) == eligibility.Decision(True, "")


def run_cli(tmp_path, capsys, **flags):
    out = tmp_path / "github-output"
    args = {"mode": "check", "event": "push", "head-fork": "", "ref": "refs/heads/main", "default-branch": "main",
            "has-secret": "true"} | flags
    argv = [x for k, v in args.items() for x in (f"--{k}", v)] + ["--github-output", str(out)]
    assert eligibility.main(argv) == 0
    return dict(line.split("=", 1) for line in out.read_text().splitlines()), capsys.readouterr().out


def test_cli_writes_outputs(tmp_path, capsys):
    outputs, text = run_cli(tmp_path, capsys)
    assert outputs == {"run_ai": "true", "reason": ""}
    assert "AI stages skipped" not in text


def test_cli_feature_branch_push_is_work_in_progress(tmp_path, capsys):
    outputs, text = run_cli(tmp_path, capsys, ref="refs/heads/feature/x")
    assert outputs == {"run_ai": "false", "reason": "work-in-progress-push"}
    assert "AI stages skipped: work-in-progress-push" in text


def test_cli_default_branch_match_is_exact(tmp_path, capsys):
    outputs, _ = run_cli(tmp_path, capsys, ref="refs/heads/main-old")
    assert outputs["reason"] == "work-in-progress-push"
    outputs, _ = run_cli(tmp_path, capsys, ref="refs/heads/main", **{"default-branch": ""})
    assert outputs["reason"] == "work-in-progress-push"


def test_cli_fork_pr_and_missing_secret(tmp_path, capsys):
    outputs, _ = run_cli(tmp_path, capsys, event="pull_request", **{"head-fork": "true", "has-secret": "false"})
    assert outputs["reason"] == "fork-pr"
    outputs, _ = run_cli(tmp_path, capsys, event="pull_request", **{"head-fork": "false", "has-secret": "false"})
    assert outputs["reason"] == "no-secret"
    outputs, _ = run_cli(tmp_path, capsys, event="pull_request", **{"head-fork": "false"})
    assert outputs["run_ai"] == "true"


def test_matrix_expects_ai_stages_in_check_mode_and_marks_them():
    ai = {s.name for s in stage_matrix.STAGES if s.ai}
    assert ai == {"threat-model", "review"}
    names = [s.name for s in stage_matrix.expected("web", "check")]
    assert ai <= set(names)
    assert set(stage_matrix.AI_SKIP_REASONS) == set(eligibility.REASONS)


def eligible(run_ai, reason, result="success"):
    return {"ai-eligible": {"result": result, "outputs": {"run_ai": run_ai, "reason": reason}}}


def rows_for(needs, mode="check"):
    return {r["stage"]: r for r in gate.stage_rows(stage_matrix.expected("web", mode), needs, {}, {}, mode)}


@pytest.mark.parametrize("reason", eligibility.REASONS)
def test_ai_skips_are_allowed_only_for_the_known_reasons(reason):
    needs = {"threat-model": {"result": "skipped"}, "review": {"result": "skipped"}} | eligible("false", reason)
    rows = rows_for(needs)
    for stage in ("threat-model", "review"):
        assert rows[stage]["status"] == "skipped" and rows[stage]["detail"] == reason


@pytest.mark.parametrize("extra", [
    {},
    eligible("false", "made-up-reason"),
    eligible("true", ""),
    eligible("false", "fork-pr", result="failure"),
    eligible("false", ""),
])
def test_ai_skip_without_a_valid_reason_is_missing(extra):
    needs = {"threat-model": {"result": "skipped"}, "review": {"result": "skipped"}} | extra
    rows = rows_for(needs)
    assert rows["threat-model"]["status"] == "missing" and rows["review"]["status"] == "missing"


def test_ai_skip_reason_does_not_excuse_spec_mode_or_scanners():
    needs = {"threat-model": {"result": "skipped"}, "review": {"result": "skipped"}, "secrets": {"result": "skipped"}} | eligible("false", "fork-pr")
    rows = rows_for(needs, "spec")
    assert rows["threat-model"]["status"] == "missing" and rows["review"]["status"] == "missing"
    check = rows_for(needs)
    assert check["secrets"]["status"] == "missing"


def test_ai_eligible_job_is_not_a_stage_row():
    needs = {"threat-model": {"result": "skipped"}} | eligible("false", "fork-pr")
    assert "ai-eligible" not in rows_for(needs)


def skipped_run(tmp_path, reason):
    root, cfg = setup_run(tmp_path, platform_stages=SCANNERS)
    needs = needs_for(SCANNERS, **{"threat-model": "skipped", "review": "skipped"}) | eligible("false", reason)
    return root, cfg, needs


@pytest.mark.parametrize("reason", eligibility.REASONS)
def test_gate_passes_and_says_why_the_ai_stages_were_skipped(tmp_path, monkeypatch, reason):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    root, cfg, needs = skipped_run(tmp_path, reason)
    assert run_gate(tmp_path, root, cfg, needs) == 0
    assert result_of(tmp_path)["ai_skipped"] == reason
    assert f"AI stages skipped: {reason}" in summary.read_text()
    assert f"| review | skipped | {reason} |" in summary.read_text()


def test_gate_summary_has_no_skip_line_when_ai_ran(tmp_path, monkeypatch):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    root, cfg = setup_run(tmp_path)
    assert run_gate(tmp_path, root, cfg, needs_for() | eligible("true", "")) == 0
    assert result_of(tmp_path)["ai_skipped"] is None
    assert "AI stages skipped" not in summary.read_text()


def test_gate_fails_closed_when_ai_was_expected_but_skipped(tmp_path):
    root, cfg = setup_run(tmp_path, platform_stages=SCANNERS)
    needs = needs_for(SCANNERS, **{"threat-model": "skipped", "review": "skipped"}) | eligible("true", "")
    assert run_gate(tmp_path, root, cfg, needs) == 1


def workflow_jobs():
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]


def test_ai_eligible_job_is_wired_without_ai_or_write_access():
    jobs = workflow_jobs()
    job = jobs["ai-eligible"]
    assert job["needs"] == "setup" and job["permissions"] == {"contents": "read"}
    assert set(job["outputs"]) == {"run_ai", "reason"}
    text = json.dumps(job)
    assert "FACTORY_APP_PRIVATE_KEY" not in text and "factory.adapter" not in text and "install claude-code" not in text
    step = job["steps"][-1]
    assert "${{" not in step["run"]
    assert step["env"]["HAS_SECRET"] == "${{ secrets.CLAUDE_CODE_OAUTH_TOKEN != '' }}"
    assert "CLAUDE_CODE_OAUTH_TOKEN:" not in json.dumps(step["env"])
    assert "ai-eligible" in jobs["gate"]["needs"]


@pytest.mark.parametrize("name", ["threat-model", "review"])
def test_ai_jobs_in_check_mode_wait_for_the_decision(name):
    job = workflow_jobs()[name]
    assert "ai-eligible" in job["needs"]
    assert "needs.ai-eligible.outputs.run_ai == 'true'" in job["if"]
    assert "needs.setup.result == 'success'" in job["if"] and "always()" not in job["if"]
    assert job["permissions"] == {"contents": "read"}
    assert "create-github-app-token" not in json.dumps(job)


def test_check_mode_ai_jobs_commit_nothing():
    for name in ("threat-model", "review"):
        text = json.dumps(workflow_jobs()[name])
        assert "git push" not in text and "git commit" not in text and "factory.stages.codegen_commit" not in text


def test_threat_model_job_uses_the_diff_without_a_plan_in_check_mode():
    job = workflow_jobs()["threat-model"]
    download = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/download-artifact"))
    assert download["if"] == "inputs.mode != 'check'"
    stage = next(s for s in job["steps"] if s.get("name") == "threat model stage")
    assert "--diff in/diff/diff.patch" in stage["run"] and stage["env"]["MODE"] == "${{ inputs.mode }}"


def test_no_workflow_or_template_uses_pull_request_target():
    paths = [*(REPO / ".github" / "workflows").glob("*.yml"), *(REPO / "templates").rglob("*.yml"), *(REPO / ".github" / "actions").rglob("*.yml")]
    assert paths
    for path in paths:
        assert "pull_request_target" not in path.read_text(), path


def test_stub_uses_plain_pull_request_and_never_checks_out_untrusted_refs():
    stub = yaml.safe_load(STUB.read_text())
    assert "pull_request" in stub[True] and "pull_request_target" not in stub[True]
    assert stub["permissions"] == {}


def test_record_is_skipped_for_dependabot_and_forks_which_have_no_app_key():
    condition = workflow_jobs()["record"]["if"]
    assert "head.repo.fork != true" in condition and "github.actor != 'dependabot[bot]'" in condition
