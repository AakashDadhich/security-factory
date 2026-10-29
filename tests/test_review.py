import json
import subprocess
from pathlib import Path

import pytest
import yaml

from factory import findings, stage_matrix
from factory.stages import review

REPO = Path(__file__).resolve().parent.parent
FAKE = REPO / "tests" / "fixtures" / "fake"
WORKFLOW = REPO / ".github" / "workflows" / "factory.yml"
NOTES = [f"line {n}" for n in range(1, 101)]
SQL = 'const row = db.query("SELECT * FROM notes WHERE id = " + req.params.id);'
THREATS = {"threats": [
    {"id": "TM-001", "element": "notes store", "title": "Injection in src/notes.ts", "status": "open", "mitigations": []},
    {"id": "TM-002", "element": "login", "title": "Closed one", "status": "mitigated", "mitigations": []},
]}


def sh(cwd, *args):
    result = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args], cwd=cwd, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def write(repo: Path, name: str, text: str) -> None:
    (repo / name).parent.mkdir(parents=True, exist_ok=True)
    (repo / name).write_text(text)


def make_repo(root: Path, changes: dict | None = None, base_files: dict | None = None) -> tuple[Path, str, str]:
    repo = root / "repo"
    repo.mkdir()
    sh(repo, "init", "-q", "-b", "main")
    base_files = base_files or {"src/notes.ts": "\n".join(NOTES) + "\n", "src/app.ts": "export const app = 1;\n"}
    for name, text in base_files.items():
        write(repo, name, text)
    sh(repo, "add", "-A")
    sh(repo, "commit", "-q", "-m", "base")
    base = sh(repo, "rev-parse", "HEAD")
    if changes is None:
        changed = list(NOTES)
        changed[49] = SQL
        changes = {
            "src/notes.ts": "\n".join(changed) + "\n",
            "security/threats.json": json.dumps(THREATS),
            "security/plan.json": json.dumps({"asvs_level": 1}),
        }
    for name, text in changes.items():
        write(repo, name, text)
    sh(repo, "add", "-A")
    sh(repo, "commit", "-q", "-m", "change")
    return repo, base, sh(repo, "rev-parse", "HEAD")


def reply_item(**overrides) -> dict:
    item = json.loads((FAKE / "review.json").read_text())["findings"][0]
    item.update(overrides)
    return item


@pytest.fixture
def responses(tmp_path, monkeypatch):
    folder = tmp_path / "responses"
    folder.mkdir()
    monkeypatch.setenv("FACTORY_MODEL_ADAPTER", "fake")
    monkeypatch.setenv("FACTORY_FAKE_RESPONSES", str(folder))

    def set_reply(*items, raw: str | None = None):
        (folder / "review.json").write_text(raw if raw is not None else json.dumps({"findings": list(items)}))

    return set_reply


def run_review(repo, base, head, out, *extra):
    return review.main(["--repo", str(repo), "--base", base, "--head", head, "--out", str(out), *extra])


def results(out: Path) -> list[dict]:
    return findings.load(out / "findings.json")


def test_real_finding_inside_the_hunk_keeps_its_severity(tmp_path, responses):
    repo, base, head = make_repo(tmp_path)
    responses(reply_item())
    assert run_review(repo, base, head, tmp_path / "out") == 0
    [f] = results(tmp_path / "out")
    assert f["severity"] == "high" and f["source"] == "ai-review" and f["stage"] == "review"
    assert f["tool"] == "fake" and f["rule_id"] == "review-cwe-89" and f["cwe"] == ["CWE-89"]
    assert f["location"] == {"path": "src/notes.ts", "start_line": 50, "end_line": 50}
    assert "TM-001" in f["description"] and "V1.2.4" in f["description"]
    assert "Downgraded" not in f["description"]


def test_path_not_in_diff_is_downgraded_to_info(tmp_path, responses):
    repo, base, head = make_repo(tmp_path)
    responses(reply_item(path="src/app.ts", start_line=1, end_line=1))
    run_review(repo, base, head, tmp_path / "out")
    [f] = results(tmp_path / "out")
    assert f["severity"] == "info"
    assert "not in the reviewed diff" in f["description"]


def test_invented_path_is_downgraded_to_info(tmp_path, responses):
    repo, base, head = make_repo(tmp_path)
    responses(reply_item(path="/etc/passwd"))
    run_review(repo, base, head, tmp_path / "out")
    assert results(tmp_path / "out")[0]["severity"] == "info"


def test_lines_outside_changed_hunks_are_downgraded_to_info(tmp_path, responses):
    repo, base, head = make_repo(tmp_path)
    responses(reply_item(start_line=95, end_line=96), reply_item(title="Straddles", start_line=68, end_line=75))
    run_review(repo, base, head, tmp_path / "out")
    items = results(tmp_path / "out")
    assert [f["severity"] for f in items] == ["info", "info"]
    assert all("outside the changed hunks" in f["description"] for f in items)


def test_context_lines_around_the_change_count_as_inside(tmp_path, responses):
    repo, base, head = make_repo(tmp_path)
    responses(reply_item(start_line=30, end_line=70))
    run_review(repo, base, head, tmp_path / "out")
    assert results(tmp_path / "out")[0]["severity"] == "high"


@pytest.mark.parametrize(("severity", "confidence", "expected"), [
    ("critical", "low", "medium"),
    ("high", "low", "medium"),
    ("medium", "low", "medium"),
    ("low", "low", "low"),
    ("info", "low", "info"),
    ("critical", "medium", "critical"),
    ("high", "high", "high"),
])
def test_low_confidence_is_capped_at_medium(tmp_path, responses, severity, confidence, expected):
    repo, base, head = make_repo(tmp_path)
    responses(reply_item(severity=severity, confidence=confidence))
    run_review(repo, base, head, tmp_path / "out")
    assert results(tmp_path / "out")[0]["severity"] == expected


def test_unknown_references_are_dropped_and_noted(tmp_path, responses):
    repo, base, head = make_repo(tmp_path)
    responses(reply_item(asvs_refs=["V1.2.4", "V99.9.9"], threat_ids=["TM-001", "TM-777", "TM-002"]))
    run_review(repo, base, head, tmp_path / "out")
    [f] = results(tmp_path / "out")
    assert "TM-001" in f["description"] and "TM-777" not in f["description"]
    assert "V99.9.9" not in f["description"] and "references were dropped" in f["description"]


def test_only_open_threats_reach_the_model(tmp_path, responses):
    repo, base, head = make_repo(tmp_path)
    responses()
    run_review(repo, base, head, tmp_path / "out")
    sent = json.loads((tmp_path / "out" / "threats.json").read_text())["threats"]
    assert [t["id"] for t in sent] == ["TM-001"]


def test_duplicate_findings_keep_the_most_severe(tmp_path, responses):
    repo, base, head = make_repo(tmp_path)
    responses(reply_item(severity="low"), reply_item(severity="critical", title="Same line, worse"))
    run_review(repo, base, head, tmp_path / "out")
    [f] = results(tmp_path / "out")
    assert f["severity"] == "critical" and f["title"] == "Same line, worse"


def test_clean_review_has_no_findings(tmp_path, responses):
    repo, base, head = make_repo(tmp_path)
    responses()
    assert run_review(repo, base, head, tmp_path / "out") == 0
    assert results(tmp_path / "out") == []
    summary = json.loads((tmp_path / "out" / "summary.json").read_text())
    assert summary["model_called"] is True and summary["files_reviewed"] == ["src/notes.ts"]
    assert summary["truncated"] is False


def test_security_folder_is_not_part_of_the_reviewed_diff(tmp_path, responses):
    repo, base, head = make_repo(tmp_path)
    responses()
    run_review(repo, base, head, tmp_path / "out")
    diff = (tmp_path / "out" / "diff.patch").read_text()
    assert "src/notes.ts" in diff and "security/" not in diff
    assert "@@ -" in diff and "+" + SQL in diff


def test_asvs_level_comes_from_the_plan_on_the_branch(tmp_path, responses):
    repo, base, head = make_repo(tmp_path)
    responses()
    run_review(repo, base, head, tmp_path / "out", "--asvs-level", "3")
    assert json.loads((tmp_path / "out" / "summary.json").read_text())["asvs_level"] == 1
    checklist = json.loads((tmp_path / "out" / "checklist.json").read_text())
    assert checklist and {c["level"] for c in checklist} == {1}


def test_asvs_level_option_applies_without_a_plan(tmp_path, responses):
    changed = list(NOTES)
    changed[49] = SQL
    repo, base, head = make_repo(tmp_path, {"src/notes.ts": "\n".join(changed) + "\n"})
    responses()
    run_review(repo, base, head, tmp_path / "out", "--asvs-level", "3")
    assert json.loads((tmp_path / "out" / "summary.json").read_text())["asvs_level"] == 3
    assert not (tmp_path / "out" / "threats.json").exists()


def test_diff_with_no_reviewable_files_skips_the_model(tmp_path, responses):
    repo, base, head = make_repo(tmp_path, {"security/threats.json": json.dumps(THREATS)})
    assert run_review(repo, base, head, tmp_path / "out") == 0
    assert results(tmp_path / "out") == []
    assert json.loads((tmp_path / "out" / "summary.json").read_text())["model_called"] is False


def big_repo(root: Path) -> tuple[Path, str, str]:
    base = {f"src/{n}.ts": "\n".join(f"{n} {i}" for i in range(1, 60)) + "\n" for n in ("alpha", "beta", "gamma")}
    changes = {name: text.replace(f"{name[4:-3]} 30", f"{name[4:-3]} changed") for name, text in base.items()}
    return make_repo(root, changes, base)


def test_oversized_diff_is_truncated_with_relevant_files_first(tmp_path, responses):
    repo, base, head = big_repo(tmp_path)
    threats = {"threats": [{"id": "TM-003", "element": "gamma", "title": "Abuse of src/gamma.ts", "status": "open"}]}
    (repo / "security").mkdir()
    (repo / "security" / "threats.json").write_text(json.dumps(threats))
    sh(repo, "add", "-A")
    sh(repo, "commit", "-q", "-m", "threats")
    head = sh(repo, "rev-parse", "HEAD")
    responses()
    assert run_review(repo, base, head, tmp_path / "out", "--max-diff-bytes", "1000") == 0
    out = tmp_path / "out"
    summary = json.loads((out / "summary.json").read_text())
    assert summary["truncated"] is True
    assert summary["files_reviewed"][0] == "src/gamma.ts"
    assert len(summary["files_reviewed"]) < 3 and summary["omitted"]
    assert len((out / "diff.patch").read_bytes()) <= 1000
    [f] = results(out)
    assert f["rule_id"] == "review-truncated" and f["severity"] == "info" and f["source"] == "check"
    assert "src/alpha.ts" in f["description"] or "src/beta.ts" in f["description"]


def test_hunks_that_do_not_fit_are_dropped_and_not_reviewable(tmp_path, responses):
    lines = [f"row {i}" for i in range(1, 201)]
    changed = list(lines)
    changed[9] = "early change"
    changed[189] = "late change"
    repo, base, head = make_repo(tmp_path, {"src/big.ts": "\n".join(changed) + "\n"}, {"src/big.ts": "\n".join(lines) + "\n"})
    selection = review.select(review.file_diffs(repo, base, head), [], 420)
    assert selection.truncated is True
    assert len(selection.included["src/big.ts"]) == 1
    assert any("1 of 2 hunks" in o for o in selection.omitted)


def test_untruncated_diff_has_no_truncation_note(tmp_path):
    repo, base, head = big_repo(tmp_path)
    selection = review.select(review.file_diffs(repo, base, head), [], review.DEFAULT_MAX_BYTES)
    assert selection.truncated is False and selection.omitted == []
    assert sorted(selection.included) == ["src/alpha.ts", "src/beta.ts", "src/gamma.ts"]


def test_deleted_lines_only_hunk_has_no_reviewable_lines():
    diff = review.parse_file_diff("a.ts", "diff --git a/a.ts b/a.ts\n--- a/a.ts\n+++ b/a.ts\n@@ -5,3 +4,0 @@\n-x\n-y\n-z\n")
    assert [(h.start, h.end) for h in diff.hunks] == [(4, 3)]


def test_invalid_reply_exits_2_and_writes_nothing(tmp_path, responses):
    repo, base, head = make_repo(tmp_path)
    responses(reply_item(severity="catastrophic"))
    assert run_review(repo, base, head, tmp_path / "out") == 2
    assert not (tmp_path / "out" / "findings.json").exists()


def test_unresolvable_revision_is_an_error(tmp_path, responses, capsys):
    repo, base, head = make_repo(tmp_path)
    responses()
    assert run_review(repo, "nosuchbranch", head, tmp_path / "out") == 1
    assert "error" in capsys.readouterr().err


def schema_errors(instance) -> list:
    return list(findings.validator("review.schema.json").iter_errors(instance))


def test_schema_accepts_the_fixture_and_an_empty_review():
    assert not schema_errors(json.loads((FAKE / "review.json").read_text()))
    assert not schema_errors({"findings": []})


@pytest.mark.parametrize("change", [
    {"severity": "urgent"},
    {"confidence": "certain"},
    {"cwe": ["89"]},
    {"asvs_refs": ["1.2.4"]},
    {"threat_ids": ["T-1"]},
    {"start_line": 0},
    {"unexpected": True},
])
def test_schema_rejects_bad_findings(change):
    assert schema_errors({"findings": [reply_item(**change)]})


def test_schema_requires_every_field():
    for key in reply_item():
        item = reply_item()
        del item[key]
        assert schema_errors({"findings": [item]}), key


def jobs() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]


def test_review_runs_after_codegen_commit_and_before_every_scanner():
    all_jobs = jobs()
    assert "codegen-commit" in all_jobs["review"]["needs"]
    for name in ("secrets", "sast-semgrep", "sast-codeql", "sast-eslint", "deps-sbom", "dast-web"):
        assert "review" in all_jobs[name]["needs"], name
    assert "review" in all_jobs["gate"]["needs"]


def test_review_job_has_read_only_access_and_no_app_key():
    job = jobs()["review"]
    assert job["permissions"] == {"contents": "read"}
    text = json.dumps(job)
    assert "FACTORY_APP_PRIVATE_KEY" not in text and "create-github-app-token" not in text
    assert "CLAUDE_CODE_OAUTH_TOKEN" in text
    for step in job["steps"]:
        assert "${{" not in str(step.get("run", ""))


def test_review_job_reviews_the_pushed_commit_against_the_default_branch():
    job = jobs()["review"]
    assert job["steps"][0]["with"]["ref"].startswith("${{ needs.codegen-commit.outputs.sha ||")
    assert job["steps"][0]["with"]["fetch-depth"] == 0
    run = next(s for s in job["steps"] if s.get("name") == "security review stage")
    assert 'origin/$DEFAULT_BRANCH' in run["run"] and "PR_BASE" in run["env"] and "PUSH_BEFORE" in run["env"]


def test_review_job_in_check_mode_follows_the_ai_eligible_decision():
    condition = jobs()["review"]["if"]
    assert "needs.ai-eligible.outputs.run_ai == 'true'" in condition
    assert "ai-eligible" in jobs()["review"]["needs"]
    assert "needs.setup.result == 'success'" in condition


def test_manifest_lists_the_review_stage():
    run = next(s["run"] for s in jobs()["setup"]["steps"] if s.get("name") == "write run manifest")
    assert "--stage review" in " ".join(run.split())


@pytest.mark.parametrize(("mode", "expected"), [("spec", True), ("change", True), ("fix", True), ("check", True)])
def test_matrix_expects_review_by_mode(mode, expected):
    assert ("review" in [s.name for s in stage_matrix.expected("web", mode)]) is expected
