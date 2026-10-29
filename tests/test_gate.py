import dataclasses
import datetime
import json

import pytest

from factory import config, findings, gate, stage_matrix
from factory.config import ConfigError

TODAY = datetime.date(2026, 10, 29)
WEB_STAGES = ["threat-model", "review", "secrets", "sast-semgrep", "sast-codeql", "sast-eslint", "deps-sbom", "dast-web"]
CONFIG = """\
platform: web
web:
  port: 3000
  health_path: /health
  dockerfile: Dockerfile
"""


def finding(severity="high", *, stage="sast-semgrep", tool="semgrep", rule="r1", path="a.ts", line=10, end=None, cwe=("CWE-79",), source="scanner"):
    return findings.make_finding(
        stage=stage, tool=tool, source=source, rule_id=rule, title=f"{rule} {severity}", severity=severity,
        location={"path": path, "start_line": line, "end_line": end or line}, cwe=list(cwe),
    )


def setup_run(tmp_path, stage_findings=None, *, extra_config="", platform_stages=WEB_STAGES, mode="check"):
    stage_findings = stage_findings or {}
    root = tmp_path / "in"
    for stage in platform_stages:
        findings.write(root / stage / "findings.json", stage_findings.get(stage, []))
    for stage, items in stage_findings.items():
        if stage not in platform_stages:
            findings.write(root / stage / "findings.json", items)
    (root / "setup").mkdir(parents=True, exist_ok=True)
    manifest = {
        "run_id": "1-1", "mode": mode, "platform": "web", "iteration": 0, "issue": None, "repo": "o/r",
        "commit_sha": "a" * 40, "factory_ref": "main", "asvs_level": 2,
        "stages": [{"name": "setup", "status": "success"}], "tool_versions": {"python": "3.12"},
    }
    (root / "setup" / "run-manifest.json").write_text(json.dumps(manifest))
    cfg = tmp_path / ".factory.yml"
    cfg.write_text(CONFIG + extra_config)
    return root, cfg


def needs_for(stages=WEB_STAGES, **overrides):
    needs = {"setup": {"result": "success"}}
    needs.update({s: {"result": "success"} for s in stages})
    needs.update({k: {"result": v} for k, v in overrides.items()})
    return needs


def run_gate(tmp_path, root, cfg, needs=None, extra=()):
    args = ["--artifacts", str(root), "--config", str(cfg), "--manifest", str(root / "setup" / "run-manifest.json"),
            "--out", str(tmp_path / "out"), "--today", TODAY.isoformat(), *extra]
    if needs is not None:
        args += ["--needs", json.dumps(needs)]
    return gate.main(args)


def result_of(tmp_path):
    return json.loads((tmp_path / "out" / "gate-result.json").read_text())


def report_of(tmp_path):
    return json.loads((tmp_path / "out" / "report.json").read_text())


def test_stage_matrix_web_check_mode():
    names = [s.name for s in stage_matrix.expected("web", "check")]
    assert names == WEB_STAGES


def test_stage_matrix_apple_has_no_web_only_stages():
    names = [s.name for s in stage_matrix.expected("ios", "check")]
    assert "sast-codeql" not in names and "sast-eslint" not in names
    assert {"secrets", "sast-semgrep", "deps-sbom"} <= set(names)


def test_stage_matrix_rejects_unknown_platform_and_mode():
    with pytest.raises(ValueError):
        stage_matrix.expected("android", "check")
    with pytest.raises(ValueError):
        stage_matrix.expected("web", "nightly")


def test_clean_run_passes_and_writes_all_outputs(tmp_path, monkeypatch):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    root, cfg = setup_run(tmp_path)
    assert run_gate(tmp_path, root, cfg, needs_for()) == 0
    out = tmp_path / "out"
    assert {p.name for p in out.iterdir()} == {"report.json", "report.md", "gate-result.json", "merged.sarif"}
    result = result_of(tmp_path)
    assert result["status"] == "pass" and result["mode"] == "check" and result["iteration"] == 0
    assert all(r["status"] == "ok" for r in result["stages"])
    text = summary.read_text()
    assert "### Stages" in text
    for stage in WEB_STAGES:
        assert f"| {stage} | ok |" in text
    for severity in findings.SEVERITIES:
        assert f"| {severity} | 0 |" in text


def test_dedupe_semgrep_and_codeql_on_same_line_keeps_highest_severity():
    semgrep = finding("medium", stage="sast-semgrep", tool="semgrep", rule="s1", line=10, cwe=("CWE-89",))
    codeql = finding("high", stage="sast-codeql", tool="codeql", rule="js/sql-injection", line=10, cwe=("CWE-89", "CWE-564"))
    merged = gate.dedupe([semgrep, codeql])
    assert len(merged) == 1
    assert merged[0]["severity"] == "high"
    assert merged[0]["tools"] == ["codeql", "semgrep"]
    assert merged[0]["stages"] == ["sast-codeql", "sast-semgrep"]
    assert merged[0]["cwe"] == ["CWE-564", "CWE-89"]
    assert set(merged[0]["merged_fingerprints"]) == {semgrep["fingerprint"], codeql["fingerprint"]}


def test_dedupe_overlapping_ranges_merge_but_distinct_ones_do_not():
    a = finding(tool="semgrep", line=10, end=14, rule="a")
    b = finding(tool="codeql", stage="sast-codeql", line=14, end=20, rule="b")
    far = finding(tool="eslint", stage="sast-eslint", line=30, rule="c")
    other_file = finding(tool="codeql", stage="sast-codeql", path="b.ts", line=12, rule="d")
    other_cwe = finding(tool="eslint", stage="sast-eslint", line=11, rule="e", cwe=("CWE-22",))
    merged = gate.dedupe([a, b, far, other_file, other_cwe])
    assert len(merged) == 4
    assert sorted(len(m["merged_fingerprints"]) for m in merged) == [1, 1, 1, 2]


def test_dedupe_needs_a_shared_cwe():
    a = finding(tool="semgrep", cwe=())
    b = finding(tool="codeql", stage="sast-codeql", cwe=())
    assert len(gate.dedupe([a, b])) == 2


def test_policy_extra_levels_can_only_tighten():
    base = ["critical", "high"]
    assert gate.effective_fail_on(base, ["medium"]) == ["critical", "high", "medium"]
    assert gate.effective_fail_on(base, None) == base
    assert gate.effective_fail_on(base, []) == base


def test_project_cannot_loosen_policy(tmp_path):
    for text in ("policy:\n  fail_on: [critical]\n", "policy:\n  fail_on_extra: [high]\n", "policy:\n  fail_on_extra: [critical]\n"):
        path = tmp_path / ".factory.yml"
        path.write_text(CONFIG + text)
        with pytest.raises(ConfigError):
            config.load(path)


def test_factory_policy_file_blocks_critical_and_high():
    assert gate.load_policy() == ["critical", "high"]


def test_high_finding_fails_gate(tmp_path):
    root, cfg = setup_run(tmp_path, {"sast-semgrep": [finding("high")]})
    assert run_gate(tmp_path, root, cfg, needs_for()) == 1
    result = result_of(tmp_path)
    assert result["status"] == "fail"
    assert result["counts"]["high"] == 1
    assert result["blocking_fingerprints"]


def test_medium_passes_unless_project_adds_it(tmp_path):
    items = {"sast-eslint": [finding("medium", stage="sast-eslint", tool="eslint")]}
    root, cfg = setup_run(tmp_path, items)
    assert run_gate(tmp_path, root, cfg, needs_for()) == 0
    root, cfg = setup_run(tmp_path, items, extra_config="policy:\n  fail_on_extra: [medium]\n")
    assert run_gate(tmp_path, root, cfg, needs_for()) == 1
    assert result_of(tmp_path)["fail_on"] == ["critical", "high", "medium"]


def test_missing_stage_artifact_fails_closed(tmp_path):
    root, cfg = setup_run(tmp_path, platform_stages=[s for s in WEB_STAGES if s != "sast-semgrep"])
    assert run_gate(tmp_path, root, cfg, needs_for()) == 1
    report = report_of(tmp_path)
    missing = [f for f in report if f["rule_id"] == "stage-missing"]
    assert len(missing) == 1
    assert missing[0]["severity"] == "critical" and missing[0]["source"] == "check"
    assert "sast-semgrep" in missing[0]["title"]
    rows = {r["stage"]: r["status"] for r in result_of(tmp_path)["stages"]}
    assert rows["sast-semgrep"] == "missing"


def test_missing_stage_fails_closed_without_needs(tmp_path):
    root, cfg = setup_run(tmp_path, platform_stages=[s for s in WEB_STAGES if s != "secrets"])
    assert run_gate(tmp_path, root, cfg) == 1
    assert any(f["rule_id"] == "stage-missing" for f in report_of(tmp_path))


def test_failed_job_is_stage_failed_even_with_findings_file(tmp_path):
    root, cfg = setup_run(tmp_path)
    assert run_gate(tmp_path, root, cfg, needs_for(secrets="failure")) == 1
    assert any(f["rule_id"] == "stage-failed" and f["severity"] == "critical" for f in report_of(tmp_path))


def test_invalid_findings_file_is_stage_failed(tmp_path):
    root, cfg = setup_run(tmp_path)
    (root / "deps-sbom" / "findings.json").write_text('[{"nope": 1}]')
    assert run_gate(tmp_path, root, cfg, needs_for()) == 1
    assert any(f["rule_id"] == "stage-failed" and "deps-sbom" in f["title"] for f in report_of(tmp_path))


def test_required_stage_cannot_be_skipped(tmp_path):
    root, cfg = setup_run(tmp_path)
    assert run_gate(tmp_path, root, cfg, needs_for(secrets="skipped")) == 1
    assert any(f["rule_id"] == "stage-missing" for f in report_of(tmp_path))


def test_extra_job_skipped_is_fine_but_extra_job_failure_blocks(tmp_path):
    root, cfg = setup_run(tmp_path)
    needs = needs_for()
    needs["hello-ai"] = {"result": "skipped"}
    assert run_gate(tmp_path, root, cfg, needs) == 0
    rows = {r["stage"]: r for r in result_of(tmp_path)["stages"]}
    assert rows["hello-ai"]["status"] == "skipped"
    needs["hello-ai"] = {"result": "failure"}
    assert run_gate(tmp_path, root, cfg, needs) == 1


def test_stage_matrix_skip_reason_is_allowed(tmp_path, monkeypatch):
    stages = tuple(dataclasses.replace(s, skippable=("fork-pr",)) if s.name == "sast-codeql" else s for s in stage_matrix.STAGES)
    monkeypatch.setattr(stage_matrix, "STAGES", stages)
    root, cfg = setup_run(tmp_path, platform_stages=[s for s in WEB_STAGES if s != "sast-codeql"])
    assert run_gate(tmp_path, root, cfg, needs_for(**{"sast-codeql": "skipped"})) == 0
    rows = {r["stage"]: r for r in result_of(tmp_path)["stages"]}
    assert rows["sast-codeql"]["status"] == "skipped" and rows["sast-codeql"]["detail"] == "fork-pr"


def test_empty_needs_is_rejected(tmp_path):
    root, cfg = setup_run(tmp_path)
    assert run_gate(tmp_path, root, cfg, {}) == 1


def test_unusable_manifest_fails_closed(tmp_path):
    root, cfg = setup_run(tmp_path)
    (root / "setup" / "run-manifest.json").write_text("{}")
    assert run_gate(tmp_path, root, cfg, needs_for()) == 1
    assert any("manifest" in r for r in result_of(tmp_path)["reasons"])


def suppression(fp, **over):
    entry = {"fingerprint": fp, "reason": "accepted risk", "expires": "2026-12-01", "approved_by": "AakashDadhich"}
    entry.update(over)
    return entry


def test_active_suppression_unblocks_but_stays_in_report(tmp_path):
    f = finding("high")
    extra = "suppressions:\n" + "".join(f"  - {k}: {v}\n" if i == 0 else f"    {k}: {v}\n" for i, (k, v) in enumerate(suppression(f["fingerprint"]).items()))
    root, cfg = setup_run(tmp_path, {"sast-semgrep": [f]}, extra_config=extra)
    assert run_gate(tmp_path, root, cfg, needs_for()) == 0
    report = report_of(tmp_path)
    assert len(report) == 1 and report[0]["suppressed"] is True
    assert report[0]["suppression"]["approved_by"] == "AakashDadhich"
    assert result_of(tmp_path)["suppressed"] == 1
    assert "### Suppressed" in (tmp_path / "out" / "report.md").read_text()
    sarif = json.loads((tmp_path / "out" / "merged.sarif").read_text())
    assert sarif["runs"][0]["results"][0]["suppressions"][0]["justification"] == "accepted risk"


def test_suppression_matches_any_merged_fingerprint():
    a = finding("high", tool="semgrep")
    b = finding("high", tool="codeql", stage="sast-codeql")
    merged = gate.dedupe([a, b])
    active, _ = gate.check_suppressions([suppression(b["fingerprint"])], TODAY)
    gate.apply_suppressions(merged, active)
    assert merged[0]["suppressed"]


def test_expired_suppression_is_ignored_and_reported():
    fp = "a" * 64
    active, problems = gate.check_suppressions([suppression(fp, expires="2026-10-28")], TODAY)
    assert active == {}
    assert len(problems) == 1
    assert problems[0]["severity"] == "medium" and problems[0]["source"] == "check"
    assert problems[0]["rule_id"].startswith("suppression-expired")


def test_suppression_expiring_today_is_still_active():
    active, problems = gate.check_suppressions([suppression("a" * 64, expires="2026-10-29")], TODAY)
    assert "a" * 64 in active and not problems


@pytest.mark.parametrize("entry", [
    "not a mapping",
    {"fingerprint": "a" * 64, "reason": "x", "expires": "2026-12-01"},
    {"fingerprint": "short", "reason": "x", "expires": "2026-12-01", "approved_by": "me"},
    {"fingerprint": "a" * 64, "reason": "", "expires": "2026-12-01", "approved_by": "me"},
    {"fingerprint": "a" * 64, "reason": "x", "expires": "next week", "approved_by": "me"},
    {"fingerprint": "a" * 64, "reason": "x", "expires": "2027-02-01", "approved_by": "me"},
])
def test_malformed_suppression_is_ignored_and_reported(entry):
    active, problems = gate.check_suppressions([entry], TODAY)
    assert active == {}
    assert len(problems) == 1 and problems[0]["rule_id"].startswith("suppression-invalid")


def test_suppression_ninety_days_ahead_is_allowed():
    last = (TODAY + datetime.timedelta(days=90)).isoformat()
    active, problems = gate.check_suppressions([suppression("b" * 64, expires=last)], TODAY)
    assert "b" * 64 in active and not problems


def test_stage_failures_cannot_be_suppressed(tmp_path):
    root, cfg = setup_run(tmp_path, platform_stages=[s for s in WEB_STAGES if s != "secrets"])
    problem = gate.problem_findings([{"stage": "secrets", "status": "missing", "detail": "x"}])[0]
    extra = f"suppressions:\n  - fingerprint: {problem['fingerprint']}\n    reason: nope\n    expires: 2026-12-01\n    approved_by: me\n"
    cfg.write_text(CONFIG + extra)
    assert run_gate(tmp_path, root, cfg, needs_for()) == 1


def test_bad_suppression_in_config_shows_up_in_report_and_blocks_only_with_medium(tmp_path):
    extra = "suppressions:\n  - fingerprint: bad\n"
    root, cfg = setup_run(tmp_path, extra_config=extra)
    assert run_gate(tmp_path, root, cfg, needs_for()) == 0
    assert any(f["rule_id"].startswith("suppression-invalid") for f in report_of(tmp_path))
    root, cfg = setup_run(tmp_path, extra_config=extra + "policy:\n  fail_on_extra: [medium]\n")
    assert run_gate(tmp_path, root, cfg, needs_for()) == 1


def test_markdown_escapes_table_cells(tmp_path):
    f = findings.make_finding(
        stage="sast-semgrep", tool="semgrep", source="scanner", rule_id="r", title="a | b\nc `x`", severity="low",
        location={"path": "a.ts", "start_line": 1},
    )
    root, cfg = setup_run(tmp_path, {"sast-semgrep": [f]})
    run_gate(tmp_path, root, cfg, needs_for())
    text = (tmp_path / "out" / "report.md").read_text()
    assert "a \\| b c 'x'" in text


def test_merged_sarif_is_valid_shape_with_security_severity(tmp_path):
    root, cfg = setup_run(tmp_path, {"sast-semgrep": [finding("high")], "deps-sbom": [finding("low", stage="deps-sbom", tool="osv-scanner", path="package-lock.json", line=None, cwe=())]})
    run_gate(tmp_path, root, cfg, needs_for())
    sarif = json.loads((tmp_path / "out" / "merged.sarif").read_text())
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert [r["level"] for r in results] == ["error", "note"]
    assert results[0]["properties"]["security-severity"] == "8.0"
    assert "region" not in results[1]["locations"][0]["physicalLocation"]
    assert {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]} == {"r1"}


def test_report_is_deterministic(tmp_path):
    items = {"sast-semgrep": [finding("high"), finding("low", rule="z", line=40)]}
    root, cfg = setup_run(tmp_path, items)
    run_gate(tmp_path, root, cfg, needs_for())
    first = (tmp_path / "out" / "report.json").read_text()
    run_gate(tmp_path, root, cfg, needs_for())
    assert (tmp_path / "out" / "report.json").read_text() == first


def test_policy_file_must_be_valid(tmp_path):
    bad = tmp_path / "policy.yml"
    bad.write_text("fail_on: [loud]\n")
    with pytest.raises(gate.PolicyError):
        gate.load_policy(bad)


SPEC_STAGES = [s.name for s in stage_matrix.expected("web", "spec")]


def review_finding(severity="high"):
    return finding(severity, stage="review", tool="claude-code", rule="review-cwe-89", path="src/notes.ts", line=50, cwe=("CWE-89",), source="ai-review")


def test_report_has_a_review_section_that_is_empty_when_nothing_was_found(tmp_path):
    root, cfg = setup_run(tmp_path, platform_stages=SPEC_STAGES, mode="spec")
    assert run_gate(tmp_path, root, cfg, needs_for(SPEC_STAGES)) == 0
    assert "### Review\n\nNone.\n" in (tmp_path / "out" / "report.md").read_text()


def test_review_findings_are_listed_in_the_review_section_and_block_the_gate(tmp_path):
    root, cfg = setup_run(tmp_path, {"review": [review_finding("high")]}, platform_stages=SPEC_STAGES, mode="spec")
    assert run_gate(tmp_path, root, cfg, needs_for(SPEC_STAGES)) == 1
    section = (tmp_path / "out" / "report.md").read_text().split("### Review")[1].split("### Findings")[0]
    assert "src/notes.ts:50" in section and "high" in section
    assert result_of(tmp_path)["status"] == "fail"


def test_missing_review_artifact_fails_closed_in_spec_mode(tmp_path):
    present = [s for s in SPEC_STAGES if s != "review"]
    root, cfg = setup_run(tmp_path, platform_stages=present, mode="spec")
    assert run_gate(tmp_path, root, cfg, needs_for(SPEC_STAGES)) == 1
    rows = {r["stage"]: r["status"] for r in result_of(tmp_path)["stages"]}
    assert rows["review"] == "missing"
