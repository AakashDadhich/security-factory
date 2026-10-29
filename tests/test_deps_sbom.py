import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from factory import findings, sbom
from factory.stages import deps_sbom as stage

FIXTURES = Path(__file__).parent / "fixtures" / "deps"


def entries(name: str, tool: str) -> list[dict]:
    return stage.load_results(FIXTURES / name, tool)


def merged() -> list:
    return stage.merge(entries("osv.sarif", stage.OSV), entries("grype.sarif", stage.GRYPE))


def test_same_vulnerability_from_both_tools_becomes_one_finding():
    osv, grype = entries("osv.sarif", stage.OSV), entries("grype.sarif", stage.GRYPE)
    express = [e for e in osv if e["package"][0] == "express"] + [e for e in grype if e["package"][0] == "express"]
    assert len(express) == 2
    result = stage.merge(osv, grype)
    assert len([f for f in result if "express" in f["description"]]) == 1


def test_merged_finding_has_combined_tool_and_higher_severity():
    result = [f for f in merged() if f["tool"] == stage.MERGED_TOOL]
    assert len(result) == 1
    assert result[0]["severity"] == "high"
    assert result[0]["rule_id"] == "GHSA-rv95-896h-c2vc"


def test_unmatched_results_keep_their_own_tool():
    by_tool = {f["tool"] for f in merged()}
    assert by_tool == {stage.MERGED_TOOL, stage.OSV, stage.GRYPE}
    assert len(merged()) == 3


def test_alias_in_message_links_ghsa_to_cve():
    osv = entries("osv.sarif", stage.OSV)[0]
    assert {"GHSA-RV95-896H-C2VC", "CVE-2024-29041"} <= osv["ids"]


def test_different_version_is_not_merged():
    osv, grype = entries("osv.sarif", stage.OSV), entries("grype.sarif", stage.GRYPE)
    for g in grype:
        if g["package"][0] == "express":
            g["package"] = ("express", "4.18.0")
    assert len(stage.merge(osv, grype)) == 4


def test_no_overlapping_id_is_not_merged():
    osv, grype = entries("osv.sarif", stage.OSV), entries("grype.sarif", stage.GRYPE)
    for g in grype:
        g["ids"] = {"CVE-2000-0001"}
    assert len(stage.merge(osv, grype)) == 4


def test_unparseable_package_is_never_merged():
    osv, grype = entries("osv.sarif", stage.OSV), entries("grype.sarif", stage.GRYPE)
    grype[0]["package"] = None
    assert len(stage.merge(osv, grype)) == 4


def test_merge_output_validates_and_is_stable():
    first, second = merged(), merged()
    assert findings.dumps(first) == findings.dumps(second)
    findings.validate(first)


def test_merge_with_one_side_empty_returns_the_other():
    assert len(stage.merge(entries("osv.sarif", stage.OSV), [])) == 2
    assert len(stage.merge([], entries("grype.sarif", stage.GRYPE))) == 2


def test_package_parsing():
    assert stage.package_of(stage.OSV, "Package '@types/node@20.1.0' is vulnerable to 'X'") == ("@types/node", "20.1.0")
    assert stage.package_of(stage.GRYPE, "A High vulnerability in npm package: express, version 4.17.1 was found at: /x") == ("express", "4.17.1")
    assert stage.package_of(stage.OSV, "something else") is None


def test_vuln_id_extraction_normalises_case():
    assert stage.vuln_ids("see ghsa-rv95-896h-c2vc and cve-2024-1234") == {"GHSA-RV95-896H-C2VC", "CVE-2024-1234"}


def test_load_results_rejects_non_sarif(tmp_path):
    bad = tmp_path / "bad.sarif"
    bad.write_text("{}")
    with pytest.raises(findings.FindingsError, match="not a SARIF log"):
        stage.load_results(bad, stage.OSV)


def test_grype_db_meta_reads_build_date():
    meta = stage.grype_db_meta((FIXTURES / "grype-db-status.json").read_text())
    assert meta["built"] == "2026-10-28T01:32:07Z"


def test_grype_db_meta_keeps_raw_text_when_not_json():
    meta = stage.grype_db_meta("Built: today")
    assert meta["built"] is None and meta["raw"] == "Built: today"


class FakeTools:
    def __init__(self, osv_exit=1, syft_exit=0, grype_exit=0, status_built=True):
        self.osv_exit, self.syft_exit, self.grype_exit, self.status_built = osv_exit, syft_exit, grype_exit, status_built
        self.calls = []

    def __call__(self, cmd, env=None, stdout=None, capture_output=False, text=False):
        self.calls.append(cmd)
        name = Path(cmd[0]).name
        if name == "osv-scanner":
            if self.osv_exit in (0, 1):
                stdout.write((FIXTURES / "osv.sarif").read_text())
            return SimpleNamespace(returncode=self.osv_exit)
        if name == "syft":
            output = [a for a in cmd if a.startswith("cyclonedx-json=")][0].split("=", 1)[1]
            shutil.copyfile(FIXTURES / "sbom.cdx.json", output)
            return SimpleNamespace(returncode=self.syft_exit)
        if cmd[1:3] == ["db", "update"]:
            return SimpleNamespace(returncode=0)
        if cmd[1:3] == ["db", "status"]:
            out = (FIXTURES / "grype-db-status.json").read_text() if self.status_built else "{}"
            return SimpleNamespace(returncode=0, stdout=out)
        report = [a for a in cmd if a.startswith("sarif=")][0].split("=", 1)[1]
        shutil.copyfile(FIXTURES / "grype.sarif", report)
        return SimpleNamespace(returncode=self.grype_exit)


def test_run_writes_all_outputs(tmp_path):
    result = stage.run(tmp_path, tmp_path / "out", runner=FakeTools())
    out = tmp_path / "out"
    assert len(result) == 3
    assert findings.load(out / "findings.json") == result
    assert json.loads((out / "tool-meta.json").read_text())["grype"]["db"]["built"] == "2026-10-28T01:32:07Z"
    assert any(c["name"] == "express" for c in sbom.components(out / "sbom.cdx.json"))
    assert not (out / "sbom-image.cdx.json").exists()


def test_run_writes_image_sbom_when_image_given(tmp_path):
    tools = FakeTools()
    stage.run(tmp_path, tmp_path / "out", image="factory-test-web:ci", runner=tools)
    assert (tmp_path / "out" / "sbom-image.cdx.json").is_file()
    assert any(c[1:3] == ["scan", "factory-test-web:ci"] for c in tools.calls)


def test_osv_exit_one_counts_as_findings_not_failure(tmp_path):
    assert stage.run(tmp_path, tmp_path / "out", runner=FakeTools(osv_exit=1))


def test_osv_exit_zero_is_fine(tmp_path):
    assert stage.run(tmp_path, tmp_path / "out", runner=FakeTools(osv_exit=0))


def test_osv_no_packages_yields_empty_osv_side(tmp_path):
    result = stage.run(tmp_path, tmp_path / "out", runner=FakeTools(osv_exit=128))
    assert {f["tool"] for f in result} == {stage.GRYPE}


def test_osv_other_exit_codes_fail(tmp_path):
    with pytest.raises(stage.StageError, match="osv-scanner failed with exit code 127"):
        stage.run(tmp_path, tmp_path / "out", runner=FakeTools(osv_exit=127))


def test_syft_failure_fails(tmp_path):
    with pytest.raises(stage.StageError, match="syft failed"):
        stage.run(tmp_path, tmp_path / "out", runner=FakeTools(syft_exit=1))


def test_grype_failure_fails(tmp_path):
    with pytest.raises(stage.StageError, match="grype failed"):
        stage.run(tmp_path, tmp_path / "out", runner=FakeTools(grype_exit=2))


def test_missing_db_date_fails(tmp_path):
    with pytest.raises(stage.StageError, match="build date"):
        stage.run(tmp_path, tmp_path / "out", runner=FakeTools(status_built=False))


def test_missing_binary_names_the_installer(tmp_path):
    def missing(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])

    with pytest.raises(stage.StageError, match="python -m factory.tools install osv-scanner"):
        stage.run(tmp_path, tmp_path / "out", runner=missing)


def test_main_returns_one_on_stage_error(tmp_path, capsys, monkeypatch):
    def boom(*a, **k):
        raise stage.StageError("nope")

    monkeypatch.setattr(stage, "run", boom)
    assert stage.main(["--src", str(tmp_path), "--out", str(tmp_path / "o")]) == 1
    assert "error: nope" in capsys.readouterr().err


def test_osv_skips_the_factory_checkout_and_vendored_dirs(tmp_path):
    tools = FakeTools()
    stage.run(tmp_path, tmp_path / "out", runner=tools)
    osv_cmd = tools.calls[0]
    excluded = [osv_cmd[i + 1] for i, a in enumerate(osv_cmd) if a == "--x-exclude"]
    assert ".factory" in excluded and "node_modules" in excluded


def test_absolute_paths_are_made_relative_to_the_source_root(tmp_path):
    report = tmp_path / "osv.sarif"
    log = json.loads((FIXTURES / "osv.sarif").read_text())
    for result in log["runs"][0]["results"]:
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = f"{tmp_path.resolve()}/app/package-lock.json"
    report.write_text(json.dumps(log))
    paths = {e["finding"]["location"]["path"] for e in stage.load_results(report, stage.OSV, tmp_path)}
    assert paths == {"app/package-lock.json"}
