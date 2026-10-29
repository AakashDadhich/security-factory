import json
import shutil
import sys
from pathlib import Path

import pytest

from factory import findings
from factory.stages import plan, threat_model

REPO = Path(__file__).resolve().parent.parent
FAKE = REPO / "tests" / "fixtures" / "fake"
TM_FIXTURES = REPO / "tests" / "fixtures" / "threat-model"
DIFF = "diff --git a/src/app.ts b/src/app.ts\n+app.get('/notes', handler)\n"


@pytest.fixture
def fake_pytm(tmp_path) -> Path:
    wrapper = tmp_path / "fake-python"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{TM_FIXTURES / "fake_pytm.py"}" "$@"\n')
    wrapper.chmod(0o755)
    return wrapper


@pytest.fixture
def project(tmp_path, monkeypatch) -> Path:
    monkeypatch.setenv("FACTORY_MODEL_ADAPTER", "fake")
    responses = tmp_path / "responses"
    responses.mkdir()
    for name in ("threat-model-pytm.json", "threat-model-stride.json", "threat-model-linddun.json",
                 "threat-model-attack-tree-f1.json"):
        shutil.copy(FAKE / name, responses / name)
    monkeypatch.setenv("FACTORY_FAKE_RESPONSES", str(responses))
    root = tmp_path / "project"
    root.mkdir()
    reply = json.loads((FAKE / "plan.json").read_text())
    for feature in reply["features"]:
        feature["risk"] = "high" if feature["id"] == "F1" else "low"
    (root / "plan.json").write_text(json.dumps(plan.finalize(reply, None) | {"personal_data": True}))
    (root / "diff.patch").write_text(DIFF)
    return root


def run_with(project, python, *flags, out="out", previous="security"):
    return threat_model.main([
        *flags, "--out", str(project / out), "--previous", str(project / previous),
        "--pytm-python", str(python), "--workdir", str(project), "--sandbox", "none",
    ])


def test_bootstraps_a_model_from_the_code_without_a_plan(project, fake_pytm):
    assert run_with(project, fake_pytm, "--diff", str(project / "diff.patch")) == 0
    out = project / "out"
    doc = json.loads((out / "threats.json").read_text())
    assert doc["threats"] and {t["framework"] for t in doc["threats"]} == {"stride"}
    assert not list(findings.validator("threats.schema.json").iter_errors(doc))
    passes = json.loads((out / "passes.json").read_text())
    assert passes["stride"]["status"] == "ran"
    assert passes["linddun"]["status"] == "skipped" and passes["attack-trees"]["status"] == "skipped"
    assert not (out / "attack-trees").exists()
    assert findings.load(out / "findings.json")


def test_updating_without_a_plan_keeps_linddun_and_attack_tree_threats(project, fake_pytm):
    assert run_with(project, fake_pytm, "--plan", str(project / "plan.json"), out="first") == 0
    first = project / "first"
    before = json.loads((first / "threats.json").read_text())
    assert {t["framework"] for t in before["threats"]} == {"stride", "linddun", "attack-tree"}
    security = project / "security"
    security.mkdir()
    shutil.copy(first / "tm.py", security / "tm.py")
    shutil.copy(first / "threats.json", security / "threats.json")

    assert run_with(project, fake_pytm, "--diff", str(project / "diff.patch"), out="second") == 0
    after = json.loads((project / "second" / "threats.json").read_text())
    by_id = lambda doc: sorted(doc["threats"], key=lambda t: t["id"])
    assert by_id(after) == by_id(before)
    assert after["removed"] == []


def test_the_update_passes_the_diff_and_previous_files_to_the_model(project, fake_pytm, monkeypatch):
    seen = []
    from factory import adapter
    real = adapter.run_stage

    def spy(**kwargs):
        seen.append((kwargs["stage"], [p.name for p in kwargs["inputs"]]))
        return real(**kwargs)

    monkeypatch.setattr(adapter, "run_stage", spy)
    security = project / "security"
    security.mkdir()
    assert run_with(project, fake_pytm, "--plan", str(project / "plan.json"), out="first") == 0
    shutil.copy(project / "first" / "tm.py", security / "tm.py")
    shutil.copy(project / "first" / "threats.json", security / "threats.json")
    seen.clear()
    assert run_with(project, fake_pytm, "--diff", str(project / "diff.patch"), out="second") == 0
    inputs = dict(seen)
    assert inputs["threat-model-pytm"] == ["diff.patch", "tm.py", "threats.json"]
    assert inputs["threat-model-stride"] == ["elements.json", "diff.patch", "threats.json"]
    assert "threat-model-linddun" not in inputs


@pytest.mark.parametrize("flags", [[], ["--plan", "p.json", "--diff", "d.patch"]])
def test_exactly_one_of_plan_and_diff_is_required(project, fake_pytm, flags):
    with pytest.raises(SystemExit):
        run_with(project, fake_pytm, *flags)


def test_run_needs_a_plan_or_a_diff(project, fake_pytm):
    with pytest.raises(threat_model.ThreatModelError):
        threat_model.run(None, project / "out", None, fake_pytm, project, image=None)
