import json
import shutil
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from factory import findings, rules
from factory.stages import plan, threat_model
from factory.threatmodel import attack_tree

REPO = Path(__file__).resolve().parent.parent
FAKE = REPO / "tests" / "fixtures" / "fake"
TM_FIXTURES = REPO / "tests" / "fixtures" / "threat-model"
SNAPSHOT = REPO / "tests" / "snapshots" / "attack-tree-F1.md"
NAMES = ["Internet", "Server", "User", "Web app", "Notes DB", "Sign-in request", "Create note request", "Store note",
         "Read notes", "Notes response"]


def tree_reply(goal: str | None = None) -> dict:
    reply = json.loads((FAKE / "threat-model-attack-tree-f1.json").read_text())
    if goal:
        reply["root"]["goal"] = goal
    return reply


@pytest.fixture
def fake_pytm(tmp_path) -> Path:
    wrapper = tmp_path / "fake-python"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{TM_FIXTURES / "fake_pytm.py"}" "$@"\n')
    wrapper.chmod(0o755)
    return wrapper


def make_plan(root: Path, personal_data: bool, high_risk: list[str]) -> None:
    reply = json.loads((FAKE / "plan.json").read_text())
    for feature in reply["features"]:
        feature["risk"] = "high" if feature["id"] in high_risk else "low"
    final = plan.finalize(reply, None) | {"personal_data": personal_data}
    assert final["high_risk_features"] == high_risk
    (root / "plan.json").write_text(json.dumps(final))


@pytest.fixture
def responses(tmp_path, monkeypatch) -> Path:
    monkeypatch.setenv("FACTORY_MODEL_ADAPTER", "fake")
    responses = tmp_path / "responses"
    responses.mkdir()
    for name in ("threat-model-pytm.json", "threat-model-stride.json", "threat-model-linddun.json",
                 "threat-model-attack-tree-f1.json"):
        shutil.copy(FAKE / name, responses / name)
    (responses / "threat-model-attack-tree-f2.json").write_text(json.dumps(tree_reply("Read another user's notes.")))
    monkeypatch.setenv("FACTORY_FAKE_RESPONSES", str(responses))
    return responses


@pytest.fixture
def project(tmp_path, responses) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    make_plan(root, True, ["F1"])
    return root


def run_stage(project, python, out_name="out", previous="security"):
    out = project / out_name
    code = threat_model.main([
        "--plan", str(project / "plan.json"), "--out", str(out), "--previous", str(project / previous),
        "--pytm-python", str(python), "--workdir", str(project), "--sandbox", "none",
    ])
    return code, out


def load(out: Path, name="threats.json") -> dict:
    return json.loads((out / name).read_text())


def by_framework(doc: dict, framework: str) -> list[dict]:
    return [t for t in doc["threats"] if t["framework"] == framework]


def test_both_passes_run_when_triggered(project, fake_pytm):
    code, out = run_stage(project, fake_pytm)
    assert code == 0
    doc = load(out)
    assert not list(findings.validator("threats.schema.json").iter_errors(doc))
    assert [t["id"] for t in by_framework(doc, "stride")] == ["TM-001", "TM-002", "TM-003", "TM-004"]
    linddun = by_framework(doc, "linddun")
    assert [t["id"] for t in linddun] == ["TM-005", "TM-006", "TM-007"]
    assert {t["category"] for t in linddun} == {"linking", "unawareness", "non-compliance"}
    trees = by_framework(doc, "attack-tree")
    assert [t["id"] for t in trees] == ["TM-008", "TM-009", "TM-010"]
    assert {t["category"] for t in trees} == {"F1"}
    passes = load(out, "passes.json")
    assert passes["stride"]["status"] == "ran"
    assert passes["linddun"]["status"] == "ran"
    assert passes["attack-trees"]["status"] == "ran"
    assert passes["attack-trees"]["features"] == ["F1"]


def test_linddun_is_skipped_without_personal_data(project, responses, fake_pytm):
    make_plan(project, False, ["F1"])
    (responses / "threat-model-linddun.json").unlink()
    code, out = run_stage(project, fake_pytm)
    assert code == 0
    assert by_framework(load(out), "linddun") == []
    passes = load(out, "passes.json")
    assert passes["linddun"]["status"] == "skipped"
    assert "personal data" in passes["linddun"]["reason"]
    assert passes["attack-trees"]["status"] == "ran"
    assert not (out / "linddun-reply.json").exists()


def test_attack_trees_are_skipped_without_high_risk_features(project, responses, fake_pytm):
    make_plan(project, True, [])
    for name in ("f1", "f2"):
        (responses / f"threat-model-attack-tree-{name}.json").unlink()
    code, out = run_stage(project, fake_pytm)
    assert code == 0
    assert by_framework(load(out), "attack-tree") == []
    passes = load(out, "passes.json")
    assert passes["attack-trees"]["status"] == "skipped"
    assert "high-risk" in passes["attack-trees"]["reason"]
    assert passes["linddun"]["status"] == "ran"
    assert not (out / "attack-trees").exists()


def test_low_risk_plan_skips_both_passes(project, responses, fake_pytm):
    make_plan(project, False, [])
    for name in ("threat-model-linddun", "threat-model-attack-tree-f1", "threat-model-attack-tree-f2"):
        (responses / f"{name}.json").unlink(missing_ok=True)
    code, out = run_stage(project, fake_pytm)
    assert code == 0
    passes = load(out, "passes.json")
    assert {k: v["status"] for k, v in passes.items()} == {"stride": "ran", "linddun": "skipped", "attack-trees": "skipped"}
    assert {t["framework"] for t in load(out)["threats"]} == {"stride"}


def test_one_attack_tree_per_high_risk_feature(project, fake_pytm):
    make_plan(project, True, ["F1", "F2"])
    code, out = run_stage(project, fake_pytm)
    assert code == 0
    folder = out / "attack-trees"
    assert sorted(p.name for p in folder.glob("*.md")) == ["F1.md", "F2.md"]
    assert sorted(p.name for p in folder.glob("*.json") if not p.name.endswith(("reply.json", "schema.json", "feature.json"))
                  ) == ["F1.json", "F2.json"]
    assert "Read another user's notes." in (folder / "F2.md").read_text()
    doc = load(out)
    assert {t["category"] for t in by_framework(doc, "attack-tree")} == {"F1", "F2"}
    assert len(by_framework(doc, "attack-tree")) == 6
    assert load(out, "passes.json")["attack-trees"]["features"] == ["F1", "F2"]
    assert (folder / "F1.feature.json").is_file() and (folder / "F2.feature.json").is_file()


def test_missing_reply_for_a_feature_fails_the_stage(project, responses, fake_pytm):
    make_plan(project, True, ["F1", "F2"])
    (responses / "threat-model-attack-tree-f2.json").unlink()
    code, out = run_stage(project, fake_pytm)
    assert code == 1
    assert not (out / "threats.json").exists()


def test_mermaid_rendering_matches_the_snapshot(project, fake_pytm):
    code, out = run_stage(project, fake_pytm)
    assert code == 0
    text = (out / "attack-trees" / "F1.md").read_text()
    assert text == SNAPSHOT.read_text()
    assert "```mermaid\nflowchart TD" in text


def test_rendering_is_deterministic():
    tree = {"feature_id": "F1", "root": tree_reply()["root"]}
    assert attack_tree.render_markdown(tree, "Sign in") == attack_tree.render_markdown(tree, "Sign in")


def test_labels_cannot_break_out_of_the_diagram():
    root = tree_reply()["root"]
    root["goal"] = 'Take "over" <b>an</b> account `now` #1 & more'
    tree = {"feature_id": "F1", "root": root}
    text = attack_tree.render_markdown(tree, "Sign\n```\nin")
    assert text.count("```") == 2
    diagram = text.split("```mermaid\n")[1]
    assert "#quot;over#quot;" in diagram and "#lt;b#gt;" in diagram and "#35;1" in diagram and "#amp;" in diagram
    assert "<b>" not in diagram and '"over"' not in diagram
    assert text.splitlines()[0] == "# Attack tree: Sign ''' in (F1)"


def test_flattened_leaves_validate_against_the_threats_schema(project, fake_pytm):
    code, out = run_stage(project, fake_pytm)
    assert code == 0
    doc = load(out)
    assert not list(findings.validator("threats.schema.json").iter_errors(doc))
    trees = by_framework(doc, "attack-tree")
    tree = load(out / "attack-trees", "F1.json")
    assert not list(findings.validator("attack-tree.schema.json").iter_errors(tree))
    assert [leaf["leaf_threat_id"] for leaf in attack_tree.leaves(tree)] == [t["id"] for t in trees]
    assert [t["title"] for t in trees] == [leaf["goal"] for leaf in attack_tree.leaves(tree)]
    for threat in trees:
        assert threat["status"] == "open"
        assert threat["mitigations"] and all(m["asvs_refs"] for m in threat["mitigations"])
    assert trees[1]["severity"] == "critical"
    assert trees[1]["mitigations"][0]["id"] == "TM-009-M1"
    assert "previous_id" not in json.dumps(tree)
    assert len(rules.load_threats(out / "threats.json")) == 10


def test_findings_cover_every_open_threat(project, fake_pytm):
    code, out = run_stage(project, fake_pytm)
    assert code == 0
    emitted = findings.load(out / "findings.json")
    assert [f["rule_id"] for f in emitted] == [f"TM-{n:03d}" for n in range(1, 11)]
    assert {f["severity"] for f in emitted} == {"info"}
    titles = {f["rule_id"]: f["title"] for f in emitted}
    assert titles["TM-005"].startswith("Linking: ")
    assert titles["TM-008"] == "Attack tree F1: Obtain leaked email and password pairs"


def test_ids_stay_stable_and_skipped_passes_move_threats_to_removed(project, fake_pytm):
    code, first = run_stage(project, fake_pytm, "first")
    assert code == 0
    security = project / "security"
    security.mkdir()
    for name in ("tm.py", "threats.json"):
        shutil.copy(first / name, security / name)

    code, second = run_stage(project, fake_pytm, "second")
    assert code == 0
    assert load(second)["threats"] == load(first)["threats"]
    assert load(second)["removed"] == []

    make_plan(project, False, [])
    code, third = run_stage(project, fake_pytm, "third")
    assert code == 0
    doc = load(third)
    assert [t["id"] for t in doc["threats"]] == ["TM-001", "TM-002", "TM-003", "TM-004"]
    assert sorted(t["id"] for t in doc["removed"]) == [f"TM-{n:03d}" for n in range(5, 11)]

    make_plan(project, True, ["F1"])
    shutil.copy(third / "threats.json", security / "threats.json")
    code, fourth = run_stage(project, fake_pytm, "fourth")
    assert code == 0
    new_ids = [t["id"] for t in load(fourth)["threats"] if t["framework"] != "stride"]
    assert new_ids == [f"TM-{n:03d}" for n in range(11, 17)]


def test_previous_id_keeps_a_renamed_leaf(project, responses, fake_pytm):
    code, first = run_stage(project, fake_pytm, "first")
    assert code == 0
    security = project / "security"
    security.mkdir()
    for name in ("tm.py", "threats.json"):
        shutil.copy(first / name, security / name)
    reply = tree_reply()
    leaf = reply["root"]["children"][1]
    leaf["goal"] = "Read the session cookie from a script"
    leaf["previous_id"] = "TM-010"
    (responses / "threat-model-attack-tree-f1.json").write_text(json.dumps(reply))
    code, second = run_stage(project, fake_pytm, "second")
    assert code == 0
    trees = by_framework(load(second), "attack-tree")
    assert [t["id"] for t in trees] == ["TM-008", "TM-009", "TM-010"]
    assert trees[2]["title"] == "Read the session cookie from a script"


def test_attack_tree_reply_schema_pins_goal_elements_and_asvs():
    asvs = threat_model.asvs_ids()
    validator = Draft202012Validator(attack_tree.reply_schema(["Take over an account."], NAMES, asvs))
    assert not list(validator.iter_errors(tree_reply()))

    def changed(edit):
        reply = tree_reply()
        edit(reply["root"])
        return reply

    for edit in (
        lambda r: r.update(goal="Something else"),
        lambda r: r["children"][1].update(element="Ghost"),
        lambda r: r["children"][1]["mitigations"][0].update(asvs_refs=["V99.9.9"]),
        lambda r: r["children"][1].update(mitigations=[]),
        lambda r: r["children"][1].pop("likelihood"),
        lambda r: r["children"][1].update(leaf_threat_id="TM-001"),
        lambda r: r["children"][1].update(type="xor"),
        lambda r: r.update(goal="# Heading"),
        lambda r: r["children"][0]["children"][0].update(children=[{"goal": "x"}]),
        lambda r: r["children"].extend(json.loads(json.dumps(r["children"][1])) for _ in range(8)),
    ):
        assert list(validator.iter_errors(changed(edit))), edit
    nested_goal = tree_reply()
    nested_goal["root"]["children"][0]["goal"] = "Any wording is fine below the root"
    assert not list(validator.iter_errors(nested_goal))


def test_tree_schema_text_rule_matches_the_threat_text_rule():
    rule = attack_tree.base_schema()["$defs"]["rules_text"]
    assert rule["pattern"] == threat_model.RULES_TEXT["pattern"]
    assert rule["maxLength"] == threat_model.RULES_TEXT["maxLength"]


def deep_tree(levels: int) -> dict:
    node = tree_reply()["root"]["children"][1]
    for _ in range(levels - 2):
        node = {"goal": "Step", "type": "or", "children": [node], "mitigations": []}
    return {"feature_id": "F1", "root": {"goal": "Take over an account.", "type": "or", "children": [node], "mitigations": []}}


def test_shape_limits():
    attack_tree.check_shape(deep_tree(attack_tree.MAX_DEPTH))
    with pytest.raises(attack_tree.AttackTreeError, match="levels deep"):
        attack_tree.check_shape(deep_tree(attack_tree.MAX_DEPTH + 1))
    wide = tree_reply()["root"]
    wide["children"] = [{"goal": f"Branch {i}", "type": "or", "mitigations": [], "children": [
        json.loads(json.dumps(tree_reply()["root"]["children"][1])) for _ in range(5)]} for i in range(8)]
    with pytest.raises(attack_tree.AttackTreeError, match="nodes"):
        attack_tree.check_shape({"feature_id": "F1", "root": wide})
    with pytest.raises(attack_tree.AttackTreeError, match="no steps"):
        attack_tree.check_shape({"feature_id": "F1", "root": {"goal": "g", "type": "or", "children": [], "mitigations": []}})


def test_too_deep_tree_fails_the_stage(project, responses, fake_pytm):
    (responses / "threat-model-attack-tree-f1.json").write_text(json.dumps({"root": deep_tree(6)["root"]}))
    code, out = run_stage(project, fake_pytm)
    assert code == 1
    assert not (out / "threats.json").exists()


def test_high_risk_feature_without_abuse_case_is_an_error(project, fake_pytm):
    document = json.loads((project / "plan.json").read_text())
    document["abuse_cases"] = [a for a in document["abuse_cases"] if a["feature_id"] != "F1"]
    (project / "plan.json").write_text(json.dumps(document))
    code, _ = run_stage(project, fake_pytm)
    assert code == 1


def test_linddun_reply_schema_has_the_seven_categories():
    schema = threat_model.linddun_reply_schema(NAMES, threat_model.asvs_ids())
    validator = Draft202012Validator(schema)
    reply = json.loads((FAKE / "threat-model-linddun.json").read_text())
    assert not list(validator.iter_errors(reply))
    assert len(threat_model.LINDDUN) == 7
    reply["threats"][0]["category"] = "spoofing"
    assert list(validator.iter_errors(reply))


def test_threats_schema_restricts_linddun_categories():
    doc = threat_model.merge(json.loads((FAKE / "threat-model-linddun.json").read_text())["threats"], None, "0" * 64, "linddun")
    validator = findings.validator("threats.schema.json")
    assert not list(validator.iter_errors(doc))
    doc["threats"][0]["category"] = "tampering"
    assert list(validator.iter_errors(doc))
