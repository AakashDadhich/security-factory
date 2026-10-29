import argparse
import hashlib
import json
import sys
from pathlib import Path

from factory import adapter, findings, rules, tools
from factory.adapter import READ_TOOLS, AdapterError
from factory.threatmodel import attack_tree, pytm_runner
from factory.threatmodel.pytm_runner import RunnerError

STAGE = "threat-model"
STRIDE_STAGE = "threat-model-stride"
FACTORY_ROOT = Path(__file__).resolve().parents[2]
STRIDE_PROMPT = FACTORY_ROOT / "prompts" / "threat-model-stride.md"
LINDDUN_STAGE = "threat-model-linddun"
LINDDUN_PROMPT = FACTORY_ROOT / "prompts" / "threat-model-linddun.md"
ATTACK_TREE_STAGE = "threat-model-attack-tree"
ATTACK_TREE_PROMPT = FACTORY_ROOT / "prompts" / "attack-tree.md"
ATTACK_TREE_SCHEMA = "attack-tree.schema.json"
ASVS = FACTORY_ROOT / "rules" / "asvs" / "asvs.json"
THREATS_SCHEMA = "threats.schema.json"
FRAMEWORK = "stride"
LINDDUN_FRAMEWORK = "linddun"
ATTACK_TREE_FRAMEWORK = "attack-tree"
ID_PREFIX = "TM"
STRIDE = ("spoofing", "tampering", "repudiation", "information-disclosure", "denial-of-service", "elevation-of-privilege")
LINDDUN = ("linking", "identifying", "non-repudiation", "detecting", "data-disclosure", "unawareness", "non-compliance")
LEVELS = {"low": 1, "medium": 2, "high": 3}
FINDING_PATH = "security/threats.json"
# Titles and mitigation texts are rendered into CLAUDE.md by factory.rules, which refuses
# Markdown structure at the start, comment or fence markers, and more than 500 characters.
RULES_TEXT = {
    "type": "string",
    "maxLength": 400,
    "pattern": r"^(?![\s\S]*(<!--|```))\s*(?![#>`|*+-]|\d+[.)]\s)\S",
}


class ThreatModelError(Exception):
    pass


def asvs_ids() -> list[str]:
    return [r["id"] for r in json.loads(ASVS.read_text())]


def stride_reply_schema(names: list[str], asvs: list[str]) -> dict:
    return reply_schema(STRIDE, names, asvs)


def linddun_reply_schema(names: list[str], asvs: list[str]) -> dict:
    return reply_schema(LINDDUN, names, asvs)


def reply_schema(categories: tuple[str, ...], names: list[str], asvs: list[str]) -> dict:
    text = {"type": "string", "minLength": 1}
    level = {"enum": list(LEVELS)}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": ["threats"],
        "properties": {"threats": {"type": "array", "minItems": 1, "items": {
            "type": "object",
            "additionalProperties": False,
            "required": ["previous_id", "category", "element", "title", "description", "likelihood", "impact",
                         "mitigations", "status"],
            "properties": {
                "previous_id": {"type": ["string", "null"]},
                "category": {"enum": list(categories)},
                "element": {"enum": names},
                "title": RULES_TEXT,
                "description": text,
                "likelihood": level,
                "impact": level,
                "mitigations": {"type": "array", "minItems": 1, "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["text", "asvs_refs"],
                    "properties": {"text": RULES_TEXT, "asvs_refs": {"type": "array", "minItems": 1, "items": {"enum": asvs}}},
                }},
                "status": {"enum": ["open", "mitigated"]},
                "evidence": text,
            },
            "if": {"properties": {"status": {"const": "mitigated"}}},
            "then": {"required": ["evidence"]},
        }}},
    }


def severity(likelihood: str, impact: str) -> str:
    score = LEVELS[likelihood] * LEVELS[impact]
    if score >= 9:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def _number(threat_id: str) -> int:
    prefix, _, number = threat_id.rpartition("-")
    return int(number) if prefix == ID_PREFIX and number.isdigit() else 0


def _key(threat: dict) -> tuple:
    return threat["category"], threat["element"], " ".join(threat["title"].casefold().split())


def _finalize(threat: dict, threat_id: str, framework: str) -> dict:
    result = {
        "id": threat_id,
        "framework": framework,
        "category": threat["category"],
        "element": threat["element"],
        "title": threat["title"],
        "description": threat["description"],
        "likelihood": threat["likelihood"],
        "impact": threat["impact"],
        "severity": severity(threat["likelihood"], threat["impact"]),
        "mitigations": [
            {"id": f"{threat_id}-M{n}", "text": m["text"], "asvs_refs": list(dict.fromkeys(m["asvs_refs"]))}
            for n, m in enumerate(threat["mitigations"], start=1)
        ],
        "status": threat["status"],
    }
    if threat.get("evidence"):
        result["evidence"] = threat["evidence"]
    return result


def merge(reply_threats: list[dict], previous: dict | None, model_version: str, framework: str = FRAMEWORK) -> dict:
    return merge_with_ids(reply_threats, previous, model_version, framework)[0]


def merge_with_ids(reply_threats: list[dict], previous: dict | None, model_version: str,
                   framework: str = FRAMEWORK) -> tuple[dict, list[str]]:
    previous = previous or {"threats": [], "removed": []}
    mine = [t for t in previous["threats"] if t["framework"] == framework]
    others = [t for t in previous["threats"] if t["framework"] != framework]
    by_id = {t["id"]: t for t in mine}
    next_number = 1 + max((_number(t["id"]) for t in previous["threats"] + previous["removed"]), default=0)
    used, current, ids = set(), [], []
    for threat in reply_threats:
        match = by_id.get(threat.get("previous_id") or "")
        if not match or match["id"] in used or (match["category"], match["element"]) != (threat["category"], threat["element"]):
            match = next((t for t in mine if t["id"] not in used and _key(t) == _key(threat)), None)
        if match:
            threat_id = match["id"]
        else:
            threat_id = f"{ID_PREFIX}-{next_number:03d}"
            next_number += 1
        used.add(threat_id)
        ids.append(threat_id)
        current.append(_finalize(threat, threat_id, framework))
    removed = [t for t in mine if t["id"] not in used]
    removed_ids = {t["id"] for t in removed}
    history = [t for t in previous["removed"] if t["id"] not in used and t["id"] not in removed_ids]
    return {"model_version": model_version, "threats": others + current, "removed": history + removed}, ids


def validate_threats(doc: dict, source: str) -> None:
    errors = sorted(findings.validator(THREATS_SCHEMA).iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path])
    if errors:
        raise ThreatModelError(f"{source} does not match {THREATS_SCHEMA}: " + "; ".join(e.message for e in errors[:5]))
    ids = [t["id"] for t in doc["threats"] + doc["removed"]]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise ThreatModelError(f"{source} has duplicate threat ids: {', '.join(dupes)}")


def _title(category: str) -> str:
    return category.replace("-", " ").capitalize()


def threat_findings(doc: dict) -> list[dict]:
    result = []
    for t in doc["threats"]:
        if t["status"] != "open":
            continue
        label = f"Attack tree {t['category']}" if t["framework"] == ATTACK_TREE_FRAMEWORK else _title(t["category"])
        mitigations = "\n".join(f"- {m['text']} (ASVS {', '.join(m['asvs_refs'])})" for m in t["mitigations"])
        result.append(findings.make_finding(
            stage=STAGE, tool=STAGE, source="ai-threat-model", rule_id=t["id"],
            title=f"{label}: {t['title']}", severity="info",
            location={"path": FINDING_PATH, "start_line": None},
            description=(f"{t['description']}\n\nFramework {t['framework']}, element '{t['element']}', "
                         f"likelihood {t['likelihood']}, impact {t['impact']}, rated {t['severity']}."),
            remediation=mitigations,
        ))
    return result


def load_previous(previous_dir: Path | None) -> tuple[list[Path], dict | None]:
    if previous_dir is None:
        return [], None
    paths = [p for p in (previous_dir / "tm.py", previous_dir / "threats.json") if p.is_file()]
    threats_path = previous_dir / "threats.json"
    if not threats_path.is_file():
        return paths, None
    try:
        doc = json.loads(threats_path.read_text())
    except json.JSONDecodeError as e:
        raise ThreatModelError(f"{threats_path}: not JSON: {e}") from None
    validate_threats(doc, str(threats_path))
    return paths, doc


def load_plan(plan_path: Path) -> dict:
    try:
        plan = json.loads(plan_path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise ThreatModelError(f"{plan_path}: cannot read plan: {e}") from None
    if list(findings.validator("plan.schema.json").iter_errors(plan)):
        raise ThreatModelError(f"{plan_path} does not match plan.schema.json")
    return plan


def linddun_pass(plan: dict, doc: dict, out: Path, inputs: list[Path], names: list[str], asvs: list[str],
                 passes: dict, workdir: Path | None) -> tuple[int, dict]:
    if not plan["personal_data"]:
        passes["linddun"] = {"status": "skipped", "reason": "the plan does not handle personal data"}
        return adapter.EXIT_OK, merge([], doc, doc["model_version"], LINDDUN_FRAMEWORK)
    schema_path = out / "linddun-reply.schema.json"
    schema_path.write_text(json.dumps(linddun_reply_schema(names, asvs), indent=2) + "\n")
    reply_path = out / "linddun-reply.json"
    code = adapter.run_stage(
        stage=LINDDUN_STAGE, prompt_path=LINDDUN_PROMPT, inputs=inputs, schema_path=schema_path,
        out_path=reply_path, workdir=workdir, allow_tools=list(READ_TOOLS),
    )
    if code != adapter.EXIT_OK:
        return code, doc
    passes["linddun"] = {"status": "ran", "reason": "the plan handles personal data"}
    return adapter.EXIT_OK, merge(json.loads(reply_path.read_text())["threats"], doc, doc["model_version"], LINDDUN_FRAMEWORK)


def _feature_stage(feature_id: str) -> str:
    return f"{ATTACK_TREE_STAGE}-{feature_id.lower().replace('_', '-')}"


def attack_tree_pass(plan: dict, doc: dict, out: Path, inputs: list[Path], names: list[str], asvs: list[str],
                     passes: dict, workdir: Path | None) -> tuple[int, dict]:
    feature_ids = plan["high_risk_features"]
    if not feature_ids:
        passes["attack-trees"] = {"status": "skipped", "reason": "the plan has no high-risk features"}
        return adapter.EXIT_OK, merge([], doc, doc["model_version"], ATTACK_TREE_FRAMEWORK)
    folder = out / "attack-trees"
    folder.mkdir(parents=True, exist_ok=True)
    features = {f["id"]: f for f in plan["features"]}
    trees, items = [], []
    for feature_id in feature_ids:
        abuse_cases = [a for a in plan["abuse_cases"] if a["feature_id"] == feature_id]
        if feature_id not in features or not abuse_cases:
            raise ThreatModelError(f"high-risk feature {feature_id} needs an abuse case to root its attack tree")
        feature_path = folder / f"{feature_id}.feature.json"
        feature_path.write_text(json.dumps({"feature": features[feature_id], "abuse_cases": abuse_cases}, indent=2) + "\n")
        goals = list(dict.fromkeys(a["attacker_goal"] for a in abuse_cases))
        schema_path = folder / f"{feature_id}.reply.schema.json"
        schema_path.write_text(json.dumps(attack_tree.reply_schema(goals, names, asvs), indent=2) + "\n")
        reply_path = folder / f"{feature_id}.reply.json"
        code = adapter.run_stage(
            stage=_feature_stage(feature_id), prompt_path=ATTACK_TREE_PROMPT, inputs=[feature_path, *inputs],
            schema_path=schema_path, out_path=reply_path, workdir=workdir, allow_tools=list(READ_TOOLS),
        )
        if code != adapter.EXIT_OK:
            return code, doc
        tree = {"feature_id": feature_id, "root": json.loads(reply_path.read_text())["root"]}
        try:
            attack_tree.check_shape(tree)
        except attack_tree.AttackTreeError as e:
            raise ThreatModelError(str(e)) from None
        trees.append(tree)
        items.extend(attack_tree.threat_items(tree))
    doc, ids = merge_with_ids(items, doc, doc["model_version"], ATTACK_TREE_FRAMEWORK)
    severities = {t["id"]: t["severity"] for t in doc["threats"]}
    position = 0
    for tree in trees:
        count = len(attack_tree.leaves(tree))
        numbered = attack_tree.with_leaf_ids(tree, ids[position:position + count])
        position += count
        errors = list(findings.validator(ATTACK_TREE_SCHEMA).iter_errors(numbered))
        if errors:
            raise ThreatModelError(f"attack tree {tree['feature_id']} does not match {ATTACK_TREE_SCHEMA}: {errors[0].message}")
        feature_id = tree["feature_id"]
        (folder / f"{feature_id}.json").write_text(json.dumps(numbered, indent=2, ensure_ascii=False) + "\n")
        (folder / f"{feature_id}.md").write_text(attack_tree.render_markdown(numbered, features[feature_id]["name"], severities))
    passes["attack-trees"] = {"status": "ran", "reason": "the plan has high-risk features", "features": list(feature_ids)}
    return adapter.EXIT_OK, doc


def run(plan_path: Path, out: Path, previous_dir: Path | None, python: Path, workdir: Path | None = None,
        timeout: int = pytm_runner.TIMEOUT_SECONDS, image: str | None = None) -> int:
    load_plan(plan_path)
    previous_paths, previous = load_previous(previous_dir)
    if previous_paths:
        print(f"updating the existing model from {', '.join(map(str, previous_paths))}")
    code, model = pytm_runner.build(plan_path, out, previous_paths, python, workdir, timeout, image)
    if model is None:
        return code
    model_version = hashlib.sha256((out / "tm.py").read_bytes()).hexdigest()

    inputs = [out / "elements.json", plan_path]
    if previous is not None:
        inputs.append(previous_dir / "threats.json")
    names, asvs = pytm_runner.element_names(model), asvs_ids()
    schema_path = out / "stride-reply.schema.json"
    schema_path.write_text(json.dumps(stride_reply_schema(names, asvs), indent=2) + "\n")
    reply_path = out / "stride-reply.json"
    code = adapter.run_stage(
        stage=STRIDE_STAGE, prompt_path=STRIDE_PROMPT, inputs=inputs, schema_path=schema_path,
        out_path=reply_path, workdir=workdir, allow_tools=list(READ_TOOLS),
    )
    if code != adapter.EXIT_OK:
        return code
    doc = merge(json.loads(reply_path.read_text())["threats"], previous, model_version)
    passes = {"stride": {"status": "ran"}}

    plan = load_plan(plan_path)
    code, doc = linddun_pass(plan, doc, out, inputs, names, asvs, passes, workdir)
    if code != adapter.EXIT_OK:
        return code
    code, doc = attack_tree_pass(plan, doc, out, inputs, names, asvs, passes, workdir)
    if code != adapter.EXIT_OK:
        return code
    (out / "passes.json").write_text(json.dumps(passes, indent=2) + "\n")

    validate_threats(doc, "threats.json")
    (out / "threats.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    try:
        rules.load_threats(out / "threats.json")
    except rules.RulesError as e:
        raise ThreatModelError(f"threats.json cannot feed the rules renderer: {e}") from None
    stage_findings = threat_findings(doc)
    findings.write(out / "findings.json", stage_findings)
    counts = {c: sum(1 for t in doc["threats"] if t["framework"] == FRAMEWORK and t["category"] == c) for c in STRIDE}
    print(f"wrote {out / 'threats.json'}: {len(doc['threats'])} threats, {len(doc['removed'])} removed, "
          f"{len(stage_findings)} open as info findings")
    print("by category: " + ", ".join(f"{c} {n}" for c, n in counts.items()))
    for name, info in passes.items():
        print(f"pass {name}: {info['status']}" + (f" ({info['reason']})" if info.get("reason") else ""))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.stages.threat_model",
                                     description="Build the pytm model and STRIDE threats for a plan")
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--out", default=Path("out/threat-model"), type=Path)
    parser.add_argument("--previous", default=Path("security"), type=Path,
                        help="directory holding the committed tm.py and threats.json, if any")
    parser.add_argument("--pytm-python", type=Path, default=tools.venv_python("pytm"))
    parser.add_argument("--timeout", type=int, default=pytm_runner.TIMEOUT_SECONDS)
    parser.add_argument("--workdir", type=Path)
    parser.add_argument("--sandbox", choices=("docker", "none"), default="docker",
                        help="run pytm in the pinned no-network container (default) or directly")
    args = parser.parse_args(argv)
    try:
        image = pytm_runner.sandbox_image(args.sandbox)
        return run(args.plan, args.out, args.previous, args.pytm_python, args.workdir, args.timeout, image)
    except (ThreatModelError, RunnerError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except AdapterError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.exit_code


if __name__ == "__main__":
    sys.exit(main())
