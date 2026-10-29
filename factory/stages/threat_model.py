import argparse
import hashlib
import json
import sys
from pathlib import Path

from factory import adapter, findings, rules, tools
from factory.adapter import READ_TOOLS, AdapterError
from factory.threatmodel import pytm_runner
from factory.threatmodel.pytm_runner import RunnerError

STAGE = "threat-model"
STRIDE_STAGE = "threat-model-stride"
FACTORY_ROOT = Path(__file__).resolve().parents[2]
STRIDE_PROMPT = FACTORY_ROOT / "prompts" / "threat-model-stride.md"
ASVS = FACTORY_ROOT / "rules" / "asvs" / "asvs.json"
THREATS_SCHEMA = "threats.schema.json"
FRAMEWORK = "stride"
ID_PREFIX = "TM"
STRIDE = ("spoofing", "tampering", "repudiation", "information-disclosure", "denial-of-service", "elevation-of-privilege")
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
                "category": {"enum": list(STRIDE)},
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


def _finalize(threat: dict, threat_id: str) -> dict:
    result = {
        "id": threat_id,
        "framework": FRAMEWORK,
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


def merge(reply_threats: list[dict], previous: dict | None, model_version: str) -> dict:
    previous = previous or {"threats": [], "removed": []}
    mine = [t for t in previous["threats"] if t["framework"] == FRAMEWORK]
    others = [t for t in previous["threats"] if t["framework"] != FRAMEWORK]
    by_id = {t["id"]: t for t in mine}
    next_number = 1 + max((_number(t["id"]) for t in previous["threats"] + previous["removed"]), default=0)
    used, current = set(), []
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
        current.append(_finalize(threat, threat_id))
    removed = [t for t in mine if t["id"] not in used]
    removed_ids = {t["id"] for t in removed}
    history = [t for t in previous["removed"] if t["id"] not in used and t["id"] not in removed_ids]
    return {"model_version": model_version, "threats": others + current, "removed": history + removed}


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
        mitigations = "\n".join(f"- {m['text']} (ASVS {', '.join(m['asvs_refs'])})" for m in t["mitigations"])
        result.append(findings.make_finding(
            stage=STAGE, tool=STAGE, source="ai-threat-model", rule_id=t["id"],
            title=f"{_title(t['category'])}: {t['title']}", severity="info",
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


def run(plan_path: Path, out: Path, previous_dir: Path | None, python: Path, workdir: Path | None = None,
        timeout: int = pytm_runner.TIMEOUT_SECONDS) -> int:
    load_plan(plan_path)
    previous_paths, previous = load_previous(previous_dir)
    if previous_paths:
        print(f"updating the existing model from {', '.join(map(str, previous_paths))}")
    code, model = pytm_runner.build(plan_path, out, previous_paths, python, workdir, timeout)
    if model is None:
        return code
    model_version = hashlib.sha256((out / "tm.py").read_bytes()).hexdigest()

    schema_path = out / "stride-reply.schema.json"
    schema_path.write_text(json.dumps(stride_reply_schema(pytm_runner.element_names(model), asvs_ids()), indent=2) + "\n")
    inputs = [out / "elements.json", plan_path]
    if previous is not None:
        inputs.append(previous_dir / "threats.json")
    reply_path = out / "stride-reply.json"
    code = adapter.run_stage(
        stage=STRIDE_STAGE, prompt_path=STRIDE_PROMPT, inputs=inputs, schema_path=schema_path,
        out_path=reply_path, workdir=workdir, allow_tools=list(READ_TOOLS),
    )
    if code != adapter.EXIT_OK:
        return code
    doc = merge(json.loads(reply_path.read_text())["threats"], previous, model_version)
    validate_threats(doc, "threats.json")
    (out / "threats.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    try:
        rules.load_threats(out / "threats.json")
    except rules.RulesError as e:
        raise ThreatModelError(f"threats.json cannot feed the rules renderer: {e}") from None
    stage_findings = threat_findings(doc)
    findings.write(out / "findings.json", stage_findings)
    counts = {c: sum(1 for t in doc["threats"] if t["category"] == c) for c in STRIDE}
    print(f"wrote {out / 'threats.json'}: {len(doc['threats'])} threats, {len(doc['removed'])} removed, "
          f"{len(stage_findings)} open as info findings")
    print("by category: " + ", ".join(f"{c} {n}" for c, n in counts.items()))
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
    args = parser.parse_args(argv)
    try:
        return run(args.plan, args.out, args.previous, args.pytm_python, args.workdir, args.timeout)
    except (ThreatModelError, RunnerError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except AdapterError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.exit_code


if __name__ == "__main__":
    sys.exit(main())
