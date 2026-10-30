import argparse
import copy
import json
import sys
from pathlib import Path

from factory import adapter, config, findings
from factory.adapter import READ_TOOLS, AdapterError
from factory.config import ConfigError

STAGE = "plan"
FACTORY_ROOT = Path(__file__).resolve().parents[2]
PROMPT = FACTORY_ROOT / "prompts" / "plan.md"
CHANGE_PROMPT = FACTORY_ROOT / "prompts" / "plan-change.md"
CHANGE_FIELDS = ("changed_features", "touched_elements")
FAILED_RUNS = 3
MAX_RECORD_FINDINGS = 40
SCHEMA_NAME = "plan.schema.json"
DERIVED = ("asvs_level", "personal_data", "high_risk_features")
PERSONAL_CLASSES = ("personal", "sensitive")
EXIT_INCONSISTENT = 2


class PlanError(Exception):
    pass


def plan_schema() -> dict:
    return json.loads((FACTORY_ROOT / "schemas" / SCHEMA_NAME).read_text())


def reply_schema(schema: dict, change: bool = False) -> dict:
    reply = copy.deepcopy(schema)
    reply["$id"] = reply["$id"].replace(SCHEMA_NAME, "plan-reply.schema.json")
    for name in DERIVED:
        reply["properties"].pop(name)
    reply["required"] = [r for r in reply["required"] if r not in DERIVED]
    if change:
        reply["required"] += list(CHANGE_FIELDS)
        reply["properties"]["touched_elements"]["minItems"] = 1
    else:
        for name in CHANGE_FIELDS:
            reply["properties"].pop(name)
    return reply


def asvs_level(plan: dict, configured: int | None, previous: int | None = None) -> int:
    if configured is not None:
        level = configured
    elif plan["risk_rating"] == "high" or plan["takes_payments"]:
        level = 3
    else:
        level = config.DEFAULT_ASVS_LEVEL
    return max(level, previous or 0)


def personal_data(plan: dict) -> bool:
    return plan["stores_personal_data"] or any(d["classification"] in PERSONAL_CLASSES for d in plan["data_handled"])


def high_risk_features(plan: dict) -> list[str]:
    return [f["id"] for f in plan["features"] if f["risk"] == "high"]


def consistency_errors(plan: dict) -> list[str]:
    errors = []
    for key in ("features", "requirements"):
        ids = [item["id"] for item in plan[key]]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            errors.append(f"duplicate {key} ids: {', '.join(dupes)}")
    feature_ids = {f["id"] for f in plan["features"]}
    covered = {a["feature_id"] for a in plan["abuse_cases"]}
    unknown = sorted(covered - feature_ids)
    if unknown:
        errors.append(f"abuse cases name unknown features: {', '.join(unknown)}")
    missing = [f["id"] for f in plan["features"] if f["id"] not in covered]
    if missing:
        errors.append(f"features without an abuse case: {', '.join(missing)}")
    return errors


def finalize(reply: dict, configured_level: int | None, previous_level: int | None = None) -> dict:
    plan = {k: v for k, v in reply.items() if k not in DERIVED}
    plan["asvs_level"] = asvs_level(plan, configured_level, previous_level)
    plan["personal_data"] = personal_data(plan)
    plan["high_risk_features"] = high_risk_features(plan)
    errors = sorted(findings.validator(SCHEMA_NAME).iter_errors(plan), key=lambda e: [str(p) for p in e.absolute_path])
    if errors:
        raise PlanError("plan does not match the schema: " + "; ".join(e.message for e in errors))
    return plan


def change_errors(plan: dict, current: dict) -> list[str]:
    errors = []
    features = {f["id"]: f for f in plan["features"]}
    for old in current["features"]:
        if old["id"] not in features:
            errors.append(f"feature {old['id']} was dropped; a change keeps every existing feature")
    kept = {r["id"] for r in plan["requirements"]}
    for old in current["requirements"]:
        if old["id"] not in kept:
            errors.append(f"requirement {old['id']} was dropped; a change keeps every existing requirement")
    declared = plan.get("changed_features", [])
    unknown = sorted(set(declared) - set(features))
    if unknown:
        errors.append(f"changed_features names unknown features: {', '.join(unknown)}")
    return errors


def changed_features(plan: dict, current: dict) -> list[str]:
    old = {f["id"]: f for f in current["features"]}
    actual = {f["id"] for f in plan["features"] if old.get(f["id"]) != f}
    return sorted(actual | set(plan.get("changed_features", [])))


def _clip(value, limit: int) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def _load_record_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def record_context(record_dir: Path | None) -> dict:
    context = {"latest_findings": [], "failed_runs": []}
    if record_dir is None or not record_dir.is_dir():
        return context
    latest = _load_record_json(record_dir / "latest" / "findings.json")
    if isinstance(latest, list):
        context["latest_findings"] = [
            {
                "rule_id": _clip(f.get("rule_id"), 120),
                "title": _clip(f.get("title"), 200),
                "severity": f.get("severity"),
                "stages": f.get("stages") or [f.get("stage")],
                "location": f.get("location"),
            }
            for f in latest[:MAX_RECORD_FINDINGS] if isinstance(f, dict)
        ]
    runs_dir = record_dir / "runs"
    entries = [_load_record_json(p) for p in sorted(runs_dir.glob("*.json"))] if runs_dir.is_dir() else []
    failed = [e for e in entries if isinstance(e, dict) and e.get("status") == "fail"]
    context["failed_runs"] = [
        {k: e.get(k) for k in ("run_id", "mode", "ref", "status", "counts", "iteration", "issue")}
        for e in failed[-FAILED_RUNS:]
    ]
    return context


def check_issue(path: Path) -> None:
    try:
        issue = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise PlanError(f"{path}: cannot read issue JSON: {e}") from e
    if not isinstance(issue, dict) or not isinstance(issue.get("title"), str) or not isinstance(issue.get("body"), str):
        raise PlanError(f"{path}: expected an object with string `title` and `body`")
    if not (issue["title"].strip() or issue["body"].strip()):
        raise PlanError(f"{path}: the issue has no text to plan from")


def load_current_plan(path: Path) -> dict:
    try:
        current = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise PlanError(f"{path}: a change needs the project's current plan: {e}") from e
    errors = list(findings.validator(SCHEMA_NAME).iter_errors(current))
    if errors:
        raise PlanError(f"{path} does not match the plan schema: {errors[0].message}")
    return current


def run(issue_file: Path, config_path: Path, out: Path, workdir: Path | None = None,
        current_plan: Path | None = None, record_dir: Path | None = None) -> int:
    cfg = config.load(config_path)
    check_issue(issue_file)
    current = load_current_plan(current_plan) if current_plan is not None else None
    out.mkdir(parents=True, exist_ok=True)
    schema_path = out / "plan-reply.schema.json"
    schema_path.write_text(json.dumps(reply_schema(plan_schema(), change=current is not None), indent=2) + "\n")
    reply_path = out / "reply.json"
    inputs, prompt = [issue_file], PROMPT
    if current is not None:
        context_path = out / "record.json"
        context_path.write_text(json.dumps(record_context(record_dir), indent=2) + "\n")
        inputs += [current_plan, context_path]
        prompt = CHANGE_PROMPT
    code = adapter.run_stage(
        stage=STAGE, prompt_path=prompt, inputs=inputs, schema_path=schema_path,
        out_path=reply_path, workdir=workdir, allow_tools=list(READ_TOOLS),
    )
    if code != adapter.EXIT_OK:
        return code
    plan = finalize(json.loads(reply_path.read_text()), cfg.get("asvs_level"), current["asvs_level"] if current else None)
    errors = consistency_errors(plan)
    if current is not None:
        errors += change_errors(plan, current)
        if not errors:
            plan["changed_features"] = changed_features(plan, current)
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return EXIT_INCONSISTENT
    (out / "plan.json").write_text(json.dumps(plan, indent=2, ensure_ascii=False) + "\n")
    findings.write(out / "findings.json", [])
    print(f"wrote {out / 'plan.json'}: asvs_level {plan['asvs_level']}, personal_data {str(plan['personal_data']).lower()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.stages.plan", description="Turn an issue spec into a validated plan")
    parser.add_argument("--issue-file", required=True, type=Path, help="JSON from `gh issue view --json title,body`")
    parser.add_argument("--config", default=Path(".factory.yml"), type=Path)
    parser.add_argument("--out", default=Path("out/plan"), type=Path)
    parser.add_argument("--workdir", type=Path)
    parser.add_argument("--current-plan", type=Path, help="change mode: the project's committed security/plan.json")
    parser.add_argument("--record", type=Path, help="change mode: output of `python -m factory.record read`")
    args = parser.parse_args(argv)
    if args.record is not None and args.current_plan is None:
        parser.error("--record only applies together with --current-plan")
    try:
        return run(args.issue_file, args.config, args.out, args.workdir, args.current_plan, args.record)
    except (ConfigError, PlanError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except AdapterError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.exit_code


if __name__ == "__main__":
    sys.exit(main())
