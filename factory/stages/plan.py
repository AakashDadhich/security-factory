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
SCHEMA_NAME = "plan.schema.json"
DERIVED = ("asvs_level", "personal_data", "high_risk_features")
PERSONAL_CLASSES = ("personal", "sensitive")
EXIT_INCONSISTENT = 2


class PlanError(Exception):
    pass


def plan_schema() -> dict:
    return json.loads((FACTORY_ROOT / "schemas" / SCHEMA_NAME).read_text())


def reply_schema(schema: dict) -> dict:
    reply = copy.deepcopy(schema)
    reply["$id"] = reply["$id"].replace(SCHEMA_NAME, "plan-reply.schema.json")
    for name in DERIVED:
        reply["properties"].pop(name)
    reply["required"] = [r for r in reply["required"] if r not in DERIVED]
    return reply


def asvs_level(plan: dict, configured: int | None) -> int:
    if configured is not None:
        return configured
    if plan["risk_rating"] == "high" or plan["takes_payments"]:
        return 3
    return config.DEFAULT_ASVS_LEVEL


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


def finalize(reply: dict, configured_level: int | None) -> dict:
    plan = {k: v for k, v in reply.items() if k not in DERIVED}
    plan["asvs_level"] = asvs_level(plan, configured_level)
    plan["personal_data"] = personal_data(plan)
    plan["high_risk_features"] = high_risk_features(plan)
    errors = sorted(findings.validator(SCHEMA_NAME).iter_errors(plan), key=lambda e: [str(p) for p in e.absolute_path])
    if errors:
        raise PlanError("plan does not match the schema: " + "; ".join(e.message for e in errors))
    return plan


def check_issue(path: Path) -> None:
    try:
        issue = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise PlanError(f"{path}: cannot read issue JSON: {e}") from e
    if not isinstance(issue, dict) or not isinstance(issue.get("title"), str) or not isinstance(issue.get("body"), str):
        raise PlanError(f"{path}: expected an object with string `title` and `body`")
    if not (issue["title"].strip() or issue["body"].strip()):
        raise PlanError(f"{path}: the issue has no text to plan from")


def run(issue_file: Path, config_path: Path, out: Path, workdir: Path | None = None) -> int:
    cfg = config.load(config_path)
    check_issue(issue_file)
    out.mkdir(parents=True, exist_ok=True)
    schema_path = out / "plan-reply.schema.json"
    schema_path.write_text(json.dumps(reply_schema(plan_schema()), indent=2) + "\n")
    reply_path = out / "reply.json"
    code = adapter.run_stage(
        stage=STAGE, prompt_path=PROMPT, inputs=[issue_file], schema_path=schema_path,
        out_path=reply_path, workdir=workdir, allow_tools=list(READ_TOOLS),
    )
    if code != adapter.EXIT_OK:
        return code
    plan = finalize(json.loads(reply_path.read_text()), cfg.get("asvs_level"))
    errors = consistency_errors(plan)
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
    args = parser.parse_args(argv)
    try:
        return run(args.issue_file, args.config, args.out, args.workdir)
    except (ConfigError, PlanError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except AdapterError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.exit_code


if __name__ == "__main__":
    sys.exit(main())
