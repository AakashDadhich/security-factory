import argparse
import json
import os
import sys
from pathlib import Path

from factory import findings
from factory.findings import SEVERITIES, FindingsError

BLOCKING = ("critical", "high")
FAILED_RESULTS = ("failure", "cancelled")


def collect(artifacts_dir: str | Path) -> tuple[dict[str, list], list[str]]:
    by_stage: dict[str, list] = {}
    errors: list[str] = []
    root = Path(artifacts_dir)
    for path in sorted(root.glob("**/findings.json")):
        stage = path.relative_to(root).parts[0]
        try:
            by_stage.setdefault(stage, []).extend(findings.load(path))
        except FindingsError as e:
            errors.append(f"{path.relative_to(root)}: {e}")
    return by_stage, errors


def count(items: list) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITIES, 0)
    for f in items:
        counts[f["severity"]] += 1
    return counts


def failed_jobs(needs: dict) -> list[str]:
    return sorted(name for name, job in needs.items() if job.get("result") in FAILED_RESULTS)


def evaluate(by_stage: dict[str, list], errors: list[str], needs: dict) -> dict:
    counts = count([f for items in by_stage.values() for f in items])
    reasons = [f"invalid findings: {e}" for e in errors]
    reasons += [f"job `{name}` {needs[name]['result']}" for name in failed_jobs(needs)]
    blocking = sum(counts[s] for s in BLOCKING)
    if blocking:
        reasons.append(f"{blocking} critical or high finding(s)")
    return {"passed": not reasons, "counts": counts, "reasons": reasons}


def summary(result: dict, by_stage: dict[str, list], needs: dict) -> str:
    lines = ["## Factory gate", "", f"**{'PASS' if result['passed'] else 'FAIL'}**", ""]
    lines += ["| Severity | Count |", "|---|---|"]
    lines += [f"| {s} | {result['counts'][s]} |" for s in SEVERITIES]
    lines += ["", "| Stage | Findings |", "|---|---|"]
    lines += [f"| {stage} | {len(items)} |" for stage, items in sorted(by_stage.items())] or ["| (none) | 0 |"]
    if needs:
        lines += ["", "| Job | Result |", "|---|---|"]
        lines += [f"| {name} | {job.get('result', 'unknown')} |" for name, job in sorted(needs.items())]
    if result["reasons"]:
        lines += ["", "Reasons:"] + [f"- {r}" for r in result["reasons"]]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.gate", description="Stub gate: validate findings, count by severity, block on critical or high")
    parser.add_argument("--artifacts", required=True, help="folder holding one sub-folder per downloaded artifact")
    parser.add_argument("--needs", default="{}", help="JSON of the workflow `needs` context")
    args = parser.parse_args(argv)
    try:
        needs = json.loads(args.needs)
    except json.JSONDecodeError as e:
        print(f"error: --needs is not valid JSON: {e}", file=sys.stderr)
        return 1
    by_stage, errors = collect(args.artifacts)
    result = evaluate(by_stage, errors, needs)
    text = summary(result, by_stage, needs)
    sys.stdout.write(text)
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a") as f:
            f.write(text)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
