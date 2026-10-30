import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

from factory.findings import SEVERITIES


class AcceptanceError(Exception):
    pass


def load_expected(path: str | Path) -> list[dict]:
    try:
        data = yaml.safe_load(Path(path).read_text())
    except (OSError, yaml.YAMLError) as e:
        raise AcceptanceError(f"{path}: {e}") from e
    items = data.get("expectations") if isinstance(data, dict) else data
    if not isinstance(items, list) or not items:
        raise AcceptanceError(f"{path}: expected a non-empty list of expectations")
    seen: set[str] = set()
    out = []
    for i, item in enumerate(items):
        out.append(_validate(item, i, seen))
    return out


def _validate(item, index: int, seen: set[str]) -> dict:
    where = f"expectation {index + 1}"
    if not isinstance(item, dict):
        raise AcceptanceError(f"{where}: not a mapping")
    ident = item.get("id")
    if not isinstance(ident, str) or not ident:
        raise AcceptanceError(f"{where}: missing id")
    if ident in seen:
        raise AcceptanceError(f"{ident}: duplicate id")
    seen.add(ident)
    stage = item.get("stage")
    stages = [stage] if isinstance(stage, str) else stage
    if not isinstance(stages, list) or not stages or not all(isinstance(s, str) and s for s in stages):
        raise AcceptanceError(f"{ident}: stage must be a name or a list of names")
    rule_id, cwe, path = item.get("rule_id"), item.get("cwe"), item.get("path")
    if rule_id is None and cwe is None:
        raise AcceptanceError(f"{ident}: needs a rule_id regex or a cwe")
    cwes = [cwe] if isinstance(cwe, str) else cwe
    if cwes is not None and (not isinstance(cwes, list) or not all(isinstance(c, str) for c in cwes)):
        raise AcceptanceError(f"{ident}: cwe must be a string or a list of strings")
    for key, value in (("rule_id", rule_id), ("path", path)):
        if value is None:
            continue
        if not isinstance(value, str):
            raise AcceptanceError(f"{ident}: {key} must be a regex string")
        try:
            re.compile(value)
        except re.error as e:
            raise AcceptanceError(f"{ident}: bad {key} regex: {e}") from e
    floor = item.get("min_severity")
    if floor not in SEVERITIES:
        raise AcceptanceError(f"{ident}: min_severity must be one of {', '.join(SEVERITIES)}")
    optional = item.get("optional", False)
    if not isinstance(optional, bool):
        raise AcceptanceError(f"{ident}: optional must be true or false")
    return {"id": ident, "stages": stages, "rule_id": rule_id, "cwe": cwes, "path": path, "min_severity": floor, "optional": optional}


def _location(finding: dict) -> str:
    loc = finding["location"]
    return loc.get("path") or loc.get("url") or ""


def matches(expectation: dict, finding: dict) -> bool:
    if finding.get("suppressed"):
        return False
    if not set(expectation["stages"]) & set(finding.get("stages") or [finding["stage"]]):
        return False
    if SEVERITIES.index(finding["severity"]) > SEVERITIES.index(expectation["min_severity"]):
        return False
    if expectation["path"] and not re.search(expectation["path"], _location(finding)):
        return False
    by_rule = expectation["rule_id"] is not None and re.search(expectation["rule_id"], finding["rule_id"]) is not None
    by_cwe = expectation["cwe"] is not None and bool(set(expectation["cwe"]) & set(finding["cwe"]))
    return by_rule or by_cwe


def _caught_by(expectation: dict, finding: dict) -> str:
    stages = finding.get("stages") or [finding["stage"]]
    named = [s for s in stages if s in expectation["stages"]]
    return ", ".join(named)


def evaluate(expectations: list[dict], report: list[dict], gate_result: dict) -> dict:
    rows = []
    for exp in expectations:
        hits = [f for f in report if matches(exp, f)]
        if hits:
            best = min(hits, key=lambda f: (SEVERITIES.index(f["severity"]), f["fingerprint"]))
            status, caught, finding = "matched", _caught_by(exp, best), f"{best['rule_id']} ({best['severity']}) at {_location(best)}"
        else:
            status, caught, finding = ("optional-missed" if exp["optional"] else "missed"), "", ""
        rows.append({"id": exp["id"], "expected_stage": " | ".join(exp["stages"]), "optional": exp["optional"], "status": status, "caught_by": caught, "finding": finding})
    gate_failed = gate_result.get("status") == "fail"
    ok = gate_failed and not any(r["status"] == "missed" for r in rows)
    return {"ok": ok, "gate_status": gate_result.get("status"), "gate_failed_as_required": gate_failed, "rows": rows}


def render_table(result: dict) -> str:
    lines = [
        f"Gate status: `{result['gate_status']}` ({'expected: fail' if result['gate_failed_as_required'] else 'MISMATCH: the gate must fail on the vulnerable app'})",
        "",
        "| Expectation | Expected stage | Optional | Result | Caught by | Finding |",
        "|---|---|---|---|---|---|",
    ]
    for r in result["rows"]:
        finding = r["finding"].replace("|", "\\|")
        lines.append(f"| {r['id']} | {r['expected_stage']} | {'yes' if r['optional'] else 'no'} | {r['status']} | {r['caught_by'] or '-'} | {finding or '-'} |")
    lines += ["", f"Acceptance: **{'PASS' if result['ok'] else 'FAIL'}**", ""]
    return "\n".join(lines)


def load_gate(directory: str | Path) -> tuple[list[dict], dict]:
    directory = Path(directory)
    try:
        report = json.loads((directory / "report.json").read_text())
        gate_result = json.loads((directory / "gate-result.json").read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise AcceptanceError(f"gate artifact unusable: {e}") from e
    if not isinstance(report, list) or not isinstance(gate_result, dict):
        raise AcceptanceError("gate artifact has the wrong shape")
    return report, gate_result


def download_gate(repo: str, run_id: str, dest: str) -> None:
    cmd = ["gh", "run", "download", run_id, "--repo", repo, "--name", "gate", "--dir", dest]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise AcceptanceError(f"could not download the gate artifact of run {run_id}: {proc.stderr.strip()}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m factory.acceptance")
    p.add_argument("--repo", required=True)
    p.add_argument("--run-id")
    p.add_argument("--expected", required=True)
    p.add_argument("--artifacts", help="folder with an already downloaded gate artifact")
    p.add_argument("--out", help="folder for acceptance.md and acceptance.json")
    args = p.parse_args(argv)
    if not args.run_id and not args.artifacts:
        p.error("give --run-id or --artifacts")
    try:
        expectations = load_expected(args.expected)
        if args.artifacts:
            report, gate_result = load_gate(args.artifacts)
        else:
            with tempfile.TemporaryDirectory() as tmp:
                download_gate(args.repo, args.run_id, tmp)
                report, gate_result = load_gate(tmp)
    except AcceptanceError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    result = evaluate(expectations, report, gate_result)
    table = render_table(result)
    print(table)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "acceptance.md").write_text(table)
        (out / "acceptance.json").write_text(json.dumps({"repo": args.repo, "run_id": args.run_id, **result}, indent=2) + "\n")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
