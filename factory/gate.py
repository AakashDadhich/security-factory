import argparse
import datetime
import json
import os
import sys
from pathlib import Path

import yaml

from factory import config as config_mod
from factory import findings, manifest as manifest_mod, stage_matrix
from factory.config import ConfigError
from factory.findings import SEVERITIES, FindingsError
from factory.manifest import ManifestError

POLICY_PATH = Path(__file__).resolve().parent.parent / "policy.yml"
SETUP_JOB = "setup"
MAX_SUPPRESSION_DAYS = 90
GATE_STAGE = "gate"
STAGE_RULES = ("stage-missing", "stage-failed")
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.5"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
TABLE_LIMIT = 50


class PolicyError(Exception):
    pass


def load_policy(path: str | Path = POLICY_PATH) -> list[str]:
    try:
        data = yaml.safe_load(Path(path).read_text())
    except (OSError, yaml.YAMLError) as e:
        raise PolicyError(f"{path}: {e}") from e
    levels = data.get("fail_on") if isinstance(data, dict) else None
    if not isinstance(levels, list) or not levels or any(level not in SEVERITIES for level in levels):
        raise PolicyError(f"{path}: fail_on must be a non-empty list of severities")
    return list(levels)


def effective_fail_on(base: list[str], extra: list[str] | None) -> list[str]:
    merged = set(base) | set(extra or [])
    return [s for s in SEVERITIES if s in merged]


def _check_finding(rule_id: str, title: str, path: str, severity: str, description: str, remediation: str) -> dict:
    return findings.make_finding(
        stage=GATE_STAGE, tool="factory", source="check", rule_id=rule_id, title=title, severity=severity,
        location={"path": path, "start_line": None}, description=description, remediation=remediation,
    )


def _parse_suppression(entry, today: datetime.date) -> tuple[dict | None, str | None, str | None]:
    if not isinstance(entry, dict):
        return None, "invalid", "entry is not a mapping"
    for key in ("fingerprint", "reason", "expires", "approved_by"):
        value = entry.get(key)
        if key == "expires" and isinstance(value, datetime.date) and not isinstance(value, datetime.datetime):
            continue
        if not isinstance(value, str) or not value.strip():
            return None, "invalid", f"missing or empty `{key}`"
    fp = entry["fingerprint"]
    if len(fp) != 64 or any(c not in "0123456789abcdef" for c in fp):
        return None, "invalid", "`fingerprint` is not a 64 character lowercase hex string"
    expires = entry["expires"]
    if isinstance(expires, str):
        try:
            expires = datetime.date.fromisoformat(expires)
        except ValueError:
            return None, "invalid", "`expires` is not an ISO date (YYYY-MM-DD)"
    if expires < today:
        return None, "expired", f"expired on {expires.isoformat()}"
    if expires > today + datetime.timedelta(days=MAX_SUPPRESSION_DAYS):
        return None, "invalid", f"`expires` is more than {MAX_SUPPRESSION_DAYS} days ahead"
    return {"fingerprint": fp, "reason": entry["reason"].strip(), "expires": expires.isoformat(), "approved_by": entry["approved_by"].strip()}, None, None


def check_suppressions(entries, today: datetime.date, config_path: str = ".factory.yml") -> tuple[dict[str, dict], list[dict]]:
    active: dict[str, dict] = {}
    problems: list[dict] = []
    if entries is None:
        return active, problems
    if not isinstance(entries, list):
        entries = [None]
    for index, entry in enumerate(entries, start=1):
        parsed, kind, detail = _parse_suppression(entry, today)
        if parsed:
            active[parsed["fingerprint"]] = parsed
            continue
        problems.append(_check_finding(
            f"suppression-{kind}-{index}", f"Suppression {index} is {kind} and was ignored", config_path, "medium",
            f"Entry {index} of `suppressions` in {config_path}: {detail}.",
            "Fix or remove the entry. A suppression needs fingerprint, reason, approved_by and an `expires` date at most 90 days ahead.",
        ))
    return active, problems


def collect(artifacts_dir: str | Path) -> tuple[dict[str, list], dict[str, str]]:
    by_stage: dict[str, list] = {}
    errors: dict[str, str] = {}
    root = Path(artifacts_dir)
    for path in sorted(root.glob("*/findings.json")):
        stage = path.parent.name
        try:
            by_stage[stage] = findings.load(path)
        except FindingsError as e:
            errors[stage] = str(e).splitlines()[0]
    return by_stage, errors


def stage_rows(expected: list[stage_matrix.Stage], needs: dict | None, by_stage: dict, errors: dict) -> list[dict]:
    expected_by_name = {s.name: s for s in expected}
    names = set(expected_by_name) | {n for n in (needs or {}) if n != SETUP_JOB} | set(by_stage) | set(errors)
    names -= {SETUP_JOB, GATE_STAGE}
    rows = []
    for name in sorted(names):
        job = (needs or {}).get(name)
        result = job.get("result") if isinstance(job, dict) else None
        stage = expected_by_name.get(name)
        row = {"stage": name, "expected": stage is not None, "status": "ok", "detail": ""}
        if needs is not None and result == "skipped":
            if stage is None or stage.skippable:
                row.update(status="skipped", detail=stage.skippable[0] if stage else "not-applicable")
            else:
                row.update(status="missing", detail="job was skipped but the stage is required")
        elif needs is not None and name in needs and result != "success":
            row.update(status="failed", detail=f"job result: {result or 'none'}")
        elif name in errors:
            row.update(status="failed", detail=f"invalid findings: {errors[name]}")
        elif name not in by_stage:
            if stage is not None or name in (needs or {}):
                row.update(status="missing", detail="no findings.json was uploaded")
            else:
                continue
        rows.append(row)
    return rows


def problem_findings(rows: list[dict]) -> list[dict]:
    out = []
    for row in rows:
        if row["status"] not in ("missing", "failed"):
            continue
        rule = f"stage-{row['status']}"
        out.append(_check_finding(
            rule, f"Stage `{row['stage']}` {row['status']}: {row['detail']}", f"stages/{row['stage']}", "critical",
            f"The gate failed closed because stage `{row['stage']}` did not produce a usable result ({row['detail']}).",
            "Open the stage job in the workflow run, fix the cause and re-run.",
        ))
    return out


def _overlap(a: dict, b: dict) -> bool:
    sa, sb = a.get("start_line"), b.get("start_line")
    if sa is None or sb is None:
        return sa is None and sb is None
    ea, eb = a.get("end_line") or sa, b.get("end_line") or sb
    return sa <= eb and sb <= ea


def _same_issue(a: dict, b: dict) -> bool:
    la, lb = a["location"], b["location"]
    if "path" not in la or "path" not in lb or la["path"] != lb["path"]:
        return False
    return bool(set(a["cwe"]) & set(b["cwe"])) and _overlap(la, lb)


def dedupe(items: list[dict]) -> list[dict]:
    parent = list(range(len(items)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i, a in enumerate(items):
        for j in range(i + 1, len(items)):
            if _same_issue(a, items[j]):
                parent[find(j)] = find(i)
    groups: dict[int, list[dict]] = {}
    for i, f in enumerate(items):
        groups.setdefault(find(i), []).append(f)
    merged = []
    for members in groups.values():
        rep = min(members, key=lambda f: (SEVERITIES.index(f["severity"]), f["source"] != "scanner", f["stage"], f["tool"], f["fingerprint"]))
        out = dict(rep)
        out["cwe"] = sorted({c for f in members for c in f["cwe"]})
        out["tools"] = sorted({t for f in members for t in f["tool"].split("+")})
        out["stages"] = sorted({f["stage"] for f in members})
        out["merged_fingerprints"] = sorted({f["fingerprint"] for f in members})
        merged.append(out)
    merged.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["location"].get("path", f["location"].get("url", "")), f["location"].get("start_line") or 0, f["fingerprint"]))
    return merged


def count(items: list[dict]) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITIES, 0)
    for f in items:
        counts[f["severity"]] += 1
    return counts


def apply_suppressions(merged: list[dict], active: dict[str, dict]) -> None:
    for f in merged:
        f["suppressed"] = False
        if f["rule_id"] in STAGE_RULES:
            continue
        for fp in f["merged_fingerprints"]:
            if fp in active:
                f["suppressed"] = True
                f["suppression"] = active[fp]
                break


def evaluate(merged: list[dict], rows: list[dict], fail_on: list[str], extra_reasons: list[str]) -> dict:
    live = [f for f in merged if not f["suppressed"]]
    blocking = [f for f in live if f["severity"] in fail_on]
    reasons = list(extra_reasons)
    bad = [r for r in rows if r["status"] in ("missing", "failed")]
    if bad:
        reasons.append("stage problem(s): " + ", ".join(f"`{r['stage']}` {r['status']}" for r in bad))
    other = len(blocking) - sum(1 for f in blocking if f["rule_id"] in STAGE_RULES)
    if other:
        reasons.append(f"{other} finding(s) at a blocking severity ({', '.join(fail_on)})")
    return {
        "status": "fail" if reasons else "pass",
        "reasons": reasons,
        "counts": count(live),
        "suppressed": len(merged) - len(live),
        "fail_on": fail_on,
        "blocking_fingerprints": sorted(f["fingerprint"] for f in blocking),
    }


def _cell(text: str) -> str:
    return " ".join(str(text).split()).replace("|", "\\|").replace("`", "'")


def _where(f: dict) -> str:
    loc = f["location"]
    if "url" in loc:
        return f"{loc['method']} {loc['url']}"
    line = loc.get("start_line")
    return f"{loc['path']}:{line}" if line else loc["path"]


def render_markdown(result: dict, rows: list[dict], merged: list[dict]) -> str:
    lines = ["## Factory gate", "", f"**{result['status'].upper()}** (mode `{result['mode']}`, iteration {result['iteration']}, fails on {', '.join(result['fail_on'])})", ""]
    lines += ["| Severity | Count |", "|---|---|"] + [f"| {s} | {result['counts'][s]} |" for s in SEVERITIES]
    if result["suppressed"]:
        lines += ["", f"{result['suppressed']} finding(s) suppressed (listed below)."]
    lines += ["", "### Stages", "", "| Stage | Status | Detail |", "|---|---|---|"]
    lines += [f"| {r['stage']} | {r['status']} | {_cell(r['detail'])} |" for r in rows] or ["| (none) | | |"]
    live = [f for f in merged if not f["suppressed"]]
    lines += ["", "### Findings", ""]
    if live:
        lines += ["| Severity | Where | Title | Tools |", "|---|---|---|---|"]
        lines += [f"| {f['severity']} | {_cell(_where(f))} | {_cell(f['title'])} | {_cell(', '.join(f['tools']))} |" for f in live[:TABLE_LIMIT]]
        if len(live) > TABLE_LIMIT:
            lines.append(f"\n{len(live) - TABLE_LIMIT} more in `report.json`.")
    else:
        lines.append("None.")
    suppressed = [f for f in merged if f["suppressed"]]
    if suppressed:
        lines += ["", "### Suppressed", "", "| Severity | Where | Title | Reason | Expires | Approved by |", "|---|---|---|---|---|---|"]
        lines += [f"| {f['severity']} | {_cell(_where(f))} | {_cell(f['title'])} | {_cell(f['suppression']['reason'])} | {f['suppression']['expires']} | {_cell(f['suppression']['approved_by'])} |" for f in suppressed]
    if result["reasons"]:
        lines += ["", "### Reasons", ""] + [f"- {_cell(r)}" for r in result["reasons"]]
    return "\n".join(lines) + "\n"


def render_sarif(merged: list[dict]) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in merged:
        rules.setdefault(f["rule_id"], {
            "id": f["rule_id"], "name": f["rule_id"], "shortDescription": {"text": f["title"]},
            "properties": {"security-severity": SECURITY_SEVERITY[f["severity"]]},
        })
        loc = f["location"]
        if "url" in loc:
            physical = {"artifactLocation": {"uri": loc["url"]}}
        else:
            physical = {"artifactLocation": {"uri": loc["path"]}}
            if loc.get("start_line"):
                physical["region"] = {"startLine": loc["start_line"], "endLine": loc.get("end_line") or loc["start_line"]}
        result = {
            "ruleId": f["rule_id"],
            "level": SARIF_LEVEL[f["severity"]],
            "message": {"text": f["title"] + (f"\n\n{f['description']}" if f["description"] else "")},
            "locations": [{"physicalLocation": physical}],
            "partialFingerprints": {"factoryFingerprint/v1": f["fingerprint"]},
            "properties": {"security-severity": SECURITY_SEVERITY[f["severity"]], "tools": f["tools"], "stages": f["stages"], "cwe": f["cwe"]},
        }
        if f["suppressed"]:
            result["suppressions"] = [{"kind": "external", "justification": f["suppression"]["reason"]}]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "security-factory-gate", "rules": list(rules.values())}}, "results": results}],
    }


def run(*, artifacts: str, config_path: str, manifest_path: str | None, needs: dict | None, policy_path: str | Path, today: datetime.date) -> tuple[dict, list[dict], list[dict]]:
    cfg = config_mod.load(config_path)
    base = load_policy(policy_path)
    fail_on = effective_fail_on(base, cfg.get("policy", {}).get("fail_on_extra"))
    extra_reasons: list[str] = []
    platform, mode, iteration = cfg["platform"], "check", 0
    if manifest_path:
        try:
            m = manifest_mod.load(manifest_path)
            platform, mode, iteration = m["platform"], m["mode"], m["iteration"]
        except ManifestError as e:
            extra_reasons.append(f"run manifest unusable: {str(e).splitlines()[0]}")
    by_stage, errors = collect(artifacts)
    rows = stage_rows(stage_matrix.expected(platform, mode), needs, by_stage, errors)
    active, suppression_problems = check_suppressions(cfg.get("suppressions"), today, config_path)
    everything = [f for items in by_stage.values() for f in items] + problem_findings(rows) + suppression_problems
    merged = dedupe(everything)
    apply_suppressions(merged, active)
    result = evaluate(merged, rows, fail_on, extra_reasons)
    result.update(mode=mode, iteration=iteration, platform=platform)
    return result, rows, merged


def write_outputs(out: str | Path, result: dict, rows: list[dict], merged: list[dict]) -> str:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(merged, indent=2) + "\n")
    (out / "gate-result.json").write_text(json.dumps({**result, "stages": rows}, indent=2) + "\n")
    (out / "merged.sarif").write_text(json.dumps(render_sarif(merged), indent=2) + "\n")
    text = render_markdown(result, rows, merged)
    (out / "report.md").write_text(text)
    return text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.gate", description="Merge stage findings, apply policy and suppressions, fail closed")
    parser.add_argument("--artifacts", required=True, help="folder holding one sub-folder per downloaded artifact")
    parser.add_argument("--config", default=".factory.yml")
    parser.add_argument("--manifest", help="run manifest written by the setup job")
    parser.add_argument("--out", default="out/gate")
    parser.add_argument("--needs", help="JSON of the workflow `needs` context")
    parser.add_argument("--policy", default=str(POLICY_PATH))
    parser.add_argument("--today", help="ISO date to use as today (tests)")
    args = parser.parse_args(argv)
    needs = None
    if args.needs is not None:
        try:
            needs = json.loads(args.needs)
        except json.JSONDecodeError as e:
            print(f"error: --needs is not valid JSON: {e}", file=sys.stderr)
            return 1
        if not isinstance(needs, dict) or not needs:
            print("error: --needs must be a non-empty JSON object", file=sys.stderr)
            return 1
    today = datetime.date.fromisoformat(args.today) if args.today else datetime.date.today()
    try:
        result, rows, merged = run(
            artifacts=args.artifacts, config_path=args.config, manifest_path=args.manifest,
            needs=needs, policy_path=args.policy, today=today,
        )
    except (ConfigError, PolicyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    text = write_outputs(args.out, result, rows, merged)
    sys.stdout.write(text)
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a") as f:
            f.write(text)
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
