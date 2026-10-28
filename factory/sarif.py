import argparse
import json
import re
import sys
from pathlib import Path

from factory import findings
from factory.findings import SEVERITIES, FindingsError

LEVEL_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
SKIPPED_KINDS = ("pass", "notApplicable")
CWE_TAG = re.compile(r"^(?:external/cwe/)?cwe-0*([1-9][0-9]*)\b", re.IGNORECASE)


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _security_severity(*property_bags: dict) -> float | None:
    for props in property_bags:
        value = props.get("security-severity")
        if value is None:
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return None


def cwes_from_tags(tags: list) -> list[str]:
    ids = set()
    for tag in tags:
        if isinstance(tag, str) and (m := CWE_TAG.match(tag.strip())):
            ids.add(int(m.group(1)))
    return [f"CWE-{n}" for n in sorted(ids)]


def _rule_for(result: dict, run: dict) -> dict:
    tool = run.get("tool", {})
    driver = tool.get("driver", {})
    extensions = tool.get("extensions", [])
    ref = result.get("rule", {})

    component = driver
    component_index = ref.get("toolComponent", {}).get("index")
    if isinstance(component_index, int) and 0 <= component_index < len(extensions):
        component = extensions[component_index]

    index = result.get("ruleIndex", ref.get("index"))
    rules = component.get("rules", [])
    if isinstance(index, int) and 0 <= index < len(rules):
        return rules[index]

    rule_id = result.get("ruleId") or ref.get("id")
    for comp in (driver, *extensions):
        for rule in comp.get("rules", []):
            if rule.get("id") == rule_id:
                return rule
    return {}


def _location(result: dict) -> dict:
    for loc in result.get("locations", []):
        physical = loc.get("physicalLocation", {})
        uri = physical.get("artifactLocation", {}).get("uri")
        if uri:
            region = physical.get("region", {})
            start = region.get("startLine")
            return {"path": uri, "start_line": start, "end_line": region.get("endLine", start)}
    return {"path": ".", "start_line": None, "end_line": None}


def _text(obj: dict | None) -> str:
    return ((obj or {}).get("text") or "").strip()


def result_to_finding(result: dict, run: dict, stage: str, tool: str) -> dict:
    rule = _rule_for(result, run)
    rule_props = rule.get("properties", {})
    result_props = result.get("properties", {})
    rule_id = result.get("ruleId") or result.get("rule", {}).get("id") or rule.get("id") or "unknown"

    score = _security_severity(result_props, rule_props)
    if score is not None:
        severity = severity_from_score(score)
    else:
        level = result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"
        severity = LEVEL_SEVERITY.get(level, "medium")

    message = _text(result.get("message"))
    title = _text(rule.get("shortDescription")) or (message.splitlines()[0] if message else "") or rule_id
    tags = list(rule_props.get("tags", [])) + list(result_props.get("tags", []))

    return findings.make_finding(
        stage=stage,
        tool=tool,
        source="scanner",
        rule_id=rule_id,
        title=title,
        severity=severity,
        location=_location(result),
        cwe=cwes_from_tags(tags),
        description=message or _text(rule.get("fullDescription")),
        remediation=_text(rule.get("help")),
    )


def sarif_to_findings(sarif_path: str | Path, stage: str, tool: str) -> list:
    try:
        sarif = json.loads(Path(sarif_path).read_text())
    except json.JSONDecodeError as e:
        raise FindingsError(f"{sarif_path}: not valid JSON: {e}") from e
    if not isinstance(sarif, dict) or not isinstance(sarif.get("runs"), list):
        raise FindingsError(f"{sarif_path}: not a SARIF log (no 'runs' array)")

    by_id: dict[str, dict] = {}
    for run in sarif["runs"]:
        for result in run.get("results", []):
            if result.get("kind") in SKIPPED_KINDS:
                continue
            finding = result_to_finding(result, run, stage, tool)
            kept = by_id.get(finding["id"])
            if kept is None or SEVERITIES.index(finding["severity"]) < SEVERITIES.index(kept["severity"]):
                by_id[finding["id"]] = finding
    return findings.validate(list(by_id.values()))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.sarif", description="Convert SARIF 2.1.0 to factory findings")
    parser.add_argument("sarif")
    parser.add_argument("--stage", required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--out", help="write findings.json here instead of printing")
    args = parser.parse_args(argv)
    try:
        result = sarif_to_findings(args.sarif, args.stage, args.tool)
        if args.out:
            findings.write(args.out, result)
        else:
            sys.stdout.write(findings.dumps(result))
    except (FindingsError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
