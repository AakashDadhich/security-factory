import argparse
import json
import sys
from pathlib import Path

from factory.plan_comment import escape

COMPARED = ("title", "description", "likelihood", "impact", "severity", "status", "element")
LIST_LIMIT = 15
EMPTY = {"threats": [], "removed": []}


class DiffError(Exception):
    pass


def _summary(threat: dict) -> dict:
    return {k: threat[k] for k in ("id", "framework", "element", "title", "severity", "status")}


def _mitigation_view(threat: dict) -> list:
    return [(m["text"], tuple(m["asvs_refs"])) for m in threat["mitigations"]]


def changed_fields(old: dict, new: dict) -> list[str]:
    fields = [f for f in COMPARED if old.get(f) != new.get(f)]
    if _mitigation_view(old) != _mitigation_view(new):
        fields.append("mitigations")
    return fields


def diff_threats(old: dict | None, new: dict) -> dict:
    old = old or EMPTY
    before = {t["id"]: t for t in old["threats"]}
    after = {t["id"]: t for t in new["threats"]}
    added = [_summary(t) for i, t in after.items() if i not in before]
    removed = [_summary(t) for i, t in before.items() if i not in after]
    changed = []
    for threat_id, threat in after.items():
        if threat_id in before:
            fields = changed_fields(before[threat_id], threat)
            if fields:
                changed.append({**_summary(threat), "fields": fields, "was_severity": before[threat_id]["severity"]})
    return {"added": added, "changed": changed, "removed": removed}


def load(path: Path | None) -> dict | None:
    if path is None or not path.is_file():
        return None
    try:
        doc = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise DiffError(f"{path}: cannot read threats: {e}") from e
    if not isinstance(doc, dict) or not isinstance(doc.get("threats"), list):
        raise DiffError(f"{path}: not a threats document")
    doc.setdefault("removed", [])
    return doc


def _line(item: dict, extra: str = "") -> str:
    return f"- **{escape(item['id'], 20)}** {escape(item['title'], 160)} ({escape(item['element'], 60)}, {item['severity']}){extra}"


def _section(title: str, lines: list[str]) -> list[str]:
    if not lines:
        return [f"**{title}:** none", ""]
    shown = lines[:LIST_LIMIT]
    if len(lines) > LIST_LIMIT:
        shown.append(f"- ...and {len(lines) - LIST_LIMIT} more in `security/threats.json`")
    return [f"**{title} ({len(lines)}):**", *shown, ""]


def render_markdown(diff: dict) -> str:
    lines = ["### Threat model changes", ""]
    lines += _section("Added", [_line(t) for t in diff["added"]])
    lines += _section("Changed", [
        _line(t, f", was {t['was_severity']}; changed {', '.join(t['fields'])}") for t in diff["changed"]
    ])
    lines += _section("Removed", [_line(t) for t in diff["removed"]])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.threatmodel.diff", description="Summarise threats added, changed and removed")
    parser.add_argument("--base", type=Path, help="threats.json before the change; a missing file means no earlier model")
    parser.add_argument("--head", required=True, type=Path, help="threats.json after the change")
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    args = parser.parse_args(argv)
    try:
        new = load(args.head)
        if new is None:
            raise DiffError(f"{args.head}: no threat model to compare")
        diff = diff_threats(load(args.base), new)
    except DiffError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(diff, indent=2) + "\n")
    text = render_markdown(diff)
    if args.out_md:
        args.out_md.parent.mkdir(parents=True, exist_ok=True)
        args.out_md.write_text(text)
    print(f"threat diff: {len(diff['added'])} added, {len(diff['changed'])} changed, {len(diff['removed'])} removed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
