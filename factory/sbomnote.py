import argparse
import json
import re
import sys
from pathlib import Path

from factory.plan_comment import escape

BRANCH = re.compile(r"factory/([1-9][0-9]{0,14})")
MARKER = "<!-- factory:sbom-diff -->"
LIST_LIMIT = 20


class SbomNoteError(Exception):
    pass


def issue_for_pulls(pulls: list) -> int | None:
    for pull in pulls:
        head = pull.get("head") if isinstance(pull, dict) else None
        ref = head.get("ref") if isinstance(head, dict) else None
        if isinstance(ref, str) and BRANCH.fullmatch(ref):
            return int(BRANCH.fullmatch(ref).group(1))
    return None


def _versions(values: list) -> str:
    return ", ".join(escape(str(v), 40) for v in values) or "none"


def _component(component: dict) -> str:
    version = f" {escape(str(component['version']), 40)}" if component.get("version") else ""
    return f"- {escape(str(component.get('name', '')), 120)}{version}"


def render(diff: dict, issue: int, commit: str | None = None) -> str:
    lines = [MARKER, "## Dependency changes after merge", ""]
    if commit:
        lines += [f"Merged in `{escape(commit[:12], 12)}`. The factory record compared the new SBOM with the previous one.", ""]
    sections = (
        ("Added", [_component(c) for c in diff.get("added", [])]),
        ("Removed", [_component(c) for c in diff.get("removed", [])]),
        ("Changed", [f"- {escape(c['name'], 120)}: {_versions(c['old_versions'])} to {_versions(c['new_versions'])}" for c in diff.get("changed", [])]),
    )
    if not any(items for _, items in sections):
        lines.append("No dependency changes.")
    for title, items in sections:
        if items:
            shown = items[:LIST_LIMIT]
            if len(items) > LIST_LIMIT:
                shown.append(f"- ...and {len(items) - LIST_LIMIT} more in `latest/sbom-diff.json` on `factory-record`")
            lines += [f"**{title} ({len(items)}):**", *shown, ""]
    return "\n".join(lines).rstrip() + "\n"


def _load(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise SbomNoteError(f"{path}: {e}") from e


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.sbomnote", description="Comment the SBOM diff on the issue of a merged factory branch")
    parser.add_argument("--pulls", required=True, type=Path, help="JSON from the commit's associated pull requests")
    parser.add_argument("--diff", required=True, type=Path, help="latest/sbom-diff.json from the record")
    parser.add_argument("--commit")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)
    try:
        pulls = _load(args.pulls)
        issue = issue_for_pulls(pulls if isinstance(pulls, list) else [])
        found = issue is not None and args.diff.is_file()
        if found:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(render(_load(args.diff), issue, args.commit))
    except SbomNoteError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"sbom note: issue {issue}, comment {'written' if found else 'not needed'}")
    if args.github_output:
        with args.github_output.open("a") as handle:
            handle.write(f"issue={issue if found else ''}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
