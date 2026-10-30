import argparse
import json
import re
import sys
from pathlib import Path

from factory import findings

MARKER = "<!-- factory:plan -->"
ITEM_LIMIT = 15
TEXT_LIMIT = 300
ZWSP = "​"
MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()<>#+!|~])")


class CommentError(Exception):
    pass


def escape(text: str, limit: int = TEXT_LIMIT) -> str:
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    text = MARKDOWN_SPECIAL.sub(r"\\\1", text)
    # Model text is derived from untrusted issue text: stop it pinging users or turning into links.
    text = text.replace("@", "@" + ZWSP).replace("://", ":/" + ZWSP + "/")
    return re.sub(r"(?i)\bwww\.", lambda m: m.group(0)[:3] + ZWSP + ".", text)


def _yes(value: bool) -> str:
    return "yes" if value else "no"


def _section(title: str, lines: list[str]) -> list[str]:
    if not lines:
        return []
    shown = lines[:ITEM_LIMIT]
    if len(lines) > ITEM_LIMIT:
        shown.append(f"- ...and {len(lines) - ITEM_LIMIT} more in `plan.json`")
    return [f"### {title}", *shown, ""]


def render(plan: dict, run_url: str | None = None) -> str:
    high = set(plan["high_risk_features"])
    features = [
        f"- **{escape(f['id'])}** {escape(f['name'])} (risk {f['risk']}{', high risk' if f['id'] in high else ''}): {escape(f['description'])}"
        for f in plan["features"]
    ]
    requirements = []
    for r in plan["requirements"]:
        refs = f" ASVS: {', '.join(r['asvs_refs'])}." if r["asvs_refs"] else ""
        requirements.append(f"- **{escape(r['id'])}** {escape(r['text'])} Check: {escape(r['testable_check'])}{refs}")
    abuse = [
        f"- **{escape(a['feature_id'])}** {escape(a['attacker_goal'])} Mitigation: {escape(a['mitigation'])}"
        for a in plan["abuse_cases"]
    ]
    lines = [
        MARKER,
        "## Factory plan",
        "",
        escape(plan["summary"], 1000),
        "",
        "| Risk | ASVS level | Personal data | Payments |",
        "|---|---|---|---|",
        f"| {plan['risk_rating']} | {plan['asvs_level']} | {_yes(plan['personal_data'])} | {_yes(plan['takes_payments'])} |",
        "",
    ]
    if plan["users"]:
        lines += [f"**Users:** {', '.join(escape(u, 80) for u in plan['users'][:ITEM_LIMIT])}", ""]
    if plan.get("changed_features"):
        lines += [f"**Changed features:** {', '.join(escape(i, 40) for i in plan['changed_features'][:ITEM_LIMIT])}", ""]
    if plan.get("touched_elements"):
        lines += [f"**Touched elements:** {', '.join(escape(e, 80) for e in plan['touched_elements'][:ITEM_LIMIT])}", ""]
    lines += _section("Features", features)
    lines += _section("Requirements", requirements)
    lines += _section("Abuse cases", abuse)
    lines += _section("Data handled", [f"- {escape(d['name'], 120)} ({d['classification']})" for d in plan["data_handled"]])
    lines += _section("Out of scope", [f"- {escape(o)}" for o in plan["out_of_scope"]])
    lines += _section("Open questions", [f"- {escape(q)}" for q in plan["open_questions"]])
    source = f"[this run]({run_url})" if run_url else "this run"
    lines.append(f"_Written by the factory's plan stage from the issue text. The full plan is the `plan` artifact of {source}. Review it before the next stage._")
    return "\n".join(lines) + "\n"


def load_plan(path: Path) -> dict:
    try:
        plan = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise CommentError(f"{path}: {e}") from e
    errors = list(findings.validator("plan.schema.json").iter_errors(plan))
    if errors:
        raise CommentError(f"{path} does not match the plan schema: {errors[0].message}")
    return plan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.plan_comment", description="Render plan.json as an issue comment")
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--run-url")
    args = parser.parse_args(argv)
    if args.run_url and not re.fullmatch(r"https://github\.com/[A-Za-z0-9._/-]+", args.run_url):
        print("error: --run-url must be a github.com URL", file=sys.stderr)
        return 1
    try:
        text = render(load_plan(args.plan), args.run_url)
    except CommentError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
