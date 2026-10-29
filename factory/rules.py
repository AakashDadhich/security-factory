import argparse
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
ASVS_PATH = RULES_DIR / "asvs" / "asvs.json"

PLATFORMS = ("web", "macos", "ios")
LEVELS = (1, 2, 3)
TARGETS = {
    "claude": "CLAUDE.md",
    "agents": "AGENTS.md",
}
CORE_ORDER = ("base", "secure-defaults")
CLOSED_STATUSES = ("closed", "mitigated", "resolved", "accepted", "rejected")

_FRONT_MATTER = re.compile(r"\A---\n(.*?)\n---\n(.*)\Z", re.S)


class RulesError(Exception):
    pass


def load_rule(path: Path) -> dict:
    match = _FRONT_MATTER.match(path.read_text())
    if not match:
        raise RulesError(f"{path}: missing YAML front matter")
    meta = yaml.safe_load(match.group(1)) or {}
    for key in ("id", "title", "applies_to"):
        if key not in meta:
            raise RulesError(f"{path}: front matter needs '{key}'")
    unknown = set(meta["applies_to"]) - {"all", *PLATFORMS}
    if unknown:
        raise RulesError(f"{path}: unknown applies_to {sorted(unknown)}")
    return {"id": meta["id"], "title": meta["title"], "applies_to": meta["applies_to"], "body": match.group(2)}


def select_rules(platform: str, rules_dir: Path = RULES_DIR) -> list[dict]:
    rules = [load_rule(p) for p in sorted(rules_dir.glob("*.md"))]
    chosen = [r for r in rules if "all" in r["applies_to"] or platform in r["applies_to"]]
    core = [r for name in CORE_ORDER for r in chosen if r["id"] == name]
    rest = sorted((r for r in chosen if r["id"] not in CORE_ORDER), key=lambda r: r["id"])
    return core + rest


def load_asvs(level: int, path: Path = ASVS_PATH) -> list[dict]:
    if level not in LEVELS:
        raise RulesError(f"asvs level must be one of {LEVELS}, got {level}")
    reqs = json.loads(path.read_text())
    return sorted((r for r in reqs if r["level"] <= level), key=lambda r: _id_key(r["id"]))


def _id_key(req_id: str) -> list[int]:
    return [int(n) for n in re.findall(r"\d+", req_id)]


def _chapter_key(chapter: str) -> int:
    return _id_key(chapter.split()[0])[0]


def _demote(body: str) -> str:
    lines = body.strip("\n").split("\n")
    if lines and lines[0].startswith("# "):
        lines = lines[1:]
    out = []
    for line in lines:
        out.append("#" + line if line.startswith("#") else line)
    return "\n".join(out).strip("\n")


def load_threats(path: str | Path) -> list[dict]:
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise RulesError(f"{path}: {e}") from e
    threats = data.get("threats") if isinstance(data, dict) else data
    if not isinstance(threats, list):
        raise RulesError(f"{path}: expected a list of threats or an object with a 'threats' list")
    result = []
    for t in threats:
        if not isinstance(t, dict) or "id" not in t:
            raise RulesError(f"{path}: every threat needs an 'id'")
        if str(t.get("status", "open")).lower() in CLOSED_STATUSES:
            continue
        mitigations = []
        for n, m in enumerate(t.get("mitigations", []), 1):
            if isinstance(m, str):
                m = {"text": m}
            if "text" not in m:
                raise RulesError(f"{path}: threat {t['id']} has a mitigation with no 'text'")
            refs = m.get("asvs", m.get("asvs_refs", []))
            mitigations.append(
                {"id": str(m.get("id", f"{t['id']}-M{n}")), "text": m["text"], "asvs": sorted(str(r) for r in refs)}
            )
        if mitigations:
            result.append({"id": str(t["id"]), "title": t.get("title", ""), "mitigations": mitigations})
    return sorted(result, key=lambda t: t["id"])


def render_threats(threats: list[dict]) -> str:
    lines = ["## Project-specific mitigations", ""]
    if not threats:
        lines.append("No open threats with mitigations are recorded yet.")
        return "\n".join(lines)
    lines.append("Each mitigation below comes from this project's threat model. Implement it and keep it in place.")
    for t in threats:
        lines += ["", f"### {t['id']}" + (f": {t['title']}" if t["title"] else "")]
        for m in t["mitigations"]:
            refs = f" (ASVS: {', '.join(m['asvs'])})" if m["asvs"] else ""
            lines.append(f"- **{m['id']}** {m['text']}{refs}")
    return "\n".join(lines)


def render_asvs(level: int, reqs: list[dict]) -> str:
    levels = "+".join(f"L{n}" for n in range(1, level + 1))
    lines = [
        f"## ASVS {levels}",
        "",
        "OWASP ASVS 5.0.0 requirements for this project's level (CC BY-SA 4.0, see rules/asvs/SOURCE.md).",
    ]
    chapters: dict[str, list[dict]] = {}
    for r in reqs:
        chapters.setdefault(r["chapter"], []).append(r)
    for chapter in sorted(chapters, key=_chapter_key):
        lines += ["", f"### {chapter}"]
        for r in chapters[chapter]:
            lines.append(f"- **{r['id']}** (L{r['level']}) {r['text']}")
    return "\n".join(lines)


def render(platform: str, level: int, target: str, threats: list[dict] | None = None, rules_dir: Path = RULES_DIR, asvs_path: Path = ASVS_PATH) -> str:
    if platform not in PLATFORMS:
        raise RulesError(f"platform must be one of {PLATFORMS}, got {platform}")
    if target not in TARGETS:
        raise RulesError(f"target must be one of {tuple(TARGETS)}, got {target}")
    parts = [
        f"<!-- Generated by the security factory; do not edit by hand. Target: {TARGETS[target]} -->",
        f"# Security rules ({platform}, ASVS level {level})",
        "Follow these rules in all code you write or change. They are mandatory, not suggestions.",
    ]
    for rule in select_rules(platform, rules_dir):
        parts.append(f"## {rule['title']}\n\n{_demote(rule['body'])}")
    parts.append(render_asvs(level, load_asvs(level, asvs_path)))
    if threats is not None:
        parts.append(render_threats(threats))
    return "\n\n".join(parts) + "\n"


def checklist(level: int, asvs_path: Path = ASVS_PATH) -> list[dict]:
    return [
        {"id": r["id"], "chapter": r["chapter"], "level": r["level"], "text": r["text"]}
        for r in load_asvs(level, asvs_path)
    ]


def _write(path: str, text: str) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.rules", description="Render the security rules")
    sub = parser.add_subparsers(dest="command", required=True)
    r = sub.add_parser("render", help="Render CLAUDE.md or AGENTS.md")
    r.add_argument("--platform", required=True, choices=PLATFORMS)
    r.add_argument("--asvs-level", required=True, type=int, choices=LEVELS)
    r.add_argument("--threats")
    r.add_argument("--target", required=True, choices=tuple(TARGETS))
    r.add_argument("--out", required=True)
    c = sub.add_parser("checklist", help="Write the ASVS review checklist as JSON")
    c.add_argument("--asvs-level", required=True, type=int, choices=LEVELS)
    c.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "render":
            threats = load_threats(args.threats) if args.threats else None
            _write(args.out, render(args.platform, args.asvs_level, args.target, threats))
        else:
            _write(args.out, json.dumps(checklist(args.asvs_level), indent=1, ensure_ascii=False) + "\n")
    except RulesError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
