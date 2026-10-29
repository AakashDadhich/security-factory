import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from factory import adapter, findings, rules
from factory.adapter import READ_TOOLS, AdapterError
from factory.findings import SEVERITIES, FindingsError
from factory.rules import RulesError

STAGE = "review"
FACTORY_ROOT = Path(__file__).resolve().parents[2]
PROMPT = FACTORY_ROOT / "prompts" / "security-review.md"
SCHEMA = FACTORY_ROOT / "schemas" / "review.schema.json"
DEFAULT_MAX_BYTES = 200_000
DEFAULT_ASVS_LEVEL = 2
CONTEXT_LINES = 20
SKIPPED_PREFIXES = ("security/",)
LOW_CONFIDENCE_CAP = "medium"
HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
HUNK_SPLIT = re.compile(r"(?m)^(?=@@ )")


class ReviewError(Exception):
    pass


@dataclass
class Hunk:
    text: str
    start: int
    end: int

    @property
    def changed(self) -> int:
        return sum(1 for line in self.text.splitlines()[1:] if line[:1] in "+-")


@dataclass
class FileDiff:
    path: str
    header: str
    hunks: list[Hunk]

    @property
    def changed(self) -> int:
        return sum(h.changed for h in self.hunks)


@dataclass
class Selection:
    text: str = ""
    included: dict[str, list[tuple[int, int]]] = field(default_factory=dict)
    omitted: list[str] = field(default_factory=list)
    truncated: bool = False


def git(repo: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-c", "core.quotepath=false", *args], cwd=repo, capture_output=True, check=False,
    )
    if check and result.returncode != 0:
        raise ReviewError(f"git {args[0]} failed: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout.decode(errors="replace") if result.returncode == 0 else ""


def resolve(repo: Path, rev: str) -> str:
    return git(repo, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}").strip()


def changed_paths(repo: Path, base: str, head: str) -> list[str]:
    raw = git(repo, "diff", "--no-renames", "--no-ext-diff", "--name-only", "-z", f"{base}...{head}")
    return sorted(p for p in raw.split("\0") if p and not p.startswith(SKIPPED_PREFIXES))


def parse_file_diff(path: str, text: str) -> FileDiff:
    parts = HUNK_SPLIT.split(text)
    header, hunk_texts = parts[0], parts[1:]
    hunks = []
    for chunk in hunk_texts:
        match = HUNK_HEADER.match(chunk)
        if not match:
            continue
        start = int(match.group(1))
        count = int(match.group(2)) if match.group(2) is not None else 1
        hunks.append(Hunk(chunk, start, start + count - 1))
    return FileDiff(path, header, hunks)


def file_diffs(repo: Path, base: str, head: str) -> list[FileDiff]:
    out = []
    for path in changed_paths(repo, base, head):
        text = git(repo, "diff", "--no-renames", "--no-ext-diff", "--no-textconv", f"--unified={CONTEXT_LINES}", f"{base}...{head}", "--", path)
        diff = parse_file_diff(path, text)
        if diff.hunks:
            out.append(diff)
    return out


def threat_blobs(threats: list[dict]) -> list[str]:
    return [json.dumps(t, ensure_ascii=False).lower() for t in threats]


def relevance(path: str, blobs: list[str]) -> int:
    needles = {path.lower(), Path(path).name.lower()}
    return sum(1 for blob in blobs if any(n in blob for n in needles))


def select(diffs: list[FileDiff], threats: list[dict], max_bytes: int) -> Selection:
    blobs = threat_blobs(threats)
    ordered = sorted(diffs, key=lambda d: (-relevance(d.path, blobs), -d.changed, d.path))
    selection = Selection()
    remaining = max_bytes
    pieces = []
    for diff in ordered:
        kept = []
        used = len(diff.header.encode())
        for hunk in diff.hunks:
            size = len(hunk.text.encode())
            if used + size > remaining:
                continue
            kept.append(hunk)
            used += size
        if not kept:
            selection.omitted.append(diff.path)
            selection.truncated = True
            continue
        if len(kept) < len(diff.hunks):
            selection.truncated = True
            selection.omitted.append(f"{diff.path} ({len(diff.hunks) - len(kept)} of {len(diff.hunks)} hunks)")
        remaining -= used
        pieces.append(diff.header + "".join(h.text for h in kept))
        selection.included[diff.path] = [(h.start, h.end) for h in kept]
    selection.text = "".join(p if p.endswith("\n") else p + "\n" for p in pieces)
    return selection


def read_at(repo: Path, rev: str, path: str) -> str | None:
    result = subprocess.run(["git", "show", f"{rev}:{path}"], cwd=repo, capture_output=True, check=False)
    return result.stdout.decode(errors="replace") if result.returncode == 0 else None


def load_open_threats(text: str | None) -> list[dict] | None:
    if text is None:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    items = data.get("threats") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return None
    return [t for t in items if isinstance(t, dict) and t.get("status", "open") == "open"]


def plan_level(text: str | None) -> int | None:
    if text is None:
        return None
    try:
        level = json.loads(text).get("asvs_level")
    except (json.JSONDecodeError, AttributeError):
        return None
    return level if level in rules.LEVELS else None


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


def guard(item: dict, selection: Selection, known_asvs: set[str], known_threats: set[str]) -> tuple[str, list[str], dict]:
    notes: list[str] = []
    severity = item["severity"]
    path = findings.normalise_path(item["path"])
    start, end = item["start_line"], max(item["end_line"], item["start_line"])
    ranges = selection.included.get(path)
    if ranges is None:
        severity = "info"
        notes.append(f"Downgraded to info: `{path}` is not in the reviewed diff.")
    elif not any(lo <= start and end <= hi for lo, hi in ranges):
        severity = "info"
        notes.append(f"Downgraded to info: lines {start}-{end} are outside the changed hunks and their context.")
    elif item["confidence"] == "low" and severity_rank(severity) < severity_rank(LOW_CONFIDENCE_CAP):
        notes.append(f"Severity capped at {LOW_CONFIDENCE_CAP} (reviewer reported {severity}) because confidence is low.")
        severity = LOW_CONFIDENCE_CAP
    asvs = [a for a in item["asvs_refs"] if a in known_asvs]
    threats = [t for t in item["threat_ids"] if t in known_threats]
    if len(asvs) != len(item["asvs_refs"]) or len(threats) != len(item["threat_ids"]):
        notes.append("Unknown ASVS or threat references were dropped.")
    return severity, notes, {"path": path, "start": start, "end": end, "asvs": asvs, "threats": threats}


def to_findings(reply: dict, selection: Selection, known_asvs: set[str], known_threats: set[str], tool: str) -> list[dict]:
    best: dict[str, dict] = {}
    for item in reply["findings"]:
        severity, notes, ref = guard(item, selection, known_asvs, known_threats)
        details = [item["description"], *notes]
        facts = [f"confidence {item['confidence']}"]
        if ref["threats"]:
            facts.append("threats " + ", ".join(ref["threats"]))
        if ref["asvs"]:
            facts.append("ASVS " + ", ".join(ref["asvs"]))
        details.append("(" + "; ".join(facts) + ")")
        finding = findings.make_finding(
            stage=STAGE, tool=tool, source="ai-review",
            rule_id="review-" + (item["cwe"][0].lower() if item["cwe"] else "general"),
            title=item["title"], severity=severity,
            location={"path": ref["path"], "start_line": ref["start"], "end_line": ref["end"]},
            cwe=item["cwe"], description="\n".join(details), remediation=item["remediation"],
        )
        current = best.get(finding["fingerprint"])
        if current is None or severity_rank(finding["severity"]) < severity_rank(current["severity"]):
            best[finding["fingerprint"]] = finding
    return sorted(best.values(), key=lambda f: (severity_rank(f["severity"]), f["location"]["path"], f["location"]["start_line"]))


def truncation_finding(selection: Selection, max_bytes: int) -> dict:
    return findings.make_finding(
        stage=STAGE, tool="factory", source="check", rule_id="review-truncated",
        title="The diff was too large to review in full", severity="info",
        location={"path": ".", "start_line": None},
        description=f"The diff is over {max_bytes} bytes, so files most relevant to the threat model were reviewed first. Not fully reviewed: " + "; ".join(selection.omitted) + ".",
        remediation="Split the change into smaller commits or review the omitted files by hand.",
    )


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def run(repo: Path, base: str, head: str, out: Path, asvs_level: int = DEFAULT_ASVS_LEVEL, max_bytes: int = DEFAULT_MAX_BYTES) -> int:
    out.mkdir(parents=True, exist_ok=True)
    base_sha, head_sha = resolve(repo, base), resolve(repo, head)
    if not base_sha or not head_sha:
        raise ReviewError(f"cannot resolve base {base!r} or head {head!r}")
    threats_text = read_at(repo, head_sha, "security/threats.json")
    threats = load_open_threats(threats_text)
    level = plan_level(read_at(repo, head_sha, "security/plan.json")) or asvs_level
    selection = select(file_diffs(repo, base_sha, head_sha), threats or [], max_bytes)
    checklist = rules.checklist(level)
    known_asvs = {r["id"] for r in checklist}
    known_threats = {t["id"] for t in threats or [] if isinstance(t.get("id"), str)}
    summary = {
        "base": base_sha, "head": head_sha, "asvs_level": level, "files_reviewed": sorted(selection.included),
        "omitted": selection.omitted, "truncated": selection.truncated, "diff_bytes": len(selection.text.encode()),
        "threats_used": len(threats or []), "model_called": False, "findings": 0, "downgraded": 0,
    }
    result: list[dict] = []
    if selection.included:
        (out / "diff.patch").write_text(selection.text)
        write_json(out / "checklist.json", checklist)
        inputs = [out / "diff.patch", out / "checklist.json"]
        if threats is not None:
            write_json(out / "threats.json", {"threats": threats})
            inputs.insert(1, out / "threats.json")
        reply_path = out / "reply.json"
        code = adapter.run_stage(
            stage=STAGE, prompt_path=PROMPT, inputs=inputs, schema_path=SCHEMA, out_path=reply_path,
            workdir=repo, allow_tools=list(READ_TOOLS),
        )
        if code != adapter.EXIT_OK:
            return code
        meta = json.loads(Path(str(reply_path) + ".meta.json").read_text())
        tool = str(meta.get("adapter", "claude_code")).replace("_", "-")
        result = to_findings(json.loads(reply_path.read_text()), selection, known_asvs, known_threats, tool)
        summary["model_called"] = True
    if selection.truncated:
        result.append(truncation_finding(selection, max_bytes))
    summary["findings"] = len(result)
    summary["downgraded"] = sum(1 for f in result if "Downgraded to info" in f["description"])
    findings.write(out / "findings.json", result)
    write_json(out / "summary.json", summary)
    print(f"reviewed {len(selection.included)} file(s), {len(result)} finding(s)" + (", diff truncated" if selection.truncated else ""))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.stages.review", description="Adversarial second-agent review of a diff")
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--out", default=Path("out/review"), type=Path)
    parser.add_argument("--repo", default=Path("."), type=Path)
    parser.add_argument("--asvs-level", default=DEFAULT_ASVS_LEVEL, type=int, choices=rules.LEVELS, help="used when security/plan.json is absent")
    parser.add_argument("--max-diff-bytes", default=DEFAULT_MAX_BYTES, type=int)
    args = parser.parse_args(argv)
    try:
        return run(args.repo, args.base, args.head, args.out, args.asvs_level, args.max_diff_bytes)
    except (ReviewError, FindingsError, RulesError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except AdapterError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.exit_code


if __name__ == "__main__":
    sys.exit(main())
