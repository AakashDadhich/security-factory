import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
LOOP_MODES = ("spec", "change", "fix")
MAX_ITERATION = 2
EVENT_TYPE = "factory-fix"
NEEDS_HUMAN_LABEL = "factory:needs-human"
STOP_HEADING = "Factory stopped after 2 fix attempts"
MARKER = "<!-- factory:next-step -->"
POSITIVE_INT = re.compile(r"[1-9][0-9]{0,14}")
MAX_FINDINGS = 40
COMMENT_LIMIT = 60000
ZWSP = "\u200b"
ACTIONS = ("dispatch", "stop", "done", "none")


class FixLoopError(Exception):
    pass


def positive_int(value, name: str) -> int:
    if isinstance(value, bool) or not POSITIVE_INT.fullmatch(str(value).strip()):
        raise FixLoopError(f"{name} must be a positive integer, got {str(value)[:40]!r}")
    return int(str(value).strip())


def fix_iteration(value) -> int:
    text = str(value).strip()
    if text not in ("1", str(MAX_ITERATION)):
        raise FixLoopError(f"iteration must be 1 or {MAX_ITERATION} in fix mode, got {text[:40]!r}")
    return int(text)


def parse_fix_inputs(issue, iteration, findings_run_id) -> dict:
    return {
        "issue": positive_int(issue, "issue"),
        "iteration": fix_iteration(iteration),
        "findings_run_id": positive_int(findings_run_id, "findings_run_id"),
    }


def decide(mode: str, gate_status: str, iteration: int) -> str:
    if mode not in LOOP_MODES or gate_status not in ("pass", "fail"):
        return "none"
    if gate_status == "pass":
        return "done"
    return "dispatch" if iteration < MAX_ITERATION else "stop"


def gate_status_of(job_result: str) -> str:
    return {"success": "pass", "failure": "fail"}.get(job_result, "none")


def dispatch_body(issue: int, iteration: int, run_id: int) -> dict:
    if iteration >= MAX_ITERATION or iteration < 0:
        raise FixLoopError(f"no further fix run after iteration {iteration}")
    return {
        "event_type": EVENT_TYPE,
        "client_payload": {
            "issue": positive_int(issue, "issue"),
            "iteration": iteration + 1,
            "findings_run_id": positive_int(run_id, "findings_run_id"),
        },
    }


def send_dispatch(repo: str, body: dict, run=subprocess.run) -> None:
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo):
        raise FixLoopError(f"{repo!r} is not owner/name")
    result = run(["gh", "api", "--method", "POST", f"repos/{repo}/dispatches", "--input", "-"],
                 input=json.dumps(body), capture_output=True, text=True)
    if result.returncode != 0:
        raise FixLoopError(f"dispatch failed: {result.stderr.strip()}")


def _load(path: Path) -> dict | list:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise FixLoopError(f"{path}: {e}") from e


def _clip(value, limit: int) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def blocking_findings(gate_dir: Path, setup_dir: Path, issue: int, iteration: int) -> list[dict]:
    result = _load(gate_dir / "gate-result.json")
    report = _load(gate_dir / "report.json")
    manifest = _load(setup_dir / "run-manifest.json")
    if result.get("status") != "fail":
        raise FixLoopError("the referenced gate run did not fail, so there is nothing to fix")
    if result.get("mode") not in LOOP_MODES:
        raise FixLoopError(f"the referenced run has mode {result.get('mode')!r}, not a loop mode")
    if manifest.get("issue") != issue:
        raise FixLoopError(f"the referenced run is for issue {manifest.get('issue')}, not {issue}")
    if result.get("iteration") != iteration - 1:
        raise FixLoopError(f"the referenced run has iteration {result.get('iteration')}, expected {iteration - 1}")
    wanted = set(result.get("blocking_fingerprints", []))
    chosen = [f for f in report if f.get("fingerprint") in wanted]
    chosen.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]) if f.get("severity") in SEVERITY_ORDER else len(SEVERITY_ORDER))
    if not chosen:
        raise FixLoopError("the referenced gate run lists no blocking findings")
    return [{
        "id": f.get("id"),
        "fingerprint": f.get("fingerprint"),
        "severity": f.get("severity"),
        "rule_id": f.get("rule_id"),
        "title": _clip(f.get("title"), 300),
        "tool": f.get("tool"),
        "stages": f.get("stages", []),
        "location": f.get("location"),
        "cwe": f.get("cwe", []),
        "description": _clip(f.get("description"), 1500),
        "remediation": _clip(f.get("remediation"), 600),
    } for f in chosen[:MAX_FINDINGS]]


def defang(text: str) -> str:
    text = text.replace("@", "@" + ZWSP).replace("://", ":/" + ZWSP + "/")
    return re.sub(r"(?i)\bwww\.", lambda m: m.group(0)[:3] + ZWSP + ".", text)


def render_comment(kind: str, issue: int, report: str, run_url: str | None = None) -> str:
    if kind == "stop":
        lines = [MARKER, f"## {STOP_HEADING}", "",
                 f"The gate still fails on `factory/{issue}`. A person needs to look at the findings below.", ""]
    elif kind == "done":
        lines = [MARKER, f"Gate passed. Branch `factory/{issue}` is ready to merge.", ""]
    else:
        raise FixLoopError(f"unknown comment kind {kind!r}")
    if run_url:
        lines += [f"Run: {run_url}", ""]
    body = defang(report.strip())
    room = COMMENT_LIMIT - len("\n".join(lines)) - 80
    if len(body) > room:
        body = body[:room].rstrip() + "\n\n(report truncated, see the gate artifact)"
    return "\n".join(lines + [body, ""])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.fixloop", description="Fix loop decisions and helpers")
    sub = parser.add_subparsers(dest="command", required=True)
    d = sub.add_parser("decide")
    d.add_argument("--mode", required=True)
    d.add_argument("--gate-result", required=True, help="the gate job result: success, failure, skipped, ...")
    d.add_argument("--iteration", required=True, type=int)
    d.add_argument("--github-output", type=Path)
    b = sub.add_parser("blocking")
    b.add_argument("--gate", required=True, type=Path)
    b.add_argument("--setup", required=True, type=Path)
    b.add_argument("--issue", required=True)
    b.add_argument("--iteration", required=True)
    b.add_argument("--out", required=True, type=Path)
    s = sub.add_parser("dispatch")
    s.add_argument("--repo", required=True)
    s.add_argument("--issue", required=True)
    s.add_argument("--iteration", required=True, type=int)
    s.add_argument("--run-id", required=True)
    c = sub.add_parser("comment")
    c.add_argument("--kind", required=True, choices=("stop", "done"))
    c.add_argument("--issue", required=True)
    c.add_argument("--report", required=True, type=Path)
    c.add_argument("--run-url")
    c.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "decide":
            action = decide(args.mode, gate_status_of(args.gate_result), args.iteration)
            print(f"fix loop: mode {args.mode}, gate {args.gate_result}, iteration {args.iteration} -> {action}")
            if args.github_output:
                with args.github_output.open("a") as handle:
                    handle.write(f"action={action}\n")
        elif args.command == "blocking":
            issue, iteration = positive_int(args.issue, "issue"), fix_iteration(args.iteration)
            items = blocking_findings(args.gate, args.setup, issue, iteration)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(items, indent=2) + "\n")
            print(f"fix loop: {len(items)} blocking finding(s) written to {args.out}")
        elif args.command == "dispatch":
            body = dispatch_body(positive_int(args.issue, "issue"), args.iteration, positive_int(args.run_id, "run id"))
            send_dispatch(args.repo, body)
            print(f"fix loop: dispatched {EVENT_TYPE} {json.dumps(body['client_payload'])}")
        else:
            text = render_comment(args.kind, positive_int(args.issue, "issue"), args.report.read_text(), args.run_url)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(text)
    except (FixLoopError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
