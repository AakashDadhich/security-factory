import argparse
import datetime
import json
import subprocess
import sys
import time

WORKFLOW = "factory.yml"
POLL_SECONDS = 30
TIMEOUT_SECONDS = 60 * 60
FIND_ATTEMPTS = 10


class RunError(Exception):
    pass


def _gh(args: list[str]) -> str:
    proc = subprocess.run(["gh", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RunError(f"gh {' '.join(args[:3])} failed: {proc.stderr.strip()}")
    return proc.stdout


def _parse(stamp: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def pick_run(runs: list[dict], since: datetime.datetime) -> dict | None:
    fresh = [r for r in runs if _parse(r["createdAt"]) >= since]
    return min(fresh, key=lambda r: _parse(r["createdAt"])) if fresh else None


def dispatch(repo: str, ref: str, factory_ref: str | None = None, gh=_gh, now=lambda: datetime.datetime.now(datetime.timezone.utc)) -> datetime.datetime:
    since = now().replace(microsecond=0)
    cmd = ["workflow", "run", WORKFLOW, "--repo", repo, "--ref", ref]
    if factory_ref:
        cmd += ["-f", f"factory-ref={factory_ref}"]
    gh(cmd)
    return since


def find_run(repo: str, since: datetime.datetime, gh=_gh, sleep=time.sleep, attempts: int = FIND_ATTEMPTS) -> int:
    for _ in range(attempts):
        out = gh(["run", "list", "--repo", repo, "--workflow", WORKFLOW, "--event", "workflow_dispatch", "--limit", "10", "--json", "databaseId,createdAt"])
        run = pick_run(json.loads(out), since)
        if run:
            return int(run["databaseId"])
        sleep(5)
    raise RunError("the dispatched run did not appear")


def wait_for(repo: str, run_id: int, gh=_gh, sleep=time.sleep, poll: int = POLL_SECONDS, timeout: int = TIMEOUT_SECONDS) -> str:
    waited = 0
    while True:
        out = gh(["run", "view", str(run_id), "--repo", repo, "--json", "status,conclusion"])
        state = json.loads(out)
        if state["status"] == "completed":
            return state.get("conclusion") or "unknown"
        if waited >= timeout:
            raise RunError(f"run {run_id} did not finish within {timeout // 60} minutes")
        sleep(poll)
        waited += poll


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m factory.acceptance_run")
    p.add_argument("--repo", required=True)
    p.add_argument("--ref", default="main")
    p.add_argument("--factory-ref", help="factory ref the target run must check out (default: the stub's default)")
    p.add_argument("--github-output")
    args = p.parse_args(argv)
    try:
        since = dispatch(args.repo, args.ref, args.factory_ref)
        run_id = find_run(args.repo, since)
        print(f"dispatched run {run_id}", flush=True)
        conclusion = wait_for(args.repo, run_id)
    except RunError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"run {run_id} finished: {conclusion}")
    if args.github_output:
        with open(args.github_output, "a") as fh:
            fh.write(f"run_id={run_id}\nconclusion={conclusion}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
