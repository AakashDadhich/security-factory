import argparse
import datetime
import json
import subprocess
import sys

SELFTEST = "selftest.yml"
ACCEPTANCE = "acceptance.yml"
MAX_AGE_DAYS = 7
MAJOR_TAG = "v1"
CONFIRM = "v1"


class ReleaseError(Exception):
    pass


def _gh(args: list[str]) -> str:
    proc = subprocess.run(["gh", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise ReleaseError(f"gh {' '.join(args[:2])} failed: {proc.stderr.strip()}")
    return proc.stdout


def _parse(stamp: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def latest_success(runs: list[dict], sha: str, now: datetime.datetime, max_age_days: int) -> dict | None:
    oldest = now - datetime.timedelta(days=max_age_days)
    good = [
        r for r in runs
        if r.get("head_sha") == sha and r.get("conclusion") == "success" and r.get("status") == "completed"
        and _parse(r["updated_at"]) >= oldest
    ]
    return max(good, key=lambda r: _parse(r["updated_at"])) if good else None


def check(repo: str, sha: str, now: datetime.datetime, gh=_gh, max_age_days: int = MAX_AGE_DAYS) -> list[str]:
    lines = []
    problems = []
    for workflow, label in ((SELFTEST, "selftest"), (ACCEPTANCE, "acceptance")):
        out = gh(["api", f"repos/{repo}/actions/workflows/{workflow}/runs?head_sha={sha}&per_page=100"])
        run = latest_success(json.loads(out).get("workflow_runs", []), sha, now, max_age_days)
        if run:
            lines.append(f"{label}: run {run['id']} succeeded at {run['updated_at']}")
        else:
            problems.append(f"no successful {label} run for {sha} in the last {max_age_days} days")
    if problems:
        raise ReleaseError("; ".join(problems) + ". Run the missing workflow on this commit, then release again.")
    return lines


def require_confirmation(value: str) -> None:
    if value != CONFIRM:
        raise ReleaseError(f"confirm must be exactly {CONFIRM!r}, got {value!r}")


def dated_tag(today: datetime.date) -> str:
    return f"{MAJOR_TAG}.{today:%Y%m%d}"


def _ref_sha(repo: str, tag: str, gh) -> str | None:
    try:
        out = gh(["api", f"repos/{repo}/git/ref/tags/{tag}"])
    except ReleaseError as e:
        if "404" in str(e):
            return None
        raise
    obj = json.loads(out)["object"]
    if obj["type"] != "commit":
        raise ReleaseError(f"tag {tag} is not a lightweight tag")
    return obj["sha"]


def move_tags(repo: str, sha: str, today: datetime.date, gh=_gh) -> list[str]:
    dated = dated_tag(today)
    existing = _ref_sha(repo, dated, gh)
    if existing not in (None, sha):
        raise ReleaseError(f"{dated} already points at {existing}; wait until tomorrow to release a different commit")
    if existing is None:
        gh(["api", "-X", "POST", f"repos/{repo}/git/refs", "-f", f"ref=refs/tags/{dated}", "-f", f"sha={sha}"])
    if _ref_sha(repo, MAJOR_TAG, gh) is None:
        gh(["api", "-X", "POST", f"repos/{repo}/git/refs", "-f", f"ref=refs/tags/{MAJOR_TAG}", "-f", f"sha={sha}"])
    else:
        gh(["api", "-X", "PATCH", f"repos/{repo}/git/refs/tags/{MAJOR_TAG}", "-f", f"sha={sha}", "-F", "force=true"])
    return [MAJOR_TAG, dated]


def release(repo: str, sha: str, confirm: str, now: datetime.datetime, gh=_gh) -> list[str]:
    require_confirmation(confirm)
    lines = check(repo, sha, now, gh)
    tags = move_tags(repo, sha, now.date(), gh)
    return [*lines, f"moved {tags[0]} and created {tags[1]} at {sha}"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.release", description="Gate and cut a factory release")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("check", "release"):
        p = sub.add_parser(name)
        p.add_argument("--repo", required=True)
        p.add_argument("--sha", required=True)
        if name == "release":
            p.add_argument("--confirm", required=True)
    args = parser.parse_args(argv)
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        lines = check(args.repo, args.sha, now) if args.cmd == "check" else release(args.repo, args.sha, args.confirm, now)
    except ReleaseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
