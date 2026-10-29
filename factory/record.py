import argparse
import base64
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from factory import sbom

BRANCH = "factory-record"
RUNS_TO_READ = 10
PUSH_ATTEMPTS = 3
BOT_NAME = "aakashdadhich-factory-bot[bot]"
BOT_EMAIL = "349043243+aakashdadhich-factory-bot[bot]@users.noreply.github.com"


class RecordError(Exception):
    pass


def _git(args: list[str], cwd: Path | None = None, token: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    cmd = ["git"]
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        cmd += ["-c", f"http.extraheader=AUTHORIZATION: basic {basic}"]
    cmd += args
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env)
    if check and result.returncode != 0:
        raise RecordError(f"git {args[0]} failed: {result.stderr.strip()}")
    return result


def remote_url(repo: str) -> str:
    return f"https://github.com/{repo}.git"


def branch_exists(url: str, token: str | None) -> bool:
    result = _git(["ls-remote", "--exit-code", "--heads", url, BRANCH], token=token, check=False)
    if result.returncode == 0:
        return True
    if result.returncode == 2:
        return False
    raise RecordError(f"git ls-remote failed: {result.stderr.strip()}")


def run_entry_name(timestamp: datetime.datetime, run_id: str) -> str:
    return f"{timestamp.astimezone(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{run_id}.json"


def is_default_branch_push(event: str, ref: str, default_branch: str) -> bool:
    return event == "push" and ref in (default_branch, f"refs/heads/{default_branch}")


def _load_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise RecordError(f"cannot read {path}: {e}") from e


def build_run_entry(gate: dict, manifest: dict | None, ref: str, commit: str | None, run_id: str) -> dict:
    manifest = manifest or {}
    return {
        "run_id": run_id,
        "mode": gate.get("mode", manifest.get("mode")),
        "ref": ref,
        "commit": manifest.get("commit_sha") or commit,
        "status": gate["status"],
        "counts": gate.get("counts", {}),
        "blocking_fingerprints": gate.get("blocking_fingerprints", []),
        "iteration": gate.get("iteration", manifest.get("iteration", 0)),
        "issue": manifest.get("issue"),
    }


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def apply_changes(work: Path, entry_name: str, entry: dict, update_latest: bool, artifacts: Path) -> None:
    _write_json(work / "runs" / entry_name, entry)
    if not update_latest:
        return
    latest = work / "latest"
    previous = latest / "sbom.cdx.json"
    previous_components = sbom.components(previous) if previous.exists() else []
    new_bom = artifacts / "deps-sbom" / "sbom.cdx.json"
    staged = Path(tempfile.mkdtemp(prefix="record-latest-"))
    try:
        shutil.copyfile(artifacts / "gate" / "report.json", staged / "findings.json")
        manifest = artifacts / "setup" / "run-manifest.json"
        if manifest.exists():
            shutil.copyfile(manifest, staged / "run-manifest.json")
        if new_bom.exists():
            shutil.copyfile(new_bom, staged / "sbom.cdx.json")
            _write_json(staged / "sbom-diff.json", sbom.diff(previous_components, sbom.components(new_bom)))
        if latest.exists():
            shutil.rmtree(latest)
        shutil.copytree(staged, latest)
    finally:
        shutil.rmtree(staged, ignore_errors=True)


def read(url: str, out: Path, token: str | None = None) -> bool:
    out.mkdir(parents=True, exist_ok=True)
    if not branch_exists(url, token):
        return False
    with tempfile.TemporaryDirectory(prefix="record-read-") as tmp:
        clone = Path(tmp) / "clone"
        _git(["clone", "--quiet", "--depth", "1", "--branch", BRANCH, url, str(clone)], token=token)
        if (clone / "latest").is_dir():
            shutil.copytree(clone / "latest", out / "latest", dirs_exist_ok=True)
        runs = sorted((clone / "runs").glob("*.json")) if (clone / "runs").is_dir() else []
        if runs:
            (out / "runs").mkdir(exist_ok=True)
            for path in runs[-RUNS_TO_READ:]:
                shutil.copyfile(path, out / "runs" / path.name)
    return True


def _prepare_worktree(url: str, work: Path, token: str | None) -> None:
    if branch_exists(url, token):
        _git(["clone", "--quiet", "--depth", "1", "--branch", BRANCH, url, str(work)], token=token)
    else:
        work.mkdir(parents=True)
        _git(["init", "--quiet", "--initial-branch", BRANCH], cwd=work)
        _git(["remote", "add", "origin", url], cwd=work)
    _git(["config", "user.name", os.environ.get("FACTORY_BOT_NAME", BOT_NAME)], cwd=work)
    _git(["config", "user.email", os.environ.get("FACTORY_BOT_EMAIL", BOT_EMAIL)], cwd=work)
    _git(["config", "commit.gpgsign", "false"], cwd=work)


def _sync_to_remote(work: Path, token: str | None) -> None:
    _git(["fetch", "--quiet", "--depth", "1", "origin", BRANCH], cwd=work, token=token)
    _git(["reset", "--quiet", "--hard", "FETCH_HEAD"], cwd=work)


def write(url: str, artifacts: Path, event: str, ref: str, default_branch: str, run_id: str | None = None,
          commit: str | None = None, token: str | None = None, now: datetime.datetime | None = None) -> dict:
    gate = _load_json(artifacts / "gate" / "gate-result.json")
    manifest_path = artifacts / "setup" / "run-manifest.json"
    manifest = _load_json(manifest_path) if manifest_path.exists() else None
    run_id = run_id or (manifest or {}).get("run_id")
    if not run_id:
        raise RecordError("run id missing: pass --run-id or provide setup/run-manifest.json")
    entry = build_run_entry(gate, manifest, ref, commit, str(run_id))
    update_latest = gate["status"] == "pass" and is_default_branch_push(event, ref, default_branch)
    if update_latest and not (artifacts / "gate" / "report.json").exists():
        raise RecordError("gate passed but report.json is missing")
    name = run_entry_name(now or datetime.datetime.now(datetime.timezone.utc), str(run_id))
    message = f"chore(record): {entry['mode']} run {run_id} {entry['status']}"

    with tempfile.TemporaryDirectory(prefix="record-write-") as tmp:
        work = Path(tmp) / "work"
        _prepare_worktree(url, work, token)
        for attempt in range(1, PUSH_ATTEMPTS + 1):
            apply_changes(work, name, entry, update_latest, artifacts)
            _git(["add", "--all"], cwd=work)
            _git(["commit", "--quiet", "-m", message], cwd=work)
            pushed = _git(["push", "--quiet", "origin", f"HEAD:refs/heads/{BRANCH}"], cwd=work, token=token, check=False)
            if pushed.returncode == 0:
                return {"entry": name, "latest_updated": update_latest, "attempts": attempt}
            if attempt == PUSH_ATTEMPTS:
                raise RecordError(f"push failed after {PUSH_ATTEMPTS} attempts: {pushed.stderr.strip()}")
            _sync_to_remote(work, token)
    raise RecordError("unreachable")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.record", description="Read and write the factory-record branch")
    sub = parser.add_subparsers(dest="command", required=True)
    read_cmd = sub.add_parser("read", help="copy latest/ and the last runs/ entries into a directory")
    write_cmd = sub.add_parser("write", help="add a run entry and, on a default-branch pass, replace latest/")
    for cmd in (read_cmd, write_cmd):
        cmd.add_argument("--repo", required=True, help="owner/name")
        cmd.add_argument("--remote", help="git remote URL, overrides the GitHub URL (tests)")
    read_cmd.add_argument("--out", required=True)
    write_cmd.add_argument("--artifacts", required=True)
    write_cmd.add_argument("--event", required=True)
    write_cmd.add_argument("--ref", required=True)
    write_cmd.add_argument("--default-branch", required=True)
    write_cmd.add_argument("--run-id")
    write_cmd.add_argument("--commit")
    args = parser.parse_args(argv)
    url = args.remote or remote_url(args.repo)
    token = os.environ.get("GH_TOKEN") or None
    try:
        if args.command == "read":
            found = read(url, Path(args.out), token)
            print(f"record: {'read ' + BRANCH if found else 'no ' + BRANCH + ' branch yet'}")
        else:
            result = write(url, Path(args.artifacts), args.event, args.ref, args.default_branch,
                           run_id=args.run_id, commit=args.commit, token=token)
            print(f"record: wrote runs/{result['entry']} (latest updated: {result['latest_updated']}, attempts: {result['attempts']})")
    except (RecordError, sbom.SbomError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
