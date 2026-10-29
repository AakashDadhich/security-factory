import argparse
import base64
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from factory import findings, patch_policy, precommit
from factory.findings import FindingsError
from factory.patch_policy import PolicyError
from factory.precommit import HookError

STAGE = "codegen-commit"
BOT_NAME = "aakashdadhich-factory-bot[bot]"
BOT_EMAIL = "349043243+aakashdadhich-factory-bot[bot]@users.noreply.github.com"
SHA = re.compile(r"[0-9a-f]{40}")


class CommitError(Exception):
    pass


def git(repo: Path, *args: str, token: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    cmd = ["git"]
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        cmd += ["-c", f"http.extraheader=AUTHORIZATION: basic {basic}"]
    env = {**{k: v for k, v in os.environ.items() if k in precommit.HOOK_ENV_KEYS}, "GIT_TERMINAL_PROMPT": "0"}
    result = subprocess.run([*cmd, *args], cwd=repo, capture_output=True, text=True, env=env)
    if check and result.returncode != 0:
        raise CommitError(f"git {args[0]} failed: {result.stderr.strip()}")
    return result


def commit_message(issue: int, iteration: int) -> str:
    return f"feat: implement #{issue} (factory iteration {iteration})"


def refusal(out: Path, rule_id: str, title: str, detail: str) -> int:
    findings.write(out / "findings.json", [findings.make_finding(
        stage=STAGE, tool="factory", source="check", rule_id=rule_id, title=title, severity="high",
        location={"path": ".", "start_line": None}, description=detail[-6000:],
        remediation="Review the patch in the codegen-ai artifact; the factory never commits it as is.",
    )])
    print(f"error: {title}: {detail}", file=sys.stderr)
    return 1


def apply_patch(repo: Path, patch_path: Path, summary: dict, platform: str, out: Path, hooks=precommit.run_hooks) -> int:
    branch, base_sha = summary["branch"], summary["base_sha"]
    patch_policy.assert_push_target(branch)
    if not SHA.fullmatch(base_sha):
        raise CommitError(f"base_sha {base_sha!r} is not a commit hash")
    patch = patch_path.read_text()
    problems = patch_policy.inspect_patch(patch)
    if not patch.strip():
        problems.append("the patch is empty")
    if problems:
        return refusal(out, "patch-refused", "Patch refused by the path and content policy", "\n".join(f"- {p}" for p in problems))
    git(repo, "checkout", "-q", "-B", branch, base_sha)
    applied = git(repo, "apply", "--index", "--whitespace=nowarn", str(patch_path.resolve()), check=False)
    if applied.returncode != 0:
        return refusal(out, "patch-refused", "Patch does not apply to the recorded base commit", applied.stderr)
    config = out / "pre-commit-config.yaml"
    config.write_text(precommit.render_config(platform))
    result = hooks(repo, config)
    if result.blocked:
        return refusal(out, "precommit-blocked", "Pre-commit hooks blocked the patch", result.output)
    git(repo, "-c", f"user.name={BOT_NAME}", "-c", f"user.email={BOT_EMAIL}", "commit", "-q", "--no-verify",
        "-m", commit_message(summary["issue"], summary["iteration"]))
    sha = git(repo, "rev-parse", "HEAD").stdout.strip()
    (out / "commit.json").write_text(json.dumps({"branch": branch, "base_sha": base_sha, "sha": sha}, indent=2) + "\n")
    print(f"committed {sha} on {branch}")
    return 0


def push(repo: Path, url: str, commit: dict, default_branch: str, token: str) -> None:
    branch = commit["branch"]
    patch_policy.assert_push_target(branch, default_branch)
    if not token:
        raise CommitError("GH_TOKEN is not set")
    head = git(repo, "rev-parse", "HEAD").stdout.strip()
    if head != commit["sha"]:
        raise CommitError(f"HEAD {head} is not the recorded commit {commit['sha']}")
    git(repo, "push", "--quiet", url, f"HEAD:refs/heads/{branch}", token=token)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.stages.codegen_commit",
                                     description="Apply the codegen patch and push it to factory/<issue>")
    sub = parser.add_subparsers(dest="command", required=True)
    a = sub.add_parser("apply", help="check, apply and commit the patch locally (no token)")
    a.add_argument("--codegen", required=True, type=Path, help="folder with changes.patch and summary.json")
    a.add_argument("--platform", required=True, choices=("web", "macos", "ios"))
    a.add_argument("--repo", default=Path("."), type=Path)
    a.add_argument("--out", default=Path("out/codegen-commit"), type=Path)
    a.add_argument("--github-output", type=Path)
    p = sub.add_parser("push", help="push the committed branch with the token in GH_TOKEN")
    p.add_argument("--repo", default=Path("."), type=Path)
    p.add_argument("--slug", required=True, help="owner/name")
    p.add_argument("--commit-file", required=True, type=Path)
    p.add_argument("--default-branch", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "apply":
            args.out.mkdir(parents=True, exist_ok=True)
            findings.write(args.out / "findings.json", [])
            summary = json.loads((args.codegen / "summary.json").read_text())
            code = apply_patch(args.repo, args.codegen / "changes.patch", summary, args.platform, args.out)
            if code == 0 and args.github_output:
                sha = json.loads((args.out / "commit.json").read_text())["sha"]
                with args.github_output.open("a") as handle:
                    handle.write(f"sha={sha}\n")
            return code
        commit = json.loads(args.commit_file.read_text())
        push(args.repo, f"https://github.com/{args.slug}.git", commit, args.default_branch, os.environ.get("GH_TOKEN", ""))
        print(f"pushed {commit['sha']} to {commit['branch']}")
        return 0
    except (CommitError, PolicyError, HookError, FindingsError, OSError, KeyError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
