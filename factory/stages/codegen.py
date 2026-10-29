import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from factory import adapter, findings, patch_policy, precommit, rules
from factory.adapter import READ_TOOLS, AdapterError
from factory.findings import FindingsError
from factory.patch_policy import PolicyError
from factory.precommit import HookError
from factory.rules import RulesError

STAGE = "codegen-ai"
FACTORY_ROOT = Path(__file__).resolve().parents[2]
PROMPT = FACTORY_ROOT / "prompts" / "codegen.md"
FIX_PROMPT = FACTORY_ROOT / "prompts" / "fix.md"
REPLY_SCHEMA = FACTORY_ROOT / "schemas" / "codegen-reply.schema.json"
FIX_REPLY_SCHEMA = FACTORY_ROOT / "schemas" / "fix-reply.schema.json"
MAX_RETRIES = 2
MAX_FILES = 300
MAX_FILE_BYTES = 1024 * 1024
FEEDBACK_LIMIT = 6000
SHA = re.compile(r"[0-9a-f]{40}")
TRUSTED_TREE_FILES = ("tm.py", "threats.json")


class CodegenError(Exception):
    pass


def git(repo: Path, *args: str, check: bool = True, data: bytes | None = None) -> subprocess.CompletedProcess:
    env = {**{k: v for k, v in os.environ.items() if k in precommit.HOOK_ENV_KEYS}, "GIT_TERMINAL_PROMPT": "0"}
    result = subprocess.run(["git", *args], cwd=repo, capture_output=True, input=data, env=env)
    if check and result.returncode != 0:
        raise CodegenError(f"git {args[0]} failed: {result.stderr.decode(errors='replace').strip()}")
    return result


def ensure_branch(repo: Path, branch: str, require_remote: bool = False) -> str:
    patch_policy.assert_push_target(branch)
    remote = git(repo, "rev-parse", "--verify", "--quiet", f"refs/remotes/origin/{branch}", check=False)
    if require_remote and remote.returncode != 0:
        raise CodegenError(f"fix mode needs the existing branch {branch}, but origin has none")
    if remote.returncode == 0:
        git(repo, "checkout", "-q", "-B", branch, f"refs/remotes/origin/{branch}")
    else:
        git(repo, "checkout", "-q", "-B", branch)
    sha = git(repo, "rev-parse", "HEAD").stdout.decode().strip()
    if not SHA.fullmatch(sha):
        raise CodegenError(f"unexpected HEAD value {sha!r}")
    return sha


def tracked_files(repo: Path) -> list[str]:
    raw = git(repo, "ls-files", "-z").stdout.decode()
    paths = []
    for path in filter(None, raw.split("\0")):
        full = repo / path
        if full.is_file() and not full.is_symlink():
            paths.append(path)
    return paths


def _tree_files(tm_dir: Path) -> list[tuple[Path, str]]:
    pairs = []
    for name in TRUSTED_TREE_FILES:
        source = tm_dir / name
        if not source.is_file():
            raise CodegenError(f"{source} not found; codegen needs the threat-model artifact")
        pairs.append((source, f"security/{name}"))
    trees = tm_dir / "attack-trees"
    if trees.is_dir():
        for source in sorted(trees.iterdir()):
            if source.is_file() and source.name.count(".") == 1 and source.suffix in (".md", ".json"):
                pairs.append((source, f"security/attack-trees/{source.name}"))
    return pairs


def write_trusted(repo: Path, plan_path: Path, tm_dir: Path, platform: str, level: int) -> list[str]:
    threats = rules.load_threats(tm_dir / "threats.json") if (tm_dir / "threats.json").is_file() else None
    written = []
    for target, name in (("claude", "CLAUDE.md"), ("agents", "AGENTS.md")):
        (repo / name).write_text(rules.render(platform, level, target, threats))
        written.append(name)
    pairs = [(plan_path, "security/plan.json"), *_tree_files(tm_dir)]
    for source, relative in pairs:
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        written.append(relative)
    return written


def hash_files(root: Path, paths) -> dict[str, str]:
    return {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in paths}


def scan_tree(root: Path) -> tuple[dict[str, str], list[str]]:
    hashes, problems = {}, []
    for current, dirs, files in os.walk(root):
        for name in list(dirs):
            full = Path(current) / name
            if full.is_symlink():
                problems.append(f"{full.relative_to(root).as_posix()}: symbolic link")
                dirs.remove(name)
            elif name == ".git":
                problems.append(f"{full.relative_to(root).as_posix()}: git metadata")
                dirs.remove(name)
        for name in files:
            full = Path(current) / name
            relative = full.relative_to(root).as_posix()
            if full.is_symlink():
                problems.append(f"{relative}: symbolic link")
            elif not full.is_file():
                problems.append(f"{relative}: not a regular file")
            elif full.stat().st_size > MAX_FILE_BYTES:
                problems.append(f"{relative}: larger than {MAX_FILE_BYTES} bytes")
            else:
                hashes[relative] = hashlib.sha256(full.read_bytes()).hexdigest()
    return hashes, problems


def copy_to_work(repo: Path, paths, work: Path) -> None:
    for path in paths:
        target = work / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repo / path, target)
        shutil.copymode(repo / path, target)


def change_problems(repo: Path, work: Path, baseline: dict, hashes: dict, scan_problems: list[str]) -> tuple[list[str], list[str], list[str]]:
    changed = sorted(p for p, h in hashes.items() if baseline.get(p) != h)
    deleted = sorted(p for p in baseline if p not in hashes)
    problems = list(scan_problems)
    if len(changed) + len(deleted) > MAX_FILES:
        problems.append(f"{len(changed) + len(deleted)} files changed; the limit is {MAX_FILES}")
    for path in [*changed, *deleted]:
        reason = patch_policy.agent_path_violation(path)
        if reason:
            problems.append(f"{path}: {reason}")
    for path in changed:
        if path.rsplit("/", 1)[-1] == "package.json":
            old = (repo / path).read_text() if path in baseline else None
            reason = patch_policy.package_json_violation(old, (work / path).read_text())
            if reason:
                problems.append(f"{path}: {reason}")
    return changed, deleted, problems


def ignored_paths(repo: Path, paths: list[str]) -> set[str]:
    if not paths:
        return set()
    result = git(repo, "check-ignore", "-z", "--no-index", "--stdin", check=False, data=("\0".join(paths) + "\0").encode())
    return set(filter(None, result.stdout.decode().split("\0")))


def restore(repo: Path, paths) -> None:
    for path in sorted(paths):
        in_head = git(repo, "cat-file", "-e", f"HEAD:{path}", check=False).returncode == 0
        if in_head:
            git(repo, "checkout", "-q", "HEAD", "--", path)
        else:
            (repo / path).unlink(missing_ok=True)


def apply_changes(repo: Path, work: Path, changed: list[str], deleted: list[str]) -> None:
    for path in deleted:
        (repo / path).unlink(missing_ok=True)
    for path in changed:
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(work / path, target)
        shutil.copymode(work / path, target)


def stage_paths(repo: Path, paths) -> None:
    ordered = sorted(paths)
    for start in range(0, len(ordered), 100):
        git(repo, "add", "-A", "--", *ordered[start:start + 100])


def staged_patch(repo: Path) -> str:
    raw = git(repo, "diff", "--binary", "--cached").stdout
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise CodegenError("the staged patch is not valid UTF-8") from None


def staged_names(repo: Path) -> list[str]:
    return sorted(filter(None, git(repo, "diff", "--cached", "--name-only", "-z").stdout.decode().split("\0")))


def blocked_finding(rule_id: str, title: str, output: str):
    return findings.make_finding(
        stage=STAGE,
        tool="pre-commit" if rule_id == "precommit-blocked" else "factory",
        source="check",
        rule_id=rule_id,
        title=title,
        severity="high",
        location={"path": ".", "start_line": None},
        description=output[-FEEDBACK_LIMIT:],
        remediation="Fix the reported problems in the generated code, or implement the change by hand.",
    )


def adapter_agent(stage: str, inputs: list[Path], reply_path: Path, work: Path,
                  prompt: Path = PROMPT, schema: Path = REPLY_SCHEMA) -> int:
    return adapter.run_stage(
        stage=stage, prompt_path=prompt, inputs=inputs, schema_path=schema, out_path=reply_path,
        workdir=work, allow_tools=list(READ_TOOLS), allow_write=True,
    )


def fix_agent(stage: str, inputs: list[Path], reply_path: Path, work: Path) -> int:
    return adapter_agent(stage, inputs, reply_path, work, FIX_PROMPT, FIX_REPLY_SCHEMA)


def snapshot_security(repo: Path, dest: Path) -> tuple[Path, Path]:
    source = repo / "security"
    plan_path, tm_dir = dest / "plan.json", dest / "threat-model"
    tm_dir.mkdir(parents=True)
    if not (source / "plan.json").is_file():
        raise CodegenError("the factory branch has no security/plan.json to fix against")
    shutil.copyfile(source / "plan.json", plan_path)
    for name in TRUSTED_TREE_FILES:
        if not (source / name).is_file():
            raise CodegenError(f"the factory branch has no security/{name}")
        shutil.copyfile(source / name, tm_dir / name)
    trees = source / "attack-trees"
    if trees.is_dir():
        shutil.copytree(trees, tm_dir / "attack-trees", symlinks=False, ignore=lambda d, names: [n for n in names if (Path(d) / n).is_symlink()])
    return plan_path, tm_dir


def run_fix(repo: Path, findings_path: Path, platform: str, issue: int, iteration: int, out: Path,
            agent=fix_agent, hooks=precommit.run_hooks, github_output: Path | None = None) -> int:
    if not findings_path.is_file():
        raise CodegenError(f"{findings_path} not found; fix mode needs the blocking findings")
    branch = patch_policy.branch_name(issue)
    ensure_branch(repo, branch, require_remote=True)
    held = Path(tempfile.mkdtemp(prefix="codegen-security-"))
    try:
        plan_path, tm_dir = snapshot_security(repo, held)
        return run(repo, plan_path, tm_dir, platform, issue, iteration, out, agent, hooks, github_output,
                   extra_inputs=[findings_path], stage_names=("fix", "fix-retry"), fixing=True)
    finally:
        shutil.rmtree(held, ignore_errors=True)


def run(repo: Path, plan_path: Path, tm_dir: Path, platform: str, issue: int, iteration: int, out: Path,
        agent=adapter_agent, hooks=precommit.run_hooks, github_output: Path | None = None,
        extra_inputs: list[Path] | None = None, stage_names: tuple[str, str] = ("codegen", "codegen-fix"),
        fixing: bool = False) -> int:
    out.mkdir(parents=True, exist_ok=True)
    findings.write(out / "findings.json", [])
    plan = json.loads(plan_path.read_text())
    level = plan["asvs_level"]
    branch = patch_policy.branch_name(issue)
    base_sha = ensure_branch(repo, branch)
    if github_output:
        with github_output.open("a") as handle:
            handle.write(f"base_sha={base_sha}\n")
    config = out / "pre-commit-config.yaml"
    config.write_text(precommit.render_config(platform))

    trusted = write_trusted(repo, plan_path, tm_dir, platform, level)
    baseline = hash_files(repo, sorted(set(tracked_files(repo)) | set(trusted)))
    work = Path(tempfile.mkdtemp(prefix="codegen-work-"))
    feedback_dir = out / "feedback"
    feedback_dir.mkdir(exist_ok=True)
    try:
        copy_to_work(repo, baseline, work)
        inputs = [work / "CLAUDE.md", work / "security" / "plan.json", work / "security" / "threats.json"]
        touched: set[str] = set(trusted)
        feedback, rule_id, title = "", "", ""
        for attempt in range(MAX_RETRIES + 1):
            stage = stage_names[0] if attempt == 0 else f"{stage_names[1]}-{attempt}"
            attempt_inputs = [*inputs, *(extra_inputs or [])]
            if attempt:
                feedback_file = feedback_dir / f"blocked-{attempt}.txt"
                feedback_file.write_text(feedback[-FEEDBACK_LIMIT:])
                attempt_inputs.append(feedback_file)
            reply_path = out / f"{stage}-reply.json"
            code = agent(stage, attempt_inputs, reply_path, work)
            if code != adapter.EXIT_OK:
                return code
            hashes, scan_problems = scan_tree(work)
            changed, deleted, problems = change_problems(repo, work, baseline, hashes, scan_problems)
            skipped = ignored_paths(repo, changed)
            changed = [p for p in changed if p not in skipped]
            if not problems and not (changed or deleted):
                problems = ["the agent changed no files"]
            git(repo, "reset", "-q")
            restore(repo, touched)
            touched = set(trusted)
            write_trusted(repo, plan_path, tm_dir, platform, level)
            if problems:
                rule_id, title = "patch-policy-blocked", "Generated changes break the patch policy"
                feedback = "The changes were refused:\n" + "\n".join(f"- {p}" for p in problems)
                print(feedback, file=sys.stderr)
                continue
            apply_changes(repo, work, changed, deleted)
            touched |= set(changed) | set(deleted)
            stage_paths(repo, touched)
            patch = staged_patch(repo)
            patch_problems = patch_policy.inspect_patch(patch)
            if patch_problems:
                rule_id, title = "patch-policy-blocked", "Generated changes break the patch policy"
                feedback = "The patch was refused:\n" + "\n".join(f"- {p}" for p in patch_problems)
                print(feedback, file=sys.stderr)
                continue
            result = hooks(repo, config)
            if result.blocked:
                rule_id, title = "precommit-blocked", "Pre-commit hooks blocked the generated code"
                feedback = result.output
                print(feedback, file=sys.stderr)
                continue
            return finish(out, repo, patch, base_sha, branch, issue, iteration, platform, level, attempt + 1, reply_path, fixing)
        findings.write(out / "findings.json", [blocked_finding(rule_id, title, feedback)])
        print(f"error: generated code still blocked after {MAX_RETRIES + 1} attempts ({rule_id})", file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


def finish(out: Path, repo: Path, patch: str, base_sha: str, branch: str, issue: int, iteration: int,
           platform: str, level: int, attempts: int, reply_path: Path, fixing: bool = False) -> int:
    (out / "changes.patch").write_text(patch)
    meta_path = Path(f"{reply_path}.meta.json")
    model = json.loads(meta_path.read_text()).get("model") if meta_path.is_file() else None
    summary = {
        "issue": issue,
        "iteration": iteration,
        "branch": branch,
        "base_sha": base_sha,
        "platform": platform,
        "asvs_level": level,
        "attempts": attempts,
        "model": model,
        "files_changed": staged_names(repo),
    }
    if fixing:
        reply = json.loads(reply_path.read_text())
        summary.update(mode="fix", account=reply["summary"], fixes=reply["fixes"], open_questions=reply["open_questions"])
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"codegen: {len(summary['files_changed'])} file(s) staged on {branch} after {attempts} attempt(s)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.stages.codegen",
                                     description="Implement the plan on factory/<issue> and write a patch")
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--threat-model", type=Path, dest="tm_dir")
    parser.add_argument("--platform", required=True, choices=("web", "macos", "ios"))
    parser.add_argument("--issue", required=True, type=int)
    parser.add_argument("--iteration", default=0, type=int)
    parser.add_argument("--fix-findings", type=Path, help="fix mode: blocking findings JSON; the plan and threat model come from the factory branch")
    parser.add_argument("--repo", default=Path("."), type=Path)
    parser.add_argument("--out", default=Path("out/codegen"), type=Path)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)
    if args.fix_findings is None and not (args.plan and args.tm_dir):
        parser.error("--plan and --threat-model are required unless --fix-findings is given")
    if args.fix_findings is not None and (args.plan or args.tm_dir):
        parser.error("--fix-findings reads the plan and threat model from the factory branch; do not pass --plan or --threat-model")
    try:
        if args.fix_findings is not None:
            return run_fix(args.repo.resolve(), args.fix_findings.resolve(), args.platform, args.issue,
                           args.iteration, args.out.resolve(), github_output=args.github_output)
        return run(args.repo.resolve(), args.plan.resolve(), args.tm_dir.resolve(), args.platform, args.issue,
                   args.iteration, args.out.resolve(), github_output=args.github_output)
    except (CodegenError, PolicyError, HookError, RulesError, FindingsError, OSError, KeyError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except AdapterError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.exit_code


if __name__ == "__main__":
    sys.exit(main())
