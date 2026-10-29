import json
import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

from factory.stages import sast_semgrep

FACTORY_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = FACTORY_ROOT / "templates" / "precommit" / ".pre-commit-config.yaml"
GITLEAKS_CONFIG = FACTORY_ROOT / "rules" / "gitleaks.toml"
HOOK_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "USER", "CI", "RUNNER_TEMP")
BLOCKED_EXIT = 1


class HookError(Exception):
    pass


@dataclass(frozen=True)
class HookResult:
    blocked: bool
    output: str


def _entry(argv: list[str]) -> str:
    return json.dumps(shlex.join(argv))


def semgrep_argv(platform: str, community_root: Path = sast_semgrep.COMMUNITY_RULES) -> list[str]:
    argv = ["semgrep", "scan", "--error", "--metrics=off", "--disable-version-check", "--disable-nosem"]
    for config in sast_semgrep.select_configs(platform, community_root):
        argv += ["--config", config]
    return argv


def gitleaks_argv(config: Path = GITLEAKS_CONFIG) -> list[str]:
    return ["gitleaks", "git", "--pre-commit", "--staged", "--redact=100", "--no-banner", "--verbose", "--config", str(config)]


def render_config(platform: str, template: Path = TEMPLATE, community_root: Path = sast_semgrep.COMMUNITY_RULES) -> str:
    text = template.read_text()
    for marker in ("__SEMGREP_ENTRY__", "__GITLEAKS_ENTRY__"):
        if text.count(marker) != 1:
            raise HookError(f"{template}: expected exactly one {marker}")
    text = text.replace("__SEMGREP_ENTRY__", _entry(semgrep_argv(platform, community_root)))
    return text.replace("__GITLEAKS_ENTRY__", _entry(gitleaks_argv()))


def hook_env() -> dict[str, str]:
    env = {k: os.environ[k] for k in HOOK_ENV_KEYS if k in os.environ}
    env["PRE_COMMIT_COLOR"] = "never"
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def run_hooks(repo: Path, config: Path, runner=subprocess.run) -> HookResult:
    cmd = ["pre-commit", "run", "--config", str(config), "--color", "never"]
    print("+ " + " ".join(cmd), flush=True)
    try:
        proc = runner(cmd, cwd=repo, capture_output=True, text=True, env=hook_env())
    except FileNotFoundError as e:
        raise HookError("pre-commit not found; install it with python -m factory.tools install pre-commit") from e
    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode == 0:
        return HookResult(False, output)
    if proc.returncode == BLOCKED_EXIT:
        return HookResult(True, output)
    raise HookError(f"pre-commit failed with exit code {proc.returncode}: {output.strip()[-2000:]}")
