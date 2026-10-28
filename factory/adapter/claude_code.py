import json
import os
import re
import shutil
import subprocess

from factory.adapter import AdapterError, AdapterTimeout, Reply, Request, UsageLimitError

TOKEN_ENV = "CLAUDE_CODE_OAUTH_TOKEN"
DEFAULT_TIMEOUT = 600
DEFAULT_MAX_TURNS = 25
DENIED_TOOLS = ("Bash", "WebFetch", "WebSearch")
PASSTHROUGH_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "USER", "CI", "RUNNER_TEMP")

USAGE_LIMIT = re.compile(
    r"usage limit|rate[ _-]?limit|hit your (?:(?:usage|session|weekly) )?limit|limit (?:reached|exceeded)|\b429\b",
    re.IGNORECASE,
)


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise AdapterError(f"{name} must be a whole number, got '{raw}'") from None
    if value <= 0:
        raise AdapterError(f"{name} must be positive, got {value}")
    return value


def build_command(binary: str, request: Request, model: str | None, max_turns: int) -> list[str]:
    tools = ",".join(request.tools)
    cmd = [
        binary,
        "--print",
        "--output-format", "json",
        "--restricted",
        "--tools", tools,
        "--allowed-tools", tools,
        "--disallowed-tools", ",".join(DENIED_TOOLS),
        "--permission-mode", "dontAsk",
        "--strict-mcp-config",
        "--no-session-persistence",
        "--max-turns", str(max_turns),
    ]
    for directory in request.extra_dirs:
        cmd += ["--add-dir", str(directory)]
    if model:
        cmd += ["--model", model]
    return cmd


def child_env(token: str) -> dict[str, str]:
    env = {k: os.environ[k] for k in PASSTHROUGH_ENV if k in os.environ}
    env[TOKEN_ENV] = token
    env["DISABLE_AUTOUPDATER"] = "1"
    env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    return env


def _redact(text: str, token: str) -> str:
    return text.replace(token, "***") if token else text


def _tail(text: str, limit: int = 2000) -> str:
    text = text.strip()
    return text if len(text) <= limit else "..." + text[-limit:]


def _model_from(data: dict, fallback: str | None) -> str:
    usage = data.get("modelUsage") or {}
    if usage:
        return max(usage, key=lambda m: (usage[m] or {}).get("outputTokens", 0))
    return fallback or "default"


def run(request: Request) -> Reply:
    token = os.environ.get(TOKEN_ENV)
    if not token:
        raise AdapterError(f"{TOKEN_ENV} is not set")
    binary = shutil.which("claude")
    if not binary:
        raise AdapterError("claude CLI not found on PATH; run: python -m factory.tools install claude-code")
    model = os.environ.get("FACTORY_CLAUDE_MODEL") or None
    timeout = _int_env("FACTORY_CLAUDE_TIMEOUT", DEFAULT_TIMEOUT)
    max_turns = _int_env("FACTORY_CLAUDE_MAX_TURNS", DEFAULT_MAX_TURNS)

    try:
        result = subprocess.run(
            build_command(binary, request, model, max_turns),
            input=request.prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=request.workdir,
            env=child_env(token),
        )
    except subprocess.TimeoutExpired:
        raise AdapterTimeout(f"claude did not finish within {timeout} seconds") from None

    stdout, stderr = _redact(result.stdout, token), _redact(result.stderr, token)
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        data = None
    if not isinstance(data, dict):
        if USAGE_LIMIT.search(stdout + stderr):
            raise UsageLimitError("Claude usage limit reached; re-run later")
        raise AdapterError(
            f"claude exited {result.returncode} without a JSON result: {_tail(stderr or stdout)}"
        )

    failed = result.returncode != 0 or data.get("is_error") or data.get("subtype") != "success"
    if failed:
        message = f"{data.get('result') or ''}\n{stderr}"
        if USAGE_LIMIT.search(message):
            raise UsageLimitError("Claude usage limit reached; re-run later")
        if data.get("subtype") == "error_max_turns":
            raise AdapterError(f"claude hit the max-turns cap ({max_turns})")
        raise AdapterError(
            f"claude failed (exit {result.returncode}, {data.get('subtype')}): {_tail(message)}"
        )

    return Reply(
        text=data.get("result") or "",
        model=_model_from(data, model),
        details={"num_turns": data.get("num_turns"), "cli_duration_ms": data.get("duration_ms")},
    )
