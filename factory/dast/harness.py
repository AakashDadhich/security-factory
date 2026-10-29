import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

from factory import config as factory_config
from factory import tools

NETWORK = "factory-dast"
APP_ALIAS = "app"
HEALTH_TIMEOUT = 120
HEALTH_INTERVAL = 2


class HarnessError(Exception):
    pass


def container_name(run_id: str) -> str:
    return f"factory-app-{run_id}"


def image_tag(run_id: str) -> str:
    return f"factory-app:{run_id}"


def read_env_example(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.removeprefix("export ").strip()
        values[key] = value.strip().strip("\"'")
    return values


def network_create_cmd() -> list[str]:
    return ["docker", "network", "create", "--internal", NETWORK]


def build_cmd(run_id: str, dockerfile: str, context: str = ".") -> list[str]:
    return ["docker", "build", "-t", image_tag(run_id), "-f", dockerfile, context]


def run_cmd(run_id: str, env: dict[str, str]) -> list[str]:
    cmd = [
        "docker", "run", "--detach",
        "--name", container_name(run_id),
        "--network", NETWORK,
        "--network-alias", APP_ALIAS,
        "--read-only",
        "--tmpfs", "/tmp",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
    ]
    for key, value in env.items():
        cmd += ["-e", f"{key}={value}"]
    cmd.append(image_tag(run_id))
    return cmd


def health_cmd(curl_image: str, port: int, health_path: str) -> list[str]:
    return [
        "docker", "run", "--rm", "--network", NETWORK, curl_image,
        "--silent", "--output", "/dev/null", "--write-out", "%{http_code}",
        "--max-time", "5", f"http://{APP_ALIAS}:{port}{health_path}",
    ]


def down_cmds(run_id: str) -> list[list[str]]:
    return [
        ["docker", "rm", "--force", container_name(run_id)],
        ["docker", "network", "rm", NETWORK],
        ["docker", "rmi", "--force", image_tag(run_id)],
    ]


def _run(cmd: list[str], check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    print("+ " + " ".join(cmd), flush=True)
    proc = subprocess.run(cmd, capture_output=capture, text=True)
    if check and proc.returncode != 0:
        raise HarnessError(f"{' '.join(cmd[:3])} failed with exit code {proc.returncode}")
    return proc


def wait_healthy(curl_image: str, port: int, health_path: str, run_id: str, timeout: float = HEALTH_TIMEOUT, runner=None, sleep=time.sleep, clock=time.monotonic) -> None:
    runner = runner or (lambda cmd: _run(cmd, check=False, capture=True))
    deadline = clock() + timeout
    while True:
        proc = runner(health_cmd(curl_image, port, health_path))
        if proc.returncode == 0 and (proc.stdout or "").strip() == "200":
            print(f"app healthy at http://{APP_ALIAS}:{port}{health_path}", flush=True)
            return
        if clock() >= deadline:
            break
        sleep(HEALTH_INTERVAL)
    _run(["docker", "logs", container_name(run_id)], check=False)
    raise HarnessError(f"app did not return 200 on {health_path} within {timeout:.0f} seconds")


def up(config_path: Path, run_id: str, context: Path) -> None:
    cfg = factory_config.load(config_path)
    web = cfg.get("web")
    if cfg["platform"] != "web" or not web:
        raise HarnessError("the DAST harness only runs for platform: web")
    lock = tools.load_lock()
    curl_image = tools.get_tool(lock, "curl").image
    env = read_env_example(context / ".env.example")
    _run(network_create_cmd())
    try:
        _run(build_cmd(run_id, str(context / web["dockerfile"]), str(context)))
        _run(run_cmd(run_id, env))
        wait_healthy(curl_image, web["port"], web["health_path"], run_id)
    except (HarnessError, KeyboardInterrupt):
        down(run_id)
        raise


def down(run_id: str) -> None:
    for cmd in down_cmds(run_id):
        _run(cmd, check=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.dast.harness", description="Start or stop the throwaway app for DAST")
    parser.add_argument("action", choices=("up", "down"))
    parser.add_argument("--config", default=".factory.yml")
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", "local"))
    parser.add_argument("--context", default=".", help="docker build context and location of .env.example")
    args = parser.parse_args(argv)
    try:
        if args.action == "up":
            up(Path(args.config), args.run_id, Path(args.context))
        else:
            down(args.run_id)
    except (HarnessError, factory_config.ConfigError, tools.ToolError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
