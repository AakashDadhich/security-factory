from pathlib import Path
from urllib.parse import urlsplit

from factory.dast.harness import APP_ALIAS, NETWORK

PLAN_DIR = Path(__file__).resolve().parent.parent.parent / "zap"
PLANS = ("baseline", "full")
SPEC_MOUNT = "/zap/spec/openapi.yaml"

OPENAPI_JOB = f"""  - type: openapi
    parameters:
      apiFile: {SPEC_MOUNT}
      targetUrl: "{{{{TARGET}}}}"
      context: app"""


class PlanError(Exception):
    pass


def target_url(port: int) -> str:
    return f"http://{APP_ALIAS}:{port}"


def assert_safe_target(url: str, port: int) -> None:
    parts = urlsplit(url)
    try:
        url_port = parts.port
    except ValueError:
        url_port = None
    if parts.scheme != "http" or parts.hostname != APP_ALIAS or url_port != port or parts.path not in ("", "/") or parts.username or parts.password:
        raise PlanError(f"refusing to scan {url!r}: the target must be {target_url(port)} on the {NETWORK} network")


def assert_safe_command(cmd: list[str]) -> None:
    for i, arg in enumerate(cmd):
        if arg == "--network" and i + 1 < len(cmd) and cmd[i + 1] == NETWORK:
            return
    raise PlanError(f"refusing to run ZAP outside the {NETWORK} network")


def render(plan: str, port: int, openapi: bool = False, plan_dir: Path = PLAN_DIR) -> str:
    if plan not in PLANS:
        raise PlanError(f"unknown plan {plan!r}; choose from {', '.join(PLANS)}")
    if openapi and plan != "full":
        raise PlanError("OpenAPI import is only part of the full plan")
    url = target_url(port)
    assert_safe_target(url, port)
    text = (plan_dir / f"{plan}.yaml").read_text()
    if plan == "full":
        text = text.replace("{{OPENAPI_JOB}}\n", OPENAPI_JOB + "\n" if openapi else "")
    return text.replace("{{TARGET}}", url)


def resolve_spec(spec: str, project_dir: Path) -> Path:
    root = project_dir.resolve()
    path = (root / spec).resolve()
    if not path.is_relative_to(root):
        raise PlanError(f"OpenAPI spec {spec!r} is outside the project")
    if not path.is_file():
        raise PlanError(f"OpenAPI spec {spec!r} not found")
    return path
