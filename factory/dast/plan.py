import json
from pathlib import Path
from urllib.parse import quote, urlsplit

from factory.dast.harness import APP_ALIAS, NETWORK

PLAN_DIR = Path(__file__).resolve().parent.parent.parent / "zap"
PLANS = ("baseline", "full")
SPEC_MOUNT = "/zap/spec/openapi.yaml"
AUTH_USER = "test-user"

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


def _q(value: str) -> str:
    return json.dumps(value)


def login_target(login_url: str, port: int) -> str:
    url = target_url(port) + login_url
    parts = urlsplit(url)
    if not login_url.startswith("/") or login_url.startswith("//") or parts.hostname != APP_ALIAS or parts.port != port or parts.username or parts.password:
        raise PlanError(f"refusing login URL {login_url!r}: it must be a path on {target_url(port)}")
    return url


def login_body(auth: dict) -> str:
    if auth["type"] == "json":
        return json.dumps({auth["username_field"]: "{%username%}", auth["password_field"]: "{%password%}"}, separators=(",", ":"))
    return f"{quote(auth['username_field'])}={{%username%}}&{quote(auth['password_field'])}={{%password%}}"


def auth_block(auth: dict, port: int, username: str, password: str) -> str:
    if auth.get("type") not in ("form", "json"):
        raise PlanError(f"unknown auth type {auth.get('type')!r}")
    if not username or not password:
        raise PlanError("authenticated scans need a test username and password")
    login = login_target(auth["login_url"], port)
    lines = [
        "    authentication:",
        f"      method: {_q(auth['type'])}",
        "      parameters:",
        f"        loginPageUrl: {_q(login)}",
        f"        loginRequestUrl: {_q(login)}",
        f"        loginRequestBody: {_q(login_body(auth))}",
        "      verification:",
        '        method: "response"',
    ]
    if auth.get("logged_in_regex"):
        lines.append(f"        loggedInRegex: {_q(auth['logged_in_regex'])}")
    if auth.get("logged_out_regex"):
        lines.append(f"        loggedOutRegex: {_q(auth['logged_out_regex'])}")
    lines += [
        "    sessionManagement:",
        '      method: "cookie"',
        "    users:",
        f"      - name: {_q(AUTH_USER)}",
        "        credentials:",
        f"          username: {_q(username)}",
        f"          password: {_q(password)}",
    ]
    return "\n".join("  " + line for line in lines)


def render(plan: str, port: int, openapi: bool = False, plan_dir: Path = PLAN_DIR, auth: dict | None = None, credentials: tuple[str, str] | None = None) -> str:
    if plan not in PLANS:
        raise PlanError(f"unknown plan {plan!r}; choose from {', '.join(PLANS)}")
    if openapi and plan != "full":
        raise PlanError("OpenAPI import is only part of the full plan")
    if auth and plan != "full":
        raise PlanError("authenticated scanning is only part of the full plan")
    url = target_url(port)
    assert_safe_target(url, port)
    text = (plan_dir / f"{plan}.yaml").read_text()
    if plan == "full":
        text = text.replace("{{OPENAPI_JOB}}\n", OPENAPI_JOB + "\n" if openapi else "")
    text = text.replace("{{TARGET}}", url)
    if plan == "full":
        if auth:
            if credentials is None:
                raise PlanError("authenticated scans need test credentials")
            text = text.replace("{{AUTH_CONTEXT}}\n", auth_block(auth, port, *credentials) + "\n")
            text = text.replace("{{USER}}\n", f"      user: {_q(AUTH_USER)}\n")
        else:
            text = text.replace("{{AUTH_CONTEXT}}\n", "").replace("{{USER}}\n", "")
    return text


def resolve_spec(spec: str, project_dir: Path) -> Path:
    root = project_dir.resolve()
    path = (root / spec).resolve()
    if not path.is_relative_to(root):
        raise PlanError(f"OpenAPI spec {spec!r} is outside the project")
    if not path.is_file():
        raise PlanError(f"OpenAPI spec {spec!r} not found")
    return path
