import argparse
import ast
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

from factory import adapter, tools
from factory.adapter import READ_TOOLS

FACTORY_ROOT = Path(__file__).resolve().parents[2]
PROMPT = FACTORY_ROOT / "prompts" / "threat-model-pytm.md"
SCHEMA = FACTORY_ROOT / "schemas" / "tm-source.schema.json"
HARNESS = Path(__file__).resolve().parent / "pytm_harness.py"
STAGE = "threat-model-pytm"
RETRY_STAGE = "threat-model-pytm-retry"
EXIT_REJECTED = 2
TIMEOUT_SECONDS = 120
OUTPUT_CAP = 4000

# sys is left out: a model that edits sys.argv could make pytm read or write any file.
ALLOWED_IMPORTS = frozenset({"pytm"})
# Threat and Finding are left out on purpose: pytm eval()s a Threat's condition string.
PYTM_EXPORTS = frozenset({
    "TM", "Boundary", "Actor", "Server", "Process", "SetOfProcesses", "Lambda", "Datastore", "DatastoreType",
    "Dataflow", "Data", "Classification", "Lifetime", "TLSVersion", "ExternalEntity", "Element", "Assumption",
    "Controls", "Action", "Agent", "LLM",
})
FORBIDDEN_NAMES = frozenset({
    "open", "exec", "eval", "compile", "__import__", "subprocess", "os",
    "getattr", "setattr", "delattr", "globals", "locals", "vars", "input",
    "breakpoint", "help", "memoryview", "builtins", "importlib", "__builtins__",
    "type", "object", "super", "classmethod", "staticmethod", "property", "dir", "id",
})
FORBIDDEN_KEYWORDS = frozenset({"threatsFile", "condition", "overrides", "findings", "sourceFiles"})
# An allowlist, not a denylist: plain names such as gi_frame and f_globals reach the interpreter's internals.
# These are pytm 1.4.0's element, data and control properties (minus Data.format, which str.format would
# reach), its enum members and tm.process.
ALLOWED_ATTRS = frozenset({
    "AUTO", "AWS_S3", "FILE_SYSTEM", "HARDCODED", "IGNORE", "LDAP", "LONG", "MANUAL", "NONE", "NO_ACTION", "OS",
    "PUBLIC", "RESTRICT", "RESTRICTED", "SECRET", "SENSITIVE", "SHORT", "SQL", "SSLv1", "SSLv2", "SSLv3", "TLSv10",
    "TLSv11", "TLSv12", "TLSv13", "TOP_SECRET", "UNKNOWN", "allowsClientSideScripting", "assumptions",
    "authenticatesDestination", "authenticatesSource", "authenticationScheme", "authorizesSource", "carriedBy",
    "checksDestinationRevocation", "checksInputBounds", "classification", "codeType", "controls",
    "credentialsLife", "data", "definesConnectionTimeout", "description", "disablesDTD", "disablesiFrames",
    "dstPort", "encodesHeaders", "encodesOutput", "encryptsCookies", "encryptsSessionData", "environment",
    "executesCode", "handlesCrashes", "handlesInterruptions", "handlesResourceConsumption",
    "handlesResources", "hasAccessControl", "hasAccessToSensitiveSystems", "hasAgentCapabilities",
    "hasContentFiltering", "hasFineTuning", "hasPhysicalAccess", "hasRAG", "hasSystemPrompt", "hasWriteAccess",
    "ignoreUnused", "implementsAPI", "implementsAuthenticationScheme", "implementsCSRFToken",
    "implementsCommunicationProtocol", "implementsNonce", "implementsPOLP", "implementsServerSideValidation",
    "implementsStrictHTTPValidation", "inBoundary", "inScope", "invokesScriptFilters", "isAdmin", "isCredentials",
    "isDestEncryptedAtRest", "isEncrypted", "isEncryptedAtRest", "isHardened", "isOrdered", "isPII", "isResilient",
    "isResponse", "isSQL", "isSelfHosted", "isShared", "isSourceEncryptedAtRest", "isStored", "isThirdParty",
    "levels", "maxClassification", "mergeResponses", "minTLSVersion", "name", "note", "onAWS", "onDuplicates",
    "onRDS", "order", "port", "process", "processedBy", "processesPersonalData", "processesUntrustedInput",
    "protocol", "providesConfidentiality", "providesIntegrity", "response", "responseTo", "retainsUserData",
    "sanitizesInput", "sink", "source", "srcPort", "storesLogData", "storesPII", "storesSensitiveData",
    "tlsVersion", "tracksExecutionFlow", "type", "usesCache", "usesCodeSigning", "usesEncryptionAlgorithm",
    "usesEnvironmentVariables", "usesExternalTools", "usesMFA", "usesParameterizedInput", "usesSecureFunctions",
    "usesSessionTokens", "usesStrongSessionIdentifiers", "usesVPN", "usesXMLParser", "validatesContentType",
    "validatesHeaders", "validatesInput", "validatesToolLaunchConfig", "verifySessionIdentifiers",
}) | PYTM_EXPORTS
ALLOWED_KEYWORDS = ALLOWED_ATTRS - FORBIDDEN_KEYWORDS - PYTM_EXPORTS
FORBIDDEN_NODES = (
    ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda, ast.GeneratorExp, ast.ListComp, ast.SetComp,
    ast.DictComp, ast.Await, ast.Yield, ast.YieldFrom, ast.Global, ast.Nonlocal, ast.With, ast.AsyncWith, ast.Try,
    ast.While, ast.Starred, ast.JoinedStr, ast.NamedExpr, ast.Delete,
)
REQUIRED_CALLS = ("TM", "Boundary", "Actor", "Datastore", "Dataflow")
PROCESS_CALLS = ("Server", "Process", "SetOfProcesses", "Lambda")
ENV_KEEP = ("PATH", "LANG", "LC_ALL")
SANDBOX_TOOL = "pytm-sandbox"
CONTAINER_WORK = "/work"
CONTAINER_SCRIPTS = "/factory"


class RunnerError(Exception):
    pass


class ModelRejected(Exception):
    pass


def _called_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def validate_source(source: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [f"line {e.lineno}: syntax error: {e.msg}"]
    errors = []
    calls = set()
    module_ok = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            allowed = PYTM_EXPORTS if node.value.id == "pytm" else frozenset()
            if node.attr in allowed:
                module_ok.add(id(node.value))
    for node in ast.walk(tree):
        where = f"line {getattr(node, 'lineno', '?')}"
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in ALLOWED_IMPORTS:
                    errors.append(f"{where}: import of '{alias.name}' is not allowed, only pytm")
                elif alias.asname:
                    errors.append(f"{where}: 'import {alias.name} as {alias.asname}' is not allowed")
        elif isinstance(node, ast.ImportFrom):
            if node.level or node.module != "pytm":
                errors.append(f"{where}: import from '{node.module}' is not allowed, only pytm")
            for alias in node.names:
                if alias.name not in PYTM_EXPORTS:
                    errors.append(f"{where}: 'from pytm import {alias.name}' is not allowed, "
                                  f"use only {', '.join(sorted(PYTM_EXPORTS))}")
        elif isinstance(node, ast.Name):
            if node.id in FORBIDDEN_NAMES:
                errors.append(f"{where}: '{node.id}' is not allowed")
            elif node.id.startswith("__") and node.id != "__name__":
                errors.append(f"{where}: dunder name '{node.id}' is not allowed")
            elif node.id == "pytm" and id(node) not in module_ok:
                errors.append(f"{where}: pytm may only be used as pytm.<class>, for example pytm.Server")
        elif isinstance(node, ast.Attribute):
            if node.attr not in ALLOWED_ATTRS:
                errors.append(f"{where}: attribute '{node.attr}' is not allowed, use only pytm element properties")
        elif isinstance(node, ast.Subscript) and not (isinstance(node.slice, ast.Constant) and type(node.slice.value) is int):
            errors.append(f"{where}: only integer subscripts are allowed")
        elif isinstance(node, FORBIDDEN_NODES):
            errors.append(f"{where}: {type(node).__name__} is not allowed in a threat model")
        elif isinstance(node, ast.keyword) and node.arg is None:
            errors.append(f"{where}: ** unpacking of keyword arguments is not allowed")
        elif isinstance(node, ast.keyword) and node.arg not in ALLOWED_KEYWORDS:
            errors.append(f"{where}: keyword '{node.arg}' is not allowed, use only pytm element properties")
        elif isinstance(node, ast.Call):
            name = _called_name(node.func)
            if name:
                calls.add(name)
    for name in REQUIRED_CALLS:
        if name not in calls:
            errors.append(f"the model must declare at least one {name}(...)")
    if not calls & set(PROCESS_CALLS):
        errors.append(f"the model must declare at least one of {', '.join(PROCESS_CALLS)}(...)")
    if "process" not in calls:
        errors.append("the model must end with tm.process() under if __name__ == \"__main__\"")
    return errors


def _tail(text: str) -> str:
    return text if len(text) <= OUTPUT_CAP else "..." + text[-OUTPUT_CAP:]


def site_packages(python: Path) -> Path:
    found = sorted(python.parent.parent.glob("lib/python3*/site-packages"))
    if len(found) != 1:
        raise RunnerError(f"expected one site-packages folder in the venv of {python}, found {len(found)}")
    return found[0]


def sandbox_command(image: str, python: Path, script: Path, work: Path, args: list[str], name: str) -> list[str]:
    site = site_packages(python)
    # The venv's packages replace the image's own site-packages, which -I still loads (unlike PYTHONPATH).
    container_site = f"/usr/local/lib/{site.parent.name}/site-packages"
    return [
        "docker", "run", "--rm", "--name", name, "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "128", "--memory", "1g", "--user", f"{os.getuid()}:{os.getgid()}",
        "-e", f"HOME={CONTAINER_WORK}", "-w", CONTAINER_WORK,
        "-v", f"{work.resolve()}:{CONTAINER_WORK}:rw",
        "-v", f"{site}:{container_site}:ro",
        "-v", f"{script.resolve()}:{CONTAINER_SCRIPTS}/{script.name}:ro",
        image, "python", "-I", f"{CONTAINER_SCRIPTS}/{script.name}", *args,
    ]


def execute(python: Path, script: Path, args: list[str], timeout: int, cwd: Path | None = None,
            image: str | None = None) -> str:
    cwd = cwd or script.parent
    env = {k: os.environ[k] for k in ENV_KEEP if k in os.environ}
    env["HOME"] = str(cwd)
    name = f"factory-pytm-{uuid.uuid4().hex[:12]}"
    if image:
        cmd = sandbox_command(image, python, script, cwd, args, name)
    else:
        cmd = [str(python), "-I", str(script), *args]
    try:
        result = subprocess.run(
            cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        if image:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, env=env)
        raise ModelRejected(f"pytm {' '.join(args)} timed out after {timeout} s") from None
    if result.returncode != 0:
        raise ModelRejected(f"pytm {' '.join(args)} exited {result.returncode}:\n{_tail(result.stderr or result.stdout)}")
    return result.stdout


def sandbox_image(choice: str) -> str | None:
    return tools.get_tool(tools.load_lock(), SANDBOX_TOOL).image if choice == "docker" else None


def _strings(value) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def normalise(raw: dict) -> dict:
    def items(key):
        return [e for e in raw.get(key) or [] if isinstance(e, dict) and isinstance(e.get("name"), str) and e["name"]]

    model = {
        "name": raw.get("name"),
        "description": raw.get("description"),
        "boundaries": [
            {"name": b["name"], "boundary": b.get("inBoundary"), "description": b.get("description") or ""}
            for b in items("boundaries")
        ],
        "elements": [
            {"name": e["name"], "type": e.get("__class__") or "Element", "boundary": e.get("inBoundary"),
             "description": e.get("description") or ""}
            for e in items("elements")
        ],
        "flows": [
            {"name": f["name"], "source": f.get("source"), "sink": f.get("sink"), "protocol": f.get("protocol") or "",
             "dst_port": f.get("dstPort"), "is_response": bool(f.get("isResponse")), "data": _strings(f.get("data")),
             "description": f.get("description") or ""}
            for f in items("flows")
        ],
    }
    errors = model_errors(model)
    if errors:
        raise ModelRejected("the pytm model is incomplete:\n" + "\n".join(errors))
    return model


def model_errors(model: dict) -> list[str]:
    errors = []
    for key in ("boundaries", "elements", "flows"):
        if not model[key]:
            errors.append(f"pytm reported no {key}")
    names = [x["name"] for key in ("boundaries", "elements", "flows") for x in model[key]]
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        errors.append(f"names must be unique across boundaries, elements and dataflows: {', '.join(dupes)}")
    known = {e["name"] for e in model["elements"]}
    for flow in model["flows"]:
        for end in ("source", "sink"):
            if flow[end] not in known:
                errors.append(f"dataflow '{flow['name']}' has {end} '{flow[end]}', which is not an element")
    return errors


def element_names(model: dict) -> list[str]:
    return [x["name"] for key in ("boundaries", "elements", "flows") for x in model[key]]


def check_and_run(source: str, out: Path, python: Path, timeout: int = TIMEOUT_SECONDS,
                  image: str | None = None) -> dict:
    errors = validate_source(source)
    if errors:
        raise ModelRejected("AST validation failed:\n" + "\n".join(errors))
    tm_path = out / "tm.py"
    tm_path.write_text(source)
    print(f"AST validation passed for {tm_path}", flush=True)
    where = f"in container {image} with no network" if image else f"with {python}"
    print(f"running pytm --dfd and --json {where} (timeout {timeout} s, no secrets in env)", flush=True)
    dot = execute(python, HARNESS, ["tm.py", "--dfd"], timeout, out, image)
    if "digraph" not in dot:
        raise ModelRejected("pytm --dfd did not print a digraph")
    (out / "dfd.dot").write_text(dot)
    raw_path = out / "pytm.json"
    raw_path.unlink(missing_ok=True)
    execute(python, HARNESS, ["tm.py", "--json", "pytm.json"], timeout, out, image)
    try:
        raw = json.loads(raw_path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise ModelRejected(f"pytm --json did not write readable JSON: {e}") from None
    if not isinstance(raw, dict):
        raise ModelRejected("pytm --json did not write an object")
    model = normalise(raw)
    (out / "elements.json").write_text(json.dumps(model, indent=2, ensure_ascii=False) + "\n")
    print(f"pytm model: {len(model['boundaries'])} boundaries, {len(model['elements'])} elements, {len(model['flows'])} dataflows")
    return model


def _ask(stage: str, inputs: list[Path], out_path: Path, workdir: Path | None) -> tuple[int, str | None]:
    code = adapter.run_stage(
        stage=stage, prompt_path=PROMPT, inputs=inputs, schema_path=SCHEMA,
        out_path=out_path, workdir=workdir, allow_tools=list(READ_TOOLS),
    )
    if code != adapter.EXIT_OK:
        return code, None
    return code, json.loads(out_path.read_text())["tm_py"]


def build(plan_path: Path, out: Path, previous: list[Path], python: Path,
          workdir: Path | None = None, timeout: int = TIMEOUT_SECONDS,
          image: str | None = None) -> tuple[int, dict | None]:
    if not python.is_file():
        raise RunnerError(f"pytm interpreter not found at {python}; run `python -m factory.tools install pytm`")
    out.mkdir(parents=True, exist_ok=True)
    inputs = [plan_path, *previous]
    code, source = _ask(STAGE, inputs, out / "tm-reply.json", workdir)
    if source is None:
        return code, None
    try:
        return 0, check_and_run(source, out, python, timeout, image)
    except ModelRejected as e:
        print(f"tm.py rejected, asking the model once more:\n{e}", file=sys.stderr)
        rejected, error = out / "tm.rejected.py", out / "error.txt"
        rejected.write_text(source)
        error.write_text(str(e) + "\n")
    code, source = _ask(RETRY_STAGE, [*inputs, rejected, error], out / "tm-reply-retry.json", workdir)
    if source is None:
        return code, None
    try:
        return 0, check_and_run(source, out, python, timeout, image)
    except ModelRejected as e:
        (out / "tm.py").unlink(missing_ok=True)
        rejected.write_text(source)
        error.write_text(str(e) + "\n")
        print(f"error: tm.py rejected again:\n{e}", file=sys.stderr)
        return EXIT_REJECTED, None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.threatmodel.pytm_runner",
                                     description="Validate a tm.py with the AST allowlist and run it with pytm")
    parser.add_argument("source", type=Path)
    parser.add_argument("--out", default=Path("out/threat-model"), type=Path)
    parser.add_argument("--python", type=Path, default=tools.venv_python("pytm"))
    parser.add_argument("--timeout", type=int, default=TIMEOUT_SECONDS)
    parser.add_argument("--sandbox", choices=("docker", "none"), default="docker",
                        help="run pytm in the pinned no-network container (default) or directly")
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    try:
        check_and_run(args.source.read_text(), args.out, args.python, args.timeout, sandbox_image(args.sandbox))
    except ModelRejected as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_REJECTED
    return 0


if __name__ == "__main__":
    sys.exit(main())
