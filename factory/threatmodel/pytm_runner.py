import argparse
import ast
import json
import os
import subprocess
import sys
from pathlib import Path

from factory import adapter, tools
from factory.adapter import READ_TOOLS

FACTORY_ROOT = Path(__file__).resolve().parents[2]
PROMPT = FACTORY_ROOT / "prompts" / "threat-model-pytm.md"
SCHEMA = FACTORY_ROOT / "schemas" / "tm-source.schema.json"
STAGE = "threat-model-pytm"
RETRY_STAGE = "threat-model-pytm-retry"
EXIT_REJECTED = 2
TIMEOUT_SECONDS = 120
OUTPUT_CAP = 4000

ALLOWED_IMPORTS = frozenset({"pytm", "sys"})
SYS_ATTRS = frozenset({"argv", "exit"})
FORBIDDEN_NAMES = frozenset({
    "open", "exec", "eval", "compile", "__import__", "subprocess", "os",
    "getattr", "setattr", "delattr", "globals", "locals", "vars", "input",
    "breakpoint", "help", "memoryview", "builtins", "importlib", "__builtins__",
})
# Threat and Finding are left out on purpose: pytm eval()s a Threat's condition string.
PYTM_EXPORTS = frozenset({
    "TM", "Boundary", "Actor", "Server", "Process", "SetOfProcesses", "Lambda", "Datastore", "DatastoreType",
    "Dataflow", "Data", "Classification", "Lifetime", "TLSVersion", "ExternalEntity", "Element", "Assumption",
    "Controls", "Action", "Agent", "LLM",
})
PYTM_MODULES = frozenset({
    "actor", "asset", "base", "boundary", "dataflow", "datastore", "element", "enums", "finding", "flows",
    "json", "pytm", "report_util", "template_engine", "threat", "threatlib", "tm",
})
FORBIDDEN_KEYWORDS = frozenset({"threatsFile"})
FORBIDDEN_ATTRS = FORBIDDEN_KEYWORDS | {"report", "load", "loads", "modules", "sys"} | FORBIDDEN_NAMES | PYTM_MODULES
REQUIRED_CALLS = ("TM", "Boundary", "Actor", "Datastore", "Dataflow")
PROCESS_CALLS = ("Server", "Process", "SetOfProcesses", "Lambda")
ENV_KEEP = ("PATH", "LANG", "LC_ALL")


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
            allowed = {"sys": SYS_ATTRS, "pytm": PYTM_EXPORTS}.get(node.value.id, frozenset())
            if node.attr in allowed:
                module_ok.add(id(node.value))
    for node in ast.walk(tree):
        where = f"line {getattr(node, 'lineno', '?')}"
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in ALLOWED_IMPORTS:
                    errors.append(f"{where}: import of '{alias.name}' is not allowed, only pytm and sys")
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
            elif node.id == "sys" and id(node) not in module_ok:
                errors.append(f"{where}: only sys.argv and sys.exit may be used")
            elif node.id == "pytm" and id(node) not in module_ok:
                errors.append(f"{where}: pytm may only be used as pytm.<class>, for example pytm.Server")
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("__"):
                errors.append(f"{where}: dunder attribute '{node.attr}' is not allowed")
            elif node.attr.startswith("_"):
                errors.append(f"{where}: private attribute '{node.attr}' is not allowed")
            elif node.attr in FORBIDDEN_ATTRS:
                errors.append(f"{where}: attribute '{node.attr}' is not allowed")
        elif isinstance(node, ast.keyword) and node.arg in FORBIDDEN_KEYWORDS:
            errors.append(f"{where}: keyword '{node.arg}' is not allowed")
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


def execute(python: Path, tm_path: Path, args: list[str], timeout: int) -> str:
    env = {k: os.environ[k] for k in ENV_KEEP if k in os.environ}
    env["HOME"] = str(tm_path.parent)
    try:
        result = subprocess.run(
            [str(python), "-I", str(tm_path), *args], cwd=tm_path.parent, env=env,
            capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        raise ModelRejected(f"pytm {' '.join(args)} timed out after {timeout} s") from None
    if result.returncode != 0:
        raise ModelRejected(f"pytm {' '.join(args)} exited {result.returncode}:\n{_tail(result.stderr or result.stdout)}")
    return result.stdout


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


def check_and_run(source: str, out: Path, python: Path, timeout: int = TIMEOUT_SECONDS) -> dict:
    errors = validate_source(source)
    if errors:
        raise ModelRejected("AST validation failed:\n" + "\n".join(errors))
    tm_path = out / "tm.py"
    tm_path.write_text(source)
    print(f"AST validation passed for {tm_path}", flush=True)
    print(f"running pytm --dfd and --json with {python} (timeout {timeout} s, no secrets in env)", flush=True)
    dot = execute(python, tm_path, ["--dfd"], timeout)
    if "digraph" not in dot:
        raise ModelRejected("pytm --dfd did not print a digraph")
    (out / "dfd.dot").write_text(dot)
    raw_path = out / "pytm.json"
    raw_path.unlink(missing_ok=True)
    execute(python, tm_path, ["--json", str(raw_path.resolve())], timeout)
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
          workdir: Path | None = None, timeout: int = TIMEOUT_SECONDS) -> tuple[int, dict | None]:
    if not python.is_file():
        raise RunnerError(f"pytm interpreter not found at {python}; run `python -m factory.tools install pytm`")
    out.mkdir(parents=True, exist_ok=True)
    inputs = [plan_path, *previous]
    code, source = _ask(STAGE, inputs, out / "tm-reply.json", workdir)
    if source is None:
        return code, None
    try:
        return 0, check_and_run(source, out, python, timeout)
    except ModelRejected as e:
        print(f"tm.py rejected, asking the model once more:\n{e}", file=sys.stderr)
        rejected, error = out / "tm.rejected.py", out / "error.txt"
        rejected.write_text(source)
        error.write_text(str(e) + "\n")
    code, source = _ask(RETRY_STAGE, [*inputs, rejected, error], out / "tm-reply-retry.json", workdir)
    if source is None:
        return code, None
    try:
        return 0, check_and_run(source, out, python, timeout)
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
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    try:
        check_and_run(args.source.read_text(), args.out, args.python, args.timeout)
    except ModelRejected as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_REJECTED
    return 0


if __name__ == "__main__":
    sys.exit(main())
