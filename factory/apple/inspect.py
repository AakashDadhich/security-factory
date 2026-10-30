import plistlib
import re
import subprocess
from pathlib import Path

FLAGS_RE = re.compile(r"flags=(0x[0-9a-fA-F]+)\(([^)]*)\)")
RUNTIME_BIT = 0x10000


class InspectError(Exception):
    pass


def parse_plist(data: bytes, what: str = "plist") -> dict:
    start = data.find(b"<?xml")
    if start > 0:
        data = data[start:]
    try:
        value = plistlib.loads(data)
    except Exception as e:
        raise InspectError(f"{what} is not a valid property list: {e}") from e
    if not isinstance(value, dict):
        raise InspectError(f"{what} is not a dictionary")
    return value


def parse_entitlements(output: bytes) -> dict:
    if not output.strip():
        return {}
    return parse_plist(output, "entitlements")


def parse_code_flags(output: str) -> dict:
    match = FLAGS_RE.search(output)
    if not match:
        raise InspectError("codesign output has no 'flags=' line")
    value = int(match.group(1), 16)
    names = [n for n in match.group(2).split(",") if n]
    return {"value": value, "names": names, "runtime": "runtime" in names or bool(value & RUNTIME_BIT)}


def ats_settings(info: dict) -> dict:
    ats = info.get("NSAppTransportSecurity")
    if not isinstance(ats, dict):
        return {"arbitrary_loads": False, "web_content": False, "insecure_http_domains": []}
    domains = ats.get("NSExceptionDomains")
    insecure = []
    if isinstance(domains, dict):
        insecure = sorted(d for d, cfg in domains.items() if isinstance(cfg, dict) and cfg.get("NSExceptionAllowsInsecureHTTPLoads") is True)
    return {
        "arbitrary_loads": ats.get("NSAllowsArbitraryLoads") is True,
        "web_content": ats.get("NSAllowsArbitraryLoadsInWebContent") is True,
        "insecure_http_domains": insecure,
    }


def declared_api_types(manifest: dict) -> set[str]:
    entries = manifest.get("NSPrivacyAccessedAPITypes", [])
    if not isinstance(entries, list):
        raise InspectError("NSPrivacyAccessedAPITypes is not an array")
    declared = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("NSPrivacyAccessedAPIType"), str):
            raise InspectError("NSPrivacyAccessedAPITypes has an entry without NSPrivacyAccessedAPIType")
        declared.add(entry["NSPrivacyAccessedAPIType"])
    return declared


def _run(cmd: list[str], runner) -> subprocess.CompletedProcess:
    runner = runner or subprocess.run
    try:
        return runner(cmd, capture_output=True)
    except FileNotFoundError as e:
        raise InspectError(f"{cmd[0]} not found; run this stage on a macOS runner") from e


def _text(value) -> str:
    return value.decode(errors="replace") if isinstance(value, bytes) else (value or "")


def read_entitlements(app: str | Path, runner=None) -> dict:
    proc = _run(["codesign", "-d", "--entitlements", ":-", str(app)], runner)
    if proc.returncode != 0:
        raise InspectError(f"codesign could not read entitlements: {_text(proc.stderr).strip()}")
    return parse_entitlements(proc.stdout if isinstance(proc.stdout, bytes) else proc.stdout.encode())


def read_code_flags(app: str | Path, runner=None) -> dict:
    proc = _run(["codesign", "-dv", "--verbose=4", str(app)], runner)
    if proc.returncode != 0:
        raise InspectError(f"codesign could not read the signature: {_text(proc.stderr).strip()}")
    return parse_code_flags(_text(proc.stderr) + _text(proc.stdout))


def read_plist(path: str | Path) -> dict:
    path = Path(path)
    try:
        data = path.read_bytes()
    except OSError as e:
        raise InspectError(f"cannot read {path}: {e}") from e
    return parse_plist(data, path.name)
