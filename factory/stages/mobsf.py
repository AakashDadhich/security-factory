import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from factory import findings, tools
from factory.findings import FindingsError

STAGE = "mobsf"
TOOL = "mobsf"
PORT = 8000
CONTAINER_PORT = 8000
READY_TIMEOUT = 300
SCAN_TIMEOUT = 1500
KEY_ENV = "MOBSF_API_KEY"
SEVERITIES = {"high": "high", "warning": "medium", "info": "info"}


class StageError(Exception):
    pass


def new_api_key() -> str:
    return "fmobsf_" + secrets.token_urlsafe(32)


def redact(text: str, key: str) -> str:
    return text.replace(key, "***") if key else text


def container_name(run_id: str) -> str:
    return f"factory-mobsf-{run_id}"


def run_cmd(name: str, image: str, port: int = PORT) -> list[str]:
    return [
        "docker", "run", "--detach",
        "--name", name,
        "--publish", f"127.0.0.1:{port}:{CONTAINER_PORT}",
        "--env", KEY_ENV,
        image,
    ]


def multipart(field: str, filename: str, data: bytes) -> tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    return head + data + f"\r\n--{boundary}--\r\n".encode(), f"multipart/form-data; boundary={boundary}"


class Client:
    def __init__(self, base: str, key: str, opener=urllib.request.urlopen):
        self.base, self.key, self.opener = base.rstrip("/"), key, opener

    def _call(self, path: str, body: bytes | None = None, content_type: str | None = None, timeout: float = 60) -> bytes:
        headers = {"Authorization": self.key}
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(self.base + path, data=body, headers=headers, method="POST" if body is not None else "GET")
        try:
            with self.opener(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as e:
            raise StageError(f"MobSF {path} returned HTTP {e.code}") from None
        except (urllib.error.URLError, OSError) as e:
            raise StageError(f"MobSF {path} failed: {redact(str(e), self.key)}") from None

    def _json(self, path: str, form: dict[str, str], timeout: float) -> dict:
        body = "&".join(f"{k}={urllib.request.quote(v, safe='')}" for k, v in form.items()).encode()
        raw = self._call(path, body, "application/x-www-form-urlencoded", timeout)
        try:
            data = json.loads(raw)
        except ValueError:
            raise StageError(f"MobSF {path} did not return JSON") from None
        if not isinstance(data, dict):
            raise StageError(f"MobSF {path} did not return a JSON object")
        return data

    def ready(self) -> bool:
        try:
            self._call("/", timeout=10)
            return True
        except StageError as e:
            return "returned HTTP" in str(e)

    def upload(self, ipa: Path) -> dict:
        body, content_type = multipart("file", ipa.name, ipa.read_bytes())
        raw = self._call("/api/v1/upload", body, content_type, 300)
        try:
            data = json.loads(raw)
        except ValueError:
            raise StageError("MobSF upload did not return JSON") from None
        if not isinstance(data, dict) or not data.get("hash"):
            raise StageError("MobSF upload returned no file hash")
        return data

    def scan(self, upload: dict) -> None:
        self._json("/api/v1/scan", {"scan_type": upload["scan_type"], "file_name": upload["file_name"], "hash": upload["hash"]}, SCAN_TIMEOUT)

    def report(self, file_hash: str) -> dict:
        return self._json("/api/v1/report_json", {"hash": file_hash}, 300)


def wait_ready(client: Client, timeout: float = READY_TIMEOUT, sleep=time.sleep, clock=time.monotonic) -> None:
    deadline = clock() + timeout
    while not client.ready():
        if clock() >= deadline:
            raise StageError(f"MobSF did not answer within {timeout:.0f} seconds")
        sleep(3)


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:80] or "unnamed"


def _text(value) -> str:
    return " ".join(str(value).split()) if value is not None else ""


def convert(report: dict, ipa_name: str) -> list[dict]:
    appsec = report.get("appsec")
    if not isinstance(appsec, dict):
        raise StageError("the MobSF report has no 'appsec' section")
    best: dict[str, dict] = {}
    order = list(findings.SEVERITIES)
    for level, items in appsec.items():
        severity = SEVERITIES.get(level)
        if severity is None or not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict) or not item.get("title"):
                continue
            title = _text(item["title"])
            section = _text(item.get("section"))
            finding = findings.make_finding(
                stage=STAGE, tool=TOOL, source="scanner", rule_id=f"mobsf-{slug(title)}", title=title, severity=severity,
                location={"path": ipa_name, "start_line": None, "end_line": None},
                description=_text(item.get("description")) + (f" (MobSF section: {section})" if section else ""),
                remediation="Review the finding in the MobSF report and fix the cause, or suppress it with a reason and an expiry date.",
            )
            current = best.get(finding["id"])
            if current is None or order.index(finding["severity"]) < order.index(current["severity"]):
                best[finding["id"]] = finding
    return findings.validate(sorted(best.values(), key=lambda f: f["id"]))


def _docker(cmd: list[str], env: dict | None = None, key: str = "", check: bool = True) -> subprocess.CompletedProcess:
    print("+ " + " ".join(cmd), flush=True)
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if check and proc.returncode != 0:
        raise StageError(redact(f"{' '.join(cmd[:3])} failed with exit code {proc.returncode}: {proc.stderr.strip()}", key))
    return proc


def run(ipa: str | Path, out: str | Path, run_id: str = "local", image: str | None = None, port: int = PORT, key: str | None = None,
        docker=None, client_factory=None, ready_timeout: float = READY_TIMEOUT) -> list[dict]:
    ipa, out = Path(ipa), Path(out)
    if not ipa.is_file():
        raise StageError(f"{ipa} not found")
    image = image or tools.get_tool(tools.load_lock(), "mobsf").image
    key = key or new_api_key()
    name = container_name(run_id)
    docker = docker or _docker
    client = (client_factory or Client)(f"http://127.0.0.1:{port}", key)
    env = {**os.environ, KEY_ENV: key}
    out.mkdir(parents=True, exist_ok=True)
    docker(run_cmd(name, image, port), env=env, key=key)
    try:
        wait_ready(client, ready_timeout)
        upload = client.upload(ipa)
        client.scan(upload)
        report = client.report(upload["hash"])
        (out / "mobsf-report.json").write_text(redact(json.dumps(report, indent=2, sort_keys=True), key) + "\n")
        result = convert(report, ipa.name)
    except StageError:
        logs = docker(["docker", "logs", "--tail", "60", name], key=key, check=False)
        print(redact((logs.stdout or "") + (logs.stderr or ""), key), file=sys.stderr)
        raise
    finally:
        docker(["docker", "rm", "--force", name], key=key, check=False)
    findings.write(out / "findings.json", result)
    print(f"mobsf: {len(result)} finding(s)")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.stages.mobsf", description="Static analysis of an unsigned iOS .ipa with MobSF in Docker")
    parser.add_argument("--ipa", required=True)
    parser.add_argument("--out", default="out/mobsf")
    parser.add_argument("--run-id", default="local")
    args = parser.parse_args(argv)
    try:
        run(args.ipa, args.out, args.run_id)
    except (StageError, FindingsError, tools.ToolError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
