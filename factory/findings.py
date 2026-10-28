import hashlib
import json
from functools import cache
from pathlib import Path
from urllib.parse import unquote, urlsplit

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"
SCHEMA_BASE = "https://github.com/AakashDadhich/security-factory/schemas/"

SEVERITIES = ("critical", "high", "medium", "low", "info")
SOURCES = ("scanner", "ai-review", "ai-threat-model", "check")


class FindingsError(Exception):
    pass


@cache
def _registry() -> Registry:
    resources = []
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        schema = json.loads(path.read_text())
        resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


@cache
def validator(schema_name: str) -> Draft202012Validator:
    schema = _registry().contents(SCHEMA_BASE + schema_name)
    return Draft202012Validator(schema, registry=_registry())


def _schema_errors(schema_name: str, instance) -> list[str]:
    errors = sorted(validator(schema_name).iter_errors(instance), key=lambda e: list(e.absolute_path))
    return [f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}" for e in errors]


def normalise_path(path: str) -> str:
    path = unquote(path).replace("\\", "/")
    if path.startswith("file://"):
        path = path[len("file://"):]
    while path.startswith("./"):
        path = path[2:]
    return path or "."


def normalise_location(location: dict) -> dict:
    if "url" in location:
        return {"url": location["url"], "method": location["method"].upper()}
    start = location.get("start_line")
    end = location.get("end_line", start)
    return {"path": normalise_path(location["path"]), "start_line": start, "end_line": end}


def fingerprint(tool: str, rule_id: str, location: dict) -> str:
    location = normalise_location(location)
    if "url" in location:
        key = [tool, rule_id, urlsplit(location["url"]).path or "/", location["method"]]
    else:
        key = [tool, rule_id, location["path"], location["start_line"]]
    return hashlib.sha256(json.dumps(key, separators=(",", ":")).encode()).hexdigest()


def make_finding(**fields) -> dict:
    missing = [k for k in ("stage", "tool", "source", "rule_id", "title", "severity", "location") if k not in fields]
    if missing:
        raise FindingsError(f"make_finding is missing {', '.join(missing)}")
    location = normalise_location(fields["location"])
    fp = fingerprint(fields["tool"], fields["rule_id"], location)
    finding = {
        "id": f"{fields['stage']}:{fp}",
        "stage": fields["stage"],
        "tool": fields["tool"],
        "source": fields["source"],
        "rule_id": fields["rule_id"],
        "title": fields["title"],
        "severity": fields["severity"],
        "location": location,
        "cwe": list(fields.get("cwe", [])),
        "description": fields.get("description", ""),
        "remediation": fields.get("remediation", ""),
        "fingerprint": fp,
    }
    extra = set(fields) - set(finding)
    if extra:
        raise FindingsError(f"make_finding got unknown fields: {', '.join(sorted(extra))}")
    validate([finding])
    return finding


def validate(findings: list) -> list:
    errors = _schema_errors("findings.schema.json", findings)
    if errors:
        raise FindingsError("findings do not match the schema:\n" + "\n".join(errors))
    seen: set[str] = set()
    for i, f in enumerate(findings):
        expected_fp = fingerprint(f["tool"], f["rule_id"], f["location"])
        if f["fingerprint"] != expected_fp:
            raise FindingsError(f"{i}: fingerprint does not match tool, rule_id and location")
        if f["id"] != f"{f['stage']}:{f['fingerprint']}":
            raise FindingsError(f"{i}: id must be '<stage>:<fingerprint>'")
        if f["id"] in seen:
            raise FindingsError(f"{i}: duplicate id {f['id']}")
        seen.add(f["id"])
    return findings


def load(path: str | Path) -> list:
    try:
        data = json.loads(Path(path).read_text())
    except json.JSONDecodeError as e:
        raise FindingsError(f"{path}: not valid JSON: {e}") from e
    return validate(data)


def write(path: str | Path, findings: list) -> None:
    validate(findings)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dumps(findings))


def dumps(findings: list) -> str:
    return json.dumps(findings, indent=2) + "\n"
