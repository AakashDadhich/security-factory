import argparse
import json
import sys
from pathlib import Path


class SbomError(Exception):
    pass


def _walk(items: list):
    for item in items:
        yield item
        yield from _walk(item.get("components", []))


def _name(component: dict) -> str:
    group = component.get("group")
    name = component.get("name", "")
    return f"{group}/{name}" if group else name


def components(cyclonedx_path: str | Path) -> list[dict]:
    try:
        bom = json.loads(Path(cyclonedx_path).read_text())
    except json.JSONDecodeError as e:
        raise SbomError(f"{cyclonedx_path}: not valid JSON: {e}") from e
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX":
        raise SbomError(f"{cyclonedx_path}: not a CycloneDX JSON document")

    seen = set()
    result = []
    for component in _walk(bom.get("components", [])):
        entry = {
            "name": _name(component),
            "version": component.get("version", ""),
            "purl": component.get("purl", ""),
        }
        key = (entry["name"], entry["version"], entry["purl"])
        if entry["name"] and key not in seen:
            seen.add(key)
            result.append(entry)
    return sorted(result, key=lambda c: (c["name"], c["version"], c["purl"]))


def package_key(component: dict) -> str:
    purl = component.get("purl", "")
    if not purl:
        return component["name"]
    base = purl.split("#", 1)[0].split("?", 1)[0]
    head, _, last = base.rpartition("/")
    return f"{head}/{last.rsplit('@', 1)[0]}" if head else base


def _group(items: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for component in items:
        grouped.setdefault(package_key(component), []).append(component)
    return grouped


def diff(old: list[dict], new: list[dict]) -> dict:
    old_by_key = _group(old)
    new_by_key = _group(new)
    added, removed, changed = [], [], []
    for key in sorted(old_by_key.keys() | new_by_key.keys()):
        before = old_by_key.get(key, [])
        after = new_by_key.get(key, [])
        if not before:
            added.extend(after)
        elif not after:
            removed.extend(before)
        else:
            old_versions = sorted({c["version"] for c in before})
            new_versions = sorted({c["version"] for c in after})
            if old_versions != new_versions:
                changed.append({
                    "name": after[0]["name"],
                    "old_versions": old_versions,
                    "new_versions": new_versions,
                })
    return {"added": added, "removed": removed, "changed": changed}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.sbom", description="Read and compare CycloneDX JSON SBOMs")
    sub = parser.add_subparsers(dest="command", required=True)
    list_cmd = sub.add_parser("components", help="list name, version and purl of every component")
    list_cmd.add_argument("sbom")
    diff_cmd = sub.add_parser("diff", help="show added, removed and changed components")
    diff_cmd.add_argument("old")
    diff_cmd.add_argument("new")
    args = parser.parse_args(argv)
    try:
        if args.command == "components":
            result = components(args.sbom)
        else:
            result = diff(components(args.old), components(args.new))
    except (SbomError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
