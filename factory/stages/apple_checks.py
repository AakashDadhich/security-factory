import argparse
import re
import sys
from pathlib import Path

import yaml

from factory import config, findings
from factory.apple import inspect as ins
from factory.apple.inspect import InspectError
from factory.findings import FindingsError

STAGE = "apple-checks"
TOOL = "factory-apple-checks"
APIS = Path(__file__).resolve().parents[1] / "apple" / "required_reason_apis.yml"
SOURCE_SUFFIXES = {".swift", ".m", ".mm", ".h", ".c", ".cc", ".cpp"}
SKIP_DIRS = {".git", ".factory", ".build", "build", "Pods", "Carthage", "DerivedData", "node_modules", "out", "SourcePackages"}
SANDBOX = "com.apple.security.app-sandbox"
TASK_ALLOW = "com.apple.security.get-task-allow"
RISKY = (
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.allow-dyld-environment-variables",
)
TEMPORARY_EXCEPTION = "temporary-exception"
KEYCHAIN_RULES = (
    ("keychain-accessible-always-this-device-only", re.compile(r"\bkSecAttrAccessibleAlwaysThisDeviceOnly\b")),
    ("keychain-accessible-always", re.compile(r"\bkSecAttrAccessibleAlways\b")),
)


class StageError(Exception):
    pass


def bundle_paths(app: Path, platform: str) -> dict:
    base = app / "Contents" if platform == "macos" else app
    resources = base / "Resources" if platform == "macos" else app
    return {"info": base / "Info.plist", "privacy": resources / "PrivacyInfo.xcprivacy"}


def make(rule: str, title: str, severity: str, path: str, description: str, remediation: str, cwe: list[str], line: int | None = None) -> dict:
    return findings.make_finding(
        stage=STAGE, tool=TOOL, source="check", rule_id=rule, title=title, severity=severity,
        location={"path": path, "start_line": line, "end_line": line}, cwe=cwe,
        description=description, remediation=remediation,
    )


def spec_entitlement_paths(spec: Path) -> list[Path]:
    try:
        data = yaml.safe_load(spec.read_text())
    except (OSError, yaml.YAMLError) as e:
        raise StageError(f"cannot read the XcodeGen spec {spec}: {e}") from e
    targets = data.get("targets") if isinstance(data, dict) else None
    found = []
    for target in (targets or {}).values():
        if not isinstance(target, dict) or target.get("type") != "application":
            continue
        base = (target.get("settings") or {}).get("base") or {}
        declared = (target.get("entitlements") or {}).get("path") or base.get("CODE_SIGN_ENTITLEMENTS")
        if isinstance(declared, str):
            found.append(spec.parent / declared)
    return found


def project_entitlements(spec: Path) -> dict:
    merged: dict = {}
    for path in spec_entitlement_paths(spec):
        try:
            merged.update(ins.read_plist(path))
        except InspectError as e:
            raise StageError(str(e)) from e
    return merged


def entitlement_rule(key: str) -> str:
    return "entitlement-" + key.removeprefix("com.apple.security.").replace(".", "-")


def check_signature(platform: str, flags: dict, entitlements: dict, path: str) -> list[dict]:
    out = []
    if platform == "macos":
        if not flags["runtime"]:
            out.append(make("macos-hardened-runtime-missing", "Hardened runtime is not enabled", "high", path,
                            "The code signature has no 'runtime' flag, so the app runs without the hardened runtime protections and cannot be notarized.",
                            "Set ENABLE_HARDENED_RUNTIME = YES for the app target.", ["CWE-693"]))
        if entitlements.get(SANDBOX) is not True:
            out.append(make("macos-app-sandbox-disabled", "App Sandbox is not enabled", "high", path,
                            f"The entitlement {SANDBOX} is missing or false, so the app runs with the full privileges of the user.",
                            f"Add {SANDBOX} = true to the app's entitlements and grant only the capabilities it needs.", ["CWE-250"]))
    if entitlements.get(TASK_ALLOW) is True:
        out.append(make("get-task-allow-release", "get-task-allow is true in a Release build", "high", path,
                        "com.apple.security.get-task-allow lets other processes attach a debugger to the app.",
                        "Remove get-task-allow from the Release entitlements and sign Release builds without debugging entitlements.", ["CWE-489"]))
    for key in RISKY:
        if entitlements.get(key) is True:
            out.append(make(entitlement_rule(key), f"Risky entitlement {key}", "high", path,
                            f"{key} weakens the hardened runtime protections of the app.",
                            f"Remove {key} unless the app cannot work without it, and document why.", ["CWE-693"]))
    for key in sorted(entitlements):
        if TEMPORARY_EXCEPTION in key and entitlements[key]:
            out.append(make(entitlement_rule(key), f"Temporary exception entitlement {key}", "medium", path,
                            "Temporary exception entitlements open holes in the App Sandbox and are reviewed by Apple.",
                            f"Replace {key} with a scoped entitlement or user-granted access.", ["CWE-250"]))
    return out


def check_ats(info: dict, path: str) -> list[dict]:
    ats = ins.ats_settings(info)
    out = []
    if ats["arbitrary_loads"]:
        out.append(make("ats-allows-arbitrary-loads", "App Transport Security allows arbitrary loads", "high", path,
                        "NSAllowsArbitraryLoads is true, so the app can load any URL over plain HTTP.",
                        "Remove NSAllowsArbitraryLoads and add narrow per-domain exceptions only where unavoidable.", ["CWE-319"]))
    if ats["web_content"]:
        out.append(make("ats-allows-arbitrary-loads-in-web-content", "App Transport Security allows arbitrary loads in web content", "medium", path,
                        "NSAllowsArbitraryLoadsInWebContent is true, so web views can load any URL over plain HTTP.",
                        "Remove NSAllowsArbitraryLoadsInWebContent.", ["CWE-319"]))
    if ats["insecure_http_domains"]:
        out.append(make("ats-exception-allows-insecure-http", "App Transport Security exception allows insecure HTTP", "medium", path,
                        "NSExceptionAllowsInsecureHTTPLoads is true for: " + ", ".join(ats["insecure_http_domains"]) + ".",
                        "Serve these domains over HTTPS and remove the exceptions.", ["CWE-319"]))
    return out


def load_apis(path: Path = APIS) -> tuple[str, list[dict]]:
    data = yaml.safe_load(path.read_text())
    categories = data.get("categories") if isinstance(data, dict) else None
    if not categories or not isinstance(data.get("source"), str):
        raise StageError(f"{path}: expected 'source' and a non-empty 'categories' list")
    return data["source"], [{**c, "compiled": [re.compile(p) for p in c["patterns"]]} for c in categories]


def source_files(src: Path):
    for path in sorted(src.rglob("*")):
        rel = path.relative_to(src)
        if path.suffix in SOURCE_SUFFIXES and path.is_file() and not any(p in SKIP_DIRS or p.endswith(".xcodeproj") for p in rel.parts[:-1]):
            yield rel, path


def scan_source(src: Path, categories: list[dict]) -> tuple[dict, list]:
    api_hits: dict[str, tuple[str, int]] = {}
    keychain = []
    for rel, path in source_files(src):
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, 1):
            if line.lstrip().startswith("//"):
                continue
            for cat in categories:
                if cat["type"] not in api_hits and any(p.search(line) for p in cat["compiled"]):
                    api_hits[cat["type"]] = (rel.as_posix(), number)
            for rule, pattern in KEYCHAIN_RULES:
                if pattern.search(line):
                    keychain.append((rule, rel.as_posix(), number))
    return api_hits, keychain


def find_manifest(app: Path, platform: str, src: Path) -> Path | None:
    inside = bundle_paths(app, platform)["privacy"]
    if inside.is_file():
        return inside
    for path in sorted(src.rglob("PrivacyInfo.xcprivacy")):
        if not any(p in SKIP_DIRS for p in path.relative_to(src).parts[:-1]):
            return path
    return None


def check_privacy(manifest: Path | None, display: str, api_hits: dict, categories: list[dict]) -> list[dict]:
    if manifest is None:
        return [make("privacy-manifest-missing", "PrivacyInfo.xcprivacy is missing", "high", display,
                     "The app has no privacy manifest, which App Store submissions require.",
                     "Add a PrivacyInfo.xcprivacy file to the app target.", [])]
    try:
        declared = ins.declared_api_types(ins.read_plist(manifest))
    except InspectError as e:
        return [make("privacy-manifest-invalid", "PrivacyInfo.xcprivacy is invalid", "high", display, str(e),
                     "Fix the privacy manifest so it is a valid property list with an NSPrivacyAccessedAPITypes array.", [])]
    out = []
    by_type = {c["type"]: c for c in categories}
    for api_type, (path, line) in sorted(api_hits.items()):
        if api_type in declared:
            continue
        cat = by_type[api_type]
        out.append(make(f"privacy-required-reason-{cat['rule']}", f"Required-reason API not declared: {cat['label']}", "medium", path,
                        f"The source uses {cat['label']} but {api_type} is not listed in NSPrivacyAccessedAPITypes of the privacy manifest.",
                        f"Declare {api_type} with an approved reason in PrivacyInfo.xcprivacy.", [], line))
    return out


def check_keychain(hits: list) -> list[dict]:
    titles = {
        "keychain-accessible-always": "Keychain item accessible while the device is locked (kSecAttrAccessibleAlways)",
        "keychain-accessible-always-this-device-only": "Keychain item accessible while the device is locked (kSecAttrAccessibleAlwaysThisDeviceOnly)",
    }
    return [make(rule, titles[rule], "high", path,
                 "kSecAttrAccessibleAlways variants are deprecated and leave the item readable while the device is locked.",
                 "Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly or kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly.", ["CWE-922"], line)
            for rule, path, line in hits]


def run(app: str | Path, platform: str, src: str | Path, out: str | Path, runner=None, apis: Path = APIS, project_spec: str | Path | None = None) -> list[dict]:
    app, src, out = Path(app), Path(src), Path(out)
    if platform not in ("macos", "ios"):
        raise StageError(f"unknown platform {platform!r}")
    if not app.is_dir():
        raise StageError(f"{app} is not an app bundle folder")
    paths = bundle_paths(app, platform)
    rel = lambda p: f"{app.name}/{p.relative_to(app).as_posix()}"
    try:
        if platform == "ios":
            flags = {"runtime": False, "names": [], "value": 0}
            entitlements = project_entitlements(Path(project_spec)) if project_spec else {}
        else:
            flags = ins.read_code_flags(app, runner)
            entitlements = ins.read_entitlements(app, runner)
        info = ins.read_plist(paths["info"])
    except InspectError as e:
        raise StageError(str(e)) from e
    _, categories = load_apis(apis)
    api_hits, keychain = scan_source(src, categories)
    manifest = find_manifest(app, platform, src)
    if manifest is None:
        display = rel(paths["privacy"])
    elif app in manifest.parents:
        display = rel(manifest)
    else:
        display = manifest.relative_to(src).as_posix()
    result = (
        check_signature(platform, flags, entitlements, app.name)
        + check_ats(info, rel(paths["info"]))
        + check_privacy(manifest, display, api_hits, categories)
        + check_keychain(keychain)
    )
    result = findings.validate(result)
    findings.write(out / "findings.json", result)
    print(f"apple-checks: {len(result)} finding(s)")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.stages.apple_checks", description="Scripted Apple security checks on a built, signed .app and its source")
    parser.add_argument("--app", required=True, help="path to the .app folder")
    parser.add_argument("--platform", required=True, choices=("macos", "ios"))
    parser.add_argument("--src", default=".")
    parser.add_argument("--out", default="out/apple-checks")
    parser.add_argument("--config", help=".factory.yml; for iOS the unsigned app has no entitlements, so they are read from the files its XcodeGen spec names")
    args = parser.parse_args(argv)
    try:
        spec = None
        if args.config:
            spec = Path(args.src) / config.load(args.config)["apple"]["project_spec"]
        run(args.app, args.platform, args.src, args.out, project_spec=spec)
    except (StageError, FindingsError, config.ConfigError, OSError, yaml.YAMLError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
