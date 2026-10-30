import argparse
import shlex
import shutil
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import yaml

from factory import config, findings
from factory.findings import FindingsError

STAGE = "apple-build"
RESOLVED = Path("project.xcworkspace") / "xcshareddata" / "swiftpm" / "Package.resolved"
SIGNING = ("CODE_SIGN_IDENTITY=-", "CODE_SIGN_STYLE=Manual", "CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO")
IOS_SDK = ("-sdk", "iphoneos", "-destination", "generic/platform=iOS")
IOS_SIGNING = ("CODE_SIGNING_ALLOWED=NO",)
IPA_NAME = "app.ipa"


class StageError(Exception):
    pass


def project_name(spec: Path) -> str:
    data = yaml.safe_load(spec.read_text())
    name = data.get("name") if isinstance(data, dict) else None
    if not isinstance(name, str) or not name:
        raise StageError(f"{spec}: XcodeGen spec has no 'name'")
    return name


def xcodegen_command(spec: str | Path, binary: str = "xcodegen") -> list[str]:
    return [binary, "generate", "--spec", str(spec)]


def products_dir(platform: str) -> str:
    return "Release-iphoneos" if platform == "ios" else "Release"


def xcodebuild_command(project: str | Path, scheme: str, derived: str | Path, pinned: bool = False, platform: str = "macos") -> list[str]:
    cmd = [
        "xcodebuild",
        "-project", str(project),
        "-scheme", scheme,
        "-configuration", "Release",
        "-derivedDataPath", str(derived),
    ]
    if platform == "ios":
        cmd += IOS_SDK
    if pinned:
        cmd.append("-onlyUsePackageVersionsFromResolvedFile")
    return [*cmd, *(IOS_SIGNING if platform == "ios" else SIGNING), "build"]


def ditto_command(app: str | Path, archive: str | Path) -> list[str]:
    return ["ditto", "-c", "-k", "--keepParent", str(app), str(archive)]


def pin_packages(src: Path, project: Path) -> bool:
    resolved = src / "Package.resolved"
    if not resolved.is_file():
        return False
    target = project / RESOLVED
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(resolved, target)
    return True


def _run(cmd: list[str], runner, cwd: Path) -> None:
    print("+ " + " ".join(cmd), flush=True)
    try:
        proc = runner(cmd, cwd=cwd)
    except FileNotFoundError as e:
        raise StageError(f"{cmd[0]} not found; run this stage on a macOS runner with the tools installed") from e
    if proc.returncode != 0:
        raise StageError(f"{cmd[0]} failed with exit code {proc.returncode}")


def settings(src: Path, config_path: str | Path) -> tuple[Path, str]:
    apple = config.load(config_path).get("apple")
    if not apple:
        raise StageError(f"{config_path}: no 'apple' section")
    return Path(apple["project_spec"]), apple["scheme"]


def config_platform(config_path: str | Path) -> str:
    platform = config.load(config_path)["platform"]
    if platform not in ("macos", "ios"):
        raise StageError(f"{config_path}: platform '{platform}' is not an Apple platform")
    return platform


def generate(src: Path, spec: Path, binary: str = "xcodegen", runner=None) -> Path:
    runner = runner or subprocess.run
    _run(xcodegen_command(spec, binary), runner, src)
    project = spec.parent / f"{project_name(src / spec)}.xcodeproj"
    if not (src / project).is_dir():
        raise StageError(f"xcodegen did not create {src / project}")
    return project


def build(src: Path, project: Path, scheme: str, derived: Path, runner=None, platform: str = "macos") -> Path:
    runner = runner or subprocess.run
    pinned = pin_packages(src, src / project)
    _run(xcodebuild_command(project, scheme, derived.resolve(), pinned, platform), runner, src)
    return find_app(derived, platform)


def write_script(src: Path, project: Path, scheme: str, derived: Path, script: Path, platform: str = "macos") -> Path:
    pinned = pin_packages(src, src / project)
    cmd = xcodebuild_command(project, scheme, derived.resolve(), pinned, platform)
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(f"#!/bin/bash\nset -euo pipefail\ncd {shlex.quote(str(src.resolve()))}\nexec {shlex.join(cmd)}\n")
    script.chmod(0o755)
    return script


def find_app(derived: Path, platform: str = "macos") -> Path:
    folder = derived / "Build" / "Products" / products_dir(platform)
    apps = sorted(folder.glob("*.app"))
    if len(apps) != 1:
        raise StageError(f"expected exactly one .app in {folder}, found {len(apps)}")
    return apps[0]


def package_ipa(app: Path, out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    archive = out / IPA_NAME
    root = Path("Payload") / app.name
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(zipfile.ZipInfo("Payload/", date_time=(1980, 1, 1, 0, 0, 0)), "")
        for path in sorted([app, *app.rglob("*")]):
            name = (root / path.relative_to(app)).as_posix()
            mode = path.lstat().st_mode
            info = zipfile.ZipInfo(name + ("/" if stat.S_ISDIR(mode) else ""), date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = (mode & 0xFFFF) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            if stat.S_ISLNK(mode):
                zf.writestr(info, path.readlink().as_posix())
            elif stat.S_ISDIR(mode):
                zf.writestr(info, "")
            else:
                zf.writestr(info, path.read_bytes())
    return archive


def package(app: Path, out: Path, runner=None) -> Path:
    runner = runner or subprocess.run
    out.mkdir(parents=True, exist_ok=True)
    archive = out / f"{app.name}.zip"
    _run(ditto_command(app.name, archive.resolve()), runner, app.parent)
    if not archive.is_file():
        raise StageError(f"ditto wrote no archive at {archive}")
    return archive


def run(src: str | Path, config_path: str | Path, out: str | Path, derived: str | Path = "build/apple", binary: str = "xcodegen", runner=None) -> Path:
    src, out = Path(src), Path(out)
    spec, scheme = settings(src, config_path)
    platform = config_platform(config_path)
    project = generate(src, spec, binary, runner)
    app = build(src, project, scheme, src / derived, runner, platform)
    archive = package_ipa(app, out) if platform == "ios" else package(app, out, runner)
    findings.write(out / "findings.json", [])
    print(f"apple-build: wrote {archive}")
    return archive


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.stages.apple_build", description="Generate the Xcode project with XcodeGen and build it (macOS ad-hoc signed, iOS unsigned for device)")
    parser.add_argument("step", choices=("run", "generate", "build", "script"), help="run does generate, build and zip; script generates the project and writes the xcodebuild command to --script, so CodeQL can trace only xcodebuild")
    parser.add_argument("--src", default=".")
    parser.add_argument("--config", default=".factory.yml")
    parser.add_argument("--out", default="out/apple-build")
    parser.add_argument("--script", default="build/xcodebuild.sh", help="where the script step writes the build command")
    parser.add_argument("--derived", default="build/apple", help="derived data folder, relative to --src")
    args = parser.parse_args(argv)
    src = Path(args.src)
    try:
        if args.step == "run":
            run(src, args.config, args.out, args.derived)
        else:
            spec, scheme = settings(src, args.config)
            platform = config_platform(args.config)
            project = generate(src, spec)
            if args.step == "build":
                build(src, project, scheme, src / args.derived, platform=platform)
            elif args.step == "script":
                write_script(src, project, scheme, src / args.derived, Path(args.script), platform)
    except (StageError, FindingsError, config.ConfigError, OSError, yaml.YAMLError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
