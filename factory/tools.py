import argparse
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

FACTORY_ROOT = Path(__file__).resolve().parent.parent
LOCK_PATH = FACTORY_ROOT / "tools" / "versions.lock"
BIN_DIR = Path.home() / ".factory" / "bin"

KINDS = ("binary", "pipx", "npm", "container", "git", "venv", "xcode")
XCODE_APPS = Path("/Applications")
GIT_DIR = Path.home() / ".factory"
VENV_DIR = Path.home() / ".factory" / "venvs"
ARCHIVES = ("tar.gz", "zip", "none")
PLATFORM_FIELDS = ("url", "sha256", "archive", "bin")
NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]*")
REQUIREMENT_RE = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9.+!-]+)( --hash=sha256:[0-9a-f]{64})+")


class ToolError(Exception):
    pass


@dataclass(frozen=True)
class Tool:
    name: str
    version: str
    kind: str
    package: str | None = None
    image: str | None = None
    repo: str | None = None
    commit: str | None = None
    requirements: str | None = None
    platforms: dict[str, dict[str, str]] = field(default_factory=dict)


def _validate(entry: dict) -> Tool:
    name = entry.get("name")
    if not name:
        raise ToolError("lock entry is missing 'name'")
    if not NAME_RE.fullmatch(name):
        raise ToolError(f"{name!r}: tool names must be lowercase letters, digits, '.', '_' or '-'")
    for key in ("version", "kind"):
        if not entry.get(key):
            raise ToolError(f"{name}: lock entry is missing '{key}'")
    kind = entry["kind"]
    if kind not in KINDS:
        raise ToolError(f"{name}: unknown kind '{kind}', expected one of {', '.join(KINDS)}")

    platforms = entry.get("platforms", {})
    if kind == "binary":
        if not platforms:
            raise ToolError(f"{name}: binary entry has no platforms")
        for key, spec in platforms.items():
            missing = [f for f in PLATFORM_FIELDS if not spec.get(f)]
            if missing:
                raise ToolError(f"{name} ({key}): missing {', '.join(missing)}")
            if not spec["url"].startswith("https://"):
                raise ToolError(f"{name} ({key}): url must use https")
            sha = spec["sha256"]
            if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
                raise ToolError(f"{name} ({key}): sha256 must be 64 lowercase hex characters")
            if spec["archive"] not in ARCHIVES:
                raise ToolError(f"{name} ({key}): archive must be one of {', '.join(ARCHIVES)}")
            if "install_dir" in spec:
                if spec["archive"] == "none":
                    raise ToolError(f"{name} ({key}): install_dir needs an archive")
                if not NAME_RE.fullmatch(spec["install_dir"]):
                    raise ToolError(f"{name} ({key}): install_dir must be a plain lowercase folder name")
    if kind == "container":
        image = entry.get("image", "")
        if "@sha256:" not in image:
            raise ToolError(f"{name}: container image must be pinned with an @sha256: digest")
    if kind == "git":
        repo = entry.get("repo", "")
        commit = entry.get("commit", "")
        if not repo.startswith("https://"):
            raise ToolError(f"{name}: git repo must use https")
        if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
            raise ToolError(f"{name}: git commit must be a full 40 character lowercase hex SHA")
    if kind == "xcode" and not re.fullmatch(r"\d+(\.\d+){0,2}", entry["version"]):
        raise ToolError(f"{name}: xcode version must look like 16.4")
    if kind == "venv":
        _check_requirements(name, entry.get("package") or name, entry["version"], entry.get("requirements", ""))

    return Tool(
        name=name,
        version=entry["version"],
        kind=kind,
        package=entry.get("package"),
        image=entry.get("image"),
        repo=entry.get("repo"),
        commit=entry.get("commit"),
        requirements=entry.get("requirements"),
        platforms=platforms,
    )


def _check_requirements(name: str, package: str, version: str, requirements: str) -> None:
    rel = Path(requirements)
    if not requirements or rel.is_absolute() or ".." in rel.parts:
        raise ToolError(f"{name}: venv entry needs a 'requirements' path inside the factory")
    path = FACTORY_ROOT / rel
    if not path.is_file():
        raise ToolError(f"{name}: requirements file {requirements} not found")
    pins = []
    for line in path.read_text().splitlines():
        line = " ".join(line.split())
        if not line or line.startswith("#"):
            continue
        match = REQUIREMENT_RE.fullmatch(line)
        if not match:
            raise ToolError(f"{name}: requirement line must be 'name==version --hash=sha256:<hex>' only: {line}")
        pins.append(match.group(1))
    if f"{package}=={version}" not in pins:
        raise ToolError(f"{name}: {requirements} does not pin {package}=={version}")


def load_lock(path: Path | None = None) -> dict[str, Tool]:
    with open(path or LOCK_PATH, "rb") as f:
        data = tomllib.load(f)
    tools: dict[str, Tool] = {}
    for entry in data.get("tool", []):
        tool = _validate(entry)
        if tool.name in tools:
            raise ToolError(f"{tool.name}: duplicate lock entry")
        tools[tool.name] = tool
    return tools


def current_platform(system: str | None = None, machine: str | None = None) -> str:
    system = system or platform.system()
    machine = (machine or platform.machine()).lower()
    os_name = {"Linux": "linux", "Darwin": "macos"}.get(system)
    arch = {"x86_64": "x64", "amd64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    if not os_name or not arch:
        raise ToolError(f"unsupported platform: {system} {machine}")
    return f"{os_name}-{arch}"


def select_platform(tool: Tool, platform_key: str) -> dict[str, str]:
    spec = tool.platforms.get(platform_key)
    if spec is None:
        available = ", ".join(sorted(tool.platforms)) or "none"
        raise ToolError(
            f"{tool.name} {tool.version} is not available for {platform_key} (lock has: {available})"
        )
    return spec


def get_tool(tools: dict[str, Tool], name: str) -> Tool:
    if name not in tools:
        known = ", ".join(sorted(tools)) or "none"
        raise ToolError(f"unknown tool '{name}' (known: {known})")
    return tools[name]


def download(url: str, dest: Path) -> None:
    if not url.startswith("https://"):
        raise ToolError(f"refusing non-https download: {url}")
    with urllib.request.urlopen(url, timeout=120) as response, open(dest, "wb") as out:
        shutil.copyfileobj(response, out)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _extract_member(archive_path: Path, archive: str, member: str, dest: Path) -> None:
    if archive == "none":
        shutil.copyfile(archive_path, dest)
        return
    if archive == "tar.gz":
        with tarfile.open(archive_path, "r:gz") as tar:
            try:
                info = tar.getmember(member)
            except KeyError:
                raise ToolError(f"'{member}' not found in archive") from None
            source = tar.extractfile(info) if info.isfile() else None
            if source is None:
                raise ToolError(f"'{member}' in archive is not a regular file")
            with source, open(dest, "wb") as out:
                shutil.copyfileobj(source, out)
        return
    with zipfile.ZipFile(archive_path) as zf:
        try:
            with zf.open(member) as source, open(dest, "wb") as out:
                shutil.copyfileobj(source, out)
        except KeyError:
            raise ToolError(f"'{member}' not found in archive") from None


def add_to_github_path(directory: Path) -> None:
    github_path = os.environ.get("GITHUB_PATH")
    if not github_path:
        return
    entry = str(directory)
    existing = Path(github_path).read_text().splitlines() if Path(github_path).exists() else []
    if entry not in existing:
        with open(github_path, "a") as f:
            f.write(entry + "\n")


def _extract_tree(archive_path: Path, archive: str, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    if archive == "tar.gz":
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(dest, filter="data")
    else:
        with zipfile.ZipFile(archive_path) as zf:
            zf.extractall(dest)


def install_tree(tool: Tool, spec: dict[str, str], downloaded: Path, root: Path | None = None) -> Path:
    dest = (root or GIT_DIR) / spec["install_dir"]
    _extract_tree(downloaded, spec["archive"], dest)
    target = dest / spec["bin"]
    if not target.is_file():
        raise ToolError(f"'{spec['bin']}' not found in the {tool.name} archive")
    target.chmod(0o755)
    add_to_github_path(target.parent)
    return target


def install_binary(tool: Tool, platform_key: str, bin_dir: Path | None = None, tree_root: Path | None = None) -> Path:
    bin_dir = bin_dir or BIN_DIR
    spec = select_platform(tool, platform_key)
    with tempfile.TemporaryDirectory() as tmp:
        downloaded = Path(tmp) / "download"
        download(spec["url"], downloaded)
        actual = sha256_of(downloaded)
        if actual != spec["sha256"]:
            raise ToolError(
                f"checksum mismatch for {tool.name} {tool.version} ({platform_key}): "
                f"expected {spec['sha256']}, got {actual}. Refusing to install."
            )
        if "install_dir" in spec:
            return install_tree(tool, spec, downloaded, tree_root)
        bin_dir.mkdir(parents=True, exist_ok=True)
        target = bin_dir / Path(spec["bin"]).name
        staged = Path(tmp) / "staged"
        _extract_member(downloaded, spec["archive"], spec["bin"], staged)
        staged.chmod(0o755)
        shutil.move(staged, target)
    add_to_github_path(bin_dir)
    return target


def _run(cmd: list[str]) -> None:
    print("+ " + " ".join(cmd), flush=True)
    result = subprocess.run(cmd)
    if result.returncode != 0:
        raise ToolError(f"command failed with exit code {result.returncode}: {' '.join(cmd)}")


def install_git(tool: Tool, dest: Path | None = None, run=_run) -> Path:
    dest = dest or GIT_DIR / tool.name
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    git = ["git", "-C", str(dest)]
    run(git + ["init", "--quiet"])
    run(git + ["fetch", "--quiet", "--depth", "1", tool.repo, tool.commit])
    run(git + ["-c", "advice.detachedHead=false", "checkout", "--quiet", "FETCH_HEAD"])
    return dest


def venv_python(name: str, root: Path | None = None) -> Path:
    return (root or VENV_DIR) / name / "bin" / "python"


def install_venv(tool: Tool, root: Path | None = None, run=_run) -> Path:
    dest = (root or VENV_DIR) / tool.name
    run([sys.executable, "-m", "venv", "--clear", str(dest)])
    python = venv_python(tool.name, root)
    run([str(python), "-m", "pip", "install", "--quiet", "--disable-pip-version-check",
         "--require-hashes", "--no-deps", "--only-binary", ":all:", "-r", str(FACTORY_ROOT / tool.requirements)])
    return python


def xcode_app(tool: Tool, apps: Path | None = None) -> Path:
    return (apps or XCODE_APPS) / f"Xcode_{tool.version}.app"


def install_xcode(tool: Tool, apps: Path | None = None, run=_run) -> Path:
    app = xcode_app(tool, apps)
    if not app.is_dir():
        raise ToolError(f"{tool.name} {tool.version} is not installed on this runner ({app} not found)")
    run(["sudo", "xcode-select", "-s", str(app)])
    return app


def install(tool: Tool, platform_key: str, bin_dir: Path | None = None) -> None:
    package = tool.package or tool.name
    if tool.kind == "binary":
        target = install_binary(tool, platform_key, bin_dir)
        print(f"installed {tool.name} {tool.version} to {target}")
    elif tool.kind == "pipx":
        _run(["pipx", "install", "--force", f"{package}=={tool.version}"])
    elif tool.kind == "npm":
        _run(["npm", "install", "-g", f"{package}@{tool.version}"])
    elif tool.kind == "container":
        _run(["docker", "pull", tool.image])
    elif tool.kind == "git":
        target = install_git(tool)
        print(f"installed {tool.name} {tool.commit} to {target}")
    elif tool.kind == "venv":
        target = install_venv(tool)
        print(f"installed {tool.name} {tool.version} into the venv at {target.parent.parent}")
    elif tool.kind == "xcode":
        target = install_xcode(tool)
        print(f"selected {tool.name} {tool.version} at {target}")


def describe(tool: Tool) -> str:
    if tool.kind == "binary":
        detail = ", ".join(sorted(tool.platforms))
    elif tool.kind == "container":
        detail = tool.image
    elif tool.kind == "git":
        detail = f"{tool.repo}@{tool.commit}"
    elif tool.kind == "venv":
        detail = tool.requirements
    elif tool.kind == "xcode":
        detail = str(xcode_app(tool))
    else:
        detail = tool.package or tool.name
    return f"{tool.name}\t{tool.version}\t{tool.kind}\t{detail}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.tools")
    sub = parser.add_subparsers(dest="command", required=True)
    install_cmd = sub.add_parser("install", help="install tools from tools/versions.lock")
    install_cmd.add_argument("names", nargs="+")
    sub.add_parser("list", help="list tools in tools/versions.lock")
    args = parser.parse_args(argv)

    try:
        tools = load_lock()
        if args.command == "list":
            for tool in tools.values():
                print(describe(tool))
            return 0
        selected = [get_tool(tools, name) for name in args.names]
        needs_platform = any(t.kind == "binary" for t in selected)
        platform_key = current_platform() if needs_platform else ""
        for tool in selected:
            install(tool, platform_key)
    except ToolError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
