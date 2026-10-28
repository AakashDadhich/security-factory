import argparse
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from factory.tools import ToolError, add_to_github_path


def make_version(make_path: str) -> str:
    result = subprocess.run([make_path, "--version"], capture_output=True, text=True, check=True)
    return result.stdout.splitlines()[0].strip()


def install_make() -> Path:
    if platform.system() != "Darwin":
        raise ToolError("make is missing and automatic install is only supported on macOS")
    if not shutil.which("brew"):
        raise ToolError("make is missing and Homebrew is not available to install it")
    subprocess.run(["brew", "install", "make"], check=True)
    prefix = subprocess.run(
        ["brew", "--prefix", "make"], capture_output=True, text=True, check=True
    ).stdout.strip()
    gnubin = Path(prefix) / "libexec" / "gnubin"
    add_to_github_path(gnubin)
    return gnubin / "make"


def ensure_make() -> str:
    path = shutil.which("make")
    if path:
        version = make_version(path)
        print(f"make present: {version} at {path}")
        return version
    print("make not found, installing with Homebrew")
    installed = install_make()
    version = make_version(str(installed))
    print(f"make installed: {version} at {installed}")
    return version


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.platform_check")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("ensure-make", help="check make is available, installing it on macOS if not")
    args = parser.parse_args(argv)

    try:
        if args.command == "ensure-make":
            ensure_make()
    except (ToolError, subprocess.CalledProcessError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
