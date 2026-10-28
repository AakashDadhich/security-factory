import argparse
import subprocess
import sys
from pathlib import Path

import yaml

from factory import findings, sarif
from factory.findings import FindingsError

STAGE = "sast-eslint"
TOOL = "eslint"
FACTORY_ROOT = Path(__file__).resolve().parents[2]
TOOLING_DIR = FACTORY_ROOT / "tools" / "eslint"
FORMATTER = Path("node_modules") / "@microsoft" / "eslint-formatter-sarif" / "sarif.js"


class StageError(Exception):
    pass


def load_escalations(path: Path = TOOLING_DIR / "severity.yml") -> set[str]:
    data = yaml.safe_load(path.read_text())
    rules = data.get("escalate") if isinstance(data, dict) else None
    if not isinstance(rules, list) or not all(isinstance(r, str) for r in rules):
        raise StageError(f"{path}: expected an 'escalate' list of rule ids")
    return set(rules)


def apply_severity(items: list, escalate: set[str]) -> list:
    for item in items:
        if item["rule_id"] in escalate:
            item["severity"] = "high"
        elif item["severity"] == "high":
            item["severity"] = "medium"
    return findings.validate(items)


def relativise(items: list, src: Path) -> list:
    root = str(src.resolve()).rstrip("/") + "/"
    for item in items:
        path = item["location"].get("path", "")
        if path.startswith(root):
            item["location"]["path"] = path[len(root):]
    return items


def eslint_command(tooling: Path, report: Path, binary: str | None = None) -> list[str]:
    return [
        binary or str(tooling / "node_modules" / ".bin" / "eslint"),
        "--config", str(tooling / "eslint.config.mjs"),
        "--no-config-lookup",
        "--format", str(tooling / FORMATTER),
        "--output-file", str(report),
        "--no-warn-ignored",
        ".",
    ]


def npm_ci(tooling: Path, runner=None) -> None:
    runner = runner or subprocess.run
    try:
        proc = runner(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=tooling)
    except FileNotFoundError as e:
        raise StageError("npm not found; set up Node.js before running this stage") from e
    if proc.returncode != 0:
        raise StageError(f"npm ci failed with exit code {proc.returncode}")


def run_eslint(src: Path, report: Path, tooling: Path = TOOLING_DIR, binary: str | None = None, runner=None) -> None:
    runner = runner or subprocess.run
    report.parent.mkdir(parents=True, exist_ok=True)
    cmd = eslint_command(tooling.resolve(), report.resolve(), binary)
    print("+ " + " ".join(cmd), flush=True)
    try:
        proc = runner(cmd, cwd=src)
    except FileNotFoundError as e:
        raise StageError(f"eslint not found ({cmd[0]}); run npm ci in {tooling} first") from e
    if proc.returncode not in (0, 1):
        raise StageError(f"eslint failed with exit code {proc.returncode}")
    if not report.is_file():
        raise StageError(f"eslint exited {proc.returncode} but wrote no report at {report}")


def run(src: str | Path, out: str | Path, tooling: Path = TOOLING_DIR, install: bool = True, binary: str | None = None) -> list:
    src, out = Path(src), Path(out)
    report = out / "eslint.sarif"
    if install:
        npm_ci(tooling)
    run_eslint(src, report, tooling, binary)
    items = sarif.sarif_to_findings(report, STAGE, TOOL)
    result = apply_severity(relativise(items, src), load_escalations(tooling / "severity.yml"))
    findings.write(out / "findings.json", result)
    print(f"sast-eslint: {len(result)} finding(s)")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.stages.sast_eslint", description="Run the factory's ESLint security config over a project")
    parser.add_argument("--src", default=".")
    parser.add_argument("--out", default="out/sast-eslint")
    parser.add_argument("--tooling", default=str(TOOLING_DIR), help="directory holding the ESLint config and package.json")
    parser.add_argument("--skip-install", action="store_true", help="do not run npm ci")
    args = parser.parse_args(argv)
    try:
        run(args.src, args.out, Path(args.tooling), install=not args.skip_install)
    except (StageError, FindingsError, OSError, yaml.YAMLError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
