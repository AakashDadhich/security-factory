import argparse
import subprocess
import sys
from pathlib import Path

import yaml

from factory import findings, sarif
from factory.findings import FindingsError
from factory.stages import sast_eslint

STAGE = "sast-swiftlint"
TOOL = "swiftlint"
FACTORY_ROOT = Path(__file__).resolve().parents[2]
CONFIG = FACTORY_ROOT / "tools" / "swiftlint" / ".swiftlint.yml"
EXIT_OK = (0, 2)


class StageError(Exception):
    pass


def custom_rule_ids(config: Path = CONFIG) -> set[str]:
    data = yaml.safe_load(config.read_text())
    rules = data.get("custom_rules") if isinstance(data, dict) else None
    if not isinstance(rules, dict) or not rules:
        raise StageError(f"{config}: expected a non-empty 'custom_rules' mapping")
    return set(rules)


def apply_severity(items: list, security_rules: set[str]) -> list:
    for item in items:
        item["severity"] = "high" if item["rule_id"] in security_rules else "low"
    return findings.validate(items)


def render_config(config: Path, src: Path, dest: Path) -> Path:
    data = yaml.safe_load(config.read_text())
    data["excluded"] = [str((src.resolve() / name)) for name in data.get("excluded", [])]
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(yaml.safe_dump(data, sort_keys=False))
    return dest


def swiftlint_command(config: Path, binary: str = "swiftlint") -> list[str]:
    return [binary, "lint", "--config", str(config), "--reporter", "sarif", "--quiet"]


def run_swiftlint(src: Path, report: Path, config: Path = CONFIG, binary: str = "swiftlint", runner=None) -> None:
    runner = runner or subprocess.run
    report.parent.mkdir(parents=True, exist_ok=True)
    rendered = render_config(config, src, report.parent / "swiftlint.yml")
    cmd = swiftlint_command(rendered.resolve(), binary)
    print("+ " + " ".join(cmd), flush=True)
    try:
        with report.open("w") as handle:
            proc = runner(cmd, cwd=src, stdout=handle)
    except FileNotFoundError as e:
        raise StageError(f"swiftlint not found ({binary}); install it with python -m factory.tools install swiftlint") from e
    if proc.returncode not in EXIT_OK:
        raise StageError(f"swiftlint failed with exit code {proc.returncode}")


def run(src: str | Path, out: str | Path, config: Path = CONFIG, binary: str = "swiftlint", runner=None) -> list:
    src, out = Path(src), Path(out)
    report = out / "swiftlint.sarif"
    run_swiftlint(src, report, config, binary, runner)
    items = sarif.sarif_to_findings(report, STAGE, TOOL)
    result = apply_severity(sast_eslint.relativise(items, src), custom_rule_ids(config))
    findings.write(out / "findings.json", result)
    print(f"sast-swiftlint: {len(result)} finding(s)")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.stages.swiftlint", description="Run SwiftLint with the factory's security config over a project")
    parser.add_argument("--src", default=".")
    parser.add_argument("--out", default="out/sast-swiftlint")
    parser.add_argument("--config", default=str(CONFIG))
    parser.add_argument("--swiftlint", default="swiftlint", help="swiftlint binary to run")
    args = parser.parse_args(argv)
    try:
        run(args.src, args.out, Path(args.config), args.swiftlint)
    except (StageError, FindingsError, OSError, yaml.YAMLError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
