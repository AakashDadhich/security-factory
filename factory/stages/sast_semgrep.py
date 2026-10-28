import argparse
import subprocess
import sys
from pathlib import Path

import yaml

from factory import findings, sarif
from factory.findings import FindingsError

STAGE = "sast-semgrep"
TOOL = "semgrep"
FACTORY_ROOT = Path(__file__).resolve().parents[2]
RULESETS = FACTORY_ROOT / "semgrep-rules" / "rulesets.yml"
COMMUNITY_RULES = Path.home() / ".factory" / "semgrep-rules"
EXCLUDES = ("node_modules", "dist", "build", "Pods", ".build", ".factory")


class StageError(Exception):
    pass


def load_rulesets(path: Path = RULESETS) -> dict:
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, dict) or not {"community", "custom"} <= set(data):
        raise StageError(f"{path}: expected 'community' and 'custom' sections")
    return data


def select_configs(platform: str, community_root: Path = COMMUNITY_RULES, rulesets: dict | None = None, factory_root: Path = FACTORY_ROOT) -> list[str]:
    rulesets = rulesets or load_rulesets()
    if platform not in rulesets["community"] or platform not in rulesets["custom"]:
        known = ", ".join(sorted(rulesets["community"]))
        raise StageError(f"no Semgrep rule sets for platform '{platform}' (known: {known})")
    configs = [str(community_root / name) for name in rulesets["community"][platform]]
    configs += [str(factory_root / "semgrep-rules" / name) for name in rulesets["custom"][platform]]
    return configs


def semgrep_command(configs: list[str], src: str | Path, report: str | Path, binary: str = "semgrep") -> list[str]:
    cmd = [
        binary, "scan",
        "--metrics=off",
        "--disable-version-check",
        "--sarif",
        "--output", str(report),
    ]
    for config in configs:
        cmd += ["--config", config]
    for pattern in EXCLUDES:
        cmd += ["--exclude", pattern]
    cmd.append(str(src))
    return cmd


def run_semgrep(configs: list[str], src: str | Path, report: Path, binary: str = "semgrep", runner=None) -> None:
    runner = runner or subprocess.run
    for config in configs:
        if not Path(config).is_dir():
            raise StageError(f"rule directory not found: {config}; install community rules with python -m factory.tools install semgrep-rules")
    report.parent.mkdir(parents=True, exist_ok=True)
    cmd = semgrep_command(configs, src, report, binary)
    print("+ " + " ".join(cmd), flush=True)
    try:
        proc = runner(cmd)
    except FileNotFoundError as e:
        raise StageError(f"semgrep not found ({binary}); install it with python -m factory.tools install semgrep") from e
    if proc.returncode != 0:
        raise StageError(f"semgrep failed with exit code {proc.returncode}")
    if not report.is_file():
        raise StageError(f"semgrep exited 0 but wrote no report at {report}")


def run(platform: str, src: str | Path, out: str | Path, binary: str = "semgrep", community_root: Path = COMMUNITY_RULES) -> list:
    out = Path(out)
    report = out / "semgrep.sarif"
    run_semgrep(select_configs(platform, community_root), src, report, binary)
    result = sarif.sarif_to_findings(report, STAGE, TOOL)
    findings.write(out / "findings.json", result)
    print(f"sast-semgrep: {len(result)} finding(s) for platform {platform}")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.stages.sast_semgrep", description="Run Semgrep CE with the rule sets for a platform")
    parser.add_argument("--platform", required=True)
    parser.add_argument("--src", default=".")
    parser.add_argument("--out", default="out/sast-semgrep")
    parser.add_argument("--semgrep", default="semgrep", help="semgrep binary to run")
    parser.add_argument("--rules-dir", default=str(COMMUNITY_RULES), help="checkout of the community semgrep-rules")
    args = parser.parse_args(argv)
    try:
        run(args.platform, args.src, args.out, args.semgrep, Path(args.rules_dir))
    except (StageError, FindingsError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
