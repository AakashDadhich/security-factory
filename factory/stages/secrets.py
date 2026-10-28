import argparse
import re
import subprocess
import sys
from pathlib import Path

from factory import findings, sarif
from factory.findings import FindingsError

STAGE = "secrets"
TOOL = "gitleaks"
CONFIG = Path(__file__).resolve().parents[2] / "rules" / "gitleaks.toml"
# Gitleaks also exits 1 on its own errors, so leaks get a code of their own.
LEAKS_EXIT = 99
ENV_FILE = re.compile(r"(^|/)\.env(\.[^/]*)?$")
ENV_EXAMPLE = ".env.example"
SECRET_REMEDIATION = (
    "Treat the secret as compromised: revoke and rotate it, then remove it from the code. "
    "It stays in git history until the history is rewritten, so rotation is what matters."
)


class StageError(Exception):
    pass


def is_env_file(path: str) -> bool:
    return bool(ENV_FILE.search(path)) and path.rsplit("/", 1)[-1] != ENV_EXAMPLE


def gitleaks_command(repo: str | Path, report: str | Path, binary: str = "gitleaks", config: Path = CONFIG) -> list[str]:
    return [
        binary, "git", str(repo),
        "--config", str(config),
        "--report-format", "sarif",
        "--report-path", str(report),
        "--redact=100",
        "--exit-code", str(LEAKS_EXIT),
        "--no-banner",
    ]


def leaks_from_exit(code: int) -> bool:
    if code == 0:
        return False
    if code == LEAKS_EXIT:
        return True
    raise StageError(f"gitleaks failed with exit code {code}")


def run_gitleaks(repo: str | Path, report: Path, binary: str = "gitleaks", runner=subprocess.run) -> bool:
    report.parent.mkdir(parents=True, exist_ok=True)
    try:
        proc = runner(gitleaks_command(repo, report, binary))
    except FileNotFoundError as e:
        raise StageError(f"gitleaks not found ({binary}); install it with python -m factory.tools install gitleaks") from e
    leaks = leaks_from_exit(proc.returncode)
    if not report.is_file():
        raise StageError(f"gitleaks exited {proc.returncode} but wrote no report at {report}")
    return leaks


def secret_findings(report: Path) -> list:
    items = sarif.sarif_to_findings(report, STAGE, TOOL)
    for f in items:
        f["severity"] = "high"
        f["cwe"] = f["cwe"] or ["CWE-798"]
        f["remediation"] = f["remediation"] or SECRET_REMEDIATION
    return items


def tracked_files(repo: str | Path) -> list[str]:
    proc = subprocess.run(["git", "-C", str(repo), "ls-files", "-z"], capture_output=True)
    if proc.returncode != 0:
        raise StageError(f"git ls-files failed: {proc.stderr.decode(errors='replace').strip()}")
    return [p for p in proc.stdout.decode().split("\0") if p]


def env_file_findings(paths: list[str]) -> list:
    return [
        findings.make_finding(
            stage=STAGE,
            tool="factory",
            source="check",
            rule_id="committed-env-file",
            title="Committed .env file",
            severity="high",
            location={"path": path, "start_line": None},
            cwe=["CWE-540"],
            description=f"{path} is tracked by git. .env files hold real configuration and secrets and must never be committed.",
            remediation=(
                "Remove the file from git (git rm --cached), add it to .gitignore, rotate any secrets it held, "
                "and commit a .env.example with fake values instead."
            ),
        )
        for path in sorted(p for p in paths if is_env_file(p))
    ]


def run(repo: str | Path, out: str | Path, binary: str = "gitleaks") -> list:
    out = Path(out)
    report = out / "gitleaks.sarif"
    leaks = run_gitleaks(repo, report, binary)
    result = secret_findings(report) + env_file_findings(tracked_files(repo))
    findings.write(out / "findings.json", result)
    secrets_found = sum(1 for f in result if f["tool"] == TOOL)
    print(f"secrets: gitleaks reported {'leaks' if leaks else 'no leaks'}; {secrets_found} secret finding(s), {len(result) - secrets_found} committed .env file(s)")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.stages.secrets", description="Scan git history for secrets and committed .env files")
    parser.add_argument("--repo", default=".")
    parser.add_argument("--out", default="out/secrets")
    parser.add_argument("--gitleaks", default="gitleaks", help="gitleaks binary to run")
    args = parser.parse_args(argv)
    try:
        run(args.repo, args.out, args.gitleaks)
    except (StageError, FindingsError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
