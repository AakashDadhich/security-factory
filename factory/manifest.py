import argparse
import json
import os
import platform
import sys
from pathlib import Path

from factory import __version__, config
from factory.config import ConfigError
from factory.findings import validator


class ManifestError(Exception):
    pass


def _check(manifest) -> dict:
    errors = sorted(validator("run-manifest.schema.json").iter_errors(manifest), key=lambda e: [str(p) for p in e.absolute_path])
    if errors:
        lines = [f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}" for e in errors]
        raise ManifestError("run manifest does not match the schema:\n" + "\n".join(lines))
    return manifest


def create(cfg: dict, *, mode: str, factory_ref: str, stages: list[str], env: dict, issue: int | None = None, iteration: int = 0) -> dict:
    missing = [k for k in ("GITHUB_RUN_ID", "GITHUB_REPOSITORY", "GITHUB_SHA") if not env.get(k)]
    if missing:
        raise ManifestError(f"missing environment: {', '.join(missing)}")
    values = config.outputs(cfg)
    manifest = {
        "run_id": f"{env['GITHUB_RUN_ID']}-{env.get('GITHUB_RUN_ATTEMPT') or '1'}",
        "mode": mode,
        "platform": values["platform"],
        "iteration": iteration,
        "issue": issue or None,
        "repo": env["GITHUB_REPOSITORY"],
        "commit_sha": env["GITHUB_SHA"],
        "factory_ref": factory_ref,
        "asvs_level": int(values["asvs_level"]),
        "stages": [{"name": "setup", "status": "success"}] + [{"name": s, "status": "pending"} for s in stages],
        "tool_versions": {"python": platform.python_version(), "security-factory": __version__},
    }
    return _check(manifest)


def load(path: str | Path) -> dict:
    try:
        data = json.loads(Path(path).read_text())
    except json.JSONDecodeError as e:
        raise ManifestError(f"{path}: not valid JSON: {e}") from e
    except OSError as e:
        raise ManifestError(f"{path}: {e.strerror}") from e
    return _check(data)


def write(path: str | Path, manifest: dict) -> None:
    _check(manifest)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.manifest", description="Write the run manifest")
    sub = parser.add_subparsers(dest="command", required=True)
    create_cmd = sub.add_parser("create")
    create_cmd.add_argument("--config", default=".factory.yml")
    create_cmd.add_argument("--mode", required=True)
    create_cmd.add_argument("--factory-ref", required=True)
    create_cmd.add_argument("--stage", action="append", default=[], dest="stages")
    create_cmd.add_argument("--issue", type=int, default=0, help="issue number, 0 for none")
    create_cmd.add_argument("--iteration", type=int, default=0, help="fix loop round, 0 to 2")
    create_cmd.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        manifest = create(config.load(args.config), mode=args.mode, factory_ref=args.factory_ref, stages=args.stages, env=dict(os.environ), issue=args.issue, iteration=args.iteration)
        write(args.out, manifest)
    except (ConfigError, ManifestError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
