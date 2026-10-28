import argparse
import os
import sys
from pathlib import Path

import yaml

from factory.findings import validator

DEFAULT_ASVS_LEVEL = 2


class ConfigError(Exception):
    pass


def load(path: str | Path) -> dict:
    try:
        data = yaml.safe_load(Path(path).read_text())
    except yaml.YAMLError as e:
        raise ConfigError(f"{path}: not valid YAML: {e}") from e
    except OSError as e:
        raise ConfigError(f"{path}: {e.strerror}") from e
    errors = sorted(validator("factory-config.schema.json").iter_errors(data), key=lambda e: [str(p) for p in e.absolute_path])
    if errors:
        lines = [f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}" for e in errors]
        raise ConfigError(f"{path} does not match the factory config schema:\n" + "\n".join(lines))
    return data


def outputs(config: dict) -> dict[str, str]:
    level = config.get("asvs_level")
    return {
        "platform": config["platform"],
        "asvs_level": str(DEFAULT_ASVS_LEVEL if level is None else level),
        "openapi": config.get("web", {}).get("openapi", ""),
    }


def write_github_outputs(values: dict[str, str], output_file: str | None) -> None:
    lines = "".join(f"{k}={v}\n" for k, v in values.items())
    if output_file:
        with open(output_file, "a") as f:
            f.write(lines)
    else:
        sys.stdout.write(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.config", description="Validate .factory.yml and write GitHub outputs")
    parser.add_argument("--path", default=".factory.yml")
    args = parser.parse_args(argv)
    try:
        values = outputs(load(args.path))
    except ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    write_github_outputs(values, os.environ.get("GITHUB_OUTPUT"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
