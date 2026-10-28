import argparse
import sys

from factory import findings, manifest
from factory.manifest import ManifestError


def run(manifest_path: str, out: str) -> list:
    m = manifest.load(manifest_path)
    print(f"passthrough: run {m['run_id']} of {m['repo']} at {m['commit_sha'][:12]} ({m['platform']}, mode {m['mode']})")
    result: list = []
    findings.write(out, result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.passthrough", description="Trivial stage: read the manifest, emit no findings")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--out", default="out/passthrough/findings.json")
    args = parser.parse_args(argv)
    try:
        run(args.manifest, args.out)
    except ManifestError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
