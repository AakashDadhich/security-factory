import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from factory import findings, sarif
from factory.findings import SEVERITIES, FindingsError

STAGE = "deps-sbom"
OSV = "osv-scanner"
GRYPE = "grype"
MERGED_TOOL = "osv-scanner+grype"
OSV_EXIT_FINDINGS = 1
OSV_EXIT_NO_PACKAGES = 128
OSV_EXCLUDES = (".factory", "node_modules", "dist", "build", "Pods", ".build")
EXCLUDES = ("**/node_modules/**", "**/dist/**", "**/build/**", "**/Pods/**", "**/.build/**", "./.factory/**")
VULN_ID = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|OSV-\d{4}-\d+|[A-Z]{2,}-\d{4}-\d+)\b", re.IGNORECASE)
OSV_PACKAGE = re.compile(r"[Pp]ackage '([^']+)'")
GRYPE_PACKAGE = re.compile(r"package: (.+?), version (\S+)")


class StageError(Exception):
    pass


def vuln_ids(*texts: str) -> set[str]:
    return {m.group(0).upper() for text in texts for m in VULN_ID.finditer(text or "")}


def split_package(spec: str) -> tuple[str, str]:
    name, sep, version = spec.rpartition("@")
    if not sep or not name:
        return spec, ""
    return name, version


def package_of(tool: str, message: str) -> tuple[str, str] | None:
    if tool == OSV:
        if m := OSV_PACKAGE.search(message):
            return split_package(m.group(1))
    elif m := GRYPE_PACKAGE.search(message):
        return m.group(1), m.group(2)
    return None


def load_results(sarif_path: Path, tool: str) -> list[dict]:
    try:
        log = json.loads(sarif_path.read_text())
    except json.JSONDecodeError as e:
        raise FindingsError(f"{sarif_path}: not valid JSON: {e}") from e
    if not isinstance(log, dict) or not isinstance(log.get("runs"), list):
        raise FindingsError(f"{sarif_path}: not a SARIF log (no 'runs' array)")

    by_fingerprint: dict[str, dict] = {}
    for run in log["runs"]:
        for result in run.get("results", []):
            if result.get("kind") in sarif.SKIPPED_KINDS:
                continue
            finding = sarif.result_to_finding(result, run, STAGE, tool)
            message = sarif._text(result.get("message"))
            package = package_of(tool, message)
            entry = {"finding": finding, "package": package, "ids": vuln_ids(finding["rule_id"], message)}
            kept = by_fingerprint.get(finding["fingerprint"])
            if kept is None or SEVERITIES.index(finding["severity"]) < SEVERITIES.index(kept["finding"]["severity"]):
                by_fingerprint[finding["fingerprint"]] = entry
    return list(by_fingerprint.values())


def same_vulnerability(a: dict, b: dict) -> bool:
    if a["package"] is None or b["package"] is None:
        return False
    if (a["package"][0].lower(), a["package"][1]) != (b["package"][0].lower(), b["package"][1]):
        return False
    return bool(a["ids"] & b["ids"])


def _more_severe(a: str, b: str) -> str:
    return min(a, b, key=SEVERITIES.index)


def merge(osv: list[dict], grype: list[dict]) -> list:
    unmatched = list(grype)
    result = []
    for entry in osv:
        finding = entry["finding"]
        twins = [g for g in unmatched if same_vulnerability(entry, g)]
        if not twins:
            result.append(finding)
            continue
        unmatched = [g for g in unmatched if g not in twins]
        fields = {k: v for k, v in finding.items() if k not in ("id", "fingerprint")}
        fields["tool"] = MERGED_TOOL
        for twin in twins:
            fields["severity"] = _more_severe(fields["severity"], twin["finding"]["severity"])
            fields["cwe"] = sorted(set(fields["cwe"]) | set(twin["finding"]["cwe"]))
            fields["remediation"] = fields["remediation"] or twin["finding"]["remediation"]
        result.append(findings.make_finding(**fields))
    result += [g["finding"] for g in unmatched]
    return findings.validate(sorted(result, key=lambda f: f["id"]))


def _run(cmd: list[str], runner, env: dict | None = None, stdout=None):
    print("+ " + " ".join(cmd), flush=True)
    try:
        return runner(cmd, env=env, stdout=stdout)
    except FileNotFoundError as e:
        raise StageError(f"{cmd[0]} not found; install it with python -m factory.tools install {Path(cmd[0]).name}") from e


def _tool_env() -> dict:
    return {**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false", "GRYPE_CHECK_FOR_APP_UPDATE": "false"}


def run_osv(src: Path, report: Path, binary: str = "osv-scanner", runner=None) -> None:
    runner = runner or subprocess.run
    report.parent.mkdir(parents=True, exist_ok=True)
    cmd = [binary, "scan", "source", "-r", "--format", "sarif"]
    for name in OSV_EXCLUDES:
        cmd += ["--x-exclude", name]
    cmd.append(str(src))
    with report.open("w") as handle:
        proc = _run(cmd, runner, stdout=handle)
    if proc.returncode == OSV_EXIT_NO_PACKAGES:
        print("osv-scanner found no lockfiles or manifests; treating as no findings")
        report.write_text(json.dumps({"version": "2.1.0", "runs": []}))
    elif proc.returncode not in (0, OSV_EXIT_FINDINGS):
        raise StageError(f"osv-scanner failed with exit code {proc.returncode}")
    try:
        json.loads(report.read_text())
    except json.JSONDecodeError as e:
        raise StageError(f"osv-scanner wrote an unreadable SARIF report at {report}") from e


def run_syft(target: str, output: Path, binary: str = "syft", runner=None) -> None:
    runner = runner or subprocess.run
    output.parent.mkdir(parents=True, exist_ok=True)
    cmd = [binary, "scan", target, "-o", f"cyclonedx-json={output}"]
    for pattern in EXCLUDES:
        cmd += ["--exclude", pattern]
    proc = _run(cmd, runner, env=_tool_env())
    if proc.returncode != 0:
        raise StageError(f"syft failed with exit code {proc.returncode}")
    if not output.is_file():
        raise StageError(f"syft exited 0 but wrote no SBOM at {output}")
    bom = json.loads(output.read_text())
    if bom.get("bomFormat") != "CycloneDX":
        raise StageError(f"{output} is not a CycloneDX document")


def grype_db_meta(status_json: str) -> dict:
    try:
        status = json.loads(status_json)
    except json.JSONDecodeError:
        return {"built": None, "raw": status_json.strip()}
    built = status.get("built") if isinstance(status, dict) else None
    return {"built": built, "status": status}


def run_grype(sbom: Path, report: Path, meta_path: Path, binary: str = "grype", runner=None) -> None:
    runner = runner or subprocess.run
    env = _tool_env()
    update = _run([binary, "db", "update"], runner, env=env)
    if update.returncode != 0:
        raise StageError(f"grype db update failed with exit code {update.returncode}")
    status = runner([binary, "db", "status", "-o", "json"], env=env, capture_output=True, text=True)
    if status.returncode != 0:
        raise StageError(f"grype db status failed with exit code {status.returncode}")
    meta = {"grype": {"db": grype_db_meta(status.stdout)}}
    if not meta["grype"]["db"].get("built"):
        raise StageError("grype db status did not report a database build date")
    meta_path.write_text(json.dumps(meta, indent=2) + "\n")

    scan = _run([binary, f"sbom:{sbom}", "-o", f"sarif={report}"], runner, env=env)
    if scan.returncode != 0:
        raise StageError(f"grype failed with exit code {scan.returncode}")
    if not report.is_file():
        raise StageError(f"grype exited 0 but wrote no report at {report}")


def run(src: str | Path, out: str | Path, image: str | None = None, osv_bin: str = "osv-scanner", syft_bin: str = "syft", grype_bin: str = "grype", runner=None) -> list:
    src, out = Path(src), Path(out)
    out.mkdir(parents=True, exist_ok=True)

    osv_report = out / "osv-scanner.sarif"
    run_osv(src, osv_report, osv_bin, runner)

    sbom = out / "sbom.cdx.json"
    run_syft(f"dir:{src}", sbom, syft_bin, runner)
    if image:
        run_syft(image, out / "sbom-image.cdx.json", syft_bin, runner)

    grype_report = out / "grype.sarif"
    run_grype(sbom, grype_report, out / "tool-meta.json", grype_bin, runner)

    result = merge(load_results(osv_report, OSV), load_results(grype_report, GRYPE))
    findings.write(out / "findings.json", result)
    print(f"deps-sbom: {len(result)} finding(s)")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.stages.deps_sbom", description="Scan dependencies with OSV-Scanner and Grype and write a CycloneDX SBOM with Syft")
    parser.add_argument("--src", default=".")
    parser.add_argument("--out", default="out/deps-sbom")
    parser.add_argument("--image", help="container image to also write an SBOM for (sbom-image.cdx.json)")
    args = parser.parse_args(argv)
    try:
        run(args.src, args.out, args.image)
    except (StageError, FindingsError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
