import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from factory import config as factory_config
from factory import findings, tools
from factory.dast.harness import APP_ALIAS, NETWORK
from factory.findings import FindingsError

STAGE = "dast-web"
TOOL = "zap"
PLAN_DIR = Path(__file__).resolve().parent.parent.parent / "zap"
PLANS = ("baseline",)
RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}
REPORT_NAME = "zap-report"


class StageError(Exception):
    pass


def target_url(port: int) -> str:
    return f"http://{APP_ALIAS}:{port}"


def render_plan(plan: str, port: int, plan_dir: Path = PLAN_DIR) -> str:
    if plan not in PLANS:
        raise StageError(f"unknown plan {plan!r}; choose from {', '.join(PLANS)}")
    return (plan_dir / f"{plan}.yaml").read_text().replace("{{TARGET}}", target_url(port))


def zap_cmd(image: str, workdir: Path, plan_file: str) -> list[str]:
    return [
        "docker", "run", "--rm",
        "--network", NETWORK,
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "-v", f"{workdir}:/zap/wrk:rw",
        image,
        "zap.sh", "-cmd", "-silent", "-autorun", f"/zap/wrk/{plan_file}",
    ]


def _text(value) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.replace("</p>", "\n").replace("<p>", "").split())


def convert(report: dict) -> list[dict]:
    if not isinstance(report, dict) or not isinstance(report.get("site"), list):
        raise FindingsError("not a ZAP traditional-json report (no 'site' array)")
    by_fingerprint: dict[str, dict] = {}
    for site in report["site"]:
        for alert in site.get("alerts", []):
            severity = RISK.get(str(alert.get("riskcode")))
            if severity is None:
                raise FindingsError(f"unknown ZAP riskcode {alert.get('riskcode')!r}")
            cwe = str(alert.get("cweid", ""))
            cwes = [f"CWE-{cwe}"] if cwe.isdigit() and int(cwe) > 0 else []
            rule_id = str(alert.get("pluginid") or alert.get("alertRef"))
            for instance in alert.get("instances") or [{}]:
                uri = instance.get("uri") or site.get("@name", "")
                finding = findings.make_finding(
                    stage=STAGE,
                    tool=TOOL,
                    source="scanner",
                    rule_id=rule_id,
                    title=alert.get("name") or alert.get("alert") or rule_id,
                    severity=severity,
                    location={"url": uri, "method": instance.get("method") or "GET"},
                    cwe=cwes,
                    description=_text(alert.get("desc")),
                    remediation=_text(alert.get("solution")),
                )
                kept = by_fingerprint.get(finding["fingerprint"])
                if kept is None or findings.SEVERITIES.index(severity) < findings.SEVERITIES.index(kept["severity"]):
                    by_fingerprint[finding["fingerprint"]] = finding
    return list(by_fingerprint.values())


def run(plan: str, out: Path, config_path: Path, image: str, runner=None) -> list[dict]:
    runner = runner or subprocess.run
    cfg = factory_config.load(config_path)
    if cfg["platform"] != "web":
        raise StageError("dast-web only runs for platform: web")
    out.mkdir(parents=True, exist_ok=True)
    work = out / "zap-work"
    work.mkdir(exist_ok=True)
    work.chmod(0o777)
    plan_file = f"{plan}.yaml"
    (work / plan_file).write_text(render_plan(plan, cfg["web"]["port"]))
    cmd = zap_cmd(image, work.resolve(), plan_file)
    print("+ " + " ".join(cmd), flush=True)
    proc = runner(cmd)
    report = work / f"{REPORT_NAME}.json"
    if proc.returncode != 0 and not report.is_file():
        raise StageError(f"ZAP failed with exit code {proc.returncode}")
    if not report.is_file():
        raise StageError("ZAP did not write a JSON report")
    for name in (f"{REPORT_NAME}.json", f"{REPORT_NAME}.html"):
        if (work / name).is_file():
            shutil.copy(work / name, out / name)
    shutil.rmtree(work, ignore_errors=True)
    try:
        results = convert(json.loads((out / f"{REPORT_NAME}.json").read_text()))
    except json.JSONDecodeError as e:
        raise StageError(f"ZAP report is not valid JSON: {e}") from e
    findings.write(out / "findings.json", results)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m factory.stages.dast_web", description="Run a ZAP automation plan against the DAST harness app")
    parser.add_argument("--plan", default="baseline", choices=PLANS)
    parser.add_argument("--out", default="out/dast-web")
    parser.add_argument("--config", default=".factory.yml")
    args = parser.parse_args(argv)
    try:
        image = tools.get_tool(tools.load_lock(), "zap").image
        results = run(args.plan, Path(args.out), Path(args.config), image)
    except (StageError, FindingsError, factory_config.ConfigError, tools.ToolError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    counts = {s: sum(1 for f in results if f["severity"] == s) for s in findings.SEVERITIES}
    print(f"{len(results)} findings: " + ", ".join(f"{n} {s}" for s, n in counts.items() if n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
