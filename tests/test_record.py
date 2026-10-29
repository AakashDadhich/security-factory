import datetime
import json
import subprocess
from pathlib import Path

import pytest

from factory import record

FIXTURES = Path(__file__).resolve().parent / "fixtures"
NOW = datetime.datetime(2026, 10, 29, 6, 41, 56, tzinfo=datetime.timezone.utc)
COMMIT = "a" * 40


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


@pytest.fixture(autouse=True)
def bot_identity(monkeypatch):
    monkeypatch.setenv("FACTORY_BOT_NAME", "test-bot")
    monkeypatch.setenv("FACTORY_BOT_EMAIL", "bot@example.invalid")


@pytest.fixture
def remote(tmp_path):
    path = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--quiet", "--bare", str(path)], check=True)
    return str(path)


def make_artifacts(tmp_path, status="pass", sbom="sbom-old.cdx.json", name="in", run_id="100", with_report=True):
    root = tmp_path / name
    (root / "gate").mkdir(parents=True)
    (root / "setup").mkdir()
    (root / "deps-sbom").mkdir()
    gate = {"status": status, "counts": {"critical": 0, "high": 0 if status == "pass" else 2, "medium": 0, "low": 0, "info": 0},
            "blocking_fingerprints": [] if status == "pass" else ["f1", "f2"], "mode": "check", "iteration": 0, "platform": "web"}
    (root / "gate" / "gate-result.json").write_text(json.dumps(gate))
    if with_report:
        (root / "gate" / "report.json").write_text(json.dumps([{"id": "x", "suppressed": True}]))
    (root / "setup" / "run-manifest.json").write_text(json.dumps(
        {"run_id": run_id, "mode": "check", "platform": "web", "iteration": 0, "issue": 7, "repo": "o/n", "commit_sha": COMMIT}))
    (root / "deps-sbom" / "sbom.cdx.json").write_text((FIXTURES / sbom).read_text())
    return root


def write(remote, artifacts, event="push", ref="refs/heads/main", now=NOW):
    return record.write(remote, artifacts, event, ref, "main", now=now)


def clone(remote, tmp_path, name="check"):
    dest = tmp_path / name
    git(tmp_path, "clone", "--quiet", "--branch", record.BRANCH, remote, str(dest))
    return dest


def test_run_entry_name_uses_utc_timestamp_and_run_id():
    local = datetime.datetime(2026, 10, 29, 8, 41, 56, tzinfo=datetime.timezone(datetime.timedelta(hours=2)))
    assert record.run_entry_name(local, "42") == "20261029T064156Z-42.json"


def test_is_default_branch_push():
    assert record.is_default_branch_push("push", "refs/heads/main", "main")
    assert record.is_default_branch_push("push", "main", "main")
    assert not record.is_default_branch_push("pull_request", "refs/heads/main", "main")
    assert not record.is_default_branch_push("push", "refs/heads/feature", "main")


def test_first_write_creates_orphan_branch_with_run_entry_and_latest(remote, tmp_path):
    result = write(remote, make_artifacts(tmp_path))
    assert result == {"entry": "20261029T064156Z-100.json", "latest_updated": True, "attempts": 1}
    work = clone(remote, tmp_path)
    entry = json.loads((work / "runs" / "20261029T064156Z-100.json").read_text())
    assert entry == {"run_id": "100", "mode": "check", "ref": "refs/heads/main", "commit": COMMIT, "status": "pass",
                     "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                     "blocking_fingerprints": [], "iteration": 0, "issue": 7}
    assert sorted(p.name for p in (work / "latest").iterdir()) == ["findings.json", "run-manifest.json", "sbom-diff.json", "sbom.cdx.json"]
    assert git(work, "rev-list", "--max-parents=0", "HEAD").strip() == git(work, "rev-parse", "HEAD").strip()
    assert git(work, "log", "-1", "--format=%s%n%an%n%ae").splitlines() == ["chore(record): check run 100 pass", "test-bot", "bot@example.invalid"]


def test_findings_in_latest_is_the_merged_report_with_suppressed(remote, tmp_path):
    write(remote, make_artifacts(tmp_path))
    work = clone(remote, tmp_path)
    assert json.loads((work / "latest" / "findings.json").read_text()) == [{"id": "x", "suppressed": True}]


@pytest.mark.parametrize("status,event,ref", [
    ("fail", "push", "refs/heads/main"),
    ("pass", "pull_request", "refs/pull/3/merge"),
    ("pass", "push", "refs/heads/feature"),
])
def test_latest_is_not_updated_unless_default_branch_push_passes(remote, tmp_path, status, event, ref):
    write(remote, make_artifacts(tmp_path, run_id="1"))
    before = clone(remote, tmp_path, "before")
    latest_before = {p.name: p.read_text() for p in (before / "latest").iterdir()}

    artifacts = make_artifacts(tmp_path, status=status, sbom="sbom-new.cdx.json", name="in2", run_id="2")
    result = write(remote, artifacts, event=event, ref=ref, now=NOW + datetime.timedelta(minutes=1))
    assert result["latest_updated"] is False

    after = clone(remote, tmp_path, "after")
    assert {p.name: p.read_text() for p in (after / "latest").iterdir()} == latest_before
    assert sorted(p.name for p in (after / "runs").iterdir()) == ["20261029T064156Z-1.json", "20261029T064256Z-2.json"]


def test_failed_run_entry_records_blocking_fingerprints(remote, tmp_path):
    write(remote, make_artifacts(tmp_path, status="fail", with_report=False))
    work = clone(remote, tmp_path)
    entry = json.loads((work / "runs" / "20261029T064156Z-100.json").read_text())
    assert entry["status"] == "fail"
    assert entry["blocking_fingerprints"] == ["f1", "f2"]
    assert not (work / "latest").exists()


def test_sbom_diff_is_written_against_previous_latest(remote, tmp_path):
    write(remote, make_artifacts(tmp_path, sbom="sbom-old.cdx.json", run_id="1"))
    first = json.loads((clone(remote, tmp_path, "c1") / "latest" / "sbom-diff.json").read_text())
    assert first["removed"] == [] and first["changed"] == [] and len(first["added"]) == 8

    write(remote, make_artifacts(tmp_path, sbom="sbom-new.cdx.json", name="in2", run_id="2"), now=NOW + datetime.timedelta(minutes=1))
    work = clone(remote, tmp_path, "c2")
    from factory import sbom
    expected = sbom.diff(sbom.components(FIXTURES / "sbom-old.cdx.json"), sbom.components(FIXTURES / "sbom-new.cdx.json"))
    assert expected["added"] or expected["removed"] or expected["changed"]
    assert json.loads((work / "latest" / "sbom-diff.json").read_text()) == expected
    assert (work / "latest" / "sbom.cdx.json").read_text() == (FIXTURES / "sbom-new.cdx.json").read_text()


def test_push_race_is_retried_with_fresh_remote_state(remote, tmp_path, monkeypatch):
    write(remote, make_artifacts(tmp_path, run_id="1"))
    real_git = record._git
    raced = []

    def racing_git(args, cwd=None, token=None, check=True):
        if args[0] == "push" and not raced:
            raced.append(True)
            other = tmp_path / "other"
            git(tmp_path, "clone", "--quiet", "--branch", record.BRANCH, remote, str(other))
            (other / "runs").mkdir(exist_ok=True)
            (other / "runs" / "20261029T000000Z-999.json").write_text("{}\n")
            git(other, "add", "--all")
            git(other, "-c", "user.name=x", "-c", "user.email=x@example.invalid", "commit", "--quiet", "-m", "other")
            git(other, "push", "--quiet", "origin", f"HEAD:refs/heads/{record.BRANCH}")
        return real_git(args, cwd=cwd, token=token, check=check)

    monkeypatch.setattr(record, "_git", racing_git)
    result = write(remote, make_artifacts(tmp_path, name="in2", run_id="2"), now=NOW + datetime.timedelta(minutes=1))
    assert result["attempts"] == 2

    work = clone(remote, tmp_path, "final")
    assert sorted(p.name for p in (work / "runs").iterdir()) == [
        "20261029T000000Z-999.json", "20261029T064156Z-1.json", "20261029T064256Z-2.json"]


def test_push_gives_up_after_three_attempts(remote, tmp_path, monkeypatch):
    write(remote, make_artifacts(tmp_path, run_id="1"))
    real_git = record._git
    pushes = []

    def failing_git(args, cwd=None, token=None, check=True):
        if args[0] == "push":
            pushes.append(1)
            return subprocess.CompletedProcess(args, 1, "", "rejected")
        return real_git(args, cwd=cwd, token=token, check=check)

    monkeypatch.setattr(record, "_git", failing_git)
    with pytest.raises(record.RecordError, match="after 3 attempts"):
        write(remote, make_artifacts(tmp_path, name="in2", run_id="2"))
    assert len(pushes) == 3


def test_read_with_no_branch_creates_empty_dir(remote, tmp_path):
    out = tmp_path / "out"
    assert record.read(remote, out) is False
    assert out.is_dir() and list(out.iterdir()) == []


def test_read_copies_latest_and_last_ten_runs(remote, tmp_path):
    for i in range(12):
        write(remote, make_artifacts(tmp_path, name=f"in{i}", run_id=str(i)), now=NOW + datetime.timedelta(minutes=i))
    out = tmp_path / "out"
    assert record.read(remote, out) is True
    runs = sorted(p.name for p in (out / "runs").iterdir())
    assert len(runs) == 10
    assert runs[0].endswith("-2.json") and runs[-1].endswith("-11.json")
    assert (out / "latest" / "sbom.cdx.json").exists()


def test_write_requires_run_id(remote, tmp_path):
    artifacts = make_artifacts(tmp_path)
    (artifacts / "setup" / "run-manifest.json").unlink()
    with pytest.raises(record.RecordError, match="run id"):
        write(remote, artifacts)


def test_cli_write_and_read(remote, tmp_path, capsys):
    artifacts = make_artifacts(tmp_path)
    code = record.main(["write", "--repo", "o/n", "--remote", remote, "--artifacts", str(artifacts),
                        "--event", "push", "--ref", "refs/heads/main", "--default-branch", "main"])
    assert code == 0
    assert "latest updated: True" in capsys.readouterr().out
    out = tmp_path / "out"
    assert record.main(["read", "--repo", "o/n", "--remote", remote, "--out", str(out)]) == 0
    assert (out / "latest" / "findings.json").exists()


def test_cli_reports_missing_gate_result(remote, tmp_path, capsys):
    code = record.main(["write", "--repo", "o/n", "--remote", remote, "--artifacts", str(tmp_path / "none"),
                        "--event", "push", "--ref", "main", "--default-branch", "main"])
    assert code == 1
    assert "gate-result.json" in capsys.readouterr().err
