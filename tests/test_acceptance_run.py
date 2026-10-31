import datetime
import json

import pytest

from factory import acceptance_run as ar

T0 = datetime.datetime(2026, 10, 30, 12, 0, 0, tzinfo=datetime.timezone.utc)


def run(id_, created):
    return {"databaseId": id_, "createdAt": created}


def test_pick_run_ignores_older_runs():
    runs = [run(1, "2026-10-30T11:59:00Z"), run(2, "2026-10-30T12:00:05Z")]
    assert ar.pick_run(runs, T0)["databaseId"] == 2


def test_pick_run_takes_earliest_fresh_run():
    runs = [run(3, "2026-10-30T12:05:00Z"), run(2, "2026-10-30T12:00:05Z")]
    assert ar.pick_run(runs, T0)["databaseId"] == 2


def test_pick_run_none_when_nothing_fresh():
    assert ar.pick_run([run(1, "2026-10-30T11:00:00Z")], T0) is None
    assert ar.pick_run([], T0) is None


def test_dispatch_runs_gh_and_returns_start_time():
    calls = []
    since = ar.dispatch("o/r", "main", gh=lambda a: calls.append(a) or "", now=lambda: T0.replace(microsecond=999))
    assert since == T0
    assert calls == [["workflow", "run", "factory.yml", "--repo", "o/r", "--ref", "main"]]


def test_dispatch_passes_the_factory_ref_as_a_workflow_input():
    calls = []
    ar.dispatch("o/r", "main", "a" * 40, gh=lambda a: calls.append(a) or "", now=lambda: T0)
    assert calls == [["workflow", "run", "factory.yml", "--repo", "o/r", "--ref", "main", "-f", "factory-ref=" + "a" * 40]]


def test_main_passes_the_factory_ref_to_dispatch(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(ar, "dispatch", lambda repo, ref, factory_ref=None: seen.append((ref, factory_ref)) or T0)
    monkeypatch.setattr(ar, "find_run", lambda repo, since: 1)
    monkeypatch.setattr(ar, "wait_for", lambda repo, run_id: "success")
    assert ar.main(["--repo", "o/r", "--factory-ref", "abc"]) == 0
    assert seen == [("main", "abc")]


def test_find_run_retries_until_the_run_appears():
    answers = iter([json.dumps([]), json.dumps([run(7, "2026-10-30T12:00:09Z")])])
    sleeps = []
    assert ar.find_run("o/r", T0, gh=lambda a: next(answers), sleep=sleeps.append) == 7
    assert sleeps == [5]


def test_find_run_gives_up():
    with pytest.raises(ar.RunError, match="did not appear"):
        ar.find_run("o/r", T0, gh=lambda a: "[]", sleep=lambda s: None, attempts=3)


def test_wait_for_returns_conclusion():
    states = iter([{"status": "queued"}, {"status": "in_progress"}, {"status": "completed", "conclusion": "failure"}])
    sleeps = []
    assert ar.wait_for("o/r", 5, gh=lambda a: json.dumps(next(states)), sleep=sleeps.append, poll=30) == "failure"
    assert sleeps == [30, 30]


def test_wait_for_times_out():
    with pytest.raises(ar.RunError, match="did not finish"):
        ar.wait_for("o/r", 5, gh=lambda a: json.dumps({"status": "in_progress"}), sleep=lambda s: None, poll=30, timeout=90)


def test_main_writes_outputs(tmp_path, monkeypatch):
    monkeypatch.setattr(ar, "dispatch", lambda repo, ref, factory_ref=None: T0)
    monkeypatch.setattr(ar, "find_run", lambda repo, since: 99)
    monkeypatch.setattr(ar, "wait_for", lambda repo, run_id: "failure")
    out = tmp_path / "out"
    assert ar.main(["--repo", "o/r", "--github-output", str(out)]) == 0
    assert out.read_text() == "run_id=99\nconclusion=failure\n"


def test_main_reports_errors(monkeypatch, capsys):
    def boom(repo, ref, factory_ref=None):
        raise ar.RunError("gh workflow failed")

    monkeypatch.setattr(ar, "dispatch", boom)
    assert ar.main(["--repo", "o/r"]) == 1
    assert "gh workflow failed" in capsys.readouterr().err


def test_acceptance_workflow_is_locked_down():
    import pathlib

    import yaml

    path = pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows" / "acceptance.yml"
    wf = yaml.safe_load(path.read_text())
    assert wf["permissions"] == {}
    triggers = wf[True] if True in wf else wf["on"]
    assert set(triggers) == {"workflow_dispatch", "schedule"}
    job = wf["jobs"]["acceptance"]
    assert job["permissions"] == {"contents": "read"}
    text = path.read_text()
    assert "github.event" not in text
    assert "permission-actions: write" in text


def test_acceptance_workflow_matrix_covers_web_and_ios_and_does_not_stop_early():
    import pathlib

    import yaml

    path = pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows" / "acceptance.yml"
    job = yaml.safe_load(path.read_text())["jobs"]["acceptance"]
    assert job["strategy"]["matrix"]["target"] == ["factory-vuln-web", "factory-vuln-ios"]
    assert job["strategy"]["fail-fast"] is False
    assert job["env"]["TARGET_NAME"] == "${{ matrix.target }}"
    assert "TARGET_NAME" not in yaml.safe_load(path.read_text())["env"]


def test_acceptance_check_step_fails_when_the_matcher_fails():
    import pathlib

    import yaml

    path = pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows" / "acceptance.yml"
    steps = yaml.safe_load(path.read_text())["jobs"]["acceptance"]["steps"]
    check = next(s for s in steps if s.get("name", "").startswith("check the gate"))
    assert check["shell"] == "bash"
    assert "| tee" in check["run"]


def test_acceptance_workflow_dispatches_the_target_at_its_own_commit():
    import pathlib

    import yaml

    path = pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows" / "acceptance.yml"
    steps = yaml.safe_load(path.read_text())["jobs"]["acceptance"]["steps"]
    dispatch = next(s for s in steps if s.get("id") == "target")
    assert '--factory-ref "$GITHUB_SHA"' in dispatch["run"]
    check = next(s for s in steps if s.get("name", "").startswith("check the gate"))
    assert '--expect-factory-commit "$GITHUB_SHA"' in check["run"]
