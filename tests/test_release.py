import datetime
import json

import pytest

from factory import release

NOW = datetime.datetime(2026, 10, 31, 12, 0, 0, tzinfo=datetime.timezone.utc)
SHA = "a" * 40
OTHER = "b" * 40


def run(id_, sha=SHA, conclusion="success", status="completed", updated="2026-10-30T10:00:00Z"):
    return {"id": id_, "head_sha": sha, "conclusion": conclusion, "status": status, "updated_at": updated}


class FakeGh:
    def __init__(self, runs=None, refs=None):
        self.runs = runs or {}
        self.refs = dict(refs or {})
        self.calls = []

    def __call__(self, args):
        self.calls.append(args)
        path = args[-1] if args[0] == "api" and "-X" not in args else None
        if path and "/actions/workflows/" in path:
            wf = path.split("/workflows/")[1].split("/")[0]
            return json.dumps({"workflow_runs": self.runs.get(wf, [])})
        if path and "/git/ref/tags/" in path:
            tag = path.rsplit("/", 1)[1]
            if tag not in self.refs:
                raise release.ReleaseError("gh api failed: gh: Not Found (HTTP 404)")
            return json.dumps({"object": {"type": "commit", "sha": self.refs[tag]}})
        if "-X" in args:
            method = args[args.index("-X") + 1]
            fields = [a for a in args if "=" in a]
            if method == "POST":
                ref = next(f for f in fields if f.startswith("ref=")).split("=", 1)[1]
                self.refs[ref.removeprefix("refs/tags/")] = next(f for f in fields if f.startswith("sha=")).split("=", 1)[1]
            else:
                self.refs[args[3].rsplit("/", 1)[1]] = next(f for f in fields if f.startswith("sha=")).split("=", 1)[1]
            return "{}"
        raise AssertionError(args)


def green():
    return {"selftest.yml": [run(1)], "acceptance.yml": [run(2)]}


def test_check_passes_with_both_recent_green_runs():
    lines = release.check("o/r", SHA, NOW, gh=FakeGh(green()))
    assert [l.split(":")[0] for l in lines] == ["selftest", "acceptance"]


def test_missing_acceptance_run_fails_with_a_clear_message():
    gh = FakeGh({"selftest.yml": [run(1)], "acceptance.yml": []})
    with pytest.raises(release.ReleaseError) as e:
        release.check("o/r", SHA, NOW, gh=gh)
    assert "no successful acceptance run" in str(e.value) and SHA in str(e.value)
    assert "selftest" not in str(e.value).split(".")[0]


def test_both_missing_are_both_reported():
    with pytest.raises(release.ReleaseError) as e:
        release.check("o/r", SHA, NOW, gh=FakeGh())
    assert "selftest" in str(e.value) and "acceptance" in str(e.value)


def test_acceptance_run_older_than_seven_days_is_rejected():
    old = run(2, updated="2026-10-23T11:59:59Z")
    gh = FakeGh({"selftest.yml": [run(1)], "acceptance.yml": [old]})
    with pytest.raises(release.ReleaseError, match="acceptance"):
        release.check("o/r", SHA, NOW, gh=gh)


def test_acceptance_run_exactly_seven_days_old_is_accepted():
    gh = FakeGh({"selftest.yml": [run(1)], "acceptance.yml": [run(2, updated="2026-10-24T12:00:00Z")]})
    release.check("o/r", SHA, NOW, gh=gh)


@pytest.mark.parametrize("bad", [run(2, conclusion="failure"), run(2, conclusion="cancelled"), run(2, conclusion=None, status="in_progress"), run(2, sha=OTHER)])
def test_only_completed_successful_runs_on_the_same_commit_count(bad):
    gh = FakeGh({"selftest.yml": [run(1)], "acceptance.yml": [bad]})
    with pytest.raises(release.ReleaseError, match="acceptance"):
        release.check("o/r", SHA, NOW, gh=gh)


def test_a_later_failure_does_not_hide_an_earlier_success():
    gh = FakeGh({"selftest.yml": [run(1)], "acceptance.yml": [run(3, conclusion="failure", updated="2026-10-31T01:00:00Z"), run(2)]})
    release.check("o/r", SHA, NOW, gh=gh)


def test_confirm_must_be_exactly_v1():
    for bad in ("", "v2", "V1", "v1 "):
        with pytest.raises(release.ReleaseError):
            release.require_confirmation(bad)
    release.require_confirmation("v1")


def test_release_without_confirmation_touches_nothing():
    gh = FakeGh(green())
    with pytest.raises(release.ReleaseError):
        release.release("o/r", SHA, "yes", NOW, gh=gh)
    assert gh.calls == []


def test_failed_check_creates_no_tags():
    gh = FakeGh({"selftest.yml": [run(1)]})
    with pytest.raises(release.ReleaseError):
        release.release("o/r", SHA, "v1", NOW, gh=gh)
    assert gh.refs == {}


def test_first_release_creates_v1_and_dated_tag():
    gh = FakeGh(green())
    lines = release.release("o/r", SHA, "v1", NOW, gh=gh)
    assert gh.refs == {"v1": SHA, "v1.20261031": SHA}
    assert "moved v1 and created v1.20261031" in lines[-1]


def test_later_release_moves_v1_by_force_and_keeps_old_dated_tag():
    gh = FakeGh(green(), refs={"v1": OTHER, "v1.20261001": OTHER})
    release.release("o/r", SHA, "v1", NOW, gh=gh)
    assert gh.refs == {"v1": SHA, "v1.20261001": OTHER, "v1.20261031": SHA}
    patch = next(c for c in gh.calls if "PATCH" in c)
    assert "force=true" in patch


def test_same_day_rerun_on_the_same_commit_is_allowed():
    gh = FakeGh(green(), refs={"v1": SHA, "v1.20261031": SHA})
    release.release("o/r", SHA, "v1", NOW, gh=gh)
    assert gh.refs == {"v1": SHA, "v1.20261031": SHA}


def test_same_day_release_of_a_different_commit_is_refused():
    gh = FakeGh(green(), refs={"v1": OTHER, "v1.20261031": OTHER})
    with pytest.raises(release.ReleaseError, match="already points"):
        release.release("o/r", SHA, "v1", NOW, gh=gh)
    assert gh.refs["v1"] == OTHER


def test_api_errors_other_than_not_found_are_not_treated_as_missing():
    def gh(args):
        raise release.ReleaseError("gh api failed: HTTP 500")
    with pytest.raises(release.ReleaseError, match="500"):
        release.move_tags("o/r", SHA, NOW.date(), gh=gh)


def test_cli_reports_failure_on_stderr(monkeypatch, capsys):
    monkeypatch.setattr(release, "_gh", lambda a: json.dumps({"workflow_runs": []}))
    monkeypatch.setattr(release, "check", lambda *a, **k: (_ for _ in ()).throw(release.ReleaseError("no successful acceptance run")))
    assert release.main(["check", "--repo", "o/r", "--sha", SHA]) == 1
    assert "no successful acceptance run" in capsys.readouterr().err
