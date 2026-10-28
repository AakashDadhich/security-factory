import subprocess
from types import SimpleNamespace

import pytest

from factory import platform_check
from factory.tools import ToolError


class FakeRun:
    def __init__(self, outputs):
        self.outputs = outputs
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)
        return SimpleNamespace(stdout=self.outputs.get(cmd[-1], ""), returncode=0)


def test_ensure_make_reports_existing_make(monkeypatch, capsys):
    monkeypatch.setattr(platform_check.shutil, "which", lambda name: "/usr/bin/make")
    fake = FakeRun({"--version": "GNU Make 3.81\nCopyright\n"})
    monkeypatch.setattr(platform_check.subprocess, "run", fake)

    assert platform_check.ensure_make() == "GNU Make 3.81"
    assert fake.calls == [["/usr/bin/make", "--version"]]
    assert "make present: GNU Make 3.81 at /usr/bin/make" in capsys.readouterr().out


def test_ensure_make_installs_with_brew_on_macos(monkeypatch, tmp_path):
    monkeypatch.setattr(
        platform_check.shutil, "which", lambda name: "/opt/homebrew/bin/brew" if name == "brew" else None
    )
    monkeypatch.setattr(platform_check.platform, "system", lambda: "Darwin")
    fake = FakeRun({"make": "/opt/homebrew/opt/make\n", "--version": "GNU Make 4.4.1\n"})
    monkeypatch.setattr(platform_check.subprocess, "run", fake)
    github_path = tmp_path / "github_path"
    monkeypatch.setenv("GITHUB_PATH", str(github_path))

    assert platform_check.ensure_make() == "GNU Make 4.4.1"
    assert fake.calls[0] == ["brew", "install", "make"]
    assert fake.calls[-1] == ["/opt/homebrew/opt/make/libexec/gnubin/make", "--version"]
    assert github_path.read_text().splitlines() == ["/opt/homebrew/opt/make/libexec/gnubin"]


def test_ensure_make_refuses_install_off_macos(monkeypatch):
    monkeypatch.setattr(platform_check.shutil, "which", lambda name: None)
    monkeypatch.setattr(platform_check.platform, "system", lambda: "Linux")
    with pytest.raises(ToolError, match="only supported on macOS"):
        platform_check.ensure_make()


def test_ensure_make_needs_brew(monkeypatch):
    monkeypatch.setattr(platform_check.shutil, "which", lambda name: None)
    monkeypatch.setattr(platform_check.platform, "system", lambda: "Darwin")
    with pytest.raises(ToolError, match="Homebrew is not available"):
        platform_check.ensure_make()


def test_main_returns_error_code(monkeypatch, capsys):
    def boom():
        raise subprocess.CalledProcessError(1, ["brew", "install", "make"])

    monkeypatch.setattr(platform_check, "ensure_make", boom)
    assert platform_check.main(["ensure-make"]) == 1
    assert "error:" in capsys.readouterr().err


def test_main_runs_on_this_machine():
    assert platform_check.main(["ensure-make"]) == 0
