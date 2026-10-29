import hashlib
import io
import os
import re
import shutil
import tarfile
import zipfile
from pathlib import Path

import pytest

from factory import tools
from factory.tools import Tool, ToolError

PAYLOAD = b"#!/bin/sh\necho fake-tool\n"


def make_tar_gz(path: Path, member: str, data: bytes = PAYLOAD) -> Path:
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo(member)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return path


def make_zip(path: Path, member: str, data: bytes = PAYLOAD) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(member, data)
    return path


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def binary_tool(url: str, sha256: str, archive: str = "tar.gz", bin_path: str = "fake") -> Tool:
    return Tool(
        name="fake",
        version="1.0.0",
        kind="binary",
        platforms={
            "linux-x64": {"url": url, "sha256": sha256, "archive": archive, "bin": bin_path}
        },
    )


@pytest.fixture
def served(monkeypatch):
    files: dict[str, Path] = {}

    def fake_download(url, dest):
        shutil.copyfile(files[url], dest)

    monkeypatch.setattr(tools, "download", fake_download)
    return files


def write_lock(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "versions.lock"
    path.write_text(text)
    return path


def test_real_lock_parses_and_has_first_entries():
    lock = tools.load_lock()
    assert {"gitleaks", "actionlint", "zizmor"} <= set(lock)
    assert lock["gitleaks"].kind == "binary"
    assert lock["actionlint"].kind == "binary"
    assert lock["zizmor"].kind == "pipx"


def test_real_lock_binaries_have_full_checksums_and_containers_have_digests():
    for tool in tools.load_lock().values():
        if tool.kind == "binary":
            for spec in tool.platforms.values():
                assert re.fullmatch(r"[0-9a-f]{64}", spec["sha256"])
                assert spec["url"].startswith("https://")
        if tool.kind == "container":
            assert re.search(r"@sha256:[0-9a-f]{64}$", tool.image)


def test_load_lock_reads_all_kinds(tmp_path):
    lock = write_lock(
        tmp_path,
        f"""
[[tool]]
name = "bin1"
version = "2.0.0"
kind = "binary"
[tool.platforms.linux-x64]
url = "https://example.com/bin1.tar.gz"
sha256 = "{'a' * 64}"
archive = "tar.gz"
bin = "dir/bin1"
[tool.platforms.macos-arm64]
url = "https://example.com/bin1-mac.zip"
sha256 = "{'b' * 64}"
archive = "zip"
bin = "bin1"

[[tool]]
name = "py1"
version = "3.0"
kind = "pipx"

[[tool]]
name = "js1"
version = "4.0"
kind = "npm"
package = "@scope/js1"

[[tool]]
name = "img1"
version = "5.0"
kind = "container"
image = "ghcr.io/x/img1@sha256:{'c' * 64}"
""",
    )
    parsed = tools.load_lock(lock)
    assert set(parsed) == {"bin1", "py1", "js1", "img1"}
    assert set(parsed["bin1"].platforms) == {"linux-x64", "macos-arm64"}
    assert parsed["bin1"].platforms["linux-x64"]["bin"] == "dir/bin1"
    assert parsed["js1"].package == "@scope/js1"
    assert parsed["img1"].image.endswith("c" * 64)


@pytest.mark.parametrize(
    "body, message",
    [
        ('name = "t"\nversion = "1"\nkind = "brew"', "unknown kind"),
        ('name = "t"\nkind = "pipx"', "missing 'version'"),
        ('name = "t"\nversion = "1"\nkind = "container"\nimage = "nginx:latest"', "@sha256:"),
        ('name = "t"\nversion = "1"\nkind = "binary"', "no platforms"),
        (
            'name = "t"\nversion = "1"\nkind = "binary"\n[tool.platforms.linux-x64]\n'
            'url = "https://e.com/t"\nsha256 = "abc"\narchive = "none"\nbin = "t"',
            "64 lowercase hex",
        ),
        (
            'name = "t"\nversion = "1"\nkind = "binary"\n[tool.platforms.linux-x64]\n'
            f'url = "http://e.com/t"\nsha256 = "{"a" * 64}"\narchive = "none"\nbin = "t"',
            "https",
        ),
        (
            'name = "t"\nversion = "1"\nkind = "binary"\n[tool.platforms.linux-x64]\n'
            f'url = "https://e.com/t"\nsha256 = "{"a" * 64}"\narchive = "rar"\nbin = "t"',
            "archive must be",
        ),
        (
            'name = "t"\nversion = "1"\nkind = "binary"\n[tool.platforms.linux-x64]\n'
            f'url = "https://e.com/t"\nsha256 = "{"a" * 64}"\narchive = "none"',
            "missing bin",
        ),
    ],
)
def test_load_lock_rejects_invalid_entries(tmp_path, body, message):
    lock = write_lock(tmp_path, "[[tool]]\n" + body + "\n")
    with pytest.raises(ToolError, match=message):
        tools.load_lock(lock)


def test_load_lock_rejects_duplicates(tmp_path):
    entry = '[[tool]]\nname = "t"\nversion = "1"\nkind = "pipx"\n'
    with pytest.raises(ToolError, match="duplicate"):
        tools.load_lock(write_lock(tmp_path, entry + entry))


@pytest.mark.parametrize(
    "system, machine, expected",
    [
        ("Linux", "x86_64", "linux-x64"),
        ("Linux", "aarch64", "linux-arm64"),
        ("Darwin", "arm64", "macos-arm64"),
        ("Darwin", "x86_64", "macos-x64"),
    ],
)
def test_current_platform(system, machine, expected):
    assert tools.current_platform(system, machine) == expected


@pytest.mark.parametrize("system, machine", [("Windows", "AMD64"), ("Linux", "riscv64")])
def test_current_platform_unsupported(system, machine):
    with pytest.raises(ToolError, match="unsupported platform"):
        tools.current_platform(system, machine)


def test_select_platform_picks_matching_entry():
    tool = binary_tool("https://e.com/fake.tar.gz", "a" * 64)
    assert tools.select_platform(tool, "linux-x64")["url"] == "https://e.com/fake.tar.gz"


def test_select_platform_refuses_missing_platform():
    tool = binary_tool("https://e.com/fake.tar.gz", "a" * 64)
    with pytest.raises(ToolError, match="not available for macos-arm64.*linux-x64"):
        tools.select_platform(tool, "macos-arm64")


def test_install_binary_rejects_wrong_checksum(tmp_path, served, monkeypatch):
    archive = make_tar_gz(tmp_path / "fake.tar.gz", "fake")
    url = "https://example.com/fake.tar.gz"
    served[url] = archive
    github_path = tmp_path / "github_path"
    monkeypatch.setenv("GITHUB_PATH", str(github_path))
    bin_dir = tmp_path / "bin"

    wrong = "0" * 64
    with pytest.raises(ToolError, match=f"checksum mismatch.*expected {wrong}, got {sha(archive)}"):
        tools.install_binary(binary_tool(url, wrong), "linux-x64", bin_dir)

    assert not (bin_dir / "fake").exists()
    assert not github_path.exists()


def test_install_binary_verifies_before_extracting(tmp_path, served, monkeypatch):
    url = "https://example.com/fake.tar.gz"
    served[url] = make_tar_gz(tmp_path / "fake.tar.gz", "fake")
    extracted = []
    monkeypatch.setattr(tools, "_extract_member", lambda *a: extracted.append(a))

    with pytest.raises(ToolError, match="checksum mismatch"):
        tools.install_binary(binary_tool(url, "f" * 64), "linux-x64", tmp_path / "bin")
    assert extracted == []


@pytest.mark.parametrize(
    "archive, bin_path, builder",
    [
        ("tar.gz", "pkg/fake", lambda p, m: make_tar_gz(p, m)),
        ("zip", "fake", lambda p, m: make_zip(p, m)),
        ("none", "fake", lambda p, m: (p.write_bytes(PAYLOAD), p)[1]),
    ],
)
def test_install_binary_installs_on_matching_checksum(
    tmp_path, served, monkeypatch, archive, bin_path, builder
):
    source = builder(tmp_path / "download", bin_path)
    url = "https://example.com/download"
    served[url] = source
    github_path = tmp_path / "github_path"
    monkeypatch.setenv("GITHUB_PATH", str(github_path))
    bin_dir = tmp_path / "bin"
    tool = binary_tool(url, sha(source), archive, bin_path)

    target = tools.install_binary(tool, "linux-x64", bin_dir)
    tools.install_binary(tool, "linux-x64", bin_dir)

    assert target == bin_dir / "fake"
    assert target.read_bytes() == PAYLOAD
    assert os.access(target, os.X_OK)
    assert github_path.read_text().splitlines() == [str(bin_dir)]


def test_install_binary_missing_member(tmp_path, served):
    source = make_tar_gz(tmp_path / "fake.tar.gz", "other")
    url = "https://example.com/fake.tar.gz"
    served[url] = source
    with pytest.raises(ToolError, match="'fake' not found"):
        tools.install_binary(binary_tool(url, sha(source)), "linux-x64", tmp_path / "bin")


def test_install_binary_skips_github_path_when_unset(tmp_path, served, monkeypatch):
    monkeypatch.delenv("GITHUB_PATH", raising=False)
    source = make_tar_gz(tmp_path / "fake.tar.gz", "fake")
    url = "https://example.com/fake.tar.gz"
    served[url] = source
    target = tools.install_binary(binary_tool(url, sha(source)), "linux-x64", tmp_path / "bin")
    assert target.exists()


def test_download_refuses_plain_http(tmp_path):
    with pytest.raises(ToolError, match="non-https"):
        tools.download("http://example.com/x", tmp_path / "x")


@pytest.mark.parametrize(
    "tool, expected",
    [
        (Tool("zizmor", "1.2.3", "pipx"), ["pipx", "install", "--force", "zizmor==1.2.3"]),
        (Tool("lint", "4.5.6", "npm", package="@s/lint"), ["npm", "install", "-g", "@s/lint@4.5.6"]),
        (
            Tool("zap", "2.0", "container", image="ghcr.io/z/zap@sha256:" + "d" * 64),
            ["docker", "pull", "ghcr.io/z/zap@sha256:" + "d" * 64],
        ),
    ],
)
def test_install_non_binary_kinds(monkeypatch, tool, expected):
    calls = []
    monkeypatch.setattr(tools, "_run", calls.append)
    tools.install(tool, "")
    assert calls == [expected]


def test_run_raises_on_failure():
    with pytest.raises(ToolError, match="exit code 3"):
        tools._run(["sh", "-c", "exit 3"])


def test_main_unknown_tool(capsys):
    assert tools.main(["install", "no-such-tool"]) == 1
    err = capsys.readouterr().err
    assert "unknown tool 'no-such-tool'" in err
    assert "gitleaks" in err


def test_main_unsupported_platform(monkeypatch, capsys):
    monkeypatch.setattr(tools.platform, "system", lambda: "Windows")
    assert tools.main(["install", "gitleaks"]) == 1
    assert "unsupported platform" in capsys.readouterr().err


def test_main_checksum_mismatch_exits_non_zero(tmp_path, served, monkeypatch, capsys):
    archive = make_tar_gz(tmp_path / "fake.tar.gz", "fake")
    served["https://example.com/fake.tar.gz"] = archive
    lock = write_lock(
        tmp_path,
        f"""
[[tool]]
name = "fake"
version = "1.0.0"
kind = "binary"
[tool.platforms.linux-x64]
url = "https://example.com/fake.tar.gz"
sha256 = "{'0' * 64}"
archive = "tar.gz"
bin = "fake"
""",
    )
    monkeypatch.setattr(tools, "LOCK_PATH", lock)
    monkeypatch.setattr(tools, "BIN_DIR", tmp_path / "bin")
    monkeypatch.setattr(tools, "current_platform", lambda: "linux-x64")

    assert tools.main(["install", "fake"]) == 1
    assert "checksum mismatch" in capsys.readouterr().err
    assert not (tmp_path / "bin" / "fake").exists()


def test_main_list(capsys):
    assert tools.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "gitleaks\t8.30.1\tbinary\tlinux-x64" in out
    assert "zizmor\t1.31.1\tpipx\tzizmor" in out


GIT_SHA = "a" * 40


def test_real_lock_has_semgrep_and_pinned_rules():
    lock = tools.load_lock()
    assert lock["semgrep"].kind == "pipx"
    assert lock["semgrep-rules"].kind == "git"
    assert len(lock["semgrep-rules"].commit) == 40


@pytest.mark.parametrize(
    "body, message",
    [
        (f'repo = "http://example.com/r"\ncommit = "{GIT_SHA}"', "must use https"),
        ('repo = "https://example.com/r"\ncommit = "main"', "40 character"),
        (f'repo = "https://example.com/r"\ncommit = "{GIT_SHA.upper()}"', "40 character"),
        (f'commit = "{GIT_SHA}"', "must use https"),
    ],
)
def test_git_entry_rejects_bad_repo_or_commit(tmp_path, body, message):
    lock = write_lock(tmp_path, f'[[tool]]\nname = "g"\nversion = "1"\nkind = "git"\n{body}\n')
    with pytest.raises(ToolError, match=message):
        tools.load_lock(lock)


def test_git_entry_parses(tmp_path):
    lock = write_lock(tmp_path, f'[[tool]]\nname = "g"\nversion = "1"\nkind = "git"\nrepo = "https://example.com/r"\ncommit = "{GIT_SHA}"\n')
    tool = tools.load_lock(lock)["g"]
    assert (tool.repo, tool.commit) == ("https://example.com/r", GIT_SHA)
    assert tools.describe(tool) == f"g\t1\tgit\thttps://example.com/r@{GIT_SHA}"


def test_install_git_fetches_the_exact_commit_shallowly(tmp_path):
    tool = Tool("g", "1", "git", repo="https://example.com/r", commit=GIT_SHA)
    calls = []
    dest = tmp_path / "g"
    dest.mkdir()
    (dest / "stale").write_text("old")
    result = tools.install_git(tool, dest, run=calls.append)
    assert result == dest
    assert not (dest / "stale").exists()
    flat = [" ".join(c) for c in calls]
    assert any("fetch" in c and "--depth 1 https://example.com/r " + GIT_SHA in c for c in flat)
    assert any("checkout" in c and "FETCH_HEAD" in c for c in flat)


def test_install_dispatches_git(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(tools, "install_git", lambda tool: seen.append(tool.name) or tmp_path)
    tools.install(Tool("g", "1", "git", repo="https://example.com/r", commit=GIT_SHA), "")
    assert seen == ["g"]


HASH = "--hash=sha256:" + "e" * 64


def venv_lock(tmp_path, monkeypatch, requirements_text, extra=""):
    monkeypatch.setattr(tools, "FACTORY_ROOT", tmp_path)
    (tmp_path / "reqs.txt").write_text(requirements_text)
    return write_lock(tmp_path, f'[[tool]]\nname = "v"\nversion = "1.0"\nkind = "venv"\nrequirements = "reqs.txt"\n{extra}')


def test_real_lock_pins_pytm_in_a_hashed_venv():
    tool = tools.load_lock()["pytm"]
    assert (tool.kind, tool.version, tool.requirements) == ("venv", "1.4.0", "tools/pytm/requirements.txt")
    assert tools.describe(tool) == "pytm\t1.4.0\tvenv\ttools/pytm/requirements.txt"


def test_venv_entry_parses(tmp_path, monkeypatch):
    lock = venv_lock(tmp_path, monkeypatch, f"# pinned\nv==1.0 {HASH}\ndep==2 {HASH}\n")
    assert tools.load_lock(lock)["v"].requirements == "reqs.txt"


@pytest.mark.parametrize(
    "requirements, extra, message",
    [
        (f"v==1.0 {HASH}\ndep==2\n", "", "without a sha256 hash: dep==2"),
        (f"v==1.1 {HASH}\n", "", "does not pin v==1.0"),
        (f"v==1.0 {HASH}\n", 'package = "other"\n', "does not pin other==1.0"),
    ],
)
def test_venv_entry_rejects_unhashed_or_unpinned(tmp_path, monkeypatch, requirements, extra, message):
    lock = venv_lock(tmp_path, monkeypatch, requirements, extra)
    with pytest.raises(ToolError, match=message):
        tools.load_lock(lock)


@pytest.mark.parametrize("path", ["", "/etc/reqs.txt", "../reqs.txt", "missing.txt"])
def test_venv_entry_rejects_bad_requirements_path(tmp_path, monkeypatch, path):
    monkeypatch.setattr(tools, "FACTORY_ROOT", tmp_path)
    lock = write_lock(tmp_path, f'[[tool]]\nname = "v"\nversion = "1"\nkind = "venv"\nrequirements = "{path}"\n')
    with pytest.raises(ToolError, match="requirements"):
        tools.load_lock(lock)


def test_install_venv_requires_hashes_and_binary_wheels(tmp_path):
    calls = []
    python = tools.install_venv(Tool("v", "1", "venv", requirements="tools/v/reqs.txt"), tmp_path, run=calls.append)
    assert python == tmp_path / "v" / "bin" / "python"
    assert calls[0][1:] == ["-m", "venv", "--clear", str(tmp_path / "v")]
    pip = calls[1]
    assert pip[0] == str(python)
    for flag in ("--require-hashes", "--no-deps", "--only-binary"):
        assert flag in pip
    assert pip[-1] == str(tools.FACTORY_ROOT / "tools" / "v" / "reqs.txt")


def test_install_dispatches_venv(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(tools, "install_venv", lambda tool: seen.append(tool.name) or tmp_path / "v" / "bin" / "python")
    tools.install(Tool("v", "1", "venv", requirements="r.txt"), "")
    assert seen == ["v"]
