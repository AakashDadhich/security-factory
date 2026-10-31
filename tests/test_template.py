import re
from pathlib import Path

import yaml

from factory import config

REPO = Path(__file__).resolve().parent.parent
TEMPLATE = REPO / "templates" / "project"
STUB = TEMPLATE / ".github" / "workflows" / "factory.yml"
FILES = [".github/workflows/factory.yml", ".github/dependabot.yml", ".factory.yml", ".env.example", ".gitignore", "security/README.md", "SECURITY.md", "README.md"]


def test_every_template_file_exists_and_is_not_empty():
    for name in FILES:
        assert (TEMPLATE / name).read_text().strip(), name


def test_stub_calls_the_factory_at_v1():
    job = yaml.safe_load(STUB.read_text())["jobs"]["factory"]
    assert job["uses"] == "AakashDadhich/security-factory/.github/workflows/factory.yml@v1"
    assert job["with"]["factory-ref"] == "v1"
    assert "@main" not in STUB.read_text() and "factory-ref: main" not in STUB.read_text()


def test_stub_never_runs_in_the_template_repo_itself():
    cond = yaml.safe_load(STUB.read_text())["jobs"]["factory"]["if"]
    assert "github.repository != 'AakashDadhich/factory-project-template'" in cond
    assert re.search(r"&& \(.*factory:spec.*factory:change.*\)$", cond)


def test_gitignore_ignores_env_but_not_the_example():
    lines = (TEMPLATE / ".gitignore").read_text().split()
    assert ".env" in lines and "!.env.example" in lines


def test_env_example_holds_no_secret_like_values():
    for line in (TEMPLATE / ".env.example").read_text().splitlines():
        if line and not line.startswith("#"):
            assert re.fullmatch(r"[A-Z_]+=\d*", line), line


def test_factory_yml_examples_validate_when_uncommented(tmp_path):
    blocks = re.split(r"^# --- (\w+) ---$", (TEMPLATE / ".factory.yml").read_text(), flags=re.M)
    examples = dict(zip(blocks[1::2], blocks[2::2]))
    assert set(examples) == {"web", "macos", "ios"}
    for platform, text in examples.items():
        body = "\n".join(re.sub(r"^# ?", "", l) for l in text.splitlines() if l.startswith("#"))
        path = tmp_path / f"{platform}.yml"
        path.write_text(body)
        assert config.load(path)["platform"] == platform


def test_template_text_has_no_em_dashes():
    for name in FILES:
        assert "—" not in (TEMPLATE / name).read_text(), name
