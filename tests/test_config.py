import pytest

from factory import config
from factory.config import ConfigError

WEB = """\
platform: web
asvs_level: null
web:
  port: 3000
  health_path: /health
  openapi: openapi.yaml
  dockerfile: Dockerfile
"""

APPLE = """\
platform: ios
asvs_level: 3
apple:
  project_spec: project.yml
  scheme: App
"""


def write(tmp_path, text):
    path = tmp_path / ".factory.yml"
    path.write_text(text)
    return path


def test_web_config_outputs_default_asvs_level_and_openapi(tmp_path):
    values = config.outputs(config.load(write(tmp_path, WEB)))
    assert values == {"platform": "web", "asvs_level": "2", "openapi": "openapi.yaml"}


def test_apple_config_keeps_explicit_level_and_has_no_openapi(tmp_path):
    values = config.outputs(config.load(write(tmp_path, APPLE)))
    assert values == {"platform": "ios", "asvs_level": "3", "openapi": ""}


def test_absent_asvs_level_and_openapi_are_allowed(tmp_path):
    text = "platform: web\nweb:\n  port: 8080\n  health_path: /\n  dockerfile: docker/Dockerfile\n"
    assert config.outputs(config.load(write(tmp_path, text))) == {"platform": "web", "asvs_level": "2", "openapi": ""}


@pytest.mark.parametrize(
    "text, message",
    [
        (WEB.replace("platform: web", "platform: android"), "platform"),
        (WEB.replace("asvs_level: null", "asvs_level: 4"), "asvs_level"),
        (WEB.replace("asvs_level: null", "asvs_level: '2'"), "asvs_level"),
        ("platform: web\n", "'web' is a required property"),
        ("platform: macos\n", "'apple' is a required property"),
        (WEB.replace("port: 3000", "port: 70000"), "web/port"),
        (WEB.replace("health_path: /health", "health_path: health"), "web/health_path"),
        (WEB.replace("openapi.yaml", "../secrets/openapi.yaml"), "web/openapi"),
        (WEB.replace("openapi.yaml", "/etc/passwd"), "web/openapi"),
        (WEB.replace("openapi.yaml", '"a\\nb=c"'), "web/openapi"),
        (WEB + "extra: true\n", "extra"),
        (APPLE.replace("scheme: App", "scheme: 'App;rm'"), "apple/scheme"),
        ("- platform: web\n", "<root>"),
        ("", "<root>"),
    ],
)
def test_invalid_configs_are_rejected(tmp_path, text, message):
    with pytest.raises(ConfigError, match="does not match") as excinfo:
        config.load(write(tmp_path, text))
    assert message in str(excinfo.value)


def test_bad_yaml_and_missing_file_raise_config_error(tmp_path):
    with pytest.raises(ConfigError, match="not valid YAML"):
        config.load(write(tmp_path, "platform: [web\n"))
    with pytest.raises(ConfigError, match="No such file"):
        config.load(tmp_path / "missing.yml")


def test_main_appends_outputs_to_github_output(tmp_path, monkeypatch):
    out = tmp_path / "github_output"
    out.write_text("earlier=1\n")
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    assert config.main(["--path", str(write(tmp_path, WEB))]) == 0
    assert out.read_text() == "earlier=1\nplatform=web\nasvs_level=2\nopenapi=openapi.yaml\n"


def test_main_prints_outputs_without_github_output(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    assert config.main(["--path", str(write(tmp_path, APPLE))]) == 0
    assert capsys.readouterr().out == "platform=ios\nasvs_level=3\nopenapi=\n"


def test_main_invalid_config_exits_1(tmp_path, capsys):
    assert config.main(["--path", str(write(tmp_path, "platform: tv\n"))]) == 1
    assert "error:" in capsys.readouterr().err
