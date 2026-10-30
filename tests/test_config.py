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


AUTH = """\
  auth:
    type: json
    login_url: /login
    username_field: username
    password_field: password
    username_env: TEST_USERNAME
    password_env: TEST_PASSWORD
    logged_in_regex: 'ok'
"""


def test_web_auth_block_is_accepted(tmp_path):
    cfg = config.load(write(tmp_path, WEB + AUTH))
    assert cfg["web"]["auth"]["type"] == "json"


def test_web_auth_is_optional_and_does_not_change_outputs(tmp_path):
    values = config.outputs(config.load(write(tmp_path, WEB + AUTH)))
    assert values == {"platform": "web", "asvs_level": "2", "openapi": "openapi.yaml"}


@pytest.mark.parametrize("key", ["type", "login_url", "username_field", "password_field", "username_env", "password_env"])
def test_web_auth_rejects_a_missing_required_key(tmp_path, key):
    text = "".join(line for line in (WEB + AUTH).splitlines(keepends=True) if not line.startswith(f"    {key}:"))
    with pytest.raises(ConfigError, match="web/auth"):
        config.load(write(tmp_path, text))


def test_web_auth_needs_a_regex(tmp_path):
    text = (WEB + AUTH).replace("    logged_in_regex: 'ok'\n", "")
    with pytest.raises(ConfigError, match="web/auth"):
        config.load(write(tmp_path, text))


@pytest.mark.parametrize(
    "old, new",
    [
        ("type: json", "type: basic"),
        ("login_url: /login", "login_url: login"),
        ("login_url: /login", "login_url: //evil.test/login"),
        ("login_url: /login", "login_url: http://evil.test/login"),
        ("TEST_USERNAME", "test_username"),
        ("TEST_PASSWORD", "TEST PASSWORD"),
        ("username_field: username", "username_field: 'a=b&c'"),
    ],
)
def test_web_auth_rejects_bad_values(tmp_path, old, new):
    with pytest.raises(ConfigError, match="web/auth"):
        config.load(write(tmp_path, (WEB + AUTH).replace(old, new)))


def test_web_auth_rejects_extra_keys(tmp_path):
    with pytest.raises(ConfigError, match="web/auth"):
        config.load(write(tmp_path, WEB + AUTH + "    password: hunter2\n"))
