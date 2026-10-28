import json

import pytest

from factory import manifest, passthrough
from factory.manifest import ManifestError

CONFIG = {"platform": "web", "asvs_level": None, "web": {"port": 3000, "health_path": "/health", "dockerfile": "Dockerfile"}}
ENV = {
    "GITHUB_RUN_ID": "123",
    "GITHUB_RUN_ATTEMPT": "2",
    "GITHUB_REPOSITORY": "AakashDadhich/factory-test-web",
    "GITHUB_SHA": "a" * 40,
}


def make(**overrides):
    kwargs = {"mode": "check", "factory_ref": "main", "stages": ["passthrough", "gate"], "env": ENV} | overrides
    return manifest.create(CONFIG, **kwargs)


def test_create_fills_run_fields_from_env_and_config():
    m = make()
    assert m["run_id"] == "123-2"
    assert m["repo"] == "AakashDadhich/factory-test-web"
    assert m["commit_sha"] == "a" * 40
    assert m["platform"] == "web"
    assert m["asvs_level"] == 2
    assert m["iteration"] == 0
    assert m["issue"] is None
    assert m["stages"] == [
        {"name": "setup", "status": "success"},
        {"name": "passthrough", "status": "pending"},
        {"name": "gate", "status": "pending"},
    ]
    assert set(m["tool_versions"]) == {"python", "security-factory"}


def test_create_rejects_bad_mode_and_missing_env():
    with pytest.raises(ManifestError, match="mode"):
        make(mode="deploy")
    with pytest.raises(ManifestError, match="GITHUB_SHA"):
        make(env={k: v for k, v in ENV.items() if k != "GITHUB_SHA"})


def test_write_then_load_round_trips(tmp_path):
    path = tmp_path / "setup" / "run-manifest.json"
    manifest.write(path, make())
    assert manifest.load(path) == make()


def test_load_rejects_invalid_manifest(tmp_path):
    path = tmp_path / "m.json"
    path.write_text(json.dumps(make() | {"commit_sha": "short"}))
    with pytest.raises(ManifestError, match="commit_sha"):
        manifest.load(path)
    path.write_text("{")
    with pytest.raises(ManifestError, match="not valid JSON"):
        manifest.load(path)


def test_main_create_writes_manifest(tmp_path, monkeypatch):
    cfg = tmp_path / ".factory.yml"
    cfg.write_text("platform: web\nasvs_level: 3\nweb:\n  port: 3000\n  health_path: /health\n  dockerfile: Dockerfile\n")
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    out = tmp_path / "out" / "setup" / "run-manifest.json"
    args = ["create", "--config", str(cfg), "--mode", "check", "--factory-ref", "main", "--stage", "gate", "--out", str(out)]
    assert manifest.main(args) == 0
    assert manifest.load(out)["asvs_level"] == 3


def test_main_create_fails_on_bad_config(tmp_path, capsys):
    cfg = tmp_path / ".factory.yml"
    cfg.write_text("platform: tv\n")
    args = ["create", "--config", str(cfg), "--mode", "check", "--factory-ref", "main", "--out", str(tmp_path / "m.json")]
    assert manifest.main(args) == 1
    assert "error:" in capsys.readouterr().err


def test_passthrough_reads_manifest_and_writes_empty_findings(tmp_path):
    path = tmp_path / "run-manifest.json"
    manifest.write(path, make())
    out = tmp_path / "out" / "passthrough" / "findings.json"
    assert passthrough.main(["--manifest", str(path), "--out", str(out)]) == 0
    assert json.loads(out.read_text()) == []


def test_passthrough_fails_without_valid_manifest(tmp_path):
    out = tmp_path / "findings.json"
    assert passthrough.main(["--manifest", str(tmp_path / "missing.json"), "--out", str(out)]) == 1
    assert not out.exists()
