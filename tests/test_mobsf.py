import json
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest

from factory import findings, tools
from factory.stages import mobsf as stage

FIXTURE = Path(__file__).parent / "fixtures" / "mobsf" / "report.json"
KEY = "fmobsf_test-key"


def report() -> dict:
    return json.loads(FIXTURE.read_text())


def test_severities_map_high_warning_info_and_drop_secure_and_other_sections():
    result = {f["title"]: f["severity"] for f in stage.convert(report(), "app.ipa")}
    assert result == {
        "Binary does not use ARC": "high",
        "App Transport Security is relaxed": "medium",
        "Uses the Keychain": "info",
    }


def test_converted_findings_follow_the_contract():
    result = stage.convert(report(), "app.ipa")
    findings.validate(result)
    for f in result:
        assert f["stage"] == "mobsf" and f["tool"] == "mobsf" and f["source"] == "scanner"
        assert f["location"]["path"] == "app.ipa"
        assert f["rule_id"].startswith("mobsf-")


def test_rule_ids_are_slugs_of_the_title():
    ids = {f["rule_id"] for f in stage.convert(report(), "app.ipa")}
    assert "mobsf-binary-does-not-use-arc" in ids and "mobsf-app-transport-security-is-relaxed" in ids


def test_same_title_collapses_to_one_finding_keeping_the_higher_severity():
    data = {"appsec": {"info": [{"title": "Same"}], "high": [{"title": "Same"}]}}
    result = stage.convert(data, "app.ipa")
    assert len(result) == 1 and result[0]["severity"] == "high"


def test_description_is_one_line_and_names_the_section():
    f = next(f for f in stage.convert(report(), "app.ipa") if f["rule_id"] == "mobsf-app-transport-security-is-relaxed")
    assert "\n" not in f["description"] and f["description"].endswith("(MobSF section: network)")


def test_findings_are_stable_across_runs():
    assert stage.convert(report(), "app.ipa") == stage.convert(report(), "app.ipa")


def test_entries_without_a_title_are_skipped():
    assert stage.convert({"appsec": {"high": [{"description": "x"}, "junk"]}}, "app.ipa") == []


def test_a_report_without_appsec_is_an_error():
    with pytest.raises(stage.StageError, match="appsec"):
        stage.convert({"file_name": "app.ipa"}, "app.ipa")


def test_api_key_is_random_and_prefixed():
    first, second = stage.new_api_key(), stage.new_api_key()
    assert first != second and first.startswith("fmobsf_") and len(first) > 40


def test_redact_hides_the_key():
    assert stage.redact(f"Authorization: {KEY} ok", KEY) == "Authorization: *** ok"
    assert stage.redact("nothing", "") == "nothing"


def test_run_command_passes_the_key_by_name_only():
    cmd = stage.run_cmd("factory-mobsf-1", "img@sha256:abc", 8000)
    assert cmd[:3] == ["docker", "run", "--detach"]
    assert "MOBSF_API_KEY" in cmd and not any("=" in part and "MOBSF" in part for part in cmd)
    assert "127.0.0.1:8000:8000" in cmd and cmd[-1] == "img@sha256:abc"


def test_container_name_uses_the_run_id():
    assert stage.container_name("42") == "factory-mobsf-42"


def test_multipart_body_holds_the_file_and_boundary():
    body, content_type = stage.multipart("file", "app.ipa", b"PK\x03\x04data")
    boundary = content_type.split("boundary=")[1]
    assert body.startswith(f"--{boundary}\r\n".encode()) and body.endswith(f"--{boundary}--\r\n".encode())
    assert b'name="file"; filename="app.ipa"' in body and b"PK\x03\x04data" in body


class FakeResponse:
    def __init__(self, payload: bytes):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self.payload


class FakeServer:
    def __init__(self, up_after: int = 0, scan_fails: bool = False):
        self.calls, self.up_after, self.scan_fails = [], up_after, scan_fails

    def __call__(self, request, timeout=None):
        path = request.full_url.split("127.0.0.1:8000")[1]
        self.calls.append((request.get_method(), path, dict(request.header_items()), request.data))
        if path == "/":
            if len([c for c in self.calls if c[1] == "/"]) <= self.up_after:
                raise urllib.error.URLError(ConnectionRefusedError(f"refused {KEY}"))
            return FakeResponse(b"<html/>")
        if path == "/api/v1/upload":
            return FakeResponse(json.dumps({"hash": "abc123", "scan_type": "ipa", "file_name": "app.ipa", "status": "success"}).encode())
        if path == "/api/v1/scan":
            if self.scan_fails:
                raise urllib.error.HTTPError(request.full_url, 500, "boom", {}, None)
            return FakeResponse(b"{}")
        if path == "/api/v1/report_json":
            return FakeResponse(FIXTURE.read_bytes())
        raise AssertionError(path)


def client(server: FakeServer) -> stage.Client:
    return stage.Client("http://127.0.0.1:8000", KEY, server)


def test_client_sends_the_key_in_the_authorization_header_on_every_call(tmp_path):
    server = FakeServer()
    c = client(server)
    ipa = tmp_path / "app.ipa"
    ipa.write_bytes(b"PK")
    upload = c.upload(ipa)
    c.scan(upload)
    c.report(upload["hash"])
    assert len(server.calls) == 3
    for _, _, headers, _ in server.calls:
        assert headers["Authorization"] == KEY


def test_scan_posts_the_upload_fields_and_report_posts_the_hash(tmp_path):
    server = FakeServer()
    c = client(server)
    c.scan({"hash": "abc123", "scan_type": "ipa", "file_name": "app.ipa"})
    assert server.calls[0][3] == b"scan_type=ipa&file_name=app.ipa&hash=abc123"
    assert c.report("abc123")["file_name"] == "app.ipa"
    assert server.calls[1][3] == b"hash=abc123"


def test_wait_ready_polls_until_the_server_answers():
    server = FakeServer(up_after=2)
    sleeps = []
    stage.wait_ready(client(server), timeout=60, sleep=sleeps.append)
    assert len(sleeps) == 2


def test_wait_ready_times_out():
    ticks = iter(range(0, 1000, 10))
    with pytest.raises(stage.StageError, match="did not answer"):
        stage.wait_ready(client(FakeServer(up_after=999)), timeout=30, sleep=lambda s: None, clock=lambda: next(ticks))


def test_http_errors_do_not_leak_details_and_connection_errors_are_redacted():
    server = FakeServer(scan_fails=True)
    with pytest.raises(stage.StageError) as e:
        client(server).scan({"hash": "h", "scan_type": "ipa", "file_name": "a"})
    assert str(e.value) == "MobSF /api/v1/scan returned HTTP 500"
    with pytest.raises(stage.StageError) as e:
        client(FakeServer(up_after=99))._call("/")
    assert KEY not in str(e.value)


def test_upload_without_a_hash_is_an_error(tmp_path):
    ipa = tmp_path / "app.ipa"
    ipa.write_bytes(b"PK")
    c = stage.Client("http://127.0.0.1:8000", KEY, lambda request, timeout=None: FakeResponse(b'{"status": "error"}'))
    with pytest.raises(stage.StageError, match="no file hash"):
        c.upload(ipa)


class FakeDocker:
    def __init__(self):
        self.calls = []

    def __call__(self, cmd, env=None, key="", check=True):
        self.calls.append((cmd, env, key))
        out = "log line with " + KEY if cmd[1] == "logs" else ""
        return SimpleNamespace(returncode=0, stdout=out, stderr="")


def run(tmp_path, server=None, docker=None, **kwargs):
    ipa = tmp_path / "app.ipa"
    ipa.write_bytes(b"PK")
    server = server or FakeServer()
    docker = docker or FakeDocker()
    result = stage.run(ipa, tmp_path / "out", "7", "img@sha256:abc", 8000, KEY, docker, lambda base, key: stage.Client(base, key, server), ready_timeout=30, **kwargs)
    return result, docker, server


def test_run_starts_the_container_scans_and_always_removes_it(tmp_path):
    result, docker, _ = run(tmp_path)
    assert [c[0][1] for c in docker.calls] == ["run", "rm"]
    assert docker.calls[0][1]["MOBSF_API_KEY"] == KEY
    assert docker.calls[1][0] == ["docker", "rm", "--force", "factory-mobsf-7"]
    assert (tmp_path / "out" / "mobsf-report.json").is_file()
    assert findings.load(tmp_path / "out" / "findings.json") == result
    assert len(result) == 3


def test_run_removes_the_container_and_redacts_logs_when_the_scan_fails(tmp_path, capsys):
    with pytest.raises(stage.StageError):
        run(tmp_path, server=FakeServer(scan_fails=True))
    captured = capsys.readouterr()
    assert KEY not in captured.out + captured.err
    assert "***" in captured.err


def test_run_never_prints_the_key(tmp_path, capsys):
    run(tmp_path)
    captured = capsys.readouterr()
    assert KEY not in captured.out + captured.err
    assert KEY not in (tmp_path / "out" / "mobsf-report.json").read_text()


def test_run_redacts_the_key_if_the_report_echoes_it(tmp_path):
    class Echo(FakeServer):
        def __call__(self, request, timeout=None):
            if request.full_url.endswith("/api/v1/report_json"):
                data = report()
                data["note"] = f"key {KEY}"
                return FakeResponse(json.dumps(data).encode())
            return super().__call__(request, timeout)

    run(tmp_path, server=Echo())
    assert KEY not in (tmp_path / "out" / "mobsf-report.json").read_text()


def test_missing_ipa_is_an_error(tmp_path):
    with pytest.raises(stage.StageError, match="not found"):
        stage.run(tmp_path / "nope.ipa", tmp_path / "out", docker=FakeDocker())


def test_the_lock_pins_mobsf_by_digest():
    tool = tools.get_tool(tools.load_lock(), "mobsf")
    assert tool.kind == "container"
    assert tool.image.startswith("docker.io/opensecurity/mobile-security-framework-mobsf@sha256:")


def test_cli_returns_one_on_stage_error(tmp_path, capsys):
    assert stage.main(["--ipa", str(tmp_path / "nope.ipa"), "--out", str(tmp_path / "o")]) == 1
    assert "error:" in capsys.readouterr().err
