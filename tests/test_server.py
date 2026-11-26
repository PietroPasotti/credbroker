"""Tests for credbroker.server: policy engine, agent validation, prompt flow,
hot-reload, and the HTTP handler.
"""
import http.client
import json
import subprocess
import threading
import time
from http.server import ThreadingHTTPServer

import pytest

from credbroker import board as board_module
from credbroker import server

FIXTURE_TOML = """
listen = "127.0.0.1:8765"
allowed_peers = ["10.0.0.1"]
default = "deny"

[[exec]]
args = ["pr", "list"]
action = "allow"

[[exec]]
args = ["api"]
action = "deny"

[[git]]
repo = "owner/repo"
op = "push"
refs = ["refs/heads/*"]
action = "allow"
"""


@pytest.fixture
def policy(tmp_path, monkeypatch):
    p = tmp_path / "p.toml"
    p.write_text(FIXTURE_TOML)
    loaded = server.load_policy(str(p))
    monkeypatch.setattr(server, "POLICY", loaded)
    return loaded


def test_match_exec_first_match_wins(policy):
    action, _via = server.match_exec(["pr", "list", "--x"])
    assert action == "allow"

    action, _via = server.match_exec(["api", "user"])
    assert action == "deny"

    assert server.match_exec(["totally", "unmatched"]) == ("deny", "default")


def test_match_git_push_refs_glob(policy):
    action, _via = server.match_git("owner/repo", "push", refs=["refs/heads/x"])
    assert action == "allow"

    # refs/tags/v1 doesn't match the refs/heads/* glob -> rule doesn't apply -> default
    action, via = server.match_git("owner/repo", "push", refs=["refs/tags/v1"])
    assert (action, via) == ("deny", "default")


def test_load_policy_rejects_unknown_top_level_key(tmp_path):
    p = tmp_path / "p.toml"
    p.write_text('listen = "x:1"\ndefault = "deny"\nbogus = 1\n')
    with pytest.raises(server.PolicyError):
        server.load_policy(str(p))


def test_load_policy_rejects_bad_action(tmp_path):
    p = tmp_path / "p.toml"
    p.write_text(
        'listen = "x:1"\ndefault = "deny"\n'
        '[[exec]]\nargs = ["pr"]\naction = "maybe"\n'
    )
    with pytest.raises(server.PolicyError):
        server.load_policy(str(p))


def test_load_policy_rejects_default_allow(tmp_path):
    p = tmp_path / "p.toml"
    p.write_text('listen = "x:1"\ndefault = "allow"\n')
    with pytest.raises(server.PolicyError):
        server.load_policy(str(p))


def test_load_policy_defaults_prompt_backend_to_notify_send_when_available(tmp_path, monkeypatch):
    monkeypatch.setattr(server.shutil, "which", lambda name: "/usr/bin/notify-send" if name == "notify-send" else None)
    p = tmp_path / "p.toml"
    p.write_text('listen = "x:1"\ndefault = "deny"\n')
    assert server.load_policy(str(p))["prompt_backend"] == "notify-send"


def test_load_policy_defaults_prompt_backend_to_zenity_when_notify_send_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(server.shutil, "which", lambda name: None)
    p = tmp_path / "p.toml"
    p.write_text('listen = "x:1"\ndefault = "deny"\n')
    assert server.load_policy(str(p))["prompt_backend"] == "zenity"


def test_load_policy_explicit_prompt_backend_overrides_autodetect(tmp_path, monkeypatch):
    monkeypatch.setattr(server.shutil, "which", lambda name: "/usr/bin/notify-send")
    p = tmp_path / "p.toml"
    p.write_text('listen = "x:1"\ndefault = "deny"\nprompt_backend = "zenity"\n')
    assert server.load_policy(str(p))["prompt_backend"] == "zenity"


def test_load_policy_rejects_bad_prompt_backend(tmp_path):
    p = tmp_path / "p.toml"
    p.write_text('listen = "x:1"\ndefault = "deny"\nprompt_backend = "espeak"\n')
    with pytest.raises(server.PolicyError):
        server.load_policy(str(p))


def test_load_policy_default_gui_listen_is_loopback_8766(tmp_path):
    p = tmp_path / "p.toml"
    p.write_text('listen = "x:1"\ndefault = "deny"\n')
    assert server.load_policy(str(p))["gui_listen"] == "127.0.0.1:8766"


@pytest.mark.parametrize("gui_listen", ["0.0.0.0:8766", "100.64.0.1:8766"])
def test_load_policy_rejects_non_loopback_gui_listen(tmp_path, gui_listen):
    p = tmp_path / "p.toml"
    p.write_text(f'listen = "x:1"\ndefault = "deny"\ngui_listen = "{gui_listen}"\n')
    with pytest.raises(server.PolicyError, match="loopback"):
        server.load_policy(str(p))


@pytest.mark.parametrize("gui_listen", ["[::1]:8766", "localhost:9000"])
def test_load_policy_accepts_loopback_gui_listen_forms(tmp_path, gui_listen):
    p = tmp_path / "p.toml"
    p.write_text(f'listen = "x:1"\ndefault = "deny"\ngui_listen = "{gui_listen}"\n')
    assert server.load_policy(str(p))["gui_listen"] == gui_listen


def test_validate_runtime_rejects_missing_prompt_backend_binary(monkeypatch):
    monkeypatch.setattr(server.shutil, "which", lambda name: None)
    with pytest.raises(server.PolicyError):
        server.validate_runtime({"prompt_backend": "zenity"})


@pytest.mark.parametrize(
    "value, expected",
    [
        ("omp:issue 2321", "omp:issue 2321"),
        ("claude-code:race condition in SlurpGrader.foo_bar()", "claude-code:race condition in SlurpGrader.foo_bar()"),
        ("a" * 160, "a" * 160),
        ("a" * 161, "a" * 160),
        (None, "unknown:unknown"),
        ("", "unknown:unknown"),
        ("   ", "unknown:unknown"),
        (123, "unknown:unknown"),
        ("line1\r\nline2", "line1line2"),
        ("bell\x07gone", "bellgone"),
        ("tab\tgone", "tabgone"),
    ],
)
def test_sanitize_agent(value, expected):
    assert server.sanitize_agent(value) == expected


def test_gh_stdin_kwargs_none_uses_devnull():
    assert server.gh_stdin_kwargs(None) == {"stdin": subprocess.DEVNULL}


def test_gh_stdin_kwargs_bytes_pipes_as_input():
    assert server.gh_stdin_kwargs(b"x") == {"input": b"x"}


def test_decide_exec_ask_prompt_includes_stdin_preview(monkeypatch):
    monkeypatch.setattr(server, "POLICY", {"exec": [], "default": "ask"})
    captured = {}

    def fake_do_prompt(summary, **kwargs):
        captured["summary"] = summary
        return True, "prompt"

    monkeypatch.setattr(server, "do_prompt", fake_do_prompt)

    action, via = server.decide_exec("1.2.3.4", "alpha", ["pr", "create"], None, stdin_preview="## test body")

    assert (action, via) == ("allow", "prompt")
    assert "stdin: ## test body" in captured["summary"]


def test_decide_exec_ask_prompt_omits_stdin_line_when_no_preview(monkeypatch):
    monkeypatch.setattr(server, "POLICY", {"exec": [], "default": "ask"})
    captured = {}

    def fake_do_prompt(summary, **kwargs):
        captured["summary"] = summary
        return True, "prompt"

    monkeypatch.setattr(server, "do_prompt", fake_do_prompt)

    server.decide_exec("1.2.3.4", "alpha", ["pr", "create"], None)

    assert "stdin:" not in captured["summary"]


def test_notify_send_argv_escapes_markup():
    argv = server._notify_send_argv("<script>&boom</script>", 30)
    assert argv[0] == "notify-send"
    assert argv[-1] == "&lt;script&gt;&amp;boom&lt;/script&gt;"


def test_parse_notify_send_true_only_on_literal_allow():
    assert server._parse_notify_send(0, "allow\n") is True
    assert server._parse_notify_send(0, "deny\n") is False


def test_parse_zenity_based_on_returncode():
    assert server._parse_zenity(0, "") is True
    assert server._parse_zenity(1, "") is False


class _FakeStdout:
    def __init__(self, text):
        self._text = text

    def read(self):
        return self._text


class _FakeProc:
    def __init__(self, returncode=0, stdout_text="allow\n"):
        self.returncode = returncode
        self.stdout = _FakeStdout(stdout_text)

    def poll(self):
        return self.returncode

    def terminate(self):
        pass

    def wait(self, timeout=None):
        pass


def test_do_prompt_dispatches_desktop_prompt_and_records_argv(monkeypatch):
    monkeypatch.setattr(server, "BOARD", board_module.Board())
    monkeypatch.setattr(server, "POLICY", {"prompt_backend": "notify-send", "prompt_timeout": 2})
    calls = []

    def fake_popen(argv, **kwargs):
        calls.append(argv)
        return _FakeProc()

    monkeypatch.setattr(server.subprocess, "Popen", fake_popen)

    result = server.do_prompt("s", peer="p", agent="a", kind="exec", detail={})

    assert result == (True, "prompt")
    assert calls and calls[0][0] == "notify-send"


def test_do_prompt_skips_desktop_prompt_while_gui_open_and_resolves_via_board(monkeypatch):
    fresh_board = board_module.Board()
    fresh_board.touch_gui()
    monkeypatch.setattr(server, "BOARD", fresh_board)
    monkeypatch.setattr(server, "POLICY", {"prompt_backend": "notify-send", "prompt_timeout": 2})

    def fail_popen(*a, **k):
        raise AssertionError("Popen must not be called while the GUI is open")

    monkeypatch.setattr(server.subprocess, "Popen", fail_popen)

    results = []

    def run():
        results.append(server.do_prompt("s", peer="p", agent="a", kind="exec", detail={}))

    t = threading.Thread(target=run)
    t.start()
    try:
        deadline = time.time() + 2
        item_id = None
        while time.time() < deadline:
            pending = fresh_board.snapshot()["pending"]
            if pending:
                item_id = pending[0]["id"]
                break
            time.sleep(0.01)
        assert item_id is not None
        assert fresh_board.resolve([item_id], "allow") == [item_id]
    finally:
        t.join(5)

    assert results == [(True, "gui")]


def test_reload_policy_updates_policy_and_clears_fetch_cache(tmp_path, monkeypatch):
    p = tmp_path / "p.toml"
    p.write_text(FIXTURE_TOML)
    monkeypatch.setattr(server, "POLICY_PATH", str(p))
    monkeypatch.setattr(server, "validate_runtime", lambda policy: None)
    monkeypatch.setattr(
        server,
        "POLICY_STATUS",
        {"path": str(p), "loaded_at": None, "error": None, "restart_required": False},
    )
    monkeypatch.setattr(server, "STARTUP_LISTEN", ("127.0.0.1:8765", server.DEFAULT_GUI_LISTEN))

    assert server.reload_policy() is None
    assert server.POLICY["default"] == "deny"

    server.fetch_cache[("x", "agent", "owner/repo")] = time.time() + 60
    p.write_text(FIXTURE_TOML.replace('default = "deny"', 'default = "ask"'))
    assert server.reload_policy() is None
    assert server.POLICY["default"] == "ask"
    assert server.fetch_cache == {}

    p.write_text("not valid toml =::")
    err = server.reload_policy()
    assert isinstance(err, str)
    assert server.POLICY["default"] == "ask"
    assert server.POLICY_STATUS["error"] == err


def test_watch_policy_reloads_when_file_changes_on_disk(tmp_path, monkeypatch):
    p = tmp_path / "p.toml"
    p.write_text(FIXTURE_TOML)
    monkeypatch.setattr(server, "POLICY_PATH", str(p))
    monkeypatch.setattr(server, "_policy_sig", server._stat_sig(str(p)))
    monkeypatch.setattr(server, "validate_runtime", lambda policy: None)
    monkeypatch.setattr(
        server,
        "POLICY_STATUS",
        {"path": str(p), "loaded_at": None, "error": None, "restart_required": False},
    )
    monkeypatch.setattr(server, "STARTUP_LISTEN", ("127.0.0.1:8765", server.DEFAULT_GUI_LISTEN))
    monkeypatch.setattr(server, "POLICY", server.load_policy(str(p)))

    stop = threading.Event()
    t = threading.Thread(target=server.watch_policy, args=(stop, 0.02))
    t.start()
    try:
        time.sleep(0.05)
        p.write_text(FIXTURE_TOML.replace('default = "deny"', 'default = "ask"'))
        deadline = time.time() + 2
        while time.time() < deadline and server.POLICY["default"] != "ask":
            time.sleep(0.02)
        assert server.POLICY["default"] == "ask"
    finally:
        stop.set()
        t.join(5)


class _StubHandler:
    headers = {}


def _pkt_line(content: bytes) -> bytes:
    length = 4 + len(content)
    return f"{length:04x}".encode() + content


def test_parse_receive_pack_refs():
    old = "0" * 40
    new = "1" * 40
    line = _pkt_line(f"{old} {new} refs/heads/main\x00 report-status side-band-64k\n".encode())
    body = line + b"0000"

    refs = server.Handler.parse_receive_pack_refs(_StubHandler(), body)

    assert refs == [{"old": old, "new": new, "refname": "refs/heads/main"}]


@pytest.fixture
def running_broker(tmp_path, monkeypatch):
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(server, "AUDIT_DIR", str(tmp_path))
    monkeypatch.setattr(server, "AUDIT_PATH", str(audit_path))
    p = tmp_path / "p.toml"
    p.write_text(FIXTURE_TOML.replace('allowed_peers = ["10.0.0.1"]', 'allowed_peers = ["127.0.0.1"]'))
    monkeypatch.setattr(server, "POLICY", server.load_policy(str(p)))

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_address, audit_path
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(5)


def test_handle_exec_without_agent_is_sanitized_to_unknown_and_audited(running_broker):
    (host, port), audit_path = running_broker
    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        conn.request(
            "POST",
            "/exec",
            body=json.dumps({"args": ["gh", "pr", "merge"]}),
            headers={"Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        resp.read()
    finally:
        conn.close()

    assert resp.status == 403  # falls through to policy: "pr merge" has no matching rule -> default deny
    last_line = audit_path.read_text().strip().splitlines()[-1]
    assert json.loads(last_line)["agent"] == "unknown:unknown"


def test_handle_exec_with_agent_denied_by_default_is_audited(running_broker):
    (host, port), audit_path = running_broker
    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        conn.request(
            "POST",
            "/exec",
            body=json.dumps({"args": ["gh", "pr", "merge"], "agent": "alpha"}),
            headers={"Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        resp.read()
    finally:
        conn.close()

    assert resp.status == 403
    last_line = audit_path.read_text().strip().splitlines()[-1]
    assert json.loads(last_line)["agent"] == "alpha"


def test_handle_git_get_info_refs_without_agent_header_is_sanitized_and_denied(running_broker):
    (host, port), _audit_path = running_broker
    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        conn.request("GET", "/git/o/r/info/refs?service=git-upload-pack")
        resp = conn.getresponse()
        resp.read()
    finally:
        conn.close()

    assert resp.status == 403



def test_parse_policy_accepts_peer_names_table():
    text = FIXTURE_TOML + '\n[peer_names]\n"10.0.0.1" = "darkmoon-vm"\n'
    policy = server.parse_policy(text, "test")
    assert policy["peer_names"] == {"10.0.0.1": "darkmoon-vm"}


def test_parse_policy_defaults_peer_names_to_empty_dict():
    policy = server.parse_policy(FIXTURE_TOML, "test")
    assert policy["peer_names"] == {}


def test_parse_policy_rejects_non_ip_peer_names_key():
    text = FIXTURE_TOML + '\n[peer_names]\nnot-an-ip = "x"\n'
    with pytest.raises(server.PolicyError):
        server.parse_policy(text, "test")


def test_parse_policy_rejects_non_string_peer_names_value():
    text = FIXTURE_TOML + '\n[peer_names]\n"10.0.0.1" = 123\n'
    with pytest.raises(server.PolicyError):
        server.parse_policy(text, "test")


def test_parse_policy_defaults_audit_max_bytes_to_50mb():
    policy = server.parse_policy(FIXTURE_TOML, "test")
    assert policy["audit_max_bytes"] == 50 * 1024 * 1024


def test_parse_policy_accepts_custom_audit_max_bytes(tmp_path):
    p = tmp_path / "p.toml"
    p.write_text('listen = "x:1"\ndefault = "deny"\naudit_max_bytes = 1000\n')
    assert server.load_policy(str(p))["audit_max_bytes"] == 1000


@pytest.mark.parametrize("value", [0, -1, "50mb", 1.5, True])
def test_parse_policy_rejects_invalid_audit_max_bytes(tmp_path, value):
    p = tmp_path / "p.toml"
    toml_value = "true" if value is True else repr(value).replace("'", '"')
    p.write_text(f'listen = "x:1"\ndefault = "deny"\naudit_max_bytes = {toml_value}\n')
    with pytest.raises(server.PolicyError, match="audit_max_bytes"):
        server.load_policy(str(p))


def test_audit_rotates_log_once_it_exceeds_max_bytes(tmp_path, monkeypatch):
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(server, "AUDIT_DIR", str(tmp_path))
    monkeypatch.setattr(server, "AUDIT_PATH", str(audit_path))
    monkeypatch.setattr(server, "POLICY", {"audit_max_bytes": 100})
    monkeypatch.setattr(server, "BOARD", board_module.Board())

    for _ in range(20):
        server.audit(peer="1.2.3.4", agent="a", kind="exec", detail={"args": ["x"]}, decision="allow", via="rule")

    backup = tmp_path / "audit.jsonl.1"
    assert backup.exists()
    assert audit_path.stat().st_size < 100 + 300


def test_audit_does_not_rotate_below_max_bytes(tmp_path, monkeypatch):
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(server, "AUDIT_DIR", str(tmp_path))
    monkeypatch.setattr(server, "AUDIT_PATH", str(audit_path))
    monkeypatch.setattr(server, "POLICY", {"audit_max_bytes": 50 * 1024 * 1024})
    monkeypatch.setattr(server, "BOARD", board_module.Board())

    server.audit(peer="1.2.3.4", agent="a", kind="exec", detail={"args": ["x"]}, decision="allow", via="rule")

    assert not (tmp_path / "audit.jsonl.1").exists()