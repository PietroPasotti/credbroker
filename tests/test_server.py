"""Tests for credbroker.server policy engine and pkt-line parsing."""
import pytest

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


def test_do_prompt_dispatches_to_configured_backend(monkeypatch):
    monkeypatch.setattr(server, "POLICY", {"prompt_backend": "notify-send", "prompt_timeout": 1})
    calls = []
    monkeypatch.setattr(server, "_prompt_zenity", lambda summary: calls.append("zenity") or True)
    monkeypatch.setattr(server, "_prompt_notify_send", lambda summary: calls.append("notify-send") or True)

    assert server.do_prompt("peer: 1.2.3.4") is True
    assert calls == ["notify-send"]


def test_prompt_notify_send_parses_allow_action(monkeypatch):
    monkeypatch.setattr(server, "POLICY", {"prompt_timeout": 1})

    class FakeResult:
        stdout = "allow\n"

    monkeypatch.setattr(server.subprocess, "run", lambda *a, **k: FakeResult())
    assert server._prompt_notify_send("peer: 1.2.3.4\ngh pr merge") is True


def test_prompt_notify_send_escapes_markup(monkeypatch):
    monkeypatch.setattr(server, "POLICY", {"prompt_timeout": 1})
    captured = {}

    class FakeResult:
        stdout = "deny\n"

    def fake_run(args, **kwargs):
        captured["body"] = args[-1]
        return FakeResult()

    monkeypatch.setattr(server.subprocess, "run", fake_run)
    server._prompt_notify_send("<script>&boom</script>")
    assert captured["body"] == "&lt;script&gt;&amp;boom&lt;/script&gt;"


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
