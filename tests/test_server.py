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
