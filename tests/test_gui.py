"""Tests for credbroker.gui.GuiHandler: host/CSRF guards and API routes."""
import hashlib
import http.client
import json
import threading

import pytest

from credbroker import board as board_module
from credbroker import gui, server

POLICY_TOML = """
listen = "127.0.0.1:8765"
allowed_peers = []
default = "deny"
"""


@pytest.fixture
def running_gui(tmp_path, monkeypatch):
    p = tmp_path / "policy.toml"
    p.write_text(POLICY_TOML)
    monkeypatch.setattr(server, "POLICY_PATH", str(p))
    monkeypatch.setattr(server, "POLICY", server.load_policy(str(p)))
    monkeypatch.setattr(server, "validate_runtime", lambda policy: None)
    monkeypatch.setattr(
        server,
        "POLICY_STATUS",
        {"path": str(p), "loaded_at": None, "error": None, "restart_required": False},
    )
    monkeypatch.setattr(server, "STARTUP_LISTEN", ("127.0.0.1:8765", "127.0.0.1:0"))
    monkeypatch.setattr(server, "BOARD", board_module.Board())

    srv = gui.make_gui_server("127.0.0.1:0")
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv.server_address, p
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(5)


def _conn(address):
    host, port = address
    return http.client.HTTPConnection(host, port, timeout=5)


def _gui_headers(extra=None):
    headers = {"X-Credbroker-GUI": "1", "Content-Type": "application/json"}
    if extra:
        headers.update(extra)
    return headers


def test_wrong_host_header_is_forbidden(running_gui):
    address, _p = running_gui
    conn = _conn(address)
    try:
        conn.request("GET", "/api/state", headers={"Host": "evil.example"})
        resp = conn.getresponse()
        resp.read()
    finally:
        conn.close()
    assert resp.status == 403


def test_resolve_without_csrf_header_is_forbidden(running_gui):
    address, _p = running_gui
    conn = _conn(address)
    try:
        conn.request(
            "POST",
            "/api/resolve",
            body=json.dumps({"ids": [], "decision": "allow"}),
            headers={"Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        resp.read()
    finally:
        conn.close()
    assert resp.status == 403


def test_put_policy_with_stale_sha_is_conflict(running_gui):
    address, _p = running_gui
    conn = _conn(address)
    try:
        conn.request(
            "PUT",
            "/api/policy",
            body=json.dumps({"text": POLICY_TOML, "sha256": "0" * 64}),
            headers=_gui_headers(),
        )
        resp = conn.getresponse()
        resp.read()
    finally:
        conn.close()
    assert resp.status == 409


def test_put_policy_with_invalid_toml_is_unprocessable_and_file_unchanged(running_gui):
    address, p = running_gui
    original_bytes = p.read_bytes()
    sha = hashlib.sha256(original_bytes).hexdigest()
    conn = _conn(address)
    try:
        conn.request(
            "PUT",
            "/api/policy",
            body=json.dumps({"text": "not valid toml =::", "sha256": sha}),
            headers=_gui_headers(),
        )
        resp = conn.getresponse()
        resp.read()
    finally:
        conn.close()
    assert resp.status == 422
    assert p.read_bytes() == original_bytes


def test_put_policy_with_valid_change_applies_and_reloads(running_gui):
    address, p = running_gui
    sha = hashlib.sha256(p.read_bytes()).hexdigest()
    new_text = POLICY_TOML.replace('default = "deny"', 'default = "ask"')
    conn = _conn(address)
    try:
        conn.request(
            "PUT",
            "/api/policy",
            body=json.dumps({"text": new_text, "sha256": sha}),
            headers=_gui_headers(),
        )
        resp = conn.getresponse()
        resp.read()
    finally:
        conn.close()
    assert resp.status == 200
    assert p.read_text() == new_text
    assert server.POLICY["default"] == "ask"


def test_get_state_marks_gui_as_open(running_gui):
    address, _p = running_gui
    assert server.BOARD.gui_open() is False
    conn = _conn(address)
    try:
        conn.request("GET", "/api/state")
        resp = conn.getresponse()
        resp.read()
    finally:
        conn.close()
    assert resp.status == 200
    assert server.BOARD.gui_open() is True


def test_settings_toggles_notify_while_open(running_gui):
    address, _p = running_gui
    conn = _conn(address)
    try:
        conn.request(
            "POST",
            "/api/settings",
            body=json.dumps({"notify_while_open": True}),
            headers=_gui_headers(),
        )
        resp = conn.getresponse()
        resp.read()
    finally:
        conn.close()
    assert resp.status == 200
    assert server.BOARD.notify_while_open is True


def test_settings_rejects_non_boolean_value(running_gui):
    address, _p = running_gui
    conn = _conn(address)
    try:
        conn.request(
            "POST",
            "/api/settings",
            body=json.dumps({"notify_while_open": "yes"}),
            headers=_gui_headers(),
        )
        resp = conn.getresponse()
        resp.read()
    finally:
        conn.close()
    assert resp.status == 400


def test_index_served_with_security_headers(running_gui):
    address, _p = running_gui
    conn = _conn(address)
    try:
        conn.request("GET", "/")
        resp = conn.getresponse()
        resp.read()
    finally:
        conn.close()
    assert resp.status == 200
    assert resp.getheader("Content-Security-Policy") == "default-src 'self'"
