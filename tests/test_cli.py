"""Tests for credbroker.cli client-install and credbroker.credx.broker_url."""
import io
import os
import subprocess
import sys

import pytest

from credbroker import credx


def _run_client_install(home, broker):
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["GIT_CONFIG_GLOBAL"] = str(home / "gitconfig")
    return subprocess.run(
        [sys.executable, "-m", "credbroker.cli", "client-install", "--broker", broker],
        env=env,
        capture_output=True,
        text=True,
    )


def test_client_install_idempotent(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    broker = "http://10.0.0.1:8765"
    base = broker + "/git/"

    for _ in range(2):
        result = _run_client_install(home, broker)
        assert result.returncode == 0, result.stderr

    env = dict(os.environ)
    env["HOME"] = str(home)
    env["GIT_CONFIG_GLOBAL"] = str(home / "gitconfig")

    insteadof = subprocess.run(
        ["git", "config", "--global", "--get-all", f"url.{base}.insteadOf"],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    lines = insteadof.stdout.strip().splitlines()
    assert lines == ["https://github.com/", "git@github.com:", "ssh://git@github.com/"]

    url_cfg = subprocess.run(
        ["git", "config", "--global", "--get", "credbroker.url"],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert url_cfg.stdout.strip() == broker

    shim = home / ".local/bin/gh"
    assert shim.read_text() == '#!/bin/sh\nexec credx -- gh "$@"\n'
    assert oct(shim.stat().st_mode)[-3:] == "755"


def test_broker_url_env_takes_precedence(monkeypatch):
    monkeypatch.setenv("CREDBROKER_URL", "http://env-broker:8765")
    assert credx.broker_url() == "http://env-broker:8765"


def test_broker_url_exits_125_without_env_or_git_config(monkeypatch, tmp_path):
    monkeypatch.delenv("CREDBROKER_URL", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    with pytest.raises(SystemExit) as exc_info:
        credx.broker_url()
    assert exc_info.value.code == 125


class _FakeStdin:
    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)


def test_extract_body_stdin_dash_reads_stdin(monkeypatch):
    monkeypatch.setattr(credx.sys, "stdin", _FakeStdin(b"## test body\nhello from stdin\n"))
    args = ["pr", "create", "--body-file", "-", "--title", "x"]

    new_args, data = credx.extract_body_stdin(args)

    assert new_args == args
    assert data == b"## test body\nhello from stdin\n"


def test_extract_body_stdin_reads_local_file_separate_arg(tmp_path):
    f = tmp_path / "body.md"
    f.write_bytes(b"from a file\n")
    args = ["pr", "create", "--body-file", str(f), "--title", "x"]

    new_args, data = credx.extract_body_stdin(args)

    assert new_args == ["pr", "create", "--body-file", "-", "--title", "x"]
    assert data == b"from a file\n"


def test_extract_body_stdin_reads_local_file_equals_form(tmp_path):
    f = tmp_path / "body.md"
    f.write_bytes(b"equals form\n")
    args = ["pr", "create", f"--body-file={f}", "--title", "x"]

    new_args, data = credx.extract_body_stdin(args)

    assert new_args == ["pr", "create", "--body-file=-", "--title", "x"]
    assert data == b"equals form\n"


def test_extract_body_stdin_short_flag_separate_arg(tmp_path):
    f = tmp_path / "body.md"
    f.write_bytes(b"short flag\n")
    args = ["pr", "comment", "123", "-F", str(f)]

    new_args, data = credx.extract_body_stdin(args)

    assert new_args == ["pr", "comment", "123", "-F", "-"]
    assert data == b"short flag\n"


def test_extract_body_stdin_missing_file_exits_1(tmp_path, capsys):
    missing = tmp_path / "does-not-exist.md"
    args = ["pr", "create", "--body-file", str(missing)]

    with pytest.raises(SystemExit) as exc_info:
        credx.extract_body_stdin(args)

    assert exc_info.value.code == 1
    assert str(missing) in capsys.readouterr().err


def test_extract_body_stdin_no_flag_present_is_noop():
    args = ["pr", "view", "123"]

    new_args, data = credx.extract_body_stdin(args)

    assert new_args == args
    assert data is None
