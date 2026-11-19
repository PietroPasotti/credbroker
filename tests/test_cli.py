"""Tests for credbroker.cli client-install and credbroker.credx.broker_url."""
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
