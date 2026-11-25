"""Tests for credbroker.cli client-install and credbroker.credx.broker_url."""
import io
import os
import re
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

    git_shim = home / ".local/bin/git"
    git_shim_text = git_shim.read_text()
    assert oct(git_shim.stat().st_mode)[-3:] == "755"
    real_git_match = re.search(r"exec (\S+) -c", git_shim_text)
    assert real_git_match is not None, git_shim_text
    real_git_path = real_git_match.group(1)
    assert not real_git_path.startswith(str(home / ".local/bin")), (
        f"git shim resolved to itself: {real_git_path}"
    )
    assert "credx --print-agent-header" in git_shim_text
    assert f'http.{base}.extraHeader=X-Credbroker-Agent: $(credx --print-agent-header)"' in git_shim_text


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


def _clear_harness_env(monkeypatch):
    for var in ("OMPCODE", "CLAUDECODE", "CODEX_HOME", "GEMINI_CLI", "CREDBROKER_SESSION_DESCRIPTION"):
        monkeypatch.delenv(var, raising=False)


def test_detect_harness_prefers_ompcode(monkeypatch):
    _clear_harness_env(monkeypatch)
    monkeypatch.setenv("OMPCODE", "1")
    monkeypatch.setenv("CLAUDECODE", "1")
    assert credx.detect_harness() == "omp"


def test_detect_harness_falls_back_through_known_markers(monkeypatch):
    _clear_harness_env(monkeypatch)
    monkeypatch.setenv("CLAUDECODE", "1")
    assert credx.detect_harness() == "claude-code"
    monkeypatch.delenv("CLAUDECODE")
    monkeypatch.setenv("CODEX_HOME", "/home/x/.codex")
    assert credx.detect_harness() == "codex"
    monkeypatch.delenv("CODEX_HOME")
    monkeypatch.setenv("GEMINI_CLI", "1")
    assert credx.detect_harness() == "gemini-cli"


def test_detect_harness_defaults_to_cli(monkeypatch):
    _clear_harness_env(monkeypatch)
    assert credx.detect_harness() == "cli"


def test_compose_agent_explicit_overrides_everything(monkeypatch):
    _clear_harness_env(monkeypatch)
    monkeypatch.setenv("OMPCODE", "1")
    monkeypatch.setenv("CREDBROKER_SESSION_DESCRIPTION", "ignored")
    assert credx.compose_agent(explicit="literal-name") == "literal-name"


def test_compose_agent_uses_harness_and_description(monkeypatch):
    _clear_harness_env(monkeypatch)
    monkeypatch.setenv("OMPCODE", "1")
    monkeypatch.setenv("CREDBROKER_SESSION_DESCRIPTION", "issue 2321")
    assert credx.compose_agent() == "omp:issue 2321"


def test_compose_agent_defaults_description_to_unknown(monkeypatch):
    _clear_harness_env(monkeypatch)
    assert credx.compose_agent() == "cli:unknown"


def test_credx_print_agent_header_writes_composed_agent(monkeypatch, capsys):
    monkeypatch.delenv("OMPCODE", raising=False)
    monkeypatch.delenv("CLAUDECODE", raising=False)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.delenv("GEMINI_CLI", raising=False)
    monkeypatch.setenv("CREDBROKER_SESSION_DESCRIPTION", "testing")
    monkeypatch.setattr(sys, "argv", ["credx", "--print-agent-header"])
    with pytest.raises(SystemExit) as exc_info:
        credx.main()
    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == "cli:testing"


def test_credx_print_agent_header_respects_explicit_agent_flag(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["credx", "--agent", "pinned-name", "--print-agent-header"])
    with pytest.raises(SystemExit) as exc_info:
        credx.main()
    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == "pinned-name"
