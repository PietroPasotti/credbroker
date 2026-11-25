#!/usr/bin/env python3
"""credx: client shim that forwards `gh` invocations to credbroker.

Usage: credx [--agent NAME] [--reason TEXT] -- gh ARGS...
       credx --print-agent-header   # print the composed agent string and exit
Broker URL is resolved by broker_url(): env CREDBROKER_URL takes
precedence, otherwise git config credbroker.url is used. The agent
identity is always present: an explicit --agent NAME wins outright;
otherwise it's "{harness}:{description}", where harness is auto-detected
from known coding-agent env markers and description comes from
CREDBROKER_SESSION_DESCRIPTION (falling back to "unknown").
"""
import base64
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

BODY_FILE_FLAGS = ("--body-file", "--notes-file", "-F")


HARNESS_MARKERS = (
    ("OMPCODE", "omp"),
    ("CLAUDECODE", "claude-code"),
    ("CODEX_HOME", "codex"),
    ("GEMINI_CLI", "gemini-cli"),
)


def detect_harness() -> str:
    for var, label in HARNESS_MARKERS:
        if os.environ.get(var):
            return label
    return "cli"


def compose_agent(explicit=None) -> str:
    if explicit:
        return explicit.strip()
    description = os.environ.get("CREDBROKER_SESSION_DESCRIPTION", "").strip() or "unknown"
    return f"{detect_harness()}:{description}"


def extract_body_stdin(args):
    """Rewrite the first --body-file/--notes-file/-F occurrence to read from
    stdin, returning (possibly-rewritten args, raw body bytes or None).

    Mirrors gh's own "-F -" contract: "-" means read local stdin (exactly what
    unshimmed gh would do); any other value is a local file path that only
    exists on this (client) host, so it must be read here and forwarded,
    because the broker runs gh on a different machine. Only the --flag value /
    --flag=value forms are recognized (no "-Fvalue" concatenated shorthand —
    not seen in practice and ambiguous with other shorthand clusters).
    """
    for i, arg in enumerate(args):
        flag = value = value_index = None
        if arg in BODY_FILE_FLAGS and i + 1 < len(args):
            flag, value, value_index = arg, args[i + 1], i + 1
        elif "=" in arg:
            head, _, tail = arg.partition("=")
            if head in BODY_FILE_FLAGS:
                flag, value, value_index = head, tail, i
        if flag is None:
            continue
        if value == "-":
            data = sys.stdin.buffer.read()
        else:
            try:
                with open(value, "rb") as f:
                    data = f.read()
            except OSError as e:
                print(f"credx: {e}", file=sys.stderr)
                sys.exit(1)
        new_args = list(args)
        if value_index != i:
            new_args[value_index] = "-"
        else:
            new_args[i] = f"{flag}=-"
        return new_args, data
    return args, None


def broker_url() -> str:
    env = os.environ.get("CREDBROKER_URL", "")
    if env:
        return env.rstrip("/")

    try:
        result = subprocess.run(
            ["git", "config", "--get", "credbroker.url"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().rstrip("/")
    except FileNotFoundError:
        pass

    print(
        "credx: no broker URL; set CREDBROKER_URL or "
        "'git config --global credbroker.url http://<broker>:8765'",
        file=sys.stderr,
    )
    sys.exit(125)


def main():
    argv = sys.argv[1:]
    agent = None
    reason = os.environ.get("CREDX_REASON")
    print_agent_header = False

    while argv[:1] and argv[0] in ("--agent", "--reason", "--print-agent-header"):
        flag = argv[0]
        if flag == "--print-agent-header":
            print_agent_header = True
            argv = argv[1:]
            continue
        if len(argv) < 2:
            print(f"credx: {flag} requires a value", file=sys.stderr)
            sys.exit(125)
        if flag == "--agent":
            agent = argv[1]
        else:
            reason = argv[1]
        argv = argv[2:]

    if print_agent_header:
        print(compose_agent(explicit=agent))
        sys.exit(0)

    if argv[:1] != ["--"]:
        print("credx: usage: credx [--agent NAME] [--reason TEXT] -- gh ARGS...", file=sys.stderr)
        sys.exit(125)
    args = argv[1:]

    if not args:
        print("credx: usage: credx [--agent NAME] [--reason TEXT] -- gh ARGS...", file=sys.stderr)
        sys.exit(125)

    agent = compose_agent(explicit=agent)

    args, stdin_bytes = extract_body_stdin(args)
    broker = broker_url()

    payload = {"args": args, "agent": agent}
    if reason:
        payload["reason"] = reason
    if stdin_bytes is not None:
        payload["stdin"] = base64.b64encode(stdin_bytes).decode()

    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{broker}/exec",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=400) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print("credx: denied by credbroker", file=sys.stderr)
            sys.exit(77)
        print(f"credx: {e}: {e.read().decode(errors='replace').strip()}", file=sys.stderr)
        sys.exit(125)
    except Exception as e:
        print(f"credx: {e}", file=sys.stderr)
        sys.exit(125)

    sys.stdout.buffer.write(base64.b64decode(body["stdout"]))
    sys.stderr.buffer.write(base64.b64decode(body["stderr"]))
    sys.exit(body["exit"])


if __name__ == "__main__":
    main()
