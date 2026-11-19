#!/usr/bin/env python3
"""credx: client shim that forwards `gh` invocations to credbroker.

Usage: credx [--reason TEXT] -- gh ARGS...
Broker URL is resolved by broker_url(): env CREDBROKER_URL takes
precedence, otherwise git config credbroker.url is used.
"""
import base64
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request


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
    reason = os.environ.get("CREDX_REASON")

    if argv[:1] == ["--reason"]:
        if len(argv) < 2:
            print("credx: --reason requires a value", file=sys.stderr)
            sys.exit(125)
        reason = argv[1]
        argv = argv[2:]

    if argv[:1] != ["--"]:
        print("credx: usage: credx [--reason TEXT] -- gh ARGS...", file=sys.stderr)
        sys.exit(125)
    args = argv[1:]

    if not args:
        print("credx: usage: credx [--reason TEXT] -- gh ARGS...", file=sys.stderr)
        sys.exit(125)

    broker = broker_url()

    payload = {"args": args}
    if reason:
        payload["reason"] = reason

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
        print(f"credx: {e}", file=sys.stderr)
        sys.exit(125)
    except Exception as e:
        print(f"credx: {e}", file=sys.stderr)
        sys.exit(125)

    sys.stdout.buffer.write(base64.b64decode(body["stdout"]))
    sys.stderr.buffer.write(base64.b64decode(body["stderr"]))
    sys.exit(body["exit"])


if __name__ == "__main__":
    main()
