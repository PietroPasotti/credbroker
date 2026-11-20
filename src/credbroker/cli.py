#!/usr/bin/env python3
"""credbroker: CLI entry point with serve/init/client-install subcommands."""
import argparse
import ipaddress
import json
import os
import shutil
import subprocess
import sys

from credbroker import server

DEFAULT_POLICY_PATH = os.path.expanduser("~/.config/credbroker/policy.toml")
UNIT_PATH = os.path.expanduser("~/.config/systemd/user/credbroker.service")
TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "policy.template.toml")

UNIT_TEMPLATE = """[Unit]
Description=credbroker policy-gated credential broker

[Service]
ExecStart={exe} serve
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
"""


def fail(msg: str) -> None:
    print(f"credbroker: {msg}", file=sys.stderr)
    sys.exit(1)


def _resolve_peer(value: str) -> str:
    """Accept a literal IP or a tailscale hostname; resolve hostnames via `tailscale ip`."""
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    result = subprocess.run(["tailscale", "ip", "-4", value], capture_output=True, text=True)
    if result.returncode != 0 or not result.stdout.strip():
        fail(f"could not resolve tailscale peer {value!r}; pass a literal IP or a reachable tailnet hostname")
    return result.stdout.splitlines()[0].strip()


def cmd_serve(args: argparse.Namespace) -> None:
    path = args.policy or os.environ.get("CREDBROKER_POLICY") or DEFAULT_POLICY_PATH
    try:
        server.serve(path)
    except server.PolicyError as e:
        print(f"credbroker: {e}", file=sys.stderr)
        sys.exit(2)


def cmd_init(args: argparse.Namespace) -> None:
    # 1. Preflight
    if shutil.which("gh") is None or subprocess.run(
        ["gh", "auth", "token"], capture_output=True
    ).returncode != 0:
        fail("gh is not authenticated; run 'gh auth login' first")
    if shutil.which(args.prompt_backend) is None:
        hint = "apt install zenity" if args.prompt_backend == "zenity" else "apt install libnotify-bin"
        fail(f"{args.prompt_backend} not found; install it ({hint})")
    if shutil.which("systemctl") is None:
        fail("systemctl not found")

    # 2. Resolve listen
    listen = args.listen
    if not listen:
        result = subprocess.run(["tailscale", "ip", "-4"], capture_output=True, text=True)
        if result.returncode != 0 or not result.stdout.strip():
            fail("could not detect tailscale IP; pass --listen HOST:PORT")
        ip = result.stdout.splitlines()[0].strip()
        listen = f"{ip}:8765"

    # 3. Policy
    policy_path = DEFAULT_POLICY_PATH
    peers = [_resolve_peer(p) for p in args.peer]
    if os.path.exists(policy_path) and not args.force:
        print(f"policy exists, keeping {policy_path}")
        print(
            "note: pass --force to regenerate from the template "
            f"(defaults: default=deny, prompt_timeout=120s, command_timeout=300s, "
            f"prompt_backend={args.prompt_backend})"
        )
    else:
        os.makedirs(os.path.dirname(policy_path), exist_ok=True)
        with open(TEMPLATE_PATH) as f:
            template = f.read()
        content = template.format(
            listen=listen,
            peers=", ".join(json.dumps(p) for p in peers),
            prompt_backend=args.prompt_backend,
        )
        with open(policy_path, "w") as f:
            f.write(content)
        print(
            f"wrote {policy_path} (default=deny, prompt_timeout=120s, "
            f"command_timeout=300s, prompt_backend={args.prompt_backend})"
        )

    # 4. Unit file
    exe = shutil.which("credbroker") or os.path.abspath(sys.argv[0])
    os.makedirs(os.path.dirname(UNIT_PATH), exist_ok=True)
    with open(UNIT_PATH, "w") as f:
        f.write(UNIT_TEMPLATE.format(exe=exe))
    print(f"wrote {UNIT_PATH}")

    # 5. ufw: allow each peer through the tailscale interface, best-effort
    ufw_active = shutil.which("ufw") and subprocess.run(
        ["systemctl", "is-active", "--quiet", "ufw"]
    ).returncode == 0
    if ufw_active:
        port = listen.rsplit(":", 1)[-1]
        for peer in peers:
            rule = subprocess.run(
                [
                    "sudo", "-n", "ufw", "allow", "in", "on", "tailscale0",
                    "from", peer, "to", "any", "port", port, "proto", "tcp",
                ],
                capture_output=True, text=True,
            )
            if rule.returncode == 0:
                print(f"ufw: allowed {peer} -> port {port}/tcp")
            else:
                print(
                    f"warning: ufw is active but could not add the rule without a password; "
                    f"run manually: sudo ufw allow in on tailscale0 from {peer} to any port {port} proto tcp"
                )

    # 6. systemd
    was_active = subprocess.run(["systemctl", "--user", "is-active", "--quiet", "credbroker"]).returncode == 0
    if was_active:
        print("note: credbroker is already running; restarting it now (brief interruption to in-flight requests)")
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "--user", "enable", "credbroker"], check=True)
    subprocess.run(["systemctl", "--user", "restart", "credbroker"], check=True)
    print("credbroker service enabled and restarted")

    # 7. DISPLAY check
    env_result = subprocess.run(
        ["systemctl", "--user", "show-environment"], capture_output=True, text=True
    )
    if not any(line.startswith("DISPLAY=") for line in env_result.stdout.splitlines()):
        print("warning: systemd user manager has no DISPLAY; ask prompts will auto-deny")

    # 8. Client command
    print(f"on the client run: credbroker client-install --broker http://{listen}")


def _git_config(scope_args, *rest, check=False):
    return subprocess.run(["git", "config", *scope_args, *rest], capture_output=True, text=True, check=check)


def cmd_client_install(args: argparse.Namespace) -> None:
    url = args.broker.rstrip("/")
    base = url + "/git/"
    scope_args = ["--system"] if args.system else ["--global"]
    shimdir = "/usr/local/bin" if args.system else os.path.expanduser("~/.local/bin")

    _git_config(scope_args, "credbroker.url", url, check=True)

    unset = _git_config(scope_args, "--unset-all", f"url.{base}.insteadOf")
    if unset.returncode not in (0, 5):
        fail(f"git config --unset-all failed: {unset.stderr.strip()}")
    _git_config(scope_args, "url." + base + ".insteadOf", "https://github.com/", check=True)
    _git_config(scope_args, "--add", "url." + base + ".insteadOf", "git@github.com:", check=True)
    _git_config(scope_args, "--add", "url." + base + ".insteadOf", "ssh://git@github.com/", check=True)

    _git_config(scope_args, "http.postBuffer", "524288000", check=True)

    os.makedirs(shimdir, exist_ok=True)
    gh_shim_path = os.path.join(shimdir, "gh")
    with open(gh_shim_path, "w") as f:
        f.write('#!/bin/sh\nexec credx -- gh "$@"\n')
    os.chmod(gh_shim_path, 0o755)
    print(f"wrote {gh_shim_path}")

    if shutil.which("credx") is None:
        print("warning: credx not on PATH; the gh shim needs it")

    print("done; test with: gh repo view PietroPasotti/credbroker")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="credbroker")
    sub = parser.add_subparsers(dest="command", required=True)

    p_serve = sub.add_parser("serve", help="run the broker server")
    p_serve.add_argument("--policy", default=None)
    p_serve.set_defaults(func=cmd_serve)

    p_init = sub.add_parser("init", help="set up the trusted host")
    p_init.add_argument("--peer", action="append", required=True)
    p_init.add_argument("--listen", default=None)
    p_init.add_argument("--force", action="store_true")
    p_init.add_argument(
        "--prompt-backend",
        choices=["zenity", "notify-send"],
        default="zenity",
        help="how to ask: a blocking zenity dialog, or a native desktop notification with Allow/Deny actions",
    )
    p_init.set_defaults(func=cmd_init)

    p_client = sub.add_parser("client-install", help="set up a client host")
    p_client.add_argument("--broker", required=True)
    p_client.add_argument("--system", action="store_true")
    p_client.set_defaults(func=cmd_client_install)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
