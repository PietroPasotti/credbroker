# credbroker

Policy-gated GitHub credential broker: `gh` and `git` for credential-less hosts.

## What it is

The trusted host keeps the GitHub token. Clients run `gh`/`git` normally,
but every credentialed request is routed through the broker over HTTP.
Each request is allowed, denied, or prompted on the trusted host's desktop
according to `policy.toml` — by default a native notification with Allow/Deny
buttons (`notify-send`), falling back to a blocking `zenity` dialog if
`notify-send` isn't installed; either can be forced explicitly.

## Requirements

- Both hosts are on the same tailnet, reachable by `tailscale ip -4 <hostname>`.
- Trusted host: Linux desktop session with `$DISPLAY` set, `gh auth login` done,
  `uv`, systemd user session, and a prompt backend: `notify-send`/
  `libnotify-bin` is used automatically if present (needs a notification
  daemon that supports actions — GNOME Shell does), otherwise `zenity` is
  used — and (if `ufw` is active) passwordless `sudo ufw` for `init` to open
  the port itself, otherwise it prints the exact `ufw allow` command to run
  manually.
- Client: `uv` and `git`, and no GitHub credential (`gh auth logout` if one exists).
  `~/.local/bin` must precede `/usr/bin` on `PATH` — true in login shells on Ubuntu.

## Trusted host

```sh
uv tool install git+https://github.com/PietroPasotti/credbroker
credbroker init --peer <client-hostname-or-ip> [--prompt-backend zenity]
```

`--peer` accepts a tailscale MagicDNS hostname (resolved for you) or a literal
IP; pass it more than once for multiple clients. `init` is safe to re-run: it
regenerates the systemd unit and restarts the service every time (briefly
interrupting in-flight requests), but only touches `policy.toml` when
`--force` is given — an existing policy is left alone. Its last line of
output is the exact command to run on that client next; copy it. Then edit
`~/.config/credbroker/policy.toml` to taste and `systemctl --user restart
credbroker`.

Check it's up: `systemctl --user is-active credbroker`.

## Client

```sh
uv tool install git+https://github.com/PietroPasotti/credbroker
credbroker client-install --broker http://<broker-hostname-or-ip>:8765
```

`client-install` prints `done; test with: gh repo view PietroPasotti/credbroker`
— run it. A command denied by policy exits `77` with `credx: denied by
credbroker` on stderr (e.g. `gh api` is denied by default, see Caveats).

## Workshop container

Two files plus `- name: project-credx` in `.workshop.yaml`. Remove the
`gh-cli` SDK, because its wrapper shadows the shim and it carries a token
plug.

- `.workshop/credx/sdk.yaml`:
  ```yaml
  name: credx
  ```
- `.workshop/credx/hooks/setup-base` (0755):
  ```bash
  #!/bin/bash
  set -euo pipefail
  BROKER=http://<BROKER_TAILSCALE_IP>:8765
  curl -fsS "$BROKER/client/credx" -o /usr/local/bin/credx
  chmod 755 /usr/local/bin/credx
  printf '#!/bin/sh\nexec credx -- gh "$@"\n' > /usr/local/bin/gh
  chmod 755 /usr/local/bin/gh
  git config --system credbroker.url "$BROKER"
  git config --system --unset-all url."$BROKER/git/".insteadOf || true
  git config --system url."$BROKER/git/".insteadOf https://github.com/
  git config --system --add url."$BROKER/git/".insteadOf git@github.com:
  git config --system --add url."$BROKER/git/".insteadOf ssh://git@github.com/
  git config --system http.postBuffer 524288000
  ```

Then `workshop refresh <name>`. The container's traffic reaches the broker
from the client host's tailnet IP, so `allowed_peers` needs no change.

## Policy reference

- Keys: `listen`, `allowed_peers`, `default` (`deny|ask`), `prompt_timeout`, `command_timeout`, `prompt_backend` (`zenity|notify-send`).
- `init` generates a policy with `default = "deny"`, `prompt_timeout = 120`,
  `command_timeout = 300`, `prompt_backend` set to whatever `--prompt-backend`
  was passed, or auto-detected (`notify-send` if installed, else `zenity`),
  a pre-seeded `[[git]]` fetch-allow rule for
  `PietroPasotti/credbroker` itself (required so `uv tool upgrade` keeps
  working — see Upgrade below), plus starter `[[exec]]` rules for common
  read-only `gh` subcommands (`pr view/list/diff`, `issue view/list`, …). To
  switch backends later, edit `prompt_backend` in `policy.toml` directly and
  `systemctl --user restart credbroker` — no need to re-run `init --force`.
- `[[exec]] args, action`: a prefix after `gh`.
- `[[git]] repo` (fnmatch on `owner/name`), `op` (`fetch|push`), `refs` (push only), `action` (`allow|deny|ask`).
- First match wins. Audit log: `~/.local/state/credbroker/audit.jsonl`.

## Caveats

- Plain HTTP over WireGuard, authenticated by source IP only.
- `gh` output is buffered, so interactive `gh` (no flags, needing a TTY) won't work.
- `ask` resolves to deny on timeout or when there is no display.
- `gh api` is denied by default because it can do anything.
- `prompt_backend = "notify-send"` needs a notification daemon advertising the
  `actions` capability (check with `dbus-send --session --print-reply
  --dest=org.freedesktop.Notifications /org/freedesktop/Notifications
  org.freedesktop.Notifications.GetCapabilities`); GNOME Shell has this, some
  minimal/tiling-WM notification daemons don't — fall back to `zenity` there.

## Upgrade

Run `uv tool upgrade credbroker` on both hosts, then
`credbroker init --peer <ip>` on the trusted host (keeps the policy,
restarts the service).

If `uv tool install`/`upgrade` on a client does not honor git `insteadOf`
(uv's git fetch bypasses it) and fails, rerun with
`GIT_CONFIG_GLOBAL=/dev/null`. The repo is public, so the direct fetch
works. Either way, upgrading depends on the `PietroPasotti/credbroker`
fetch-allow rule staying in `policy.toml` (see Policy reference) — don't
remove it when editing the policy to taste.
