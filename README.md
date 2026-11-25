# credbroker

Policy-gated GitHub credential broker: `gh` and `git` for credential-less hosts.

## What it is

The trusted host keeps the GitHub token. Clients run `gh`/`git` normally,
but every credentialed request is routed through the broker over HTTP.
Each request is allowed, denied, or prompted according to `policy.toml`,
`ask` prompts default to a native desktop notification with Allow/Deny
buttons (`notify-send`), falling back to a blocking `zenity` dialog if
`notify-send` isn't installed; either can be forced explicitly. The broker
also serves a loopback-only web GUI (default `127.0.0.1:8766`) with the
same pending/history queue, a policy editor, and a toggle to suppress
desktop notifications while the page is open — useful when several `ask`
requests are in flight at once. `policy.toml` hot-reloads on save (from the
GUI or any other editor); only `listen`/`gui_listen` changes need a restart.
Every request carries an agent identity, shown next to each entry so you
know which client-side agent is asking. It's always present and never
blocks a request: an explicit `--agent NAME` on `credx` wins outright;
otherwise it's auto-derived as `{harness}:{description}`, where `harness`
is detected from known coding-agent environment markers (`OMPCODE`,
`CLAUDECODE`, `CODEX_HOME`, `GEMINI_CLI`, else `cli`) and `description`
comes from `CREDBROKER_SESSION_DESCRIPTION` (free text, e.g. `"issue
2321"`), falling back to `unknown`.

## Requirements

- Both hosts are on the same tailnet, reachable by `tailscale ip -4 <hostname>`.
- Trusted host: Linux desktop session with `gh auth login` done, `uv`,
  systemd user session, and a prompt backend: `notify-send`/
  `libnotify-bin` is used automatically if present (needs a notification
  daemon that supports actions — GNOME Shell does), otherwise `zenity` is
  used — and (if `ufw` is active) passwordless `sudo ufw` for `init` to open
  the port itself, otherwise it prints the exact `ufw allow` command to run
  manually. `$DISPLAY` is optional: without it, `ask` prompts are answered
  from the web GUI instead of a desktop toast.
- Client: `uv` and `git`, no GitHub credential (`gh auth logout` if one
  exists). `~/.local/bin` must precede `/usr/bin` on `PATH` — true in
  login shells on Ubuntu.

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

Optionally set `CREDBROKER_SESSION_DESCRIPTION` (e.g. in the shell profile
or the calling agent's environment) to a free-text description of what
this session is doing — it's folded into the auto-derived agent identity
shown in the GUI and audit log. `client-install` also writes a `git` shim
alongside the `gh` one, so plain `git fetch`/`push` over `insteadOf` carry
the same composed agent identity as an `X-Credbroker-Agent` header.

`client-install` prints `done; test with: CREDBROKER_SESSION_DESCRIPTION=me
gh repo view PietroPasotti/credbroker` — run it. A command denied by
policy exits `77` with `credx: denied by credbroker` on stderr (e.g. `gh
api` is denied by default, see Caveats).

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
  #!/bin/sh
  exec /usr/bin/git -c "http.$BROKER/git/.extraHeader=X-Credbroker-Agent: \$(credx --print-agent-header)" "\$@"
  SHIM
  chmod 755 /usr/local/bin/git
  git config --system credbroker.url "$BROKER"
  git config --system --unset-all url."$BROKER/git/".insteadOf || true
  git config --system url."$BROKER/git/".insteadOf https://github.com/
  git config --system --add url."$BROKER/git/".insteadOf git@github.com:
  git config --system --add url."$BROKER/git/".insteadOf ssh://git@github.com/
  git config --system http.postBuffer 524288000
  ```

Then `workshop refresh <name>`. The container's traffic reaches the broker
from the client host's tailnet IP, so `allowed_peers` needs no change.
Optionally set `CREDBROKER_SESSION_DESCRIPTION` in the container environment too.

## Policy reference

- Keys: `listen`, `gui_listen`, `allowed_peers`, `default` (`deny|ask`), `prompt_timeout`, `command_timeout`, `prompt_backend` (`zenity|notify-send`), `peer_names` (optional `{ip = "label"}` table, purely cosmetic in the web GUI — doesn't affect `allowed_peers` enforcement or the raw IP stored in `audit.jsonl`).
- `init` generates a policy with `default = "deny"`, `prompt_timeout = 120`,
  `command_timeout = 300`, `prompt_backend` set to whatever `--prompt-backend`
  was passed, or auto-detected (`notify-send` if installed, else `zenity`),
  `gui_listen = "127.0.0.1:8766"`, a pre-seeded `[[git]]` fetch-allow rule for
  `PietroPasotti/credbroker` itself (required so `uv tool upgrade` keeps
  working — see Upgrade below), plus starter `[[exec]]` rules for common
  read-only `gh` subcommands (`pr view/list/diff`, `issue view/list`, …). To
  switch backends later, edit `prompt_backend` in `policy.toml` directly —
  edits to `policy.toml` hot-reload within about a second, no restart needed
  unless `listen`/`gui_listen` changed.
- `[[exec]] args, action`: a prefix after `gh`.
- `[[git]] repo` (fnmatch on `owner/name`), `op` (`fetch|push`), `refs` (push only), `action` (`allow|deny|ask`).
- First match wins. Audit log: `~/.local/state/credbroker/audit.jsonl`. The
  web GUI's own in-memory history (last 500 decided requests) is separate
  and not seeded from the audit log.

## Web GUI

`gui_listen` (default `127.0.0.1:8766`, loopback only) serves the approval
queue: every pending `ask` FIFO with filter/search, per-item Approve/Deny
and an "Approve all (N)" for the currently filtered rows, a history of
decided requests, a `policy.toml` editor (saves hot-reload the running
policy; a stale-on-disk save is rejected with 409), and the "Desktop
notifications while this page is open" toggle (off by default — desktop
notifications always fire while no GUI page is open; checking it fires
both). There's no login: it's protected only by the loopback bind, a
`Host` header check, and a custom header that forces a CORS preflight
browsers never answer cross-origin. Reach it over SSH port-forwarding
(`ssh -L 8766:127.0.0.1:8766 <trusted-host>`) if you're not on the box.

## Caveats

- Plain HTTP over WireGuard, authenticated by source IP only.
- `gh` output is buffered, so interactive `gh` (no flags, needing a TTY) won't work.
- `ask` resolves to deny on timeout, or on dismissing/ignoring a desktop
  toast until it expires. A desktop prompt that can't be shown at all (no
  `$DISPLAY`, missing binary) no longer auto-denies: the request just waits
  in the web GUI until `prompt_timeout`.
- `gh api` is denied by default because it can do anything.
- `prompt_backend = "notify-send"` needs a notification daemon advertising the
  `actions` capability (check with `dbus-send --session --print-reply
  --dest=org.freedesktop.Notifications /org/freedesktop/Notifications
  org.freedesktop.Notifications.GetCapabilities`); GNOME Shell has this, some
  minimal/tiling-WM notification daemons don't — fall back to `zenity` there.
- The agent identity is informational only — a missing or malformed value
  never blocks a request; it's sanitized and shown as `unknown:unknown`
  in the GUI/audit log instead.

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
