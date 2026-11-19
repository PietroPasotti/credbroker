# credbroker

Policy-gated GitHub credential broker: `gh` and `git` for credential-less hosts.

## What it is

The trusted host keeps the GitHub token. Clients run `gh`/`git` normally,
but every credentialed request is routed through the broker over HTTP.
Each request is allowed, denied, or prompted via zenity on the trusted
host according to `policy.toml`.

## Requirements

- Both hosts are on the same tailnet.
- Trusted host: Linux desktop session, `gh auth login` done, `zenity`, `uv`, systemd user session.
- Client: `uv` and `git`, and no GitHub credential (`gh auth logout` if one exists).

## Trusted host

```sh
uv tool install git+https://github.com/PietroPasotti/credbroker
credbroker init --peer <CLIENT_TAILSCALE_IP>
```

Then: if `ufw` is active, run
`sudo ufw allow in on tailscale0 from <CLIENT_TAILSCALE_IP> to any port 8765 proto tcp`.
Edit `~/.config/credbroker/policy.toml` to taste, then `systemctl --user restart credbroker`.

## Client

```sh
uv tool install git+https://github.com/PietroPasotti/credbroker
credbroker client-install --broker http://<BROKER_TAILSCALE_IP>:8765
```

Note: `~/.local/bin` must precede `/usr/bin` on PATH; it does in login shells on Ubuntu.

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

- Keys: `listen`, `allowed_peers`, `default` (`deny|ask`), `prompt_timeout`, `command_timeout`.
- `[[exec]] args, action`: a prefix after `gh`.
- `[[git]] repo` (fnmatch on `owner/name`), `op` (`fetch|push`), `refs` (push only), `action` (`allow|deny|ask`).
- First match wins. Audit log: `~/.local/state/credbroker/audit.jsonl`.

## Caveats

- Plain HTTP over WireGuard, authenticated by source IP only.
- `gh` output is buffered, so interactive `gh` (no flags, needing a TTY) won't work.
- `ask` resolves to deny on timeout or when there is no display.
- `gh api` is denied by default because it can do anything.

## Upgrade

Run `uv tool upgrade credbroker` on both hosts, then
`credbroker init --peer <ip>` on the trusted host (keeps the policy,
restarts the service).

If `uv tool install`/`upgrade` on a client does not honor git `insteadOf`
(uv's git fetch bypasses it) and fails, rerun with
`GIT_CONFIG_GLOBAL=/dev/null`. The repo is public, so the direct fetch
works.
