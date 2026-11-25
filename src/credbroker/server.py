#!/usr/bin/env python3
"""credbroker: policy-gated credential broker for gh / git over HTTP.

Runs on a trusted host. Callers never see a GitHub credential; this
process holds it and decides per-request whether to allow, deny, or
prompt on the desktop (notify-send by default, or zenity).
"""
import base64
import fnmatch
import gzip
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import tomllib
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOME = os.path.expanduser("~")
AUDIT_DIR = os.path.join(HOME, ".local/state/credbroker")
AUDIT_PATH = os.path.join(AUDIT_DIR, "audit.jsonl")
CREDX_PATH = os.path.join(os.path.dirname(__file__), "credx.py")

ALLOWED_ACTIONS = {"allow", "deny", "ask"}
ALLOWED_TOP_KEYS = {"listen", "allowed_peers", "default", "prompt_timeout", "command_timeout", "prompt_backend", "exec", "git"}
ALLOWED_EXEC_KEYS = {"args", "action"}
ALLOWED_GIT_KEYS = {"repo", "op", "refs", "action"}

# GitHub caps PR/issue bodies at 65536 chars (<=262144 bytes of UTF-8); base64
# inflates raw bytes by 4/3, plus JSON wrapper overhead — give real bodies room.
EXEC_REQUEST_LIMIT = 400_000

prompt_lock = threading.Lock()
fetch_cache = {}  # (peer, repo) -> expiry epoch
fetch_cache_lock = threading.Lock()
audit_lock = threading.Lock()


class PolicyError(Exception):
    pass


def default_prompt_backend() -> str:
    """Prefer notify-send (native desktop toast) when it's on PATH; fall back to zenity."""
    return "notify-send" if shutil.which("notify-send") else "zenity"


def load_policy(path: str) -> dict:
    try:
        with open(path, "rb") as f:
            policy = tomllib.load(f)
    except FileNotFoundError:
        raise PolicyError(f"policy file not found: {path}")
    except tomllib.TOMLDecodeError as e:
        raise PolicyError(f"invalid TOML in {path}: {e}")

    unknown = set(policy.keys()) - ALLOWED_TOP_KEYS
    if unknown:
        raise PolicyError(f"unknown top-level policy keys: {sorted(unknown)}")

    for key in ("listen", "default"):
        if key not in policy:
            raise PolicyError(f"policy missing required key: {key}")

    if policy["default"] not in ("deny", "ask"):
        raise PolicyError(f"policy 'default' must be 'deny' or 'ask', got {policy['default']!r}")

    policy.setdefault("allowed_peers", [])
    policy.setdefault("prompt_timeout", 120)
    policy.setdefault("command_timeout", 300)
    policy.setdefault("prompt_backend", default_prompt_backend())
    if policy["prompt_backend"] not in ("zenity", "notify-send"):
        raise PolicyError(
            f"policy 'prompt_backend' must be 'zenity' or 'notify-send', got {policy['prompt_backend']!r}"
        )
    policy.setdefault("exec", [])
    policy.setdefault("git", [])

    for rule in policy["exec"]:
        unknown = set(rule.keys()) - ALLOWED_EXEC_KEYS
        if unknown:
            raise PolicyError(f"unknown exec rule keys: {sorted(unknown)}")
        if "args" not in rule or "action" not in rule:
            raise PolicyError("exec rule missing 'args' or 'action'")
        if rule["action"] not in ALLOWED_ACTIONS:
            raise PolicyError(f"invalid exec rule action: {rule['action']!r}")

    for rule in policy["git"]:
        unknown = set(rule.keys()) - ALLOWED_GIT_KEYS
        if unknown:
            raise PolicyError(f"unknown git rule keys: {sorted(unknown)}")
        if "repo" not in rule or "op" not in rule or "action" not in rule:
            raise PolicyError("git rule missing 'repo', 'op', or 'action'")
        if rule["op"] not in ("fetch", "push"):
            raise PolicyError(f"invalid git rule op: {rule['op']!r}")
        if rule["action"] not in ALLOWED_ACTIONS:
            raise PolicyError(f"invalid git rule action: {rule['action']!r}")

    return policy


POLICY: dict = {}
GH = ""


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def audit(peer, kind, detail, decision, via, exit_code=None):
    entry = {
        "ts": now_iso(),
        "peer": peer,
        "kind": kind,
        "detail": detail,
        "decision": decision,
        "via": via,
    }
    if exit_code is not None:
        entry["exit"] = exit_code
    line = json.dumps(entry)
    with audit_lock:
        os.makedirs(AUDIT_DIR, mode=0o700, exist_ok=True)
        with open(AUDIT_PATH, "a") as f:
            f.write(line + "\n")


def match_exec(args):
    """Return (action, via) for a gh exec request."""
    for rule in POLICY["exec"]:
        prefix = rule["args"]
        if args[: len(prefix)] == prefix:
            return rule["action"], "rule"
    return POLICY["default"], "default"


def match_git(repo, op, refs=None):
    for rule in POLICY["git"]:
        if rule["op"] != op:
            continue
        if not fnmatch.fnmatch(repo, rule["repo"]):
            continue
        if op == "push" and "refs" in rule:
            globs = rule["refs"]
            if refs is None:
                continue
            if not all(any(fnmatch.fnmatch(r, g) for g in globs) for r in refs):
                continue
        return rule["action"], "rule"
    return POLICY["default"], "default"


def _prompt_zenity(summary):
    result = subprocess.run(
        [
            "zenity",
            "--question",
            "--title=credbroker",
            "--width=600",
            "--no-markup",
            f"--timeout={POLICY['prompt_timeout']}",
            f"--text={summary}",
        ],
        timeout=POLICY["prompt_timeout"] + 10,
    )
    return result.returncode == 0


def _prompt_notify_send(summary):
    # notify-send escapes HTML unless told otherwise; the notification server
    # here advertises body-markup, so escape attacker-controlled text ourselves.
    escaped = summary.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    result = subprocess.run(
        [
            "notify-send",
            "--urgency=critical",
            f"--expire-time={POLICY['prompt_timeout'] * 1000}",
            "--action=allow=Allow",
            "--action=deny=Deny",
            "credbroker",
            escaped,
        ],
        capture_output=True,
        text=True,
        timeout=POLICY["prompt_timeout"] + 10,
    )
    return result.stdout.strip() == "allow"


def do_prompt(summary):
    backend = _prompt_notify_send if POLICY["prompt_backend"] == "notify-send" else _prompt_zenity
    with prompt_lock:
        try:
            return backend(summary)
        except Exception:
            return False


def shell_quote_join(args):
    import shlex

    return " ".join(shlex.quote(a) for a in args)


def gh_stdin_kwargs(stdin_bytes):
    """subprocess.run kwargs: pipe stdin_bytes in, or /dev/null if there's none."""
    return {"input": stdin_bytes} if stdin_bytes is not None else {"stdin": subprocess.DEVNULL}


def decide_exec(peer, args, reason, stdin_preview=None):
    action, via = match_exec(args)
    if action == "ask":
        summary_lines = [f"peer: {peer}", f"gh {shell_quote_join(args)}"]
        if stdin_preview:
            summary_lines.append(f"stdin: {stdin_preview}")
        if reason:
            summary_lines.append(f"reason: {reason}")
        allowed = do_prompt("\n".join(summary_lines))
        final = "allow" if allowed else "deny"
        return final, "prompt"
    return action, via


def decide_git(peer, repo, op, refs=None):
    action, via = match_git(repo, op, refs)
    if action == "ask":
        lines = [f"peer: {peer}", f"{op} {repo}"]
        if op == "push" and refs:
            for r in refs:
                lines.append(r)
        allowed = do_prompt("\n".join(lines))
        final = "allow" if allowed else "deny"
        return final, "prompt"
    return action, via


def gh_token():
    out = subprocess.run(
        [GH, "auth", "token"], capture_output=True, timeout=30, check=True
    ).stdout
    return out.decode().strip()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "credbroker/1.0"

    def log_message(self, fmt, *args):
        pass  # audit log is the record; suppress default stderr noise

    def peer_ok(self):
        peer = self.client_address[0]
        if peer not in POLICY["allowed_peers"]:
            body = f"forbidden peer {peer}\n".encode()
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            audit(peer, "peer", {"path": self.path}, "deny", "peer-check")
            return False
        return True

    def read_body(self, limit=None):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if limit is not None and length > limit:
            raise ValueError("body too large")
        data = self.rfile.read(length) if length else b""
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            data = self._read_chunked()
        return data

    def _read_chunked(self):
        chunks = []
        while True:
            size_line = self.rfile.readline().strip()
            if not size_line:
                break
            size = int(size_line.split(b";")[0], 16)
            if size == 0:
                self.rfile.readline()
                break
            chunks.append(self.rfile.read(size))
            self.rfile.readline()
        return b"".join(chunks)

    def send_json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, status, text):
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        try:
            if not self.peer_ok():
                return
            path = self.path.split("?", 1)[0]
            if path == "/client/credx":
                return self.handle_client_credx()
            if path.startswith("/git/"):
                return self.handle_git_get()
            self.send_text(404, "not found\n")
        except Exception:
            import traceback

            traceback.print_exc(file=sys.stderr)
            self.send_text(500, "credbroker: internal error\n")

    def do_POST(self):
        try:
            if not self.peer_ok():
                return
            path = self.path.split("?", 1)[0]
            if path == "/exec":
                return self.handle_exec()
            if path.startswith("/git/"):
                return self.handle_git_post()
            self.send_text(404, "not found\n")
        except Exception:
            import traceback

            traceback.print_exc(file=sys.stderr)
            self.send_text(500, "credbroker: internal error\n")

    def handle_client_credx(self):
        with open(CREDX_PATH, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/x-python")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_exec(self):
        peer = self.client_address[0]
        try:
            raw = self.read_body(limit=EXEC_REQUEST_LIMIT)
            req = json.loads(raw)
            args = req["args"]
            reason = req.get("reason")
            stdin_b64 = req.get("stdin")
            stdin_bytes = base64.b64decode(stdin_b64, validate=True) if stdin_b64 is not None else None
            if not isinstance(args, list) or len(args) == 0 or len(args) > 256:
                raise ValueError("bad args")
            if not all(isinstance(a, str) and "\0" not in a for a in args):
                raise ValueError("bad args")
            if args[0] != "gh":
                raise ValueError("args[0] must be gh")
        except Exception:
            return self.send_text(400, "credbroker: bad request\n")

        rest = args[1:]
        if args[0] != "gh":
            audit(peer, "exec", {"args": args}, "deny", "default")
            return self.send_json(403, {"error": "denied"})

        stdin_preview = stdin_bytes.decode("utf-8", "replace")[:500] if stdin_bytes else None
        decision, via = decide_exec(peer, rest, reason, stdin_preview)
        if decision != "allow":
            audit(
                peer,
                "exec",
                {"args": args, "reason": reason, "stdin_bytes": len(stdin_bytes) if stdin_bytes is not None else 0},
                "deny",
                via,
            )
            return self.send_json(403, {"error": "denied"})

        try:
            result = subprocess.run(
                [GH, *rest],
                **gh_stdin_kwargs(stdin_bytes),
                capture_output=True,
                timeout=POLICY["command_timeout"],
                cwd=HOME,
            )
            exit_code = result.returncode
            stdout_b = result.stdout
            stderr_b = result.stderr
        except subprocess.TimeoutExpired:
            exit_code = 124
            stdout_b = b""
            stderr_b = b"credbroker: command timed out\n"

        audit(
            peer,
            "exec",
            {"args": args, "reason": reason, "stdin_bytes": len(stdin_bytes) if stdin_bytes is not None else 0},
            "allow",
            via,
            exit_code=exit_code,
        )
        self.send_json(
            200,
            {
                "exit": exit_code,
                "stdout": base64.b64encode(stdout_b).decode(),
                "stderr": base64.b64encode(stderr_b).decode(),
            },
        )

    def parse_git_path(self):
        # /git/<owner>/<repo>[.git]/<rest...>  (query string stripped)
        path_no_query = self.path.split("?", 1)[0]
        parts = path_no_query[len("/git/") :].split("/", 2)
        if len(parts) < 3:
            return None
        owner, repo, rest = parts
        if repo.endswith(".git"):
            repo = repo[:-4]
        return owner, repo, rest

    def handle_git_get(self):
        peer = self.client_address[0]
        parsed = self.parse_git_path()
        if parsed is None:
            return self.send_text(404, "not found\n")
        owner, repo, rest = parsed
        full_repo = f"{owner}/{repo}"
        query = self.path.split("?", 1)[1] if "?" in self.path else ""
        if rest == "info/refs" and "service=git-upload-pack" in query:
            decision, via = decide_git(peer, full_repo, "fetch")
            if decision != "allow":
                audit(peer, "git", {"repo": full_repo, "op": "fetch"}, "deny", via)
                return self.send_text(403, "credbroker: denied\n")
            with fetch_cache_lock:
                fetch_cache[(peer, full_repo)] = time.time() + 60
            audit(peer, "git", {"repo": full_repo, "op": "fetch"}, "allow", via)
            return self.forward_to_github("GET", owner, repo, rest, query)
        if rest == "info/refs" and "service=git-receive-pack" in query:
            push_rules = [r for r in POLICY["git"] if r["op"] == "push" and fnmatch.fnmatch(full_repo, r["repo"])]
            if push_rules and all(r["action"] == "deny" for r in push_rules):
                audit(peer, "git", {"repo": full_repo, "op": "push-advertise"}, "deny", "rule")
                return self.send_text(403, "credbroker: denied\n")
            if not push_rules and POLICY["default"] == "deny":
                audit(peer, "git", {"repo": full_repo, "op": "push-advertise"}, "deny", "default")
                return self.send_text(403, "credbroker: denied\n")
            audit(peer, "git", {"repo": full_repo, "op": "push-advertise"}, "allow", "rule")
            return self.forward_to_github("GET", owner, repo, rest, query)
        return self.send_text(404, "not found\n")

    def handle_git_post(self):
        peer = self.client_address[0]
        parsed = self.parse_git_path()
        if parsed is None:
            return self.send_text(404, "not found\n")
        owner, repo, rest = parsed
        full_repo = f"{owner}/{repo}"
        query = self.path.split("?", 1)[1] if "?" in self.path else ""
        body = self.read_body()

        if rest == "git-upload-pack":
            with fetch_cache_lock:
                expiry = fetch_cache.get((peer, full_repo))
                cached = expiry is not None and expiry > time.time()
            if cached:
                decision, via = "allow", "cache"
            else:
                decision, via = decide_git(peer, full_repo, "fetch")
                if decision == "allow":
                    with fetch_cache_lock:
                        fetch_cache[(peer, full_repo)] = time.time() + 60
            if decision != "allow":
                audit(peer, "git", {"repo": full_repo, "op": "fetch"}, "deny", via)
                return self.send_text(403, "credbroker: denied\n")
            audit(peer, "git", {"repo": full_repo, "op": "fetch"}, "allow", via)
            return self.forward_to_github("POST", owner, repo, rest, query, body)

        if rest == "git-receive-pack":
            try:
                refs = self.parse_receive_pack_refs(body)
            except Exception:
                audit(peer, "git", {"repo": full_repo, "op": "push"}, "deny", "unparseable push")
                return self.send_text(400, "credbroker: unparseable push\n")
            refnames = [r["refname"] for r in refs]
            decision, via = decide_git(peer, full_repo, "push", refs=refnames)
            detail = {
                "repo": full_repo,
                "op": "push",
                "refs": [
                    {"refname": r["refname"], "old": r["old"], "new": r["new"]} for r in refs
                ],
            }
            if decision != "allow":
                audit(peer, "git", detail, "deny", via)
                return self.send_text(403, "credbroker: denied\n")
            audit(peer, "git", detail, "allow", via)
            return self.forward_to_github("POST", owner, repo, rest, query, body)

        return self.send_text(404, "not found\n")

    def parse_receive_pack_refs(self, body):
        data = body
        if self.headers.get("Content-Encoding", "").lower() == "gzip":
            data = gzip.decompress(body)
        refs = []
        pos = 0
        while True:
            if pos + 4 > len(data):
                raise ValueError("truncated pkt-line")
            length_hex = data[pos : pos + 4]
            pos += 4
            length = int(length_hex, 16)
            if length == 0:
                break
            line = data[pos : pos + length - 4]
            pos += length - 4
            text = line.split(b"\x00", 1)[0].decode().rstrip("\n")
            old, new, refname = text.split(" ", 2)
            refs.append({"old": old, "new": new, "refname": refname})
        return refs

    def forward_to_github(self, method, owner, repo, rest, query, body=None):
        url = f"https://github.com/{owner}/{repo}.git/{rest}"
        if query:
            url += f"?{query}"
        headers = {}
        for h in ("Content-Type", "Content-Encoding", "Accept", "Accept-Encoding", "Git-Protocol"):
            v = self.headers.get(h)
            if v is not None:
                headers[h] = v
        try:
            token = gh_token()
        except Exception:
            return self.send_text(502, "credbroker: failed to obtain token\n")
        headers["Authorization"] = "Basic " + base64.b64encode(
            f"x-access-token:{token}".encode()
        ).decode()

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=POLICY["command_timeout"]) as resp:
                status = resp.status
                resp_body = resp.read()
                resp_headers = resp.headers
        except urllib.error.HTTPError as e:
            status = e.code
            resp_body = e.read()
            resp_headers = e.headers
        except Exception:
            return self.send_text(502, "credbroker: upstream network error\n")

        self.send_response(status)
        for h in ("Content-Type", "Content-Encoding", "Cache-Control"):
            v = resp_headers.get(h)
            if v is not None:
                self.send_header(h, v)
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)


def serve(policy_path: str) -> None:
    global POLICY, GH
    POLICY = load_policy(policy_path)
    GH = shutil.which("gh") or ""
    if not GH:
        raise PolicyError("gh not found on PATH")
    if shutil.which(POLICY["prompt_backend"]) is None:
        raise PolicyError(f"prompt_backend {POLICY['prompt_backend']!r} not found on PATH")
    host, _, port = POLICY["listen"].rpartition(":")
    server = ThreadingHTTPServer((host, int(port)), Handler)
    server.serve_forever()
