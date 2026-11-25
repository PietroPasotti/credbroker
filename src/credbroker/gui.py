#!/usr/bin/env python3
"""credbroker: loopback-only web GUI for the approval queue, policy editor,
and desktop-notification toggle.

Runs as a second HTTP server inside the same `credbroker serve` process as
`server.Handler`, because pending `ask` requests live in `server.BOARD`'s
in-process memory.
"""
import hashlib
import json
import os
import stat
import tempfile
import time
from http.server import ThreadingHTTPServer

from credbroker import server

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript"),
    "/app.css": ("app.css", "text/css"),
}

policy_write_lock = __import__("threading").Lock()


class GuiHandler(server.Handler):
    def _allowed_hosts(self):
        port = self.server.server_address[1]
        return {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}

    def _host_ok(self):
        if self.headers.get("Host") not in self._allowed_hosts():
            self.send_text(403, "forbidden host\n")
            return False
        return True

    def _csrf_ok(self):
        if self.headers.get("X-Credbroker-GUI") != "1" or not self.headers.get(
            "Content-Type", ""
        ).startswith("application/json"):
            self.send_json(403, {"error": "missing X-Credbroker-GUI header"})
            return False
        return True

    def send_response(self, code, message=None):
        super().send_response(code, message)
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")

    def do_GET(self):
        try:
            if not self._host_ok():
                return
            path = self.path.split("?", 1)[0]
            if path in STATIC_FILES:
                return self.serve_static(path)
            if path == "/api/state":
                return self.api_state()
            if path == "/api/policy":
                return self.api_get_policy()
            self.send_text(404, "not found\n")
        except Exception:
            import sys
            import traceback

            traceback.print_exc(file=sys.stderr)
            self.send_text(500, "credbroker: internal error\n")

    def do_POST(self):
        try:
            if not self._host_ok() or not self._csrf_ok():
                return
            path = self.path.split("?", 1)[0]
            if path == "/api/resolve":
                return self.api_resolve()
            if path == "/api/settings":
                return self.api_settings()
            self.send_text(404, "not found\n")
        except Exception:
            import sys
            import traceback

            traceback.print_exc(file=sys.stderr)
            self.send_text(500, "credbroker: internal error\n")

    def do_PUT(self):
        try:
            if not self._host_ok() or not self._csrf_ok():
                return
            path = self.path.split("?", 1)[0]
            if path == "/api/policy":
                return self.api_put_policy()
            self.send_text(404, "not found\n")
        except Exception:
            import sys
            import traceback

            traceback.print_exc(file=sys.stderr)
            self.send_text(500, "credbroker: internal error\n")

    def serve_static(self, path):
        name, content_type = STATIC_FILES[path]
        with open(os.path.join(STATIC_DIR, name), "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def api_state(self):
        server.BOARD.touch_gui()
        self.send_json(
            200,
            {
                **server.BOARD.snapshot(),
                "now": time.time(),
                "prompt_backend": server.POLICY["prompt_backend"],
                "policy_status": server.POLICY_STATUS,
                "peer_names": server.POLICY.get("peer_names", {}),
            },
        )

    def api_resolve(self):
        try:
            req = json.loads(self.read_body(limit=65536))
            ids = req["ids"]
            decision = req["decision"]
            if not isinstance(ids, list) or len(ids) > 1000:
                raise ValueError("bad ids")
            if not all(isinstance(i, int) for i in ids):
                raise ValueError("bad ids")
            if decision not in ("allow", "deny"):
                raise ValueError("bad decision")
        except Exception:
            return self.send_json(400, {"error": "bad request"})
        resolved = server.BOARD.resolve(ids, decision)
        self.send_json(200, {"resolved": resolved})

    def api_settings(self):
        try:
            req = json.loads(self.read_body(limit=65536))
            value = req["notify_while_open"]
            if not isinstance(value, bool):
                raise ValueError("bad value")
        except Exception:
            return self.send_json(400, {"error": "bad request"})
        server.BOARD.set_notify_while_open(value)
        self.send_json(200, {"notify_while_open": value})

    def api_get_policy(self):
        try:
            with open(server.POLICY_PATH, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            data = b""
        self.send_json(200, {"text": data.decode("utf-8", errors="replace"), "sha256": hashlib.sha256(data).hexdigest()})

    def api_put_policy(self):
        try:
            req = json.loads(self.read_body(limit=1048576))
            text = req["text"]
            sha256 = req["sha256"]
            if not isinstance(text, str) or not isinstance(sha256, str):
                raise ValueError("bad body")
        except Exception:
            return self.send_json(400, {"error": "bad request"})

        path = server.POLICY_PATH
        with policy_write_lock:
            try:
                with open(path, "rb") as f:
                    current = f.read()
            except FileNotFoundError:
                current = b""
            if hashlib.sha256(current).hexdigest() != sha256:
                return self.send_json(409, {"error": "policy changed on disk; reload it first"})

            try:
                server.validate_runtime(server.parse_policy(text, "<gui>"))
            except server.PolicyError as e:
                return self.send_json(422, {"error": str(e)})

            dirname = os.path.dirname(path) or "."
            os.makedirs(dirname, exist_ok=True)
            tmp = tempfile.NamedTemporaryFile(
                "w", dir=dirname, prefix=".policy.", suffix=".toml", delete=False
            )
            try:
                tmp.write(text)
                tmp.flush()
                os.fsync(tmp.fileno())
                tmp.close()
                if os.path.exists(path):
                    os.chmod(tmp.name, stat.S_IMODE(os.stat(path).st_mode))
                else:
                    os.chmod(tmp.name, 0o600)
                os.replace(tmp.name, path)
            except Exception:
                os.unlink(tmp.name)
                raise

            err = server.reload_policy()
            if err:
                return self.send_json(422, {"error": err})
            with open(path, "rb") as f:
                new_bytes = f.read()
            return self.send_json(
                200,
                {
                    "sha256": hashlib.sha256(new_bytes).hexdigest(),
                    "restart_required": server.POLICY_STATUS["restart_required"],
                },
            )


class GuiServer(ThreadingHTTPServer):
    daemon_threads = True


def make_gui_server(listen: str) -> GuiServer:
    host, _, port = listen.rpartition(":")
    host = host.strip("[]")
    return GuiServer((host, int(port)), GuiHandler)
