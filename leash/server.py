"""Live mode: a tiny HTTP server with the dashboard, a payment-check API and human approval."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import audit, dashboard
from .engine import Engine, validate_policy


class Store:
    def __init__(self, policy_path, requests_path, out_dir):
        self.policy = validate_policy(json.loads(Path(policy_path).read_text(encoding="utf-8")))
        self.requests_path = requests_path
        self.log_path = Path(out_dir) / "audit.log"
        self.lock = threading.RLock()
        self.reset()

    def reset(self):
        with self.lock:
            self.engine = Engine(json.loads(json.dumps(self.policy)))
            self.entries = []
            if self.requests_path:
                for req in json.loads(Path(self.requests_path).read_text(encoding="utf-8")):
                    audit.append(self.entries, self.engine.evaluate(req))
            self._save()

    def _save(self):
        audit.write_log(self.log_path, self.entries)

    def evaluate(self, req):
        with self.lock:
            entry = audit.append(self.entries, self.engine.evaluate(req))
            self._save()
            return entry

    def resolve(self, ref, action, by):
        with self.lock:
            entry = audit.resolve_entries(self.entries, ref, action, by)
            if action == "approve":
                target = next(e for e in self.entries if e["seq"] == ref)
                self.engine.spent += target["request"]["amount"]
            self._save()
            return entry

    def state(self):
        with self.lock:
            return dashboard.build_data(self.entries, self.policy, live=True)

    def page(self):
        with self.lock:
            return dashboard.render(self.entries, self.policy, live=True)


def make_handler(store):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, code, payload, ctype="application/json"):
            body = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send(200, store.page(), "text/html")
            elif self.path == "/api/state":
                self._send(200, store.state())
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            try:
                n = int(self.headers.get("Content-Length") or 0)
                data = json.loads(self.rfile.read(n) or b"{}")
                if self.path == "/api/evaluate":
                    e = store.evaluate(data)
                    self._send(200, {k: e[k] for k in ("seq", "decision", "risk", "risk_level", "reasons", "hash")})
                elif self.path == "/api/resolve":
                    self._send(200, store.resolve(int(data["ref"]), data["action"], str(data.get("by", "human"))))
                elif self.path == "/api/reset":
                    store.reset()
                    self._send(200, {"ok": True})
                else:
                    self._send(404, {"error": "not found"})
            except (ValueError, KeyError, TypeError) as exc:
                self._send(400, {"error": str(exc)})

    return Handler


def serve(policy_path, requests_path, out_dir, host="127.0.0.1", port=8765):
    store = Store(policy_path, requests_path, out_dir)
    httpd = ThreadingHTTPServer((host, port), make_handler(store))
    print(f"Leash dashboard running at http://{host}:{port}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()
