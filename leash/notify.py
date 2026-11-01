"""Webhook notifications: tell a human the moment a payment needs them. The payload works with Slack incoming webhooks."""
from __future__ import annotations

import json
import threading
import urllib.request


def build_payload(entry):
    req, reasons = entry["request"], entry["reasons"]
    why = "; ".join(r["text"] for r in reasons) or "needs approval"
    verb = {"HOLD": "needs your approval", "DENY": "was blocked"}.get(entry["decision"], entry["decision"].lower())
    text = f"Leash: ${req['amount']:,.2f} to {req['payee']} {verb} (entry #{entry['seq']}, risk {entry['risk']}/100). {why}"
    return {"text": text, "decision": entry["decision"], "seq": entry["seq"], "risk": entry["risk"],
            "agent": req.get("agent"), "payee": req["payee"], "amount": req["amount"], "reasons": [r["text"] for r in reasons]}


def should_notify(entry):
    codes = {r["code"] for r in entry["reasons"]}
    return entry["decision"] == "HOLD" or bool(codes & {"injection", "lookalike", "breaker"})


def send(url, payload, timeout=5):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status


class Notifier:
    """Fire-and-forget: a slow or broken webhook never delays or breaks a payment decision."""

    def __init__(self, url):
        self.url = url
        self.sent = 0
        self.failed = 0
        self._threads = []

    def notify(self, entry):
        if not self.url or not should_notify(entry):
            return
        t = threading.Thread(target=self._run, args=(build_payload(entry),), daemon=True)
        self._threads.append(t)
        t.start()

    def _run(self, payload):
        try:
            send(self.url, payload)
            self.sent += 1
        except Exception:
            self.failed += 1

    def wait(self, timeout=5):
        for t in self._threads:
            t.join(timeout)
