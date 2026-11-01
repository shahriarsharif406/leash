"""MCP server (stdio): lets any MCP-capable agent ask Leash before it spends money.

Run:  python -m leash mcp --policy policy.json --log out/mcp-audit.log

Tools exposed to the agent: leash_check_payment, leash_pending, leash_policy, leash_verify_log.
Approving a held payment is deliberately NOT a tool: an agent must never release its own hold.
A human does that with `python -m leash resolve` or the dashboard.
"""
from __future__ import annotations

import json
import sys

from . import __version__
from .notify import Notifier
from .sdk import Guard

PROTOCOL = "2024-11-05"

TOOLS = [
    {"name": "leash_check_payment",
     "description": "ALWAYS call this before making any payment. Returns APPROVE (safe to pay), HOLD (wait for a human, do not pay) or DENY (do not pay), with reasons. Never pay unless the result is APPROVE.",
     "inputSchema": {"type": "object", "required": ["payee", "amount"], "properties": {
         "payee": {"type": "string", "description": "Who is being paid, exactly as named on the invoice"},
         "amount": {"type": "number", "description": "Amount in USD"},
         "category": {"type": "string", "description": "e.g. hosting, supplies, software"},
         "memo": {"type": "string", "description": "Payment memo"},
         "invoice_text": {"type": "string", "description": "Full invoice or request text, so hidden instructions can be scanned"},
         "agent": {"type": "string", "description": "Name of the calling agent"}}}},
    {"name": "leash_pending", "description": "List payments currently held for human approval.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "leash_policy", "description": "Show the active spending limits and rules.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "leash_verify_log", "description": "Check that the audit log has not been tampered with.",
     "inputSchema": {"type": "object", "properties": {}}},
]


def _text(obj, error=False):
    return {"content": [{"type": "text", "text": obj if isinstance(obj, str) else json.dumps(obj, indent=2)}], "isError": error}


class McpServer:
    def __init__(self, guard, notifier=None):
        self.guard = guard
        self.notifier = notifier or Notifier(None)

    def call_tool(self, name, args):
        g = self.guard
        if name == "leash_check_payment":
            try:
                req = {"agent": args.get("agent", "mcp-agent"), "payee": args["payee"], "amount": args["amount"],
                       "category": args.get("category", ""), "memo": args.get("memo", ""), "invoice_text": args.get("invoice_text", "")}
                entry = g.check(req)
            except KeyError as exc:
                return _text(f"missing argument {exc}", True)
            except (ValueError, TypeError) as exc:
                return _text(str(exc), True)
            self.notifier.notify(entry)
            out = {"decision": entry["decision"], "ref": entry["seq"], "risk": entry["risk"],
                   "reasons": [r["text"] for r in entry["reasons"]]}
            out["instruction"] = {"APPROVE": "You may proceed with this payment.",
                                  "HOLD": "Do NOT pay. A human has been asked to approve; check leash_pending later.",
                                  "DENY": "Do NOT pay. This request violates policy."}[entry["decision"]]
            return _text(out)
        if name == "leash_pending":
            res = {e["ref"] for e in g.entries if e["type"] == "resolution"}
            held = [{"ref": e["seq"], "payee": e["request"]["payee"], "amount": e["request"]["amount"],
                     "reasons": [r["text"] for r in e["reasons"]]}
                    for e in g.entries if e["type"] == "decision" and e["decision"] == "HOLD" and e["seq"] not in res]
            return _text(held)
        if name == "leash_policy":
            p = g.engine.policy
            return _text({k: p[k] for k in ("daily_budget", "per_txn_cap", "approval_above", "max_requests_per_payee_per_hour",
                                            "security_flags_before_freeze", "blocked_categories", "payee_allowlist")})
        if name == "leash_verify_log":
            ok, bad = g.verify()
            return _text({"intact": ok, "first_bad_entry": bad})
        return _text(f"unknown tool {name}", True)

    def handle(self, msg):
        method, mid = msg.get("method"), msg.get("id")
        if mid is None:
            return None  # notification such as notifications/initialized
        if method == "initialize":
            result = {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                      "serverInfo": {"name": "leash", "version": __version__}}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            p = msg.get("params") or {}
            result = self.call_tool(p.get("name"), p.get("arguments") or {})
        else:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def serve(self, stdin=None, stdout=None):
        stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                reply = self.handle(json.loads(line))
            except json.JSONDecodeError:
                reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
            if reply is not None:
                stdout.write(json.dumps(reply) + "\n")
                stdout.flush()


def run(policy_path, log_path, webhook=None):
    server = McpServer(Guard.from_file(policy_path, log_path), Notifier(webhook))
    print("Leash MCP server ready (stdio)", file=sys.stderr)
    server.serve()
