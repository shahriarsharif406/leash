"""Drop-in guard for agent code: wrap your payment function so it can only run when policy allows it.

    from leash.sdk import Guard
    guard = Guard.from_file("policy.json", log_path="audit.log")
    guard.pay({"payee": "CloudHost", "amount": 95, "category": "hosting"}, executor=send_payment)
"""
from __future__ import annotations

import json
from pathlib import Path

from . import audit
from .engine import Engine, validate_policy


class PaymentBlocked(Exception):
    """The payment was denied by policy."""

    def __init__(self, entry):
        self.entry = entry
        super().__init__("; ".join(r["text"] for r in entry["reasons"]) or "denied")


class NeedsHumanApproval(PaymentBlocked):
    """The payment was held. A human must call guard.approve(seq) before it can go out."""


class Guard:
    def __init__(self, policy, log_path=None):
        self.engine = Engine(validate_policy(policy))
        self.entries = []
        self.log_path = Path(log_path) if log_path else None
        self._held = {}

    @classmethod
    def from_file(cls, policy_path, log_path=None):
        return cls(json.loads(Path(policy_path).read_text(encoding="utf-8")), log_path)

    def _save(self):
        if self.log_path:
            audit.write_log(self.log_path, self.entries)

    def check(self, request):
        """Evaluate and log a request without paying. Returns the audit entry."""
        entry = audit.append(self.entries, self.engine.evaluate(request))
        self._save()
        return entry

    def pay(self, request, executor):
        """Call executor(request) only if policy approves. Raises PaymentBlocked or NeedsHumanApproval otherwise."""
        entry = self.check(request)
        if entry["decision"] == "APPROVE":
            return executor(request)
        if entry["decision"] == "HOLD":
            self._held[entry["seq"]] = (request, executor)
            raise NeedsHumanApproval(entry)
        raise PaymentBlocked(entry)

    def approve(self, seq, by="human"):
        """A human releases a held payment: records the decision, then runs the original executor."""
        if seq not in self._held:
            raise ValueError(f"entry {seq} is not waiting for approval")
        audit.resolve_entries(self.entries, seq, "approve", by)
        request, executor = self._held.pop(seq)
        self.engine.spent += float(request["amount"])
        self._save()
        return executor(request)

    def reject(self, seq, by="human"):
        if seq not in self._held:
            raise ValueError(f"entry {seq} is not waiting for approval")
        audit.resolve_entries(self.entries, seq, "reject", by)
        self._held.pop(seq)
        self._save()

    def tool(self, executor, agent="agent"):
        """An agent-friendly tool function. Never raises: it returns a dict the model can read and adapt to."""
        def pay_tool(payee, amount, category="", memo="", invoice_text=""):
            req = {"agent": agent, "payee": payee, "amount": amount, "category": category,
                   "memo": memo, "invoice_text": invoice_text}
            try:
                return {"status": "paid", "result": self.pay(req, executor)}
            except NeedsHumanApproval as exc:
                return {"status": "pending_human_approval", "ref": exc.entry["seq"], "reason": str(exc)}
            except PaymentBlocked as exc:
                return {"status": "blocked", "reason": str(exc)}
        return pay_tool

    def verify(self):
        return audit.verify_entries(self.entries)
