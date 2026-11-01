"""Policy engine: decides APPROVE, HOLD or DENY for every payment request an agent makes."""
from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timedelta
from difflib import SequenceMatcher

REQUIRED = {
    "daily_budget": (int, float),
    "per_txn_cap": (int, float),
    "approval_above": (int, float),
    "max_requests_per_payee_per_hour": int,
    "security_flags_before_freeze": int,
    "blocked_categories": list,
    "payee_allowlist": list,
}

# How much each finding adds to a request's 0-100 risk score.
WEIGHTS = {
    "frozen": 100, "breaker": 100, "invalid_amount": 80, "injection": 60, "lookalike": 55,
    "blocked_category": 50, "payee_limit": 40, "cap": 40, "budget": 35, "duplicate": 30,
    "new_payee": 25, "velocity": 20, "approval": 15, "structuring": 35,
}
SECURITY_CODES = {"injection", "lookalike"}

INJECTION_PATTERNS = [
    r"ignore (all |any )?(previous|prior|above|earlier) (instructions|rules|prompts?)",
    r"do not (notify|tell|inform|alert)",
    r"(new|different|changed) (bank|account)( details| number)?",
    r"wire (the )?(funds|money)",
    r"(disable|bypass|override|remove|lift) .{0,30}(limit|policy|check|approval|guardrail)",
    r"\bsystem\s*:",
    r"approve all",
    r"you (are|must) now",
    r"(reveal|send|share|leak) .{0,20}(password|api key|credentials|secret|token)",
    r"<\s*/?\s*(system|instructions?)\s*>",
]

_CONFUSABLES = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "і": "i", "ѕ": "s",
})


class PolicyError(ValueError):
    """The policy file is missing something or has the wrong type."""


def validate_policy(policy):
    for key, typ in REQUIRED.items():
        if key not in policy:
            raise PolicyError(f"policy is missing '{key}'")
        if isinstance(policy[key], bool) or not isinstance(policy[key], typ):
            raise PolicyError(f"policy '{key}' has the wrong type")
    if policy["approval_above"] > policy["per_txn_cap"]:
        raise PolicyError("approval_above cannot be higher than per_txn_cap")
    policy.setdefault("payee_limits", {})
    policy.setdefault("extra_injection_patterns", [])
    return policy


def canon(text):
    """Collapse look-alike characters (0/o, rn/m is handled by similarity) so spoofed names compare equal."""
    text = unicodedata.normalize("NFKD", str(text)).lower().translate(_CONFUSABLES)
    return re.sub(r"[^a-z]", "", text)


def risk_level(score):
    return "low" if score < 25 else "medium" if score < 60 else "high"


class Engine:
    """Stateful evaluator. Feed it requests in order; it tracks spend, history and frozen agents."""

    def __init__(self, policy):
        self.policy = validate_policy(policy)
        self.history = []
        self.spent = 0.0
        self.flags = {}
        self.frozen = {}
        self._patterns = [re.compile(p, re.I) for p in INJECTION_PATTERNS + list(self.policy["extra_injection_patterns"])]
        self._allow_lower = {a.lower(): a for a in self.policy["payee_allowlist"]}

    @staticmethod
    def _normalize(req):
        if not isinstance(req, dict):
            raise ValueError("request must be an object")
        payee = str(req.get("payee", "")).strip()
        agent = str(req.get("agent", "")).strip() or "agent"
        if not payee:
            raise ValueError("request needs a 'payee'")
        try:
            amount, valid = round(float(req.get("amount")), 2), True
            valid = amount > 0
        except (TypeError, ValueError):
            amount, valid = 0.0, False
        return {
            "id": req.get("id"), "time": req.get("time") or datetime.now().isoformat(timespec="seconds"),
            "agent": agent, "payee": payee, "amount": amount, "category": str(req.get("category", "")).strip().lower(),
            "memo": str(req.get("memo", "")), "invoice_text": str(req.get("invoice_text", "")), "_valid": valid,
        }

    def evaluate(self, raw):
        p = self.policy
        req = self._normalize(raw)
        valid = req.pop("_valid")
        reasons, security = [], False

        def add(level, code, text):
            reasons.append({"level": level, "code": code, "text": text})

        if self.frozen.get(req["agent"]):
            add("deny", "frozen", "Agent is frozen by the circuit breaker after repeated security flags")
        else:
            amount, payee = req["amount"], req["payee"]
            if not valid:
                add("deny", "invalid_amount", "Amount is missing, zero or not a number")
            scan = f"{req['memo']} {req['invoice_text']}"
            if any(rx.search(scan) for rx in self._patterns):
                add("deny", "injection", "Possible prompt injection in the memo or invoice text")
            if payee.lower() not in self._allow_lower:
                cp = canon(payee)
                best = max(p["payee_allowlist"], key=lambda a: SequenceMatcher(None, canon(a), cp).ratio())
                if cp and (cp == canon(best) or SequenceMatcher(None, canon(best), cp).ratio() >= 0.85):
                    add("deny", "lookalike", f"Look-alike payee: '{payee}' imitates trusted payee '{best}'")
                else:
                    add("hold", "new_payee", f"New payee '{payee}' is not on the allowlist")
            if req["category"] in [c.lower() for c in p["blocked_categories"]]:
                add("deny", "blocked_category", f"Category '{req['category']}' is blocked")
            if valid:
                limit = p["payee_limits"].get(self._allow_lower.get(payee.lower(), payee))
                if limit is not None and amount > limit:
                    add("deny", "payee_limit", f"Amount {amount:.2f} exceeds the {limit:.2f} limit for {payee}")
                if amount > p["per_txn_cap"]:
                    add("deny", "cap", f"Amount {amount:.2f} exceeds the per-transaction cap {p['per_txn_cap']:.2f}")
                else:
                    if amount > p["approval_above"]:
                        add("hold", "approval", f"Amount {amount:.2f} is above the auto-approval limit {p['approval_above']:.2f}")
                    if self.spent + amount > p["daily_budget"]:
                        add("deny", "budget", f"Would exceed the daily budget (spent {self.spent:.2f} of {p['daily_budget']:.2f})")
                t = datetime.fromisoformat(req["time"])
                same = [h for h in self.history if h["request"]["payee"].lower() == payee.lower()]
                if any(h["request"]["amount"] == amount and h["decision"] != "DENY"
                       and timedelta(0) <= t - datetime.fromisoformat(h["request"]["time"]) <= timedelta(hours=24) for h in same):
                    add("hold", "duplicate", "Possible duplicate: same payee and amount already requested in the last 24h")
                recent = [h for h in same if timedelta(0) <= t - datetime.fromisoformat(h["request"]["time"]) <= timedelta(hours=1)]
                if len(recent) >= p["max_requests_per_payee_per_hour"]:
                    add("hold", "velocity", f"Unusual velocity: {len(recent)} requests to this payee in the last hour")
                window = [h for h in same if timedelta(0) <= t - datetime.fromisoformat(h["request"]["time"]) <= timedelta(hours=1)
                          and h["decision"] != "DENY"]
                total = sum(h["request"]["amount"] for h in window) + amount
                if window and amount <= p["approval_above"] < total:
                    add("hold", "structuring", f"Possible structuring: {len(window) + 1} payments to this payee total "
                        f"{total:.2f} in the last hour, above the {p['approval_above']:.2f} auto-approval limit")
            security = any(r["code"] in SECURITY_CODES for r in reasons)
            if security:
                n = self.flags[req["agent"]] = self.flags.get(req["agent"], 0) + 1
                if n >= p["security_flags_before_freeze"]:
                    self.frozen[req["agent"]] = True
                    add("deny", "breaker", f"Circuit breaker tripped: agent '{req['agent']}' frozen after {n} security flags")

        decision = "DENY" if any(r["level"] == "deny" for r in reasons) else "HOLD" if reasons else "APPROVE"
        risk = min(100, sum(WEIGHTS.get(r["code"], 10) for r in reasons))
        body = {"type": "decision", "request": req, "decision": decision, "risk": risk,
                "risk_level": risk_level(risk), "security": security, "reasons": reasons}
        self.history.append(body)
        if decision == "APPROVE":
            self.spent += req["amount"]
        return body
