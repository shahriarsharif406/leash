"""Builds the data model and the self-contained HTML dashboard (bento layout, light and dark themes)."""
from __future__ import annotations

import json
from pathlib import Path

from . import audit
from .redteam import run_suite


def build_data(entries, policy, live=False):
    res = audit.resolution_map(entries)
    rows, counts, by_payee, reasons = [], {}, {}, {}
    spent = blocked = 0.0
    risks, flags, frozen = [], 0, set()
    for e in entries:
        if e.get("type") != "decision":
            continue
        r = res.get(e["seq"])
        final = e["decision"]
        if final == "HOLD" and r:
            final = "APPROVED_BY_HUMAN" if r["action"] == "approve" else "REJECTED_BY_HUMAN"
        amt = e["request"]["amount"]
        counts[final] = counts.get(final, 0) + 1
        if final in ("APPROVE", "APPROVED_BY_HUMAN"):
            spent += amt
            by_payee[e["request"]["payee"]] = by_payee.get(e["request"]["payee"], 0) + amt
        if final in ("DENY", "REJECTED_BY_HUMAN") and amt > 0:
            blocked += amt
        for x in e["reasons"]:
            reasons[x["code"]] = reasons.get(x["code"], 0) + 1
            if x["code"] == "breaker":
                frozen.add(e["request"]["agent"])
        flags += 1 if e.get("security") else 0
        risks.append(e["risk"])
        rows.append({k: e[k] for k in ("seq", "request", "decision", "risk", "risk_level", "reasons", "hash", "prev")}
                    | {"final": final, "resolution": r})
    ok, bad = audit.verify_entries(entries)
    return {
        "live": live,
        "policy": {"daily_budget": policy["daily_budget"], "per_txn_cap": policy["per_txn_cap"],
                   "approval_above": policy["approval_above"], "allowlist": policy["payee_allowlist"],
                   "blocked_categories": policy["blocked_categories"],
                   "max_requests_per_payee_per_hour": policy["max_requests_per_payee_per_hour"],
                   "security_flags_before_freeze": policy["security_flags_before_freeze"]},
        "summary": {"total": len(rows), "counts": counts, "spent": round(spent, 2), "blocked": round(blocked, 2),
                    "by_payee": sorted(by_payee.items(), key=lambda kv: -kv[1]),
                    "reasons": sorted(reasons.items(), key=lambda kv: -kv[1]),
                    "avg_risk": round(sum(risks) / len(risks)) if risks else 0,
                    "security_flags": flags, "frozen": sorted(frozen)},
        "entries": rows,
        "redteam": run_suite(policy),
        "chain": {"ok": ok, "bad": bad, "length": len(entries), "head": entries[-1]["hash"] if entries else "",
                  "items": [{"seq": e["seq"], "type": e.get("type"), "hash": e["hash"][:10], "prev": e["prev"][:10]}
                            for e in entries]},
    }


def render(entries, policy, live=False):
    data = json.dumps(build_data(entries, policy, live)).replace("</", "<\\/")
    template = Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
    return template.replace("__DATA__", data)



