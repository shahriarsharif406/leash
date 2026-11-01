"""What-if simulator: change policy limits and see instantly how the red team and the day's requests would be ruled."""
from __future__ import annotations

import copy

from . import redteam
from .engine import Engine, PolicyError, validate_policy

TUNABLE = {
    "per_txn_cap": float,
    "approval_above": float,
    "daily_budget": float,
    "max_requests_per_payee_per_hour": int,
    "security_flags_before_freeze": int,
}


def apply_overrides(policy, overrides):
    new = copy.deepcopy(policy)
    for key, value in (overrides or {}).items():
        if key not in TUNABLE:
            raise ValueError(f"'{key}' cannot be simulated")
        try:
            new[key] = TUNABLE[key](value)
        except (TypeError, ValueError):
            raise ValueError(f"'{key}' must be a number")
        if new[key] < 0:
            raise ValueError(f"'{key}' cannot be negative")
    return validate_policy(new)


def simulate(policy, overrides, entries):
    """Returns the red-team scorecard and a replay of the real requests under the changed policy."""
    try:
        new = apply_overrides(policy, overrides)
    except PolicyError as exc:
        raise ValueError(str(exc))
    suite = redteam.run_suite(new)
    engine = Engine(copy.deepcopy(new))
    counts = {"APPROVE": 0, "HOLD": 0, "DENY": 0}
    spent = 0.0
    changed = 0
    for e in entries:
        if e.get("type") != "decision":
            continue
        res = engine.evaluate(e["request"])
        counts[res["decision"]] += 1
        if res["decision"] == "APPROVE":
            spent += e["request"]["amount"]
        changed += res["decision"] != e["decision"]
    return {
        "policy": {k: new[k] for k in TUNABLE},
        "redteam": {k: suite[k] for k in ("attacks", "blocked", "legit", "legit_ok")},
        "failed": [{"name": s["name"], "kind": s["kind"]} for s in suite["scenarios"] if not s["passed"]],
        "replay": {"counts": counts, "spent": round(spent, 2), "changed": changed},
    }
