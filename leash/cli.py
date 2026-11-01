"""Command line interface: python -m leash <command>."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import audit, dashboard, redteam, __version__
from .engine import Engine, PolicyError, validate_policy

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
COLORS = {"APPROVE": "32", "HOLD": "33", "DENY": "31"}


def _paint(text, code):
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text


def _run(policy_path, requests_path, out):
    policy = validate_policy(json.loads(Path(policy_path).read_text(encoding="utf-8")))
    engine, entries = Engine(policy), []
    for req in json.loads(Path(requests_path).read_text(encoding="utf-8")):
        audit.append(entries, engine.evaluate(req))
    out = Path(out)
    audit.write_log(out / "audit.log", entries)
    (out / "report.html").write_text(dashboard.render(entries, policy), encoding="utf-8")
    for e in entries:
        r = e["request"]
        why = "; ".join(x["text"] for x in e["reasons"]) or "Within policy"
        verdict = _paint("%-7s" % e["decision"], COLORS[e["decision"]])
        print(f"#{e['seq']:>2} {verdict} {r['payee']:<20} {r['amount']:>9.2f}  risk {e['risk']:>3}  {why}")
    counts = {k: sum(1 for e in entries if e["decision"] == k) for k in COLORS}
    print(f"\nApproved {counts['APPROVE']}, held {counts['HOLD']}, denied {counts['DENY']}. Spent {engine.spent:.2f}.")
    print(f"Wrote {out / 'audit.log'} and {out / 'report.html'}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="leash", description="Policy firewall between AI agents and money.")
    ap.add_argument("--version", action="version", version=f"leash {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("run", help="evaluate a file of payment requests")
    p.add_argument("policy"), p.add_argument("requests"), p.add_argument("--out", default="out")
    p = sub.add_parser("demo", help="run the built-in 14-request scenario")
    p.add_argument("--out", default="out")
    p = sub.add_parser("verify", help="check an audit log has not been edited")
    p.add_argument("log")
    p = sub.add_parser("resolve", help="approve or reject a request that was held for a human")
    p.add_argument("log"), p.add_argument("seq", type=int), p.add_argument("action", choices=["approve", "reject"])
    p.add_argument("--by", default="cli"), p.add_argument("--note", default="")
    p = sub.add_parser("report", help="re-render report.html from an audit log")
    p.add_argument("log"), p.add_argument("policy"), p.add_argument("--out", default=None)
    p = sub.add_parser("redteam", help="replay known attacks and honest payments against a policy")
    p.add_argument("--policy", default=str(EXAMPLES / "policy.json"))
    p = sub.add_parser("serve", help="live dashboard with a payment playground and human approval")
    p.add_argument("--policy", default=str(EXAMPLES / "policy.json"))
    p.add_argument("--requests", default=str(EXAMPLES / "requests.json"))
    p.add_argument("--empty", action="store_true", help="start without the demo requests")
    p.add_argument("--out", default="out"), p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--webhook", default=os.environ.get("LEASH_WEBHOOK"), help="POST an alert here when a payment is held or flagged (Slack-compatible)")
    p = sub.add_parser("mcp", help="MCP server (stdio) so any MCP agent must ask Leash before paying")
    p.add_argument("--policy", default=str(EXAMPLES / "policy.json"))
    p.add_argument("--log", default="out/mcp-audit.log")
    p.add_argument("--webhook", default=os.environ.get("LEASH_WEBHOOK"))
    a = ap.parse_args(argv)

    try:
        if a.cmd == "run":
            _run(a.policy, a.requests, a.out)
        elif a.cmd == "demo":
            _run(EXAMPLES / "policy.json", EXAMPLES / "requests.json", a.out)
        elif a.cmd == "verify":
            ok, bad = audit.verify(a.log)
            print("Audit chain intact" if ok else f"TAMPERING DETECTED at entry {bad}")
            return 0 if ok else 1
        elif a.cmd == "resolve":
            e = audit.resolve(a.log, a.seq, a.action, a.by, a.note)
            print(f"Entry {a.seq} {a.action}d by {a.by} (recorded as entry {e['seq']})")
        elif a.cmd == "report":
            entries = audit.read_log(a.log)
            policy = validate_policy(json.loads(Path(a.policy).read_text(encoding="utf-8")))
            out = Path(a.out) if a.out else Path(a.log).parent / "report.html"
            out.write_text(dashboard.render(entries, policy), encoding="utf-8")
            print(f"Wrote {out}")
        elif a.cmd == "redteam":
            policy = validate_policy(json.loads(Path(a.policy).read_text(encoding="utf-8")))
            res = redteam.run_suite(policy)
            for sc in res["scenarios"]:
                mark = _paint("PASS", "32") if sc["passed"] else _paint("FAIL", "31")
                print(f"{mark}  {sc['kind']:<6} {sc['name']}")
            print(f"\n{res['blocked']}/{res['attacks']} attacks blocked, {res['legit_ok']}/{res['legit']} honest payments cleared")
            return 0 if res["blocked"] == res["attacks"] and res["legit_ok"] == res["legit"] else 1
        elif a.cmd == "serve":
            from .server import serve
            serve(a.policy, None if a.empty else a.requests, a.out, a.host, a.port, a.webhook)
        elif a.cmd == "mcp":
            from .mcp import run
            Path(a.log).parent.mkdir(parents=True, exist_ok=True)
            run(a.policy, a.log, a.webhook)
    except (PolicyError, ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
