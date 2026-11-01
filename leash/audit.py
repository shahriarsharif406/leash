"""Tamper-evident audit log: every entry stores the hash of the one before it."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

GENESIS = "GENESIS"


def _digest(prev, core):
    return hashlib.sha256((prev + json.dumps(core, sort_keys=True)).encode()).hexdigest()


def make_entry(prev, seq, body):
    core = {"seq": seq, **body}
    return {**core, "prev": prev, "hash": _digest(prev, core)}


def append(entries, body):
    prev = entries[-1]["hash"] if entries else GENESIS
    entry = make_entry(prev, len(entries) + 1, body)
    entries.append(entry)
    return entry


def write_log(path, entries):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")


def read_log(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def verify_entries(entries):
    """Returns (ok, seq_of_first_bad_entry_or_None)."""
    prev = GENESIS
    for i, e in enumerate(entries, 1):
        core = {k: v for k, v in e.items() if k not in ("prev", "hash")}
        if e.get("prev") != prev or e.get("hash") != _digest(prev, core) or e.get("seq") != i:
            return False, i
        prev = e["hash"]
    return True, None


def verify(path):
    return verify_entries(read_log(path))


def resolution_map(entries):
    return {e["ref"]: e for e in entries if e.get("type") == "resolution"}


def resolve_entries(entries, ref, action, by="human", note=""):
    """Record a human decision on a HELD request. Appends a new chained entry; history is never edited."""
    if action not in ("approve", "reject"):
        raise ValueError("action must be 'approve' or 'reject'")
    target = next((e for e in entries if e.get("type") == "decision" and e["seq"] == ref), None)
    if target is None:
        raise ValueError(f"no decision with seq {ref}")
    if target["decision"] != "HOLD":
        raise ValueError(f"entry {ref} is {target['decision']}, only HOLD entries can be resolved")
    if ref in resolution_map(entries):
        raise ValueError(f"entry {ref} was already resolved")
    return append(entries, {"type": "resolution", "ref": ref, "action": action, "by": by, "note": note,
                            "time": datetime.now().isoformat(timespec="seconds")})


def resolve(path, ref, action, by="human", note=""):
    entries = read_log(path)
    ok, bad = verify_entries(entries)
    if not ok:
        raise ValueError(f"audit log is tampered at entry {bad}; refusing to extend it")
    entry = resolve_entries(entries, ref, action, by, note)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return entry
