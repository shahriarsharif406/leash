# Leash: Devpost submission text

**Tagline:** A firewall between AI agents and money.

## Inspiration
Agents are being given payment access, but one poisoned invoice or look-alike vendor can drain an account. Humans have approval chains and audits. Agents have nothing between them and the money.

## What it does
Leash sits in front of the payment API. For every request an agent makes, it returns APPROVE, HOLD for a human, or DENY, with plain-language reasons and a 0-100 risk score. It catches prompt-injection text in memos and invoices, look-alike payees (including digit and Cyrillic swaps), new payees, blocked categories, over-limit amounts, budget breaches, duplicates and bursts of requests. After repeated security flags a circuit breaker freezes the agent. Held requests go to a human approval queue, from the dashboard or the CLI. Every decision, including the human's, is written to a hash-chained audit log, so any later edit or deletion is detected and pinpointed.

A live dashboard lets you act as the agent: try an injection or a look-alike payee and watch Leash respond.

## How we built it
Python, standard library only, zero dependencies. Rules are deterministic and live in a policy file, so decisions are explainable and auditable: no model decides whether money moves. The dashboard is a single self-contained HTML file. Built with Mel.

## Challenges
Keeping decisions explainable when several rules fire at once (any deny wins, a hold needs a human), making look-alike detection catch real tricks (digit swaps, Cyrillic letters, `rn` for `m`) without flagging genuine new vendors, and making the audit chain extensible by humans without ever editing history.

## Accomplishments
A 14-request scenario that exercises every rule end to end, including a frozen agent; 17 automated tests; tamper and deletion detection that points to the exact entry; a live playground and approval queue.

## What's next
A drop-in proxy for real payment APIs and an MCP wrapper for agent frameworks, human approval over Slack or email, per-agent policies, and an optional LLM intent check as a second layer on top of the rules.

## Built with
Python, Mel

## How Mel helped
(Add your real notes here: what you asked Mel to plan, build, debug or test. Judges give 20% for this.)
