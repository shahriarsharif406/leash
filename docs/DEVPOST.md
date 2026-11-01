# Leash: Devpost submission text

**Tagline:** A firewall between AI agents and money.

## Inspiration
Agents are being given payment access, but one poisoned invoice or look-alike vendor can drain an account. Humans have approval chains and audits. Agents have nothing between them and the money.

## What it does
Leash sits in front of the payment API. For every request an agent makes, it returns APPROVE, HOLD for a human, or DENY, with plain-language reasons and a 0-100 risk score.

It catches prompt-injection text in memos and invoices, fake bank-detail changes, look-alike payees (digit swaps, Cyrillic letters, "rn" for "m"), new payees, blocked categories, over-limit amounts, budget breaches, duplicates, request bursts and structuring (a payment split in two to slip under the limit). After repeated security flags a circuit breaker freezes the agent.

Held requests go to a human approval queue, from the dashboard, the CLI or the SDK. Every decision, including the human's, is written to a hash-chained audit log, so any later edit or deletion is detected and pinpointed.

A built-in red team replays 14 known attacks and 4 honest payments against any policy and scores it (14/14 blocked, 4/4 cleared on the demo policy). It exits non-zero when a policy lets an attack through, so teams can run it in CI on their policy file.

A what-if policy simulator lets a finance team drag limits and see the red-team score and the day's rulings recompute instantly. An MCP server gives any MCP-capable agent a check-before-paying tool (and deliberately no way to approve its own hold), and webhook alerts post to Slack the moment a payment is held or a security flag fires.

A small SDK wraps any payment function so it can only run when policy allows, and gives agents a tool that returns readable results instead of crashing. A modern light and dark dashboard with a one-click replay of the agent's morning lets you watch every ruling land, or act as the agent yourself and attack the policy.

## How we built it
Python, standard library only, zero dependencies. Rules are deterministic and live in a policy file, so decisions are explainable and auditable: no model decides whether money moves. The dashboard is a single self-contained HTML file. Built with Mel.

## Challenges
Keeping decisions explainable when several rules fire at once (any deny wins, a hold needs a human). Making look-alike detection catch real tricks without flagging genuine new vendors. Letting humans resolve held payments without ever editing history, by appending to the chain instead.

## Accomplishments
A 14-request scenario that exercises every rule end to end, an attack scorecard that proves the policy rather than just claiming it, 40 automated tests, tamper detection that points to the exact entry, and a polished dashboard with replay, charts and a live attack desk.

## What's next
A drop-in proxy for real payment APIs, approve and reject buttons inside the Slack alert, per-agent policies, and an optional LLM intent check as a second layer on top of the rules.

## Built with
Python, Mel

## How Mel helped
(Add your real notes here: what you asked Mel to plan, build, debug or test. Judges give 20% for this.)
