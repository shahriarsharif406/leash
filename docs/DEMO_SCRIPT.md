# 2-minute demo video script

Setup (before recording): `python -m leash serve`, open http://127.0.0.1:8765 in light theme, browser zoom 100%, close other tabs.

| Time | Screen | Say |
|---|---|---|
| 0:00 | Hero | "AI agents are starting to pay for things. But an agent that can spend can be tricked. Leash is a firewall between the agent and the money." |
| 0:12 | Click **Watch an agent get attacked** (Replay) | "Here is an agent's morning. Every request is ruled in milliseconds: green is approved, amber is held for a human, red is denied. Watch the flow diagram and the spend chart update." |
| 0:35 | Circuit-breaker alert appears | "After three security flags, Leash freezes the agent. Even a normal-looking request is now denied." |
| 0:45 | Click a denied row (look-alike or injection) | "Each ruling is explained. This memo hides an instruction to wire money to a new account. A look-alike vendor, `Arnazon`, is caught the same way." |
| 1:00 | Live desk: preset **Hidden instruction**, Evaluate | "I can be the attacker myself. Hidden instruction: denied, risk 100, with the reason." |
| 1:15 | Scroll to **Policy simulator**, drag the cap up | "Finance teams can tune the policy. Raise the limits and the red-team score drops: one attack now gets through, and it tells me which." |
| 1:32 | Red team section | "Fourteen known attacks and four honest payments, replayed against any policy. It exits non-zero in CI, so a bad policy change cannot ship." |
| 1:42 | Terminal: `python -m leash verify out/audit.log`, then edit one character in the log and run it again | "Every decision goes into a hash chain. Edit one entry and verify points to the exact one." |
| 1:52 | Terminal or README: MCP section | "And it plugs into any MCP agent. The agent can ask to pay, but it can never approve its own hold. Rules decide, models don't." |
| 2:00 | End card | "Leash. Built with Mel." |

Tips: record at 1080p, keep the mouse slow, trim any pause longer than a second. If you are short on time, cut the MCP and verify beats first.
