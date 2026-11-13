# A growing library of confirmed techniques

> **⚠️ USE AT YOUR OWN RISK — THE AUTHORS ACCEPT NO LIABILITY.**
> **ForkSploit is provided "AS IS", without warranty of any kind. It signs and
> sends real transactions and can move real funds. You use it entirely at your
> own risk and under your own full responsibility; the authors and copyright
> holders accept NO liability whatsoever for any consequences of its use, misuse
> or inability to use it.**

This file is a **real, readable record**, not a mechanism for "training a model" — the
model does not change by writing here. The purpose is that the next session (human or
agent) reads what has ACTUALLY been successfully verified in the past (PHASE 8 in
`../SKILL.md` was reached), and does not start from scratch.

**Entry rule**: a new entry is added ONLY after PHASE 8 (checking balances BEFORE/AFTER
on the real node) has actually confirmed success. Never add an entry based on "forge
script said SUCCESSFUL" or "ForkSploit said Found vulnerabilities" alone.

## Entry format

```
### <ISO DATE> — <bug_type> on <chain>

- **Target**: <contract address>
- **Recovery wallet**: <address>
- **Amount**: <how much actually arrived, confirmed by PHASE 8>
- **What worked**: <a brief summary of the steps/specifics of this target>
- **Specifics/surprises**: <anything non-standard that would help next time>
```

---

<!-- Entries are added below, newest at the top. -->
