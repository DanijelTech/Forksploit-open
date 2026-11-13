# A growing library of confirmed techniques

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
