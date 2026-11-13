---
name: Bug report
about: Report a defect in ForkSploit (NOT a security issue in ForkSploit itself)
title: "bug: "
labels: T-bug
assignees: ""
---

<!--
Do NOT report a security vulnerability in ForkSploit itself here -- see
SECURITY.md (private reporting). This template is for ordinary bugs.
-->

## What happened

A clear and concise description of the bug.

## What you expected

What you expected to happen instead.

## Reproduce

Exact commands / fixtures / inputs, from a clean checkout:

```bash
# e.g.
cargo build --release
./target/release/forksploit evm -t 'tests/evm/.../*' -f
```

## Environment

- ForkSploit version / commit (`./target/release/forksploit --version`):
- Chain (if onchain): `eth` / `etc` / `sepolia` / `mordor` / other
- Rust: `rustc --version`
- OS:
- `z3` version (`pkg-config --modversion z3`):

## Logs / output

Paste the relevant output. For a run, attach the timestamped log from
`onchain_scripts/logs/` (remove any secrets first).

## Checklist

- [ ] I reproduced this on the latest `main`.
- [ ] I removed any private keys / addresses from the logs I pasted.
- [ ] This is not a security vulnerability in ForkSploit itself.
