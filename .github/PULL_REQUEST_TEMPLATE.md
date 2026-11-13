<!--
Thanks for the pull request. Please keep the sections below; delete any that do
not apply. Ground rule R1: do not claim something works without a reproducible
proof (test, measurement, or command output).
-->

## What this changes

A short description of the change and **why**.

## Related issue

Closes #

## How it was verified

Exact commands / tests you ran and their result. Paste the real output.

```bash
# e.g.
cargo test --release -- --skip onchain_pair_discovery --skip uniswap::tests::test_get_pair --skip uniswap::tests::test_fetch_uniswap_path --skip endpoints::tests::test_get_balance
cd onchain_scripts && python -m pytest -q
```

## Checklist

- [ ] `cargo build --release` stays warning-clean.
- [ ] Rust tests pass (network/state-dependent ones skipped as in CI).
- [ ] Python tests pass (`pytest onchain_scripts`).
- [ ] New behaviour / bug fix has a regression test, and I checked it is
      non-vacuous where practical.
- [ ] Docs updated if behaviour changed (`README.md` / `AGENTS.md` / `CHANGELOG.md`).
- [ ] No secrets committed (key files, wallets/contracts registries, RPC
      overrides, run logs).
- [ ] This is not a security fix that should go through SECURITY.md instead.
