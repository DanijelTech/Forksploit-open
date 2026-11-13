# Contributing to ForkSploit

Thanks for your interest. ForkSploit is a security tool that signs real
transactions, so contributions are held to a high bar for correctness and
proof. Please read this before opening a pull request.

## Ground rule R1 — proof before claim

**Never** state that something is "done", "fixed", or "works" in a commit
message, a doc, or a PR description without a **reproducible proof**: a test, a
measurement, or a command output. Anything not measured must be labelled as
**unmeasured** in the docs.

## Getting set up

See the README's *Namestitev* (Installation) section. In short:

```bash
# System prerequisites (Debian/Ubuntu)
sudo apt-get install -y libz3-dev pkg-config clang cmake build-essential

rustup toolchain install          # reads rust-toolchain.toml
cargo build --release
pip install -r onchain_scripts/requirements.txt
```

## Before you open a PR

Run the same checks CI runs (see `.github/workflows/ci.yml`):

```bash
# Rust (the 10 network/state-dependent tests are skipped -- they need live RPC)
cargo test --release -- \
  --skip onchain_pair_discovery \
  --skip uniswap::tests::test_get_pair \
  --skip uniswap::tests::test_fetch_uniswap_path \
  --skip endpoints::tests::test_get_balance

# Python (offline; no anvil/solc needed)
cd onchain_scripts && python -m pytest -q

# Shell entry point
bash -n forksploit.sh
bash -n onchain_scripts/server_run.sh
```

`cargo build --release` must stay **warning-clean** (only the third-party
`libafl`/`nom` future-incompat notice is allowed). `cargo fmt` / `cargo clippy`
are **not** CI gates today (the tree is not rustfmt-clean); if you touch Rust,
keep the surrounding style consistent and avoid adding new clippy warnings.

## Code conventions

- **Match the surrounding style**; keep changes minimal and focused.
- **Comments**: only for genuinely non-obvious invariants, workarounds, or
  trade-offs. Do **not** narrate the diff, restate the code, or describe
  history — that belongs in the commit message / PR description.
- **Never** `.unwrap()` / `.expect()` on data from outside the process (RPC
  responses, solc/forge artifacts, ABIs, storage, user presets). Return a typed
  `Result` or a safe default. Remaining `.unwrap()`s are `.parse().unwrap()` on
  static literals, `lock().unwrap()`, or inside `#[cfg(test)]`.
- **No secrets** in code or tests. Never commit key files, wallet/contract
  registries, RPC overrides, or run logs (they are gitignored).
- Rust is pinned by `rust-toolchain.toml`; do not bump it without a reason.

## Tests

- Add a **regression test** for every bug fix and every new behaviour.
- Prove tests are **non-vacuous** where practical: temporarily break the fix
  and confirm the test fails, then restore it.
- Prefer **real code paths** over mocks. A test may use a fake transport (e.g. a
  fake Web3), but the logic under test must run for real.

## Commits and PRs

- Keep commits focused; write a clear subject and body (what changed and why).
- One pull request per issue; update the existing PR rather than opening new
  ones for the same work.
- Link the issue the PR closes.
- If your change touches behaviour, update the relevant docs (`README.md`,
  `AGENTS.md`, `CHANGELOG.md`) in the same PR.

## Reporting bugs / requesting features

Use the repository's issue templates. For a **security** issue in ForkSploit
itself, follow `SECURITY.md` (do not open a public issue).
