# Security Policy

## About ForkSploit

ForkSploit is an **audit / offensive-security platform for EVM smart
contracts**. It discovers attack surfaces and *proves* exploitability by
executing the exploit against real chain state and moving recovered funds to a
recovery wallet.

Because ForkSploit **signs and sends real transactions**, the most important
"security" concern is not a bug in ForkSploit itself, but **misuse against
contracts you are not authorised to test**. See the legal notice below.

## Authorised use only

Use ForkSploit **only** on:

- contracts **you own**, or
- contracts for which you have **explicit written permission** from the owner
  (e.g. a security engagement or a bug-bounty program), or
- **test networks** (Sepolia, Mordor, Chapel, …).

Unauthorised use against third-party contracts is illegal. ForkSploit is built
for **defensive** validation — proving a contract is vulnerable *before* funds
are loaded onto it.

## Reporting a vulnerability in ForkSploit

If you find a security issue **in ForkSploit itself** (e.g. a way to make it
sign an unintended transaction, leak a key, or bypass the wallet-policy /
mainnet-confirmation checks), please report it privately:

1. **Do not** open a public issue for a security-sensitive report.
2. Contact the maintainer directly (see the repository owner profile), or use
   GitHub's **Private vulnerability reporting** if it is enabled for this
   repository (*Security → Report a vulnerability*).

Please include:

- a clear description and the impact,
- the exact steps / command / fixture to reproduce,
- the affected version or commit,
- any proof-of-concept (a minimal test is ideal).

We aim to acknowledge reports promptly and will credit reporters who wish to be
named.

## Secrets and key handling

- ForkSploit **never** accepts a raw private key over the dashboard API — only a
  **path** to an existing key file, passed straight through as a CLI argument.
- `onchain_scripts/key.txt`, `*.key`, `keys/`, `wallets.json`,
  `contracts.json`, `rpc_overrides.json`, `attack_wallets.json`,
  `forksploit_settings.json`, `auto_work/` and `logs/` are **gitignored** and
  must never be committed.
- The dashboard binds to `127.0.0.1` only. Never expose that port externally.

## Supported versions

ForkSploit is under active development. Security fixes are applied to the
`main` branch and, where applicable, the latest tagged release.

| Version | Supported |
|---|---|
| latest `main` / latest tag | ✅ |
| older releases | best-effort |
