# Licensing

ForkSploit is **multi-licensed per component**. Different parts of this
repository are released under different licenses. The license of a file is
determined by **which component (path) it belongs to**, per the table below.
The machine-readable form of this map is [`REUSE.toml`](REUSE.toml); the full
license texts are in [`LICENSES/`](LICENSES/).

> **⚠️ USE AT YOUR OWN RISK — THE AUTHORS ACCEPT NO LIABILITY.**
> **ForkSploit is provided "AS IS", without warranty of any kind. ForkSploit
> signs and sends real transactions and is an offensive-security tool. It can
> cause loss of funds, loss of access, legal consequences, or other harm. You
> use it entirely at your own risk and under your own responsibility. The
> authors and copyright holders accept NO liability whatsoever for any
> consequences of its use, misuse, or inability to use it, to the maximum extent
> permitted by applicable law. See [`DISCLAIMER.md`](DISCLAIMER.md).**

---

## Component → license

| Component / path | License | SPDX identifier |
|---|---|---|
| **Rust core** — `src/`, `benches/` | **AGPL-3.0-or-later** | `AGPL-3.0-or-later` |
| **Python execution layer** — `onchain_scripts/**/*.py` | **Apache-2.0** | `Apache-2.0` |
| **On-chain primitives** — `onchain_scripts/contracts/**/*.sol`, `onchain_scripts/llm_poc/contracts/**/*.sol` | **Proprietary (All Rights Reserved)** | `UNLICENSED` |
| **Dashboard (frontend)** — `onchain_scripts/dashboard_static/**` (JS/HTML/CSS) | **MIT** | `MIT` |
| **Dashboard/express helper** — `server/` (JS) | **MIT** | `MIT` |
| **Documentation** — `docs/**/*.md` | **CC-BY-4.0** | `CC-BY-4.0` |
| **Build/test scripts** — `forksploit.sh`, `onchain_scripts/server_run.sh`, `benchmarks/**/run_benchmark.sh` | **Apache-2.0** | `Apache-2.0` |
| **On-chain proof script** — `onchain_scripts/contracts/proof_w1_w2_w3.sh` | **Proprietary (All Rights Reserved)** | `UNLICENSED` |
| **Skills** — `skills/**` | **CC-BY-4.0** | `CC-BY-4.0` |
| **Third-party code** — `vendor/**` | **MIT OR Apache-2.0** (upstream) | *unchanged* |

Root-level prose documents (this file, `README.md`, `DISCLAIMER.md`,
`SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`,
`AGENTS.md`, `CLAUDE.md`, `PLAN.md`, `LIMITATIONS.md`, `BLOCKERS.md`,
`TASK_SPEC.md`, `backtesting.md`) are covered by the **CC-BY-4.0** documentation
license unless they carry their own header.

Files that carry no SPDX header (Markdown, GitHub templates, JSON) inherit the
documentation license (CC-BY-4.0), **except** third-party material, which keeps
its upstream license.

---

## Why this split

ForkSploit is a **process-separated** system: the Rust core and the Python layer
do **not** link into one binary — they communicate over `subprocess` and files
(`*.plan.json`, `*.t.sol`, …). Legally that means each layer is a **separate
work**, so each can carry its own license without "infecting" the other.

- **Rust core → AGPL-3.0-or-later.** This is the engine that discovers and
  synthesizes exploits. AGPL-3.0 is a strong copyleft: anyone who distributes a
  modified version, **or runs a modified version as a network service (SaaS)**,
  must release their modified source under the AGPL. This protects the project
  against closed forks and against a hosted, closed re-offering, while remaining
  a genuine, OSI-approved open-source license.
- **Python layer → Apache-2.0.** A permissive license with an explicit patent
  grant and attribution requirement. It lets the community freely build tooling,
  integrations and pipelines on top, with legal clarity for corporate
  contributors.
- **On-chain primitives → Proprietary (All Rights Reserved).** `AttackWallet.sol`
  is the one critical on-chain component that moves real funds; it stays under
  the author's control.
- **Dashboard → MIT.** Frontend code with no security-critical logic; MIT
  maximizes contributions and reuse.
- **Documentation → CC-BY-4.0.** Documentation should spread freely, with
  attribution.

---

## What this means in practice

- **Using the Rust core** (including offering a modified core as a service):
  AGPL-3.0-or-later applies — you must provide the corresponding source to your
  users.
- **Using the Python layer** in your own project: Apache-2.0 applies — keep the
  notices; you may use it in closed-source projects.
- **Using `AttackWallet.sol`**: **not permitted** without the author's prior
  written permission.
- **Reusing the dashboard** or **the docs**: MIT / CC-BY-4.0 — keep attribution.

If you want a different combination for your use case, contact the author about a
commercial or alternative license.

---

## Contributing

By submitting a contribution, you agree that it is licensed under the license
that applies to the component you modify (see the table above), and you confirm
you have the right to submit it. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

Because the project is multi-licensed and may offer alternative/commercial
licensing, contributions may require a Contributor License Agreement (CLA) or at
minimum a `Signed-off-by` (DCO) line. This is handled in `CONTRIBUTING.md`.

---

## Third-party notices

ForkSploit depends on third-party Rust crates and Python/npm packages that carry
their own licenses. A representative list is in
[`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md). The `vendor/` directory contains a
patched copy of `serde_traitobject` under its upstream license (**MIT OR
Apache-2.0**) and is **not** relicensed here.

---

## License texts

Full license texts live in [`LICENSES/`](LICENSES/):

- [`LICENSES/AGPL-3.0-or-later.txt`](LICENSES/AGPL-3.0-or-later.txt)
- [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt)
- [`LICENSES/MIT.txt`](LICENSES/MIT.txt)
- [`LICENSES/CC-BY-4.0.txt`](LICENSES/CC-BY-4.0.txt)

The [`REUSE.toml`](REUSE.toml) file records the same mapping in machine-readable
form for the [REUSE](https://reuse.software) tooling.
