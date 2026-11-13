# PLAN.md — stanje ForkSploita po fazah

> Pravilo (R1/R2): kar ni izmerjeno, je označeno kot **neizmerjeno**; kar ni
> preverjeno v kodi, kot **nepreverjeno**. Ta dokument je **pregled stanja in
> odprtega dela**, ne dnevnik. Zgodovino sprememb vodi `CHANGELOG.md`.

ForkSploit je **avditorno-ofenzivna platforma za EVM pametne pogodbe**:
odkriva napadalne površine in **dokaže** exploitabilnost tako, da exploit
izvede na resničnem stanju verige in pobrana sredstva prenese na recovery
denarnico. Deluje na **Ethereum (ETH)** in **Ethereum Classic (ETC)**, vsak v
**testnet** in **mainnet** različici (Sepolia, Mordor / ETH id 1, ETC id 61),
in pokriva **nativno valuto ter ERC tokene**.

---

## 1. Faze — kaj je zaprto, kaj odprto

| Faza | Prioriteta | Stanje |
|---|---|---|
| **1 — Gas realnost** | kritično | **Delno.** Model `revm` ne meri gasa. Avtoritativna meritev je na Python strani (`eth_estimateGas` + živi `block.gasLimit`, `gas_utils.estimate_gas_limit`), pre-flight vrata prevelik plan označijo z `oversized_gas`. *Manjka:* merjenje v modelu. |
| **2 — Storage-aware SMT** | kritično | **Delno.** Simbolični storage (po naslovu, obstojen čez okvire) in simbolične vrnjene vrednosti klica so zaprte (FAZA 2.1/2.5). *Manjka:* simbolični `CALL` target, simbolične bilance, `keccak256` predslika. |
| **3 — Napadalec / privilegirana stranka** | kritično | **Delno.** `owner_impersonation` + strukturiran `owner_impersonation_detail` + semantični `owner_gated`. *Manjka:* splošen semantični test privilegiranih pogojev onkraj "naslov iz lastnega storage-a". |
| **4 — Semantična analiza** | srednja | **Odprto.** Vgrajeni orakli so vzorec-vezani; deklarativni invariant pokriva le izrazljive oblike. |
| **5 — Proof gate (3 vrata)** | kritično | **Večinoma.** `simulate_plan_on_fork` + gas reality + `atomic_replayable`/`owner_impersonation`; strukturiran `Proof` (`build_proof`) z `blockers`. *Manjka:* agregat dokaza na nivoju celega teka. |
| **6 — Zanesljivost / paralelizem** | srednja | **Rešeno.** Meje zunanjih podatkov utrjene (`Result`); multi-core prek procesne izolacije (`multicore.rs`, `--jobs`, clamp na jedra); concolic na omejenem bazenu (`MAX_CONCOLIC_THREADS = 2`). |
| **7 — Poročanje** | srednja | **Delno.** `chain-verified` obstaja (`is_chain_verified`, test `test_chain_verified.py`). *Manjka:* `severity`/CVSS. |
| **8 — Dokumentacija** | obvezno | **To v teku** — ta dokument, `README.md`, `OMEJITVE.md`, `BLOKATORJI.md`, `CLAUDE.md`, `AGENTS.md`. |

---

## 2. Devet prvotnih vrzeli (iz naloga) — stanje

| # | Vrzel | Stanje |
|---|---|---|
| 1 | Ni merjenja gasa v modelu | Odprto v modelu; nadomeščeno na Python strani (+ `oversized_gas`). |
| 2 | Ni mempoola / front-runninga | Odprto (zunaj modela). |
| 3 | Ozek concolic | Delno — storage + return zaprta; CALL target/balance/keccak odprti. |
| 4 | Control leak injicira lažno vrnjeno vrednost | Omejeno: concolic ne uporablja leak-a; `sim-confirmed` nikoli ne sloni na leaku. |
| 5 | Mešanje privilegiranega in napadalca | Delno rešeno: `owner_impersonation`/`owner_gated` oznaka + strukturiran zapis. |
| 6 | Pattern-based, ne semantic | Odprto (FAZA 4). |
| 7 | Enonitno | Rešeno: procesna izolacija (`--jobs`). |
| 8 | Panic-prone `.unwrap()` na zunanjih podatkih | Pretežno rešeno; ostanek ni na zunanjih podatkih. |
| 9 | Ni formalnega poročanja | Delno: `confidence`/`net_profit_wei`/`chain-verified`; `severity`/CVSS manjka. |

---

## 3. Merila uspeha (razdelek 4 naloga)

Cilj: **vsaj en** plan, ki na testni tarči prestane vsa tri vrata (state
replay, gas reality, neodvisnost od laži) in se izvede z **izmerjenim neto
dobičkom**.

**Stanje: DELNO PREVERJENO.**
- V **čistem sandboxu** tega repozitorija ni RPC egressa, zato meritev tam ni
  mogoča.
- **Zunaj sandboxa je bila izmerjena:** `benchmarks/forksploit_full_live_mordor/`
  je polni tek neposredno na živi ETC Mordor (`CyberScratchLottery`), dva
  neodvisna seed-a; `benchmarks/echidna_vs_forksploit/` primerja z Echidno na
  isti pravi pogodbi — oba neodvisno najdeta isti resnični hrošč (slaba
  naključnost, SWC-120). Glej tudi `OMEJITVE.md` §C2.

---

## 4. Baseline meritev (izmerjeno)

- **Build:** `cargo build --release` → 0 napak, 0 projektnih opozoril.
- **Rust testi:** `cargo test --release` → **140 pass, 10 fail**. Vseh 10 je
  omrežno/stanjsko odvisnih (`onchain_pair_discovery::*` (8),
  `uniswap::{test_get_pair, test_fetch_uniswap_path}`, `endpoints::test_get_balance`)
  in padejo **tudi z egressom**; CI jih preskoči z `--skip`.
- **Python testi:** `pytest onchain_scripts` → **232 pass** (brez `anvil`/`solc`).
- **CI:** `.github/workflows/ci.yml` (GitHub-hosted Linux, brezplačno) teče
  zgornja dva zelena vrata.

---

## 5. Odprto delo (prioritizirano)

1. **FAZA 2.2/2.6** — simbolični `CALL` target in simbolične bilance (concolic).
2. **FAZA 4** — semantična analiza onkraj vzorcev (storage-layout, splošne
   invariante).
3. **FAZA 5** — agregat strukturiranega dokaza čez cel tek.
4. **FAZA 7** — `severity`/CVSS.
5. **Model gas metering** v `revm` (ali trajni zapis gas polj v `PlanMeta`).
6. **Meritev več-jedrnega pospeška** na pravi tarči (trenutno neizmerjeno).

---

## 6. Kaj namenoma NE delamo

- Ne dodajamo novih oraklov, dokler faze 1–3/5 niso zaprte (nalog).
- Ne odstranjujemo harvest heuristike (nalog) — le označujemo jo.
- Ne trdimo ničesar brez meritve (R1). "Ni najdeno" ≠ "ni ranljivosti".
