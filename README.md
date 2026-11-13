# ForkSploit

<div align="center">

**Avditorno-ofenzivna platforma za pametne pogodbe EVM, ki pod strogim nadzorom operaterja dokaže, da je pogodba ranljiva — in to dokaže z dejanjem.**

**Zgrajen in preverjen za Ethereum (ETH) in Ethereum Classic (ETC) — na obeh testnetih (Sepolia, Mordor) in na obeh mainnetih — ter za vse tipe sredstev: nativno valuto (ETH/ETC) in vse ERC tokene (ERC-20, ERC-721, ERC-1155, ERC-4626 in druge).** ForkSploit dela na obeh omrežjih v obeh različicah (testnet in mainnet) in na vsakem sredstvu, ki ga pogodba uporablja.

<!-- Badges: all values are VERIFIED against the source in this repo (R1).
     47 = entries in OracleType::from_strs "all" (src/evm/mod.rs);
     25 = arms of Chain::from_str (src/evm/onchain/endpoints.rs);
     toolchain = rust-toolchain.toml; license = LICENSE. The CI badge points
     at the "CI" workflow (.github/workflows/ci.yml), which runs on main. -->
[![CI](https://github.com/DanijelTech/ForkSploit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/DanijelTech/ForkSploit/actions/workflows/ci.yml)
[![Rust nightly](https://img.shields.io/badge/Rust-nightly--2026--10--15-000000?logo=rust&logoColor=white)](rust-toolchain.toml)
[![Detectors](https://img.shields.io/badge/attack%20surfaces-47%20oracles-blue)](#napadalne-površine-ki-jih-forksploit-pokriva)
[![Chains](https://img.shields.io/badge/chains-25%20EVM-627EEA)](#verige)
[![Proof](https://img.shields.io/badge/proof-100%25%20on--chain%20exploitability-2ea043)](#zakaj-je-dokaz-drugačen-od-ugibanja)
[![License: Proprietary](https://img.shields.io/badge/license-Proprietary%20(All%20Rights%20Reserved)-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Docker-555)](#namestitev)

</div>

ForkSploit ni fuzzer. Je celovita platforma, ki odgovori na vprašanje, ki ga nobeno statično orodje in noben fuzzer ne zmore odgovoriti z gotovostjo: *"Je ta pogodba res ranljiva, kje točno, kaj vse je exploitabilno, in ali napadalec zares odnese sredstva?"* Odgovor ni verjetnostni — je **determinističen dokaz**, ker ForkSploit exploit ne le najde, ampak ga **izvede na resničnem stanju verige** in pobrana sredstva **prenese na recovery denarnico kot dokaz**.

> **Edinstvena prednost:** ForkSploit je edini znani sistem te vrste, ki poveže *odkritje* in *dokaz izvedbe* v eno neprekinjeno verigo — od napadalne površine v bajtkodu do resničnega premika sredstev na recovery denarnico. In to **na obeh omrežjih — Ethereum (ETH) in Ethereum Classic (ETC) — tako na testnetu (Sepolia, Mordor) kot na mainnetu (id 1 / 61) — ter za vsa sredstva, ki jih pogodba uporablja: nativno valuto (ETH/ETC) in ERC tokene (ERC-20, ERC-721, ERC-1155, ERC-4626).** Rezultat ni "našli smo vzorec, ki bi lahko bil ranljivost", temveč **"ta pogodba je izgubila X ETH/ETC ali X ERC-20/721/1155/4626 tokenov na ta način, tukaj je pot, tukaj je dokaz."**

---

## Kazalo

1. [Kaj ForkSploit je (in kaj ni)](#kaj-forksploit-je-in-kaj-ni)
2. [Obseg podpore: ETH + ETC, testnet + mainnet, vsa sredstva](#obseg-podpore-eth--etc-testnet--mainnet-vsa-sredstva)
3. [Zakaj je dokaz drugačen od ugibanja](#zakaj-je-dokaz-drugačen-od-ugibanja)
4. [Kje v življenjskem ciklu pogodbe nastopi](#kje-v-življenjskem-ciklu-pogodbe-nastopi)
5. [Arhitektura: dve plasti](#arhitektura-dve-plasti)
6. [Napadalne površine, ki jih ForkSploit pokriva](#napadalne-površine-ki-jih-forksploit-pokriva)
7. [Pot dokaza: od najdbe do recovery denarnice](#pot-dokaza-od-najdbe-do-recovery-denarnice)
8. [Varnostni model in nadzor operaterja](#varnostni-model-in-nadzor-operaterja)
9. [Namestitev](#namestitev)
10. [Hitri zagon](#hitri-zagon)
11. [Konfiguracija](#konfiguracija)
12. [Referenca CLI](#referenca-cli)
13. [Pomožna orodja](#pomožna-orodja)
14. [Razvoj, testi in gradnja](#razvoj-testi-in-gradnja)
15. [Omejitve (pošteno)](#omejitve-pošteno)
16. [Pravna in etična uporaba](#pravna-in-etična-uporaba)

---

## Kaj ForkSploit je (in kaj ni)

**Je:**

- **Platforma za odkrivanje napadalnih površin** na pametnih pogodbah EVM — pred deployem (na lokalnem bajtkodu iz `.sol`/`.bin`) in po njem (na živo deployani pogodbi prek RPC-ja, z ali brez izvorne kode).
- **Dokazovalec exploitabilnosti.** Za vsako resnično najdbo generira **strukturiran, ponovljiv plan** (`*.plan.json`) in ga poskusi izvesti. Če uspe in se stanje recovery denarnice realno poveča, je to **dokaz** — ne ocena.
- **Izvajalec.** Plan izvede prek ene, ponovno uporabljene `AttackWallet` pogodbe (deploy + resnični klici, po potrebi z Aave flashloanom za nič kapitala), nato **pobrana sredstva pobere na zaklenjeno recovery denarnico**.
- **Nadzornik po deployu.** `monitor.py` neprekinjeno spremlja živo pogodbo in ob sumu odliva poskusi rešiti še preostala sredstva z že znanimi plani.

**Ni:**

- **Ni generator lažnih alarmov.** Vsaka trditev o exploitabilnosti je vezana na izmerjen premik sredstev. Kar ne premakne vrednosti, se poroča kot `EXECUTED, NO PROFIT` ali `SKIPPED`, nikoli kot potrjen napad.
- **Ni nadomestilo za Foundry/Echidna, a jih dopolnjuje.** Za fuzz testiranje *lastne* izvorne kode v Solidity z ročno pisanimi harnessi ostajata [Foundry](https://github.com/foundry-rs/foundry) in [Echidna](https://github.com/crytic/echidna) odlična izbira — a ForkSploit **ni vezan le na že deployan bajtkod**. Pregleduje **tudi pogodbe pred deployem**: lokalni `.sol` (prevede ga sam) ali `.bin` (že preveden bajtkod) — takšno pogodbo v teku **deploya in napade na svežem stanju**, še preden gre na glavno omrežje. Poleg tega ima **lasten deklarativni invariantni orakel** (`--invariants file.json`, brez Rusta), tako da ekonomske invariante lahko izraziš neposredno v ForkSploitu. Deluje na **Ethereum (ETH)** in **Ethereum Classic (ETC)**, na **testnetu in mainnetu**, ter na **nativni valuti in ERC tokenih** — na lokalnem bajtkodu (pred deployem), na lokalnem/fork stanju in na živi deployani pogodbi (z ali brez izvorne kode).
- **Ni orodje brez nadzora.** Ne podpiše in ne pošlje **ničesar** brez izrecne potrditve operaterja; glej [Varnostni model](#varnostni-model-in-nadzor-operaterja).

---

## Obseg podpore: ETH + ETC, testnet + mainnet, vsa sredstva

To so **ključne informacije** o tem, kje ForkSploit dela in kaj vse pokriva.

### Omrežja — Ethereum in Ethereum Classic, vsako v obeh različicah

| Omrežje | Vrsta | Chain ID | Vloga |
|---|---|---|---|
| **Ethereum (ETH)** | **mainnet** | 1 | Prvorazredno, živo preverjeno |
| **Sepolia** | ETH **testnet** | 11155111 | Prvorazredno, živo preverjeno |
| **Ethereum Classic (ETC)** | **mainnet** | 61 | Prvorazredno, živo preverjeno |
| **Mordor** | ETC **testnet** | 63 | Prvorazredno, živo preverjeno |

Proti tem **štirim** so bili živo preverjeni tako gradnja planov kot izvedba
exploitov. Za vsako od obeh omrežij ForkSploit dela **tako na testnetu kot na
mainnetu** — testnet za varen razvoj in preizkus, mainnet za resnično
validacijo (z `--confirm-mainnet`).

Poleg tega Rust jedro podpira **25 verig** (BSC, Polygon, Arbitrum, Optimism,
Base, Avalanche, Fantom, Gnosis, Celo, Scroll, Linea, Blast, zkEVM, Iotex,
Vana, Story, …), a sta ETH in ETC edini, ki jih projekt obravnava kot
prvorazredni in proti katerima je bila izvedba živo potrjena.

### Sredstva — nativna valuta in ERC tokeni

ForkSploit sledi in pobira sredstva, ki jih ciljna pogodba uporablja:

- **Nativna valuta** — ETH (na Ethereumu) in ETC (na Ethereum Classic),
  vključno s sredstvi, ki jih pogodba drži kot `address(this).balance`.
  Pobira jih `AttackWallet.sweep()` (brez parametra destinacije).
- **ERC-20** — avtomatsko: vsak korak, ki je raw ERC-20 klic
  (`transfer`/`transferFrom`/`approve`/`mint`/`burn`/`skim`) na token pogodbi,
  se označi s `stolen_asset`, po izvedbi pa `AttackWallet.sweepToken()` pobere
  preostanek iz `AttackWallet` na recovery denarnico.
- **ERC-721 / ERC-1155 / ERC-4626** — **zaznava** napadalnih površin je
  pokrita z orakli (`Unauthorized NFT Transfer`, `Unauthorized ERC1155
  Transfer`, `ERC4626 Share Inflation`, `ERC4626 Rounding Favors User`,
  `nft_transfer`, `erc4626`), vključno z `safeTransferFrom`/`setApprovalForAll`
  (ki ju `strategy_layer` prepozna pri urejanju odvisnosti). Opomba (R3):
  avtomatski `sweepToken` je vezan na ERC-20 selektorje; za NFT-je se izvleček
  izvede prek samega exploit plan-a (prenos na recovery denarnico), ne prek
  ločenega "sweep NFT" klica.
- **Wrapped native** (WETH9 / WETC) — odvijanje/zavijanje za flashloan
  financiranje.
- **Aave V3 / Balancer V2** — flashloan za izvedbo brez kapitala napadalca.

### Dvojezično pokritje

Vse zgoraj velja **pred deployem** (na lokalnem `.sol`/`.bin`) in **po njem**
(na živi deployani pogodbi na ETH/ETC mainnetu ali Sepolia/Mordor testnetu),
z ali brez izvorne kode.

---

## Zakaj je dokaz drugačen od ugibanja

Klasična varnostna orodja se ustavijo pri *"to bi lahko bilo ranljivo"*. ForkSploit gre korak dlje in loči tri ravni, ki jih nikoli ne zameša:

| Raven | Kje nastane | Kaj pomeni | Kako se poroča |
|---|---|---|---|
| **Najdba (napadalna površina)** | Rust jedro (revm + 47 oraklov) | Opazen vzorec ali direktno opažena kršitev v simulaciji | `sim-confirmed` / `sim-review` (vedno s predpono `sim-`) |
| **Replayable dokaz** | `*.plan.json` | Vsaka najdba nosi **ponovljivo transakcijsko sled** (kdo, kaj, calldata, vrednost) | polje `evidence: "replayable_transaction_trace"` |
| **Verižni dokaz** | Python izvedbena plast | Realna transakcija je bila poslana in **recovery denarnica je zares dobila sredstva** | `CONFIRMED` + izmerjen `recovery_delta_wei` |

Ključno: raven 1 je **simulacija**. Zato je oznaka `sim-confirmed`, nikoli gola `confirmed`. Raven 3 je **resnica** — edini trenutek, ko ForkSploit trdi, da je pogodba ranljiva, je, ko je sredstvo dejansko prešlo na recovery denarnico.

---

## Kje v življenjskem ciklu pogodbe nastopi

Cilj ForkSploita je **pravočasna, dokazana pot eksploatacije — še preden lastnik naloži glavna sredstva** na pogodbo:

```
   razvoj               PRED DEPLOYEM                DEPLOY             PO DEPLOYU
 ─────────────        ─────────────────────        ──────────        ────────────────────
   .sol/.bin  ───────►  ForkSploit dokaže   ───────►  pogodba  ───────►  monitor.py čuva
                        exploitabilnost                gre na            in ob odlivu rešuje
                        BREZ tveganja                  verigo            preostala sredstva
                             │
                             ▼
                  "ali bo ta pogodba izgubila
                   sredstva, ko jih naložim?"
                             │
                    DA ──────┴────── NE
                     │               │
             dokaz + exploit    negativen rezultat
             na testnetu        (omejen, pošten)
```

ForkSploit tako rešuje ključno poslovno vprašanje: **ali je varno naložiti sredstva na to pogodbo** — in če ni, kje točno je luknja in kako se zapre.

---

## Arhitektura: dve plasti

Delitev je stroga in namerna. Rust **nikoli** ne podpisuje; Python **nikoli** ne odloča o tem, ali je vzorec ranljivost.

### 1. Rust jedro — odkrivanje in sinteza planov

- **Enota fuzzinga je ena transakcija** (`EVMInput`: klicatelj, ciljna pogodba, calldata, vrednost). Večkoračno vedenje nastane **čez genealogijo korpusa** — vsak nov testcase izhaja iz shranjenega VM stanja prejšnjega, zato se stanje akumulira skozi generacije (`full_trace` + `print_txn_corpus` sta privzeti funkciji).
- **Coverage-guided fuzzer** na `revm`, s **concolic/Z3 reševanjem** (`--concolic`, `--concolic-caller`) nad vejami, ki jih naključno mutiranje ne bi zadelo.
- **47 oraklov** (glej [napadalne površine](#napadalne-površine-ki-jih-forksploit-pokriva)) — ob vsaki najdbi Rust izpiše `*.plan.json` z natanko opaženimi koraki.
- **Naslovi in klicatelji so pristranski**: `addresses_pool` preferira deployane kontrakte (75%), klicatelji pa sveže identitete — tako so cross-contract razredi (vault, ki bere `token.balanceOf(self)`, par, ki kliče oba svoja tokena) dosegljivi.
- **Proxy razširitev**: `from_address()` razdre EIP-1967 (impl/beacon), EIP-1822 (UUPS), EIP-1167 (minimal proxy) in EIP-7702, zato fuzzа **implementacijo, ne ~45-bajtnega dispatcherja**.

### 2. Python orkestracija — denarnice, izvedba, dokaz

`auto_pipeline.py` prebere **vse** plane iz `work_dir/vulnerabilities/`, jih prek `strategy_layer.compose_plan()` **združi v en sam logičen, urejen večkoračni plan** (`unlock → neutral → objective → reentrancy zadnji`), ga izvede prek `AttackWallet` in **vsa pridobljena sredstva prenese na recovery denarnico**.

---

## Napadalne površine, ki jih ForkSploit pokriva

ForkSploit preverja **47 napadalnih površin**, implementiranih kot orakli v `src/evm/oracles/`. Vsak je označen s svojo stopnjo zaupanja (`Confirmed` = direktno opažena kršitev, `Review` = heuristika z znanim tveganjem lažnega zadetka).

**Dostop in avtorizacija**

- `access_control` — neavtorizirana sprememba lastnika, preklop pavze, proxy nadgradnja
- `tx_origin` — `tx.origin` phishing bypass
- `initializer_front_run` — front-running inicializatorja
- `centralization_risk` — centralizirane točke odpovedi (Review)
- `ecrecover` — unchecked `ecrecover(0)`
- `signature_malleability`, `signature_replay` — krhkost in ponovitev podpisov
- `forged_proof` — ponarejen Merkle/dokaz

**Izvajanje in nadzor toka**

- `reentrancy`, `readonly_reentrancy` — klasična in read-only reentranca
- `arbitrary_storage_write` — pisanje v poljubno shrambeno mesto
- `storage_collision`, `proxy_integrity`, `proxy_upgrade_hijack` — kolizije shrambe in integriteta proxyja
- `delegatecall`, `delegatecall_target` — injekcija in poljubna tarča delegatecall
- `arb_call`, `arb_transfer` — poljubni klici in prenosi
- `unchecked_call` — nepreverjeni nizkonivojski klici
- `selfdestruct` — samouničenje
- `gas_stipend` — trdo-kodiran gas limit (SWC-134)
- `assert_violation`, `uninitialized_memory` — kršitev `assert` in branje neinicializiranega spomina
- `transient_guard` — napake v transient storage guardih

**Aritmetika in ekonomija**

- `overflow` — celoštevilski preliv
- `precision_loss`, `preview_rounding` — izguba natančnosti in zaokroževanje v korist uporabnika
- `token_accounting_mismatch`, `unbacked_mint`, `forced_eth_accounting` — neskladja v računovodstvu, nekrita kovanca
- `eth_backing` — obljubljena nativna vrednost presega resnično stanje
- `erc20`, `nft_transfer`, `erc4626` — napake v ERC20/721/1155 in ERC4626 (share inflation)
- `curve_virtual_price`, `twap_manipulation`, `price_feed_staleness` — manipulacija cen in zastareli podatki
- `imbalanced_pair` (v2_pair) — neuravnotežen Uniswap par

**Logika in zanesljivost**

- `unbounded_loop`, `revert_in_loop` — neomejene zanke in revert znotraj zanke (DoS)
- `stale_guard` — zastarel števec stražarja (Review)
- `self_referral` — plačilo ne glede na validacijo (dvosmerno opaženo — Confirmed)
- `zero_address_setter` — nastavljanje na naslov nič
- `weak_randomness` — šibka/predvidljiva naključnost (SWC-120)
- `invariant` — **uporabniško deklarirane ekonomske invariante** (`--invariants file.json`), ovrednotene po vsaki transakciji

> **Opomba o pokritosti:** ForkSploit namerno privzeto teče z `--detectors all`. Zgodnja različica je privzeto uporabljala `high_confidence`, a je to povzročilo, da uporabnik "nič ni najdeno" prebere kot "ni ranljivosti" na pogodbi, katere edina resnična najdba je bila izključena iz `high_confidence`. Ožanje iskanja po tihem je slabša napaka kot občasni lažni zadetek.

---

## Pot dokaza: od najdbe do recovery denarnice

ForkSploit izvede naslednjo verigo — vsak korak je viden v terminalu **in** v časovno-žigosani datoteki pod `onchain_scripts/logs/`:

1. **Registracija / deploy.** Iz `.sol`/`.bin` (fresh deploy) ali `0x…` (že deployano). Opcijsko statična analiza (Slither) in financiranje cilja.
2. **Razrešitev proxyja.** `resolve_proxy_chain()` razdre sklad in doda vsako implementacijo kot dodatno tarčo.
3. **Fuzzing.** Zagon Rust jedra z `--run-forever` (ne ustavi se ob prvi najdbi) in concolic reševanjem.
4. **Združevanje planov.** `strategy_layer` združi vse plane v en koherenten večkoračni plan; vsak plan se poskusi tudi **samostojno**.
5. **Pre-flight vrata izplativosti (privzeto VKLOPLJENA).** Preden se katerikoli plan pošlje za res, ga ovrednoti v dveh plasteh:
   - *Metapodatki (brez omrežja):* plan z `atomic_replayable=false`, z več kot enim `msg.sender`, ali z `confirmed_exploitable=false` se preskoči takoj.
   - *Fork-simulacija:* če je `anvil` na voljo, se zažene začasni fork **istega** stanja vozlišča, plan se ponovi korak za korakom, in izmeri se **resnična** delta recovery denarnice **in** resničen porabljen gas. Plan se preskoči, če revertira ali če iztrži manj, kot znaša njegov gas.
6. **Izvedba.** Prek `AttackWallet.executeBatch` (atomsko, v eni transakciji) ali zaporedno (reentranca), po potrebi z **Aave V3 flashloanom** (nič kapitala napadalca).
7. **Pobiranje.** `sweep()` / `sweepToken()` — **brez parametra za destinacijo**, vedno na zaklenjeno recovery denarnico.
8. **Poročilo.** Za vsak plan status + izmerjen dokaz (glej [statuse](#statusi-in-dokaz)).

### Statusi in dokaz

Vsak plan dobi enega od naslednjih statusov, in **le `CONFIRMED` je dokazan napad**:

| Status | Pomen |
|---|---|
| `CONFIRMED` | Resnična, na verigi reproducirana izvedba — recovery denarnica je **izmerjeno** dobila sredstva (`recovery_delta_wei`) |
| `EXECUTED, NO PROFIT` | Vsi koraki so uspeli brez reverta, a saldo recovery denarnice se ni dvignil — **ni** potrjen napad |
| `NOT CONFIRMED` | Revert proti pravemu stanju — verjetno lažni zadetek ali potrebuje drugačne predpogoje |
| `INCONCLUSIVE` | Ni bilo dejansko poskušeno (npr. nerealistična vsota) — ni signal v nobeno smer |
| `SKIPPED, UNPROFITABLE` | Brezplačna pre-flight je že dokazala revert ali neizplativost — **noben** transakcijski ni bil podpisan |
| `SKIPPED, NOT EXTRACTABLE` | Najdeno, a brez izvedljivega koraka za izvlečenje (Review-tier heuristika, ne-predvajljiva ali več-klicateljska sled) |
| `OVERSIZED GAS` | Izmerjen gas presega blok gas limit — fizično ne-vključljivo v en blok |

Za vsako najdbo se zapiše tudi strukturiran dokaz (`build_proof`): `replayed`, `gas_used`, `net_profit_wei`, in `blockers` (npr. `owner_gated`, `owner_impersonation`, `atomic_replayable=false`).

---

## Varnostni model in nadzor operaterja

ForkSploit podpisuje in pošilja resnične transakcije, zato je nadzor operaterja vgrajen v vsako raven — ne kot priporočilo, ampak kot trda pravila v kodi.

### 1. Zaklenjena destinacija profita (`safeWallet`)

`AttackWallet.sol` ima `safeWallet` — naslov, ki se nastavi **enkrat**, ob prvi uporabi, prek `setSafeWallet()` (ponovni klic revertira). Vsaka funkcija, ki pobira sredstva (`sweep()`, `sweepToken()`, `sweepWithBuilderTip()`) **nima parametra za destinacijo** — vse nepogojno pošljejo na `safeWallet`. Noben klicni podatek, niti od ogroženega owner ključa, ne more preusmeriti profita drugam. Sprememba destinacije pomeni deploy nove `AttackWallet`, nikoli klica na tej.

### 2. Pravilo dveh denarnic (`wallet_policy.py`)

Preden kateri koli skript kaj podpiše, je treba enkrat, **za vsako verigo**, zakleniti natanko dve vlogi. Vsak klic `auto_pipeline.py`, `batch_pipeline.py`, `monitor.py` (z `--key`/`--safe-wallet`), `aave_flashloan_runner.py` in `dex_arbitrage_scanner.py` (z `--execute`) pred vsakim podpisovanjem preveri:

1. da naslov, na katerega se razreši `--key` datoteka, ujema z registriranim `funding_wallet` za to verigo,
2. da `--recovery-wallet`/`--safe-wallet` ujema z registriranim `recovery_wallet`.

`--confirm-chain` je obvezen in vanj je treba **ročno vtipkati** isto ime verige kot v `--chain` — anti-tipkarski ukrep, ker sta `eth` in `etc` eno črko narazen in obe resnični mainnet verigi.

### 3. Samodejno zaznavanje omrežja

Ob vsakem zagonu ForkSploit prebere **dejanski `eth_chainId`** s konfiguriranega RPC-ja (`chains.verify_rpc_identity`) in **zavrne** tek ob neujemanju z `--chain` — še preden je karkoli podpisano. Nato vse mehanizme, ki se obnašajo različno po omrežju (Flashbots relay, mempool-privacy preusmeritev, oznaka nativnega žetona, mainnet-potrditev, `--hardfork` za Anvil fork), prilagodi **zaznanemu** omrežju, ne vtipkanemu imenu. To zapre past `eth`/`etc` z obeh strani: napačno ime na pravem RPC-ju in pravo ime na napačnem RPC-ju.

### 4. Stroga mainnet potrditev

Za vsako verigo, ki ni v `TESTNET_CHAINS` (`sepolia`, `chapel`, `mordor`), je obvezen `--confirm-mainnet`. Ta izpiše glasno, nedvoumno ime verige (npr. `ETHEREUM CLASSIC (ETC) mainnet -- this is NOT Ethereum (ETH)`) in zahteva izrecno potrditev.

### 5. Per-plan gas budget

Poraba za gas je za vsak plan omejena na resnično, pred-zagonsko oceno + 10% rezerve (`GAS_BUDGET_MARGIN = 1.10`) — en plan, ena gasfee enota, nikoli neomejeno. Vsak transakcijski gas limit je dodatno clampan na `MAX_GAS_LIMIT = 8_000_000` (realni ETC block limit).

### 6. Poročanje z dokazom (R1)

ForkSploit nikoli ne poroča "potrjeno" brez **izmerjenega** premika sredstev. Kar ni izmerjeno, je označeno kot neizmerjeno. To velja za kodo, dokumentacijo in vsak posamezen izhod.

---

## Namestitev

### Predpogoji

ForkSploit linka sistemski **Z3**. Če ga `z3-sys` ne najde, poskusi zgraditi cel Z3 iz vira — to traja zelo dolgo in pogosto pade. Zato pred gradnjo namesti sistemski Z3, `pkg-config` in C/C++ orodja.

**Debian / Ubuntu:**

```bash
sudo apt-get install -y libz3-dev pkg-config clang cmake build-essential
pkg-config --modversion z3        # mora izpisati različico (npr. 4.13.3.0)
```

**macOS (Homebrew):**

```bash
brew install z3 pkg-config
```

**Opcijsko, priporočeno** (za pre-flight fork simulacijo in W1–W3 dokaz):

- [Foundry](https://github.com/foundry-rs/foundry) (`anvil`, `cast`) — brez `anvil` pre-flight vrata tiho degradirajo v "poskusi" (manjkajoče opcijsko orodje nikoli ne ustavi teka, le naredi ga manj varčnega).
- `solc` (0.8.24) — potreben za `.sol` tarče in za redeploy `AttackWallet`; Python ga pokliče sproti.

### Kloniranje

```bash
git clone https://github.com/DanijelTech/ForkSploit.git
cd ForkSploit
```

### Gradnja

Rust je pripet prek `rust-toolchain.toml` (nightly):

```bash
rustup toolchain install          # prebere rust-toolchain.toml
cargo build --release
./target/release/forksploit evm --help
```

Binarij vgradi git HEAD (`src/build.rs`), zato lahko preveriš, da je svež:

```bash
git rev-parse HEAD
./target/release/forksploit --version    # mora izpisati isto revizijo
```

### Python odvisnosti

```bash
pip install -r onchain_scripts/requirements.txt
```

### Docker (alternativa)

`Dockerfile` že vsebuje vse predpogoje (`libz3-dev libssl-dev pkg-config cmake`) in zgradi tri različice binarne datoteke:

```bash
docker build -t forksploit .
```

---

## Hitri zagon

### Interaktivno (priporočeno): `forksploit.sh`

En sam vstopni point: logotip, nato predletna preveritev okolja (doctor), nato **glavni meni** in 7-koračni čarovnik.

```bash
./forksploit.sh              # čarovnik + predletna preveritev okolja
./forksploit.sh --doctor     # samo preveri okolje in izpiši stanje, brez čarovnika
./forksploit.sh --dry-run    # vse preveri in sestavi ukaz, a ga NE zažene
./forksploit.sh --no-install # predletna preveritev samo POROČA, ničesar ne namešča
```

Glavni meni:

```
1) Nov tek          -> 7-koračni čarovnik
2) Nastavitve       -> privzeta key datoteka / RPC override za verigo
3) Preveri okolje   -> celoten doctor report
4) Pomoč            -> kaj orodje počne in kaj pomenijo koraki
izhod / q           -> prekini
```

Čarovnik zahteva natanko **tri vloge**, preden karkoli podpiše — *kdo financira* (datoteka s privatnim ključem), *kaj se pregleduje* (naslov ali pot), *kam gredo sredstva* (recovery denarnica) — plus verigo, RPC in zaklep wallet policy. Na koncu izpiše povzetek, ki ga potrdiš, preden se požene `auto_pipeline.py` / `batch_pipeline.py`.

### Neposredno: `auto_pipeline.py` (en cilj)

```bash
python3 onchain_scripts/auto_pipeline.py \
    --target 0xAlreadyDeployedContract \
    --key onchain_scripts/key.txt \
    --recovery-wallet 0xYourRecoveryWallet \
    --chain sepolia \
    --confirm-mainnet \
    --fuzz-seconds 300
```

ali z lokalnim `.sol`/`.bin` (fresh deploy):

```bash
python3 onchain_scripts/auto_pipeline.py \
    --target /path/to/MyContract.bin \
    --key onchain_scripts/key.txt \
    --recovery-wallet 0xYourRecoveryWallet \
    --chain sepolia \
    --confirm-mainnet \
    --fund-eth 0.01 \
    --fuzz-seconds 300
```

### Batch: `batch_pipeline.py` (mnogo ciljev)

En funding in en recovery wallet za **celo** serijo (nikoli različen wallet med tarčami):

```bash
python3 onchain_scripts/batch_pipeline.py \
    --targets targets.txt \
    --key onchain_scripts/key.txt \
    --recovery-wallet 0xYourRecoveryWallet \
    --chain sepolia \
    --confirm-mainnet \
    --fuzz-seconds 300
```

`targets.txt`: ena tarča na vrstico (pot do `.sol`/`.bin` ali `0x` naslov).

### Neposredno: Rust binarij

```bash
# Lokalna pogodba iz bajtkoda (brez verige)
./target/release/forksploit evm -t 'tests/evm/erc4626/*' -f -d all

# Živa deployana pogodba (black-box, brez izvorne kode)
./target/release/forksploit evm -t 0xContractAddress -c etc \
    -f -d all --run-forever -w work_dir

# Deklarativne invariante (lastna ekonomska pravila)
./target/release/forksploit evm -t 'tests/evm/two_step/*' -f \
    -d invariant --invariants tests/evm/two_step/invariants.json

# Samodejna izpeljava predpogojev + flashloan + concolic
./target/release/forksploit evm -t 'tests/evm/erc4626/*' -f \
    --auto-setup --concolic --concolic-caller --jobs 3
```

---

## Konfiguracija

### Datoteka s privatnim ključem (`--key`)

Ena vrstica — privatni ključ funding denarnice (hex). Ta denarnica plača **ves** gas. **Nikoli ne commitaj te datoteke** (`.gitignore` že izključuje `onchain_scripts/*.key`, `key.txt`, `keys/`).

```bash
printf '%s\n' '0xYOUR_PRIVATE_KEY' > onchain_scripts/key.txt
chmod 600 onchain_scripts/key.txt
```

### Wallet policy (`onchain_scripts/wallets.json`)

Zakleni funding in recovery vlogi za verigo **enkrat**, preden karkoli podpišeš:

```bash
python3 onchain_scripts/wallet_policy.py register \
    --chain sepolia \
    --confirm-chain sepolia \
    --funding-wallet 0xWalletThatPaysGas \
    --recovery-wallet 0xWalletWhereFundsGo \
    --confirm

python3 onchain_scripts/wallet_policy.py show
python3 onchain_scripts/wallet_policy.py contracts
```

### RPC override (`onchain_scripts/rpc_overrides.json`)

Vsaka veriga ima privzeti javni RPC (`chains.DEFAULT_RPC`). Za svoj endpoint (plačljiv, lokalni anvil fork) nastavi override — prek `forksploit.sh` (meni *Nastavitve*) ali programsko (`chains.set_rpc_override`). Gitignored.

### Invariante (`--invariants file.json`)

Lastna ekonomska pravila, ovrednotena po vsaki ne-revertani transakciji. Operandi: `native_balance`, `literal`, `call`, `sum_over_callers`; operatorji `le/lt/ge/gt/eq/ne`:

```json
{ "invariants": [
  { "name": "balances never exceed supply",
    "op": "le",
    "lhs": { "sum_over_callers": { "sig": "balanceOf(address)" } },
    "rhs": { "call": { "sig": "totalSupply()" } } },
  { "name": "vault solvent",
    "op": "le",
    "lhs": { "sum_over_callers": { "sig": "balances(address)" } },
    "rhs": { "native_balance": true } }
] }
```

- `{"native_balance": true}` — resnično nativno stanje tarče.
- `{"literal": "1000"}` — decimalna ali `0x` konstanta.
- `{"call": {"sig": "...", "args": ["$caller", "0x…", "123"]}}` — en statični klic; `$caller` je klicatelj transakcije.
- `{"sum_over_callers": {"sig": "balanceOf(address)"}}` — klic, ovrednoten enkrat na opaženega klicatelja in seštet (klic mora vzeti natanko en `address`).

### Setup / seed transakcije (`setup.json`)

Nekateri razredi hroščev so dosegljivi šele, ko so pogodbe že povezane (ERC4626 vault z `asset`, inicializiran par). `setup.json` poleg fixture-a deklarira te predpogoje; izvedejo se **enkrat, pred fuzzingom**:

```json
{ "calls": [
  { "to": "Vault", "sig": "setAsset(address)",        "args": ["Asset"] },
  { "to": "Asset", "sig": "mint(address,uint256)",    "args": ["$caller", "1000000000000000000000"] },
  { "to": "Vault", "sig": "deposit(uint256,address)", "args": ["100000000000000000000", "$caller"] }
] }
```

Z `--auto-setup` se povezovalni klici (`setX(address)`) izpeljejo samodejno, brez ročnega `setup.json` (vrednostnih seed-ov `mint`/`deposit` ForkSploit namerno **ne** ugiba).

### Okoljske spremenljivke

| Spremenljivka | Učinek |
|---|---|
| `ETH_RPC_URL` | RPC, ki ga uporabi **Rust** binarij (nepogojno, za vsako verigo) — `auto_pipeline.py` jo nastavi sam iz `chains.get_rpc_url(chain)` |
| `SOLC` / `CAST` | Pot do `solc` / `cast` (privzeto z `PATH`) |
| `OFFCHAIN_POOL_SIZE` | Vzporednost `integration_test.py offchain` |

### Verige

Rust binarij podpira **25 verig** (`Chain::from_str`): `eth`, `goerli`, `sepolia`, `bsc`, `chapel`, `polygon`, `mumbai`, `fantom`, `avalanche`, `optimism`, `arbitrum`, `gnosis`, `base`, `celo`, `zkevm`, `zkevm_testnet`, `blast`, `linea`, `local`, `iotex`, `scroll`, `vana`, `story`, `etc`, `mordor`.

Python orkestracija (`chains.known_chains()`, ki ga uporablja tudi `forksploit.sh` čarovnik) ponuja **21 verig** — vse navedene razen `goerli`, `mumbai`, `zkevm_testnet` in `local`, za katere ni privzetega RPC-ja v `chains.DEFAULT_RPC`. **Prvorazredni** sta dve omrežji, vsako v obeh različicah: **Ethereum (ETH)** mainnet (id 1) / **Sepolia** (11155111) in **Ethereum Classic (ETC)** mainnet (id 61) / **Mordor** (63). Proti njima sta bila živo preverjena tako gradnja planov kot izvedba.

Testna omrežja (varna za podpisovanje brez resnične vrednosti): `sepolia`, `chapel`, `mordor`. Vse ostalo zahteva `--confirm-mainnet`.

---

## Referenca CLI

### `forksploit evm` (Rust jedro)

| Zastavica | Opis |
|---|---|
| `-t, --target <GLOB\|ADDR>` | Glob vzorec ali `0x` naslov tarče (privzeto `none`) |
| `--target-type <TYPE>` | `glob`, `address`, `anvil_fork`, `config`, `setup` (privzeto izpeljano) |
| `-c, --chain-type <CHAIN>` | Veriga (glej [Verige](#verige)) |
| `-u, --onchain-url <URL>` | RPC endpoint (privzeto izpeljan iz `--chain-type`) |
| `-b, --onchain-block-number <N>` | Blok (privzeto `0` = latest) |
| `-k, --onchain-etherscan-api-key <K>` | Etherscan API ključ (za ABI/izvorno kodo) |
| `-d, --detectors <LIST>` | `all` (privzeto), `high_confidence`, ali seznam oraklov |
| `-f, --flashloan` | Omogoči simulirano flashloan |
| `--concolic` | Vklopi concolic/Z3 reševanje |
| `--concolic-caller` | Simbolični klicatelj (eksperimentalno) |
| `--concolic-timeout <MS>` | Časovna omejitev reševanja (privzeto 1000) |
| `--concolic-memory-mb <MB>` | Spominska omejitev Z3 (privzeto 2048; 0 = neomejeno) |
| `--concolic-num-threads <N>` | Število Z3 reševalcev (privzeto 0 = cap `min(2, cores)`) |
| `--invariants <FILE>` | JSON z uporabniškimi invariantami |
| `--auto-setup` | Samodejna izpeljava povezovalnih predpogojev |
| `-r, --replay-file <FILE>` | Ponovi shranjeno sled |
| `-w, --work-dir <DIR>` | Delovna mapa (privzeto `work_dir`) |
| `--run-forever` | Ne ustavi se ob prvi najdbi |
| `--jobs <N>` | Vzporedni fuzzing procesi (procesna izolacija) |
| `--fuzz-seconds <N>` | Časovni proračun kampanje (0 = neomejeno) |
| `--seed <N>` | Naključno seme |
| `--max-call-depth <N>` | Globina taint/concolic analize (privzeto 32) |
| `--spec-id <SPEC>` | EVM spec (npr. `Shanghai` za ETC/Mordor) |
| `--state-comp-file <FILE>` | Referenčno stanje za `state_comparison` orakel |
| `--panic-on-bug` | Panic ob `typed_bug()` |

Celoten seznam: `./target/release/forksploit evm --help`.

### `auto_pipeline.py`

| Zastavica | Opis |
|---|---|
| `--target <PATH\|ADDR>` | **Obvezno.** Pot do `.sol`/`.bin` (fresh deploy) ali `0x` naslov |
| `--key <FILE>` | **Obvezno.** Datoteka s privatnim ključem funding denarnice |
| `--recovery-wallet <ADDR>` | **Obvezno.** Kam se poberejo vsa sredstva |
| `--chain <CHAIN>` | Veriga (privzeto `sepolia`) |
| `--confirm-mainnet` | Obvezno za vsako verigo, ki ni testnet |
| `--fund-eth <ETH>` | Financiraj cilj, če ima nič stanja |
| `--fuzz-seconds <N>` | Čas fuzzinga (privzeto 300) |
| `--detectors <LIST>` | Orakli (privzeto `all`) |
| `--no-preflight` | Izklopi pre-flight vrata izplativosti (obe plasti) |
| `--no-gas-oracle` | Izklopi gas-price oracle (cene iz vozlišča namesto iz raziskovalca) |

### `batch_pipeline.py`

Enako kot `auto_pipeline.py`, le da namesto `--target` sprejme `--targets <FILE>` (ena tarča na vrstico), z **enim** `--key` in **enim** `--recovery-wallet` za celo serijo.

---

## Pomožna orodja

Vsa v `onchain_scripts/`:

| Orodje | Namen |
|---|---|
| `monitor.py` | Neprekinjen nadzor po deployu: zazna odliv salda, novo viden selektor, veliko transakcijo; opcijsko periodično re-fuzza in ob alarmu poskusi rešiti preostala sredstva |
| `strategy_layer.py` | Združi plane v koherenten večkoračni plan (`unlock → neutral → objective → reentrancy zadnji`); argument-level threading, topološko urejanje odvisnosti |
| `triage_findings.py` | Skrči na tisoče planov na peščico resničnih površin in pove, kaj vsako loči od izvedljivega exploita |
| `materialize_plan.py` | Za površine, blokirane z control leak, pove, kateri resnični spremembi stanja nadomestita ponarejen klic |
| `proxy_resolver.py` | Razdre proxy sklad (EIP-1967/UUPS/beacon/EIP-1167/EIP-7702) |
| `gas_utils.py` | Merjenje gasa (`eth_estimateGas`) + `block.gasLimit`, GasBudget, clamp na `MAX_GAS_LIMIT` |
| `gas_oracle.py` | Gas-**cena** iz uradnega raziskovalca (Etherscan v2 za ETH, Blockscout v2 za ETC) |
| `flashbots_bundle.py` | Pravi Flashbots bundle (`eth_sendBundle`/`eth_callBundle`) za atomsko vključitev |
| `chains.py` | Edini vir resnice za verige/RPC; `verify_rpc_identity`, `require_mainnet_confirmation` |
| `wallet_policy.py` | Zaklepi funding/recovery vlogi za verigo; register/show/contracts |
| `aave_flashloan_runner.py` | Validira flashloan-fundable bug proti resničnemu Aave V3 deployment-u |
| `dex_arbitrage_scanner.py` | Cross-DEX arbitražni skener z isto varnostno logiko (zaklenjen profit, gas budget) |
| `dashboard_server.py` | Lokalen web dashboard, ki projicira realno stanje in poganja skripte kot podprocese |
| `deploy_sepolia_demo.py` | Deploy namerno ranljivih demo pogodb na Sepolia (E2E validacija) |
| `gen_chain_fixture.py` | Deterministično generira N-koračni "chain" fixture (merjenje globine) |

---

## Razvoj, testi in gradnja

### Testi

```bash
# Rust unit testi
cargo test --release

# Python unit testi (brez omrežja)
cd onchain_scripts && python -m pytest -q

# W1–W3 dokaz (zahteva anvil + cast + solc)
bash onchain_scripts/contracts/proof_w1_w2_w3.sh

# Integracijski testi
python3 integration_test.py offchain     # brez RPC
python3 integration_test.py onchain      # zahteva RPC + Etherscan ključ
```

**Pričakovano stanje:** `cargo test --release` ima nekaj testov, ki se opirajo na **živo omrežje** (RPC do prave verige) ali na **pripeto živo stanje** (`test_get_balance` primerja točno določeno stanje naslova, ki se je medtem spremenilo). Izmerjeno: ti testi padejo **tudi z omrežnim dostopom** — torej niso uporabni kot CI-vrata. Gre za 10 testov: `onchain_pair_discovery::*`, `uniswap::tests::test_get_pair`, `uniswap::tests::test_fetch_uniswap_path`, `endpoints::tests::test_get_balance`. Vsak *drug* fail je regresija.

### CI (GitHub Actions, 100 % brezplačno)

`.github/workflows/ci.yml` teče na GitHub-hosted `ubuntu-22.04` (brez macOS/Windows in brez self-hosted/EC2 runnerjev) in preverja **samo zelene, deterministične** stvari — brez živega omrežja in brez `anvil`/`solc`/`forge`:

```bash
# 1) Rust: build + testi (omrežno/stanjsko odvisni testi preskočeni)
cargo build --release --features "cmp dataflow evm print_txn_corpus full_trace force_cache real_balance" --no-default-features --locked
cargo test --release -- \
  --skip onchain_pair_discovery \
  --skip uniswap::tests::test_get_pair \
  --skip uniswap::tests::test_fetch_uniswap_path \
  --skip endpoints::tests::test_get_balance
# -> 139 passed, 0 failed

# 2) Python: doctor + pytest (232 passed brez anvil/solc)
./forksploit.sh --doctor --no-install
python -m pytest onchain_scripts -q -p no:cacheprovider
```

**Namenoma NISTA vrat** (na trenutnem drevesu bi bila rdeča, in to ni naloga tega workflowa): `cargo fmt --check` (drevo ni rustfmt-čisto) in `cargo clippy` (obstoječa opozorila).

### Kakovost

```bash
cargo fmt --check
cargo clippy
```

### Feature flagi

Privzeto: `cmp`, `dataflow`, `evm`, `print_txn_corpus`, `full_trace`, `force_cache`, `real_balance`. Pomembnejši neprivzeti: `evaluation`, `ondisk_corpus`, `deployer_is_attacker`, `fuzz_static`, `print_logs`, `z3_debug`, `flashloan_debug`, `no_etherscan`.

```bash
# Produkcijska različica
cargo build --release --features "cmp dataflow evm print_txn_corpus full_trace force_cache real_balance" --no-default-features
```

---

## Omejitve (pošteno)

ForkSploit je močno orodje, a ni čarovnija. Kar **ne** zmore:

- **Ni popolnoma simbolični načrtovalec.** W5 pokriva pogoste družine odvisnosti (approve→transferFrom, deposit→withdraw); splošna sinteza zaporedij z analizo podatkovnih tokov med poljubnimi argumenti ostaja odprta.
- **Simulacijski model nima merjenja gasa.** Zato je avtoritativna številka gasa vozliščev `eth_estimateGas` proti realnemu `block.gasLimit`, ne model.
- **Ni mempool/front-running modela** (sandwich/backrun/JIT so zunaj modela).
- **Concolic je delno storage-aware.** Simbolični SLOAD/SSTORE in simbolične povratne vrednosti klica obstajajo, a `keccak256` se ne obrne, zato je mapping vnos iz uvoženega stanja nedosegljiv.
- **Kontroliran control leak.** Za ne-concolic iskanje control leak ostaja vklopljen po namenu; oznaka + downgrade (FAZA 2.3) zagotavljata, da se taka sled **nikoli** ne predstavi kot `sim-confirmed`.
- **Negativni rezultat je omejen.** "Ni najdeno" pomeni "ni najdeno v tem proračunu s temi orakli", ne "pogodba je brez ranljivosti". ForkSploit to izpiše eksplicitno.
- **Aave flashloan je vezan na verige z živim Aave V3** (`eth`, `sepolia`, in drugi iz `AAVE_V3_POOLS`); ETC/Mordor nimata Aave (preverjeno — ne obstaja).

Podrobnejša, sproti vzdrževana evidenca omejitev in blokatorjev je v `OMEJITVE.md` in `BLOKATORJI.md`.

---

## Pravna in etična uporaba

ForkSploit podpisuje in pošilja **resnične transakcije**, ki lahko premaknejo resnično vrednost. Uporabljaj ga izključno:

- na pogodbah, katerih **lastnik si ti** ali za katere imaš **pisno dovoljenje** lastnika (npr. v okviru varnostnega pregleda ali bug-bounty programa), ali
- na **testnih omrežjih** (Sepolia, Mordor, Chapel).

Recovery denarnica je po delovnem modelu tega projekta vedno lastnikova denarnica — ForkSploit je zgrajen za **obrambno** validacijo in dokazovanje ranljivosti pred naložitvijo sredstev, ne za napad na tuje pogodbe. Neavtorizirana uporaba je nezakonita.

---

## Licenca

**Lastniška licenca — vse pravice pridržane (All Rights Reserved).** ForkSploit,
vključno z izvorno kodo, arhitekturo, algoritmi, hevristikami, logiko odkrivanja
in generiranja exploitov, imenom "ForkSploit", dokumentacijo in vso pripadajočo
intelektualno lastnino, je izključna last avtorja. **Brez predhodnega pisnega
dovoljenja avtorja ni dovoljena nobena uporaba, kopiranje, spreminjanje,
distribucija ali razširjanje** — v celoti ali delno. Podrobnosti v [`LICENSE`](LICENSE).

## Zgodovina sprememb

Celotna zgodovina različic (kaj je dodano, spremenjeno, popravljeno) je v
[`CHANGELOG.md`](CHANGELOG.md). Trenutna različica: **v1.0.0**.
