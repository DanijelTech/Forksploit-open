# ForkSploit + DAOETC — Celoten status, ugotovitve in načrt

Datum: 2026-11-07 · Tarča: `0x9f5304DA62A5408416Ea58A17a92611019bD5ce3` (Ethereum Classic, chainId 61)

---

## 1. KAJ SPLOH DELAMO (namen)

**Cilj projekta:** preveriti, ali ForkSploit (EVM fuzzer/exploit-synthesis orodje)
proizvaja **RESNIČNE exploit poti**, in ne le "evidence" (dokaze), ki se na
resnični verigi ne obnesejo. Cilj je ugotoviti, katere od najdenih "površin"
(leak surfaces) je mogoče **materializirati** — tj. zamenjati ponarejen
(leak/control-leak) klic z resničnim stanjem na verigi, tako da transakcija
dejansko premakne sredstva.

**Konkretna tarča:** pogodba "DAOETC" na ETC mainnetu, ki jo je ForkSploit
označil kot najbolj obetavno (vseh 19–23 materializacijskih površin je na njej).

**Vprašanje, na katerega odgovarjamo:** Ali kateri od najdenih exploitov
dejansko izprazni pogodbo? (Da/Ne — z dokazom, ne z domnevo.)

---

## 2. KAJ JE FORKSPLOIT (orodje)

Rust (LibAFL + fork revm) + Python pipeline v `onchain_scripts/`.

Ključne komponente:
- **Fuzzer** (Rust): generira "plans" (zaporedja klicev) in najde prehode skozi
  `require` prek **control-leak** (ponarejanje vrednosti, npr. `balanceOf`).
- **`triage_findings.py`** — razvrsti najdbe v tri tiere:
  `RUNNABLE`, `NEEDS_MATERIALIZATION`, `HEURISTIC_ONLY`.
- **`materialize_plan.py`** — iz `NEEDS_MATERIALIZATION` najdb naredi delovni
  seznam receptov (kateri razred: `TOKEN_BALANCE`, `AUTH_GUARD`, `SIGNATURE`,
  `STORAGE_READ`, `NATIVE_UNWRAP` …) in pove, kaj bi bilo treba narediti.
- **`auto_pipeline.py` / `batch_pipeline.py`** — vse skupaj povežeta.

**Ključni pojem:** fuzzer najde prehod skozi `require` tako, da **ponaredi**
(leak) vrednost, ki jo `require` preverja. Taka najdba NI izkoristek — je
**hipoteza**, da bi s pravim stanjem prehod obstajal. Materializacijski sloj
pove, kako bi to stanje dosegli.

---

## 3. KAJ JE TARČA (DAOETC) — rekonstruirana iz bytecode

Runtime bytecode (2319 B) disassemblan s `pyevmasm`; celotna logika prebrana.
Rekonstruirana Solidity je v `/workspace/audit/DAOETC_reconstructed.sol`.

**Stanje (slots):**
| slot | vsebina | vrednost na verigi |
|------|---------|--------------------|
| 0 | `owner` | `0xe79aca5C8cDa44d834efa969906A377Cb987E02E` |
| 1 | `ledger` (ILedger) | `0x180826b05452ce96e157f0708c43381fee64a6b8` |
| 2 | `balances` (mapping) | vse 0 za preverjene naslove |
| 3 | `used` (signature replay) | — |
| 4 | `totalDeposits` | — |
| 5 | `closingTime` | (= timestamp ob deployu) |
| 6 | `extension` | `0xdd7c00` = 14.515.200 s (168 dni) |
| 7 | `whgDonationAddress` | `0xe79aca…` (owner) |
| 8 | `escapeAddress` | `0x87af33960b633469d2524883027b777a433bc11b` |
| 9 | `claimAddress` (+ bit 0xa0 = `sealed`) | `0xe79aca…`, **sealed = TRUE** |

**Funkcije (selektor → ime):**
| selektor | ime | dostop |
|----------|-----|--------|
| 0x02ef6c86 | `calculateWithdraw(address)` | view |
| 0x1554611f | `escapeHatch()` | **owner** |
| 0x3e2640d6 | `extendClosingTime(uint256)` | **owner** |
| 0x3fb27b85 | `seal()` | **owner** |
| 0x57211ac0 | `getPaidOut(address)` | view |
| 0x64dab283 | `getWHGDonationAddress()` | view |
| 0x7e3ef7cd | `getMyBalance(address)` | view |
| 0x884b5dc2 | `fill(uint256[])` | **owner && !sealed** (glej §5) |
| 0x893d20e8 | `getOwner()` | view |
| 0xa6f9dae1 | `transferOwnership(address)` | **owner** |
| 0xc01c1ca3 | `claimRemaining()` | timelock |
| 0xd0e30db0 | `deposit()` | javno (payable) |
| 0xe3ce9714 | `proxyWithdraw(address,uint256,uint8,bytes32,bytes32)` | javno |
| 0xeb8bbd28 | `getTotalFunds()` | view |
| 0xf3fef3a3 | `withdraw(address,uint256)` | javno |

**POPRAVEK (pomembno):** vse "payable" funkcije imajo `require(msg.value == 0)`,
NE `> 0`. Empirično: `escapeHatch` z `value=0` → OK, z `value=1` → REVERT.
(Prejšnja razlaga v mojih zapiskih je bila obrnjena.)

**Končna formula izplačila** (`calculateWithdraw`):
```
B = ledger.balanceOf(a)
T = ledger.totalSupply()          // 1.153e25
S = balances[a]
amount = S * T / totalDeposits    // delež supply-a
if (B < amount) amount = 0        // KAPICA
return amount
```
in `_withdraw`:
```
amt = calculateWithdraw(user)
if (amt > address(this).balance) amt = address(this).balance
balances[user] += amt
fee = amt * 100 / FEE_DENOM       // provizija
whgDonationAddress.call.value(fee)("")
to.call.value(amt - fee)("")
```

**Napaka `proxyWithdraw` (edini potrjeni hrošč):**
```solidity
address signer = ecrecover(h, v, r, s);   // NI preverbe signer != 0
```
→ ponarejena signatura USPE (status 1), a `_withdraw(signer=0, …)` izplača 0.

---

## 4. KAJ JE DOKAZANO (z dokazi, ne domnevami)

Vse preverjeno na **anvil forku ETC** in/ali z `eth_call` na javnem RPC
(nikoli mainnet tx).

1. **`withdraw(address,uint256)` USPE** pri 8M gasa (status 1, 37064 gas) —
   prejšnji "OOG" je bil posledica premajhnega gasa (3M). ETC block limit = 8M.
2. **A izplača 0**, ker je `balanceOf(user)` = 0 in `balances[user]` = 0.
3. **`deposit()` vzame ETH, a NE pripiše `balances[msg.sender]`** — samo
   `totalDeposits += msg.value`. Zato depozit → withdraw vrne 0.
4. **Ledger `0x180826…` ima `totalSupply` = 1.153e25 in `totalAccounts` = 22092,
   a `balanceOf` = 0 za VSAK preverjen naslov** (owner, WHG, slot8, tarča, 0x0).
   Njegov `balanceOf(a)` bere `storage[keccak(a, slot0)]` (potrjeno s sledjo).
5. **`sealed` = TRUE** na obeh pogodbah.
6. **`fill()` NI klicljiv**: reverta za naključnega klicatelja IN za lastnika,
   z `value=0` in `value=1`. Zaklep: `fill` je dovoljen samo ownerju
   **pred** `seal()`. Ker je `sealed=true`, je `fill` trajno mrtev → bilanc
   ni mogoče naložiti.
7. **V uspešnih poteh NI prenosa vrednosti:** samo 3 CALL z `value=0`
   (ecrecover, balanceOf, totalSupply), `SELFDESTRUCT=0`, `CREATE=0`, `STOP`.
8. **Kontrolni test dostopa:** RPC **upošteva `from`** (`transferOwnership` in
   `escapeHatch`: owner → OK, random → REVERT). Torej so testi dostopa veljavni.

**Zaključek:** Vseh 19–23 resničnih površin je v trenutnem stanju pogodbe
**strukturno neizkoristljivih**. Edini potrjeni hrošč (`Unchecked ecrecover(0)`)
sam ne premakne sredstev. To je hkrati **meja fuzzerja**: control-leak je
ponaredil `require`, ki ga resnična veriga ne izpolni.

---

## 5. KAJ JE TREBA ŠE NAREDITI / PREVERITI

### A) Na ForkSploit (orodje)
- [ ] **Potrditi tier-filter fix** (že commitan: `df12879`) — delovni seznam
      mora šteti SAMO `NEEDS_MATERIALIZATION`. Uporabnikov izpis: 23 površin
      / 5870 planov ✓.
- [ ] **`--lookup`** (že commitan: `1bfd775`) — deluje (4byte + User-Agent).
- [ ] **Materializacija `TOKEN_BALANCE` recepta** — trenutno recept pravi
      "priskrbi žetone"; treba je **preveriti, da je za to tarčo fizično
      neizvedljiv** in to vgraditi kot opozorilo (ker `fill` ni klicljiv in
      `balanceOf` je 0). → Dodati "dead-end" zaznavo.
- [ ] **Razširiti `AUTH_GUARD` zaznavo** — 9/19 površin je `AUTH_GUARD`
      (owner-only); orodje naj jih označi `NEEDS_PRIVILEGE` in **ne predlaga**
      materializacije.
- [ ] **Opcijsko: Rust `armCallback`** — omogoči replay poljubnega klica v
      reentrancy oknu. **Ne rešuje te tarče** (izplačilo je 0), je pa prava
      izboljšava za druge tarče. Nizka prioriteta za DAOETC.

### B) Na bytecode / tarči
- [ ] **Poiskati, ali ledger `balanceOf` ni 0 za kateri od 22092 računov.**
      Če obstaja naslov z `balanceOf > 0`, se `TOKEN_BALANCE` recept morda
      materializira. Kandidati: naslovi iz `fill` transakcij (logi na verigi).
- [ ] **Preveriti ledger `fill()` dostop** — če je klicljiv pod kakšnim
      pogojem (npr. `owner || sealed` z drugačno logiko), bi to odprlo pot.
      (Zaenkrat: reverta za vse.)
- [ ] **Preveriti `claimRemaining()`** — timelock `closingTime + extension`.
      Če je `now >= closingTime + 0xdd7c00`, lahko **kdorkoli** sproži prenos
      celotne bilance na `claimAddress` (= owner!). To ni izkoristek (gre
      ownerju), a je treba zabeležiti.

### C) Kje smo se ustavili
- Analiza bytecode tarče: **KONČANA** (vse funkcije in formula znane).
- Empirična verifikacija na forku: **KONČANA** (izplačilo 0, fill mrtev).
- Dokumentacija: **TA DOKUMENT** + `DAOETC_reconstructed.sol` v `/workspace/audit/`.
- Sandbox: `/tmp` se ponastavlja → delo shranjeno v **trajni `/workspace`**.

### D) Kako nadaljevati (konkretni koraki)
1. `cd /workspace/audit && cat AUDIT_STATUS.md` (ta dokument).
2. Za nadaljevanje bytecode analize: `python3 probe*.py` (read-only, javni RPC).
3. Za fork teste: `foundryup` → `anvil --fork-url https://etc.etcdesktop.com
   --chain-id 61 --gas-limit 8000000 --hardfork shanghai`.
4. **Naslednji konkreten korak:** poiskati, ali obstaja naslov z
   `ledger.balanceOf > 0` (prek `fill` logov na verigi). Če NE → tarča je
   dokončno zaprta. Če DA → materializiraj `TOKEN_BALANCE` recept.
5. Alternativa z več potenciala: **usmeriti ForkSploit na DRUGO tarčo** iz
   `HEURISTIC_ONLY` površin, kjer je materializacija lahko izvedljiva.

---

## 6. OPOMBA O SANDBOXU

`/tmp` je na **nepostojnem** overlayu — ob restartu se izbriše (zato je
`/tmp/ForkSploit` in Foundry večkrat izginil). **`/workspace` je trajen**
(`/dev/nvme0n2`, 25 GB). Vse delo je treba shranjevati v `/workspace`.
Disk ni poln (61 GB prosto, 2 % inodov) — težava je bila izključno
nepostojnost `/tmp`.

---

## 7. POPRAVLJENO: panic-i v concolic modulu (2026-11-07)

Commit `8e6a572`. Vsi dosegljivi `panic!`/`expect`/`unwrap` v concolic poti
so zamenjani z **graceful degradacijo** — nepodprt opcode ali nepričakovana
simbolna oblika ne more več sesuti celotnega fuzz run-a.

| Mesto | Prej | Zdaj |
|-------|------|------|
| `expect_bv`/`expect_bool` | `panic!` | konkreten 0 / false |
| `push_ctx` nepodprt opcode | `panic!` | prazen input slice |
| `pop_ctx` prazen ctx | `panic!` | reset simbolnega okvirja |
| `get_input_slice_from_ctx` | `expect("no ctx")` | ničelni slice |
| `on_step` opcode match | `panic!("Unsupported opcode")` | log + skip (0x0c-0x0f, 0x1e-0x1f, 0x21-0x2f, 0x49-0x4f, 0x5c-0x5d, 0xf6-0xf9, 0xfb-0xfc) |
| `ALREADY_SOLVED` RwLock | `expect("concolic crashed")` | `into_inner()` (odpornost na zastrupitev) |
| `ALL_WORKER_THREADS`/`ALL_SOLUTIONS`/`SOURCE_MAP_PROVIDER` | `.unwrap()` | `into_inner()` |
| `ConcolicHost::new` brez ABI | `expect` | prazen input |
| `concolic_stage` metadata/corpus | `.unwrap()`/`.expect` | skip |

**Dokazi (vsi z `cargo build --release` EXIT 0):**
- `concolic-1`: reši omejitev, najde ranljivost, **0 panic**.
- `concolic-2`, `concolic-origin`: **0 panic**.
- `concolic-for`: **0 panic**, 4.1M izvedb @ 14.7k exec/s.
- **DAOETC tarča** (anvil fork ETC, chainId 61): **0 panic**, corpus 23–25
  (= tvojih 23 površin). Najdba: `Integer Overflow: Unchecked MUL at :1029`
  → točno `S * T / totalDeposits` v `calculateWithdraw`.

**Preostalo (ni crash, ampak globina):** `concolic-for` ni našel hrošča v
4.5 min — to je vprašanje moči reševanja (Z3 timeout 1000 ms), ne panika.
