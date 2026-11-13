# Diagnoza: "2072 planov, 0 potrjenih" ni napaka pipeline-a — to je pravilno vedenje

Datum: 2026-11-07. Vir: živi tek `./forksploit.sh` na ETC mainnet tarči
`0x9f5304DA62A5408416Ea58A17a92611019bD5ce3` + lokalna reprodukcija.

## Kratek odgovor

Pipeline **ni pokvarjen**. ForkSploit je **deloval točno tako, kot je
zasnovan**: našel je 1201–2072 "najdb", a **nobena ni izvedljiv exploit**,
zato jih je vseh 2072 pravilno označil `SKIPPED, NOT EXTRACTABLE`.
To je **odsotnost rezultata, ne napaka**.

## Kaj je dejansko v tistih 2072 planih (reprodukcija)

Reproduciral sem točno ukaz iz pipeline-a (`-d all --concolic --run-forever`)
in dobil **1201 plan.json**. Razčlenitev:

| Kategorija | Število | Kaj pomeni |
|---|---|---|
| `confirmed_exploitable = false` (Review-tier) | **1191 / 1201** | "Stale Guard Counter", "Unchecked Call" ... heuristika, noben oracle ni videl premika sredstev |
| `sim-confirmed`, a `atomic_replayable = false` | **10 / 1201** | najdba se je zanašala na **control leak** (fuzzer si je izmislil povratno vrednost klica) |
| planov z `confirmed_exploitable=true` IN `atomic_replayable=true` IN samo na tarči | **0** | nič izvedljivega |

Dodatno: od 1201 planov jih **1190 vključuje TUJE kontrakte** (ne tarčo):
- `0xe79aca5C...` (755×) = **Gnosis-style multisig** = **LASTNIK tarče** (slot 0)
- `0x87af33960b...` (633×) = **escapeAddress** tarče (slot 8)
- `0x180826b054...` (18×) = **ledger** tarče (slot 1)

## Korenski vzrok (dva, oba "po načrtu")

### 1. Fuzzer namerno "izposodi" lastnikov naslov kot napadalca
`src/evm/host.rs` pri `SLOAD` **pobere konkretne naslove iz storage-a** v bazen
klicateljev (vključno z `owner` iz slota 0). Utemeljitev v kodi je legitimna:
brez tega fuzzer nikoli ne bi dosegel `owner`-gated kode. **Ampak** to pomeni,
da fuzzer pokliče `escapeHatch()` (`0x1554611f`, `require(msg.sender==owner)`)
**kot lastnik** — in to javi kot "Fund Loss".

**To je lažni pozitiv.** Preverjeno na forku:
```
escapeHatch  kot OWNER   -> OK      (sproži, ker je res lastnik)
escapeHatch  kot RANDOM  -> REVERT  (InvalidJump)
```
Fuzzer ni "vdrl" — samo je bil lastnik. `escapeHatch` je **namerna**
funkcija, ne ranljivost.

### 2. Control leak onesposobi vsak atomic replay
10 "sim-confirmed" najdb (`Fund Loss`, `Unchecked ecrecover(0)`) ima
`call_leak != u32::MAX` → `atomic_replayable=false` + `requires_control_leak=true`.
Fuzzer je dosegel globljo pot tako, da si je **izmislil povratno vrednost**
notranjega klica; `AttackWallet` tega **ne more ponoviti** na pravi verigi.
Zato `distinct_callers > 1` (2–18 različnih `msg.sender`).

## Zakaj je "0 confirmed" pravilen izid

`calculateWithdraw` zahteva `ledger.balanceOf(a) >= S*T/totalDeposits`.
Ledger (slot 1) ima **totalSupply, a nič balanc** (potrjeno v prejšnji seji:
`5db8ca1`). Torej **nobenega profita ni mogoče izvleči**, dokler se stanje
ledgerja ne spremeni. Pipeline to pravilno ugotovi in **ne pošlje nobene
prave transakcije** — kar je natanko varnostna lastnost, ne hrošč.

## Kaj TO pomeni za tarčo (dejanski zaključek audita)

- `escapeHatch`, `claimRemaining`, `transferOwnership` — owner-only, **niso**
  ranljivosti.
- Edina resnična šibkost: **`proxyWithdraw` ne preveri `signer != 0`** (v
  rekonstrukciji). A tudi ta vodi v `_withdraw(0x0, ...)`, kjer je
  `calculateWithdraw(0x0)` = 0 (ker `ledger.balanceOf(0x0)` = 0) → **brez profita**.
- **Zaključek: tarča trenutno ni izkoristljiva**, ker je ledger prazen.
  To je ekonomska lastnost, ne omejitev fuzzerja.

## Kaj (če sploh) popraviti

1. **Ne** "popravljati" tega, da fuzzer uporablja lastnikov naslov — to je
   namerno in koristno. Namesto tega bi kazalo **označiti** najdbe, kjer je
   edini "napadalec" prav `owner` tarče: dodati `owner_impersonation: true`
   v plan.json, da Python plast take najdbe loči od pravih.
2. **Ne** zniževati praga `MIN_STREAK_OF_INTEREST` — 1191 Stale Guard
   najdb je šum, a prag je že konservativen (6 zaporednih klicev).
3. Če želiš **prave** najdbe na tej tarči, je treba najprej **napolniti
   ledger** (ekonomski predpogoj), ne spreminjati fuzzerja.

## Reprodukcija

```bash
anvil --fork-url https://etc.etcdesktop.com --chain-id 61 \
      --gas-limit 8000000 --hardfork shanghai --port 8545
./target/release/forksploit evm \
  -t '0x9f5304DA62A5408416Ea58A17a92611019bD5ce3' --target-type address \
  -c etc -u http://localhost:8545 -f -d all -w /tmp/wd --run-forever \
  --concolic --concolic-caller --spec-id Shanghai
# -> /tmp/wd/vulnerabilities/*.plan.json : 1201 planov, 0 izvedljivih
```
