# PROMPT ZA AGENTA — ForkSploit: od vzorčnega fuzzerja do resnega sistema za izkoriščanje

> **Opomba (2026-11-09):** to je **izvirna naloga** (vhodni dokument), ne opis
> trenutnega stanja. Seznam "znanih vrzeli" spodaj odraža stanje **pred**
> delom; več jih je od takrat zaprtih ali delno zaprtih. Za **trenutno,
> preverjeno** stanje glej `PLAN.md` (faze), `OMEJITVE.md` (odprto) in
> `CHANGELOG.md` (zgodovina).

> Ta dokument je **nalog** za agenta (OpenHands ali drug). Kopiraj celotno
> vsebino pod črto v nov pogovor. Namen je konkreten, merljiv in razdeljen na
> faze, ki se zaključujejo z dokazi (testi, merjenja, commiti), ne z
> obljubami.

---

## 0. Kontekst in izhodišče

Deluješ v repozitoriju `ForkSploit` (Rust + Python, LibAFL, lasten fork
`revm`, z3). Trenutno stanje je **bytecode-level iskalnik znanih vzorcev z
izvedbenim slojem** — ne sistem za odkrivanje in izvedbo ekonomsko resničnih
izkoriščanj. To je ugotovljeno in dokumentirano; ne ponavljaj ugotavljanja,
ampak **odpravi vzroke**.

Znane, potrjene vrzeli (vse preveri v kodi sam, preden se lotiš dela):

1. **Ni merjenja gasa.** `revm` fork teče brez gas metering-a
   (`CLAUDE.md`, "Critical External Dependencies"). Posledica: plan, ki v
   simulaciji uspe, lahko na pravi verigi prekorači `block.gasLimit`. To se
   je že zgodilo (plan `C9f53_2`).
2. **Ni mempoola / vrstnega reda / front-runninga.** Zato so sandwich,
   backrun, JIT likvidnost in MEV izven modela.
3. **Simbolično sklepanje (z3) je ozko** (`src/evm/concolic/concolic_host.rs`):
   pokriva calldata, `callvalue`, `caller`, `origin`, simbolični *memory*.
   **Ne** pokriva simboličnega storage-a, simboličnih `CALL` target-ov,
   simboličnih vrnjenih vrednosti, simboličnih bilanc.
4. **Control leak**: fuzzer lahko prestreže klic in *injicira* lastno
   vrnjeno vrednost (`call_allow_control_leak` v `src/evm/host.rs`). Sled,
   najdena tako, lahko "dokaže" prehod skozi `require`, ki na verigi ne
   obstaja.
5. **Mešanje privilegiranega in napadalčevega**: harvest heuristika
   (`HARVESTED_STORAGE_ADDRESSES` v `src/evm/host.rs`) pobira naslove iz
   storage-a tarče v bazen klicateljev; fuzzer lahko postane lastnik in
   pokliče owner-only funkcije. Delno naslovljeno z `owner_impersonation`,
   a vzorec je globlji.
6. **Pattern-based, ne semantic**: ~48 orakljev prepoznava ~37 vnaprej
   kodiranih bytecode vzorcev. Ni AST/source-level semantike za on-chain
   tarče, ni razumevanja protokolske logike, ni razumevanja storage layout-a.
7. **Enonitno** (`src/sync_utils.rs`): glavna zanka je single-threaded;
   multi-core ni implementiran.
8. **Panic-prone** `.unwrap()`/`.expect()` na zunanjih podatkih
   (`CLAUDE.md`: "known outstanding hardening work ... not yet addressed").
9. **Ni formalnega poročanja**: ni severity/CVSS, ni dokaza o izgubi.

Cilj: **ForkSploit mora postati sistem, ki na ETH ali ETC omrežju zna
najdeni resničen plan izvesti do zadnjega koraka** — s ponovljivim,
dokazljivim, gas-ovrednotenim rezultatom — in ki **nikoli ne predstavi
neizvedljive najdbe kot izvedljivo**.

---

## 1. Nediskutabilna pravila (delovna disciplina)

Ta pravila so del naloge. Kršitev = nedokončana naloga.

- **R1 — Dokaz pred trditvijo.** Vsaka trditev v commit sporočilu, dokumentaciji
  ali poročilu mora imeti za sabo ponovljiv dokaz: test, merjenje, izpis iz
  resničnega teka. Brez "should work", "verjetno", "načeloma".
- **R2 — Brez izmišljenih rezultatov.** Če česa ne moreš preveriti, to
  napiši eksplicitno. Nikoli ne navaj številke, ki je nisi izmeril.
- **R3 — Ne skrivaj omejitev.** Če nečesa v tem nalogu ne moreš narediti,
  to jasno zapiši v `OMEJITVE.md` z razlogom, ne pa da tiho izpustiš.
- **R4 — Vsaka faza se zaključi z dokazom.** Faza ni "done", dokler ne
  tečejo testi in ne obstaja zapis merjenja (pred/po).
- **R5 — Nazaj kompatibilno.** Obstoječi testi (Rust + Python) morajo še
  naprej teči. Trenutno: 8 Rust `solution::` testov (zaporedno), 33 Python
  `test_preflight_gate` + 19 drugih suite-ov.
- **R6 — Varnost je tehnična zahteva, ne okras.** Glej razdelek 6. Sistem,
  ki izvaja prave transakcije, mora imeti trde meje, sicer je nevaren tudi
  za lastnega operaterja.

---

## 2. Ciljna arhitektura (kaj mora nastati)

Sistem mora imeti **pet ločenih, preverljivih plasti**. Vsaka plast mora
imeti jasen vmesnik, da se da testirati neodvisno.

```
[1] SEMANTIČNA ANALIZA      -> razume pogodbo, ne le vzorcev
[2] ISKANJE (fuzz+concolic) -> najde kandidate z realnimi omejitvami
[3] DOKAZ (gas + state)     -> dokaže izvedljivost na realnem stanju
[4] IZVEDBA (build+send)    -> izvede do zadnjega koraka, z dokazom
[5] POROČANJE               -> severity, dokaz, reprodukcija
```

Ključno načelo: **plast 3 je obvezna vrata med 2 in 4.** Noben plan ne sme
priti do plasti 4, če ni prestal plasti 3 z realnim gas merjenjem in realnim
state replay-em.

---

## 3. Faze dela (po prioriteti; vsaka je samostojen, zaključen korak)

### FAZA 1 — Gas metering in realnost izvedbe (KRITIČNO, prvo)

**Problem:** brez gasa simulacija laže.

**Naloga:**
1. Vgradi **gas metering** v izvedbeno pot, tako da vsak generiran plan
   nosi **oceno in dejansko porabo gasa** (`gas_estimate`, `gas_used`).
   Če `revm` fork ne omogoča metering-a, uporabi `eth_estimateGas` na
   fork-u kot avtoritativni vir in to jasno dokumentiraj.
2. Vsak plan naj nosi polje `fits_block_gas_limit: bool` in
   `gas_headroom_pct`.
3. Plan, ki ne gre v blok, mora biti **označen** (`oversized_gas`), ne
   izvršen.
4. **Dokaz:** test, ki vzame plan `C9f53_2`-podobne oblike (prekorači
   `block.gasLimit`) in dokaže, da je zdaj označen, ne "confirmed".
   Zapiši meritev pred/po.

**Sprejemni kriterij:** `sim-confirmed` plan, ki prekorači gas, se nikoli ne
prikaže kot izvedljiv.

---

### FAZA 2 — Storage-aware simbolično izvajanje (KRITIČNO)

**Problem:** z3 ne vidi storage-a, zato so owner-gated in state-dependent
poti nedosegljive ali lažne.

**Naloga:**
1. Razširi `concolic_host.rs`: **simbolični SLOAD/SSTORE** — vsaj za
   ključe, ki jih pogodba bere iz calldata (mappingi).
2. **Simbolični `CALL` target** — ko je cilj klica odvisen od calldata,
   modeliraj ga simbolično (do vnaprej določene meje globine).
3. **Odstrani ali omeji control leak kot privzeto vedenje.** Injiciranje
   lažne vrnjene vrednosti mora biti **eksplicitno izklopljeno** za
   `sim-confirmed`; dovoljeno samo v `sim-review` raziskovanju in vedno
   označeno (`requires_control_leak`, kar že obstaja).
4. **Dokaz:** test, kjer je pot do `require` odvisna od vrednosti iz
   storage-a; dokaži, da concolic zdaj najde rešitev **brez** lažne
   vrnjene vrednosti, ali pa eksplicitno poroča, da je ni mogoče najti.

**Sprejemni kriterij:** `sim-confirmed` plan nikoli ne temelji na control
leak-u.

---

### FAZA 3 — Strogo ločevanje napadalec / privilegirana stranka (KRITIČNO)

**Problem:** fuzzer postane lastnik in to javi kot vdor.

**Naloga:**
1. Vpelji **oznako izvora vsakega naslova** v planu:
   `attacker_supplied` | `harvested_from_storage` | `hardcoded_constant`
   | `privileged_role`.
2. `privileged_role` določi tako, da preveri, ali funkcija, ki jo naslov
   kliče, vsebuje `require(msg.sender == <ta naslov>)` ali ekvivalent
   (owner/admin/role). To je **semantični** test, ne heuristika.
3. Plan, kjer je **katerikoli** klicatelj `privileged_role` **in** funkcija
   ni namenjena temu, da jo ta stranka kliče kot del napada, dobi
   `privileged_caller: true` → **nikoli** `sim-confirmed`.
4. **Dokaz:** test na `escapeHatch`-podobni pogodbi: `owner_impersonation`
   in `privileged_caller` morata biti `true`, plan `sim-review`.
5. Nadgradi `owner_impersonation` iz boolean-a v **strukturiran zapis**
   (kdo, iz katerega slota, kateri `require`), da je poročilo uporabno.

**Sprejemni kriterij:** noben plan, ki se zanaša na privilegiran klicatelj,
ni predstavljen kot izvedljiv napad.

---

### FAZA 4 — Semantična analiza (srednja prioriteta)

**Problem:** ~37 bytecode vzorcev ne pokrije poslovne logike.

**Naloga:**
1. Za tarče z **dostopno izvorno kodo** (verificiran bytecode, solc
   artefakti) vpelji **AST-pot**. `src/evm/blaz/offchain_artifacts.rs` že
   zna brati solc izhod — poveži ga z analizo.
2. Prepoznaj **ekonomske invariante**: vsota bilanc == `totalSupply`,
   kolateral >= dolg, AMM `k` se ne sme zmanjšati. Vsaka najdba, ki
   invariant prelomi, je **višje** prioritete od pattern zadetka.
3. Prepoznaj **storage layout** (solc `storage-layout` je že v
   `--combined-json` seznamu v `offchain_artifacts.rs`) in ga uporabi za
   točno branje `owner`/admin slotov, **ne** za heuristično pobiranje
   naslovov.
4. **Dokaz:** na tarči z znanim namernim hroščem (npr. `ERC20TokenChallenge`
   ali `DEXChallenge` iz `test/`) dokaži, da semantična plast najde hrošč,
   ki ga pattern plast spusti.

**Sprejemni kriterij:** vsaj en razred hrošča, ki ga pattern plast
spregleda, je zdaj najden z dokazom.

---

### FAZA 5 — Dokaz izvedljivosti na realnem stanju (KRITIČNO, "zadnji korak")

**Problem:** "confirmed" v simulaciji ni "izvedljivo na verigi".

**Naloga:**
1. Vsak plan, ki kandidira za izvedbo, mora prestati **tri vrata**:
   - **(a) State replay** na byte-identičnem fork-u realnega stanja v
     trenutku izvedbe (že obstaja `simulate_plan_on_fork`).
   - **(b) Gas reality**: `eth_estimateGas` + `block.gasLimit` +
     `baseFee` + prioritetna provizija → plan mora imeti pozitiven neto
     izkupiček **po** gasu.
   - **(c) Neodvisnost od laži**: ni `control_leak`, ni
     `privileged_caller`, ni `owner_impersonation`.
2. Rezultat vrat je **strukturiran dokaz**: `{replayed: bool, gas_used,
   net_profit_wei, blockers: [...]}`.
3. **Dokaz:** zagon na tarči `0x9f5304DA62A5408416Ea58A17a92611019bD5ce3`
   (ETC) — poročilo mora pokazati, da **noben** od dosedanjih "Fund Loss"
   planov ne prestane vrat (kar je resnica: ledger je prazen).
4. **Dokaz:** na kontrolnem testu, kjer je izkoriščanje *res* mogoče
   (npr. namenski `DEXChallenge` z flash loan), dokaži, da vrata **spustijo**
   plan in da je izveden do konca z realnim neto dobičkom.

**Sprejemni kriterij:** obstaja **vsaj en** plan, ki prestane vsa tri vrata
na testni tarči in se izvede do zadnjega koraka z izmerjenim neto
dobičkom — in **noben** lažni plan tega ne naredi na ETC tarči.

---

### FAZA 6 — Zanesljivost in paralelizem (srednja prioriteta)

**Naloga:**
1. Odpravi vse panic-prone `.unwrap()`/`.expect()` na **zunanjih**
   podatkih (RPC, ABI, storage, solc izhod). Vsak mora vrniti `Result` z
   jasnim sporočilom.
2. Vpelji **multi-core** fuzzing (LibAFL to podpira; trenutno je
   namerno enonitno). Vsaka nit mora imeti izolirano stanje; globalno
   stanje naj bo `Atomic`/`Mutex` (že delno narejeno).
3. **Dokaz:** test, ki na namerno pokvarjenem RPC odgovoru (npr. prazen
   `result`, `null`, napačen hex) ne paničari, ampak vrne napako.
4. **Dokaz:** merjenje hitrosti: N jeder → vsaj ~N-krat več izvedenih
   primerov/sekundo (z izmerjeno številko, ne trditvijo).

**Sprejemni kriterij:** ni panik na zunanjih podatkih; merjenje
paralelizma obstaja.

---

### FAZA 7 — Poročanje in reprodukcija (srednja prioriteta)

**Naloga:**
1. Vsaka najdba dobi **strukturirano poročilo**: `severity` (po
   `VulnerabilityRegistry` kategorijah, če obstaja), `confidence_tier`
   (`sim-review`/`sim-confirmed`/`chain-verified`), `proof`
   (`{replay_tx, gas, net_profit}`), `reproduce` (točni koraki).
2. Uvedi novo, najvišjo oznako **`chain-verified`** — rezervirano
   izključno za plan, ki je bil **res izveden na verigi** in je premaknil
   sredstva (izmerjeno, ne ocenjeno).
3. **Dokaz:** primerjava poročila za lažen plan (ETC tarča) in resničen
   plan (testna tarča) — razlika mora biti očitna iz samega poročila.

**Sprejemni kriterij:** `chain-verified` se nikoli ne podeli brez
izmerjenega premika sredstev.

---

### FAZA 8 — Dokumentacija resnice (obvezno, zadnje)

1. Posodobi `CLAUDE.md`, `SKILL.md` in `ZAGON.md` z **dejanskim** stanjem
   po vsaki fazi (ne z načrti).
2. Napiši `OMEJITVE.md`: kaj sistem **še vedno** ne zna, z razlogom in
   predlogom naslednjega koraka.
3. Nikoli ne trdi "popolno" ali "rešeno vse" — naštej, kaj je izmerjeno.

---

## 4. Vrstni red in merila uspeha

| Faza | Prioriteta | Blokira izvedbo? |
|------|-----------|------------------|
| 1 — Gas metering | KRITIČNO | DA |
| 2 — Storage-aware SMT | KRITIČNO | DA |
| 3 — Attacker/privileged | KRITIČNO | DA |
| 5 — Proof gate (3 vrata) | KRITIČNO | DA |
| 4 — Semantična analiza | srednja | NE |
| 6 — Zanesljivost/paralelizem | srednja | NE |
| 7 — Poročanje | srednja | NE |
| 8 — Dokumentacija | obvezno | NE |

**Naloga je uspešna, ko:** obstaja vsaj en plan, ki na **testni** tarči
prestane vse tri vrata (state replay, gas reality, neodvisnost od laži) in
se izvede do zadnjega koraka z **izmerjenim neto dobičkom**; in ko **noben**
lažen plan z ETC tarče tega ne more. Vse ostalo je vmesni korak.

---

## 5. Kaj ne delati

- **Ne** odstranjuj harvest heuristike samo zato, ker dela lažne pozitive —
  brez nje fuzzer ne doseže owner-gated kode. Namesto tega jo **označi** in
  **omeji** na raziskovalni nivo (faze 2 in 3).
- **Ne** dodajaj novih orakljev, dokler faze 1–3 in 5 niso zaprte. Več
  vzorcev na lažnem izvedbenem modelu pomeni več lažnih pozitivov, ne več
  resnice.
- **Ne** poročaj "confirmed" brez gasa in realnega state replay-a.
- **Ne** piši "done" v commit sporočilo, če nisi zagnal testov in zapisal
  meritve.

---

## 6. Varnostne zahteve (tehnično obvezne)

Sistem bo podpisoval in pošiljal **prave** transakcije. Zato mora imeti:

1. **Avtorizacijski obseg.** Izvedba je dovoljena **samo** za tarče, ki so
   vnaprej vpisane v `wallet_policy.py` register, in samo za verige, ki so
   vpisane. Privzeto: **zavrni**. (`enforce_wallet_policy` že obstaja —
   razširi ga na tarče, ne le denarnice.)
2. **Pre-flight je obvezen.** Noben plan ne gre na verigo brez prestane
   plasti 3. `--no-preflight` naj bo **odstranjen** ali preimenovan v
   `--i-know-what-i-am-doing` z dodatno potrditvijo.
3. **Trdi limiti porabe.** Največji gas na transakcijo, največji gas na
   tek, največji `value` na transakcijo — vse konfigurabilno, vse
   **privzeto konzervativno**, vse preverjeno **pred** podpisom.
4. **Simulacija pred vsakim podpisom.** Vsaka transakcija se najprej
   simulira (`eth_call` / fork replay) in šele ob uspehu podpiše.
5. **Idempotenca / nonce disciplina.** Nonce se vodi eksplicitno; ob
   napaki se ne ponavlja naslepo.
6. **Dnevnik (audit log).** Vsaka resnična transakcija se zabeleži:
   kdaj, na kaj, kateri plan, hash, izid, gas. Brez izjeme.
7. **Nikoli ne pošiljaj na tarčo, ki ni izrecno navedena v nalogu.**
   Privzeti način delovanja je **fork-only**; resnična izvedba je
   opt-in za posamezno tarčo.
8. **Brez skrivanja napak.** Če vrata zavrnejo plan, mora biti razlog
   zapisan in viden, ne tiho izpuščen.

Te zahteve niso okras: brez njih "sistem, ki izvede katerikoli plan" pomeni
"orodje, ki lahko izgubi denar na napaki". Resen sistem ima meje **zato ker**
je resen.

---

## 7. Oblika poročila na koncu

Ko končaš (ali ko končaš posamezno fazo), poročaj **strukturirano**:

```
FAZA <n>: <ime>
STATUS: done | delno | blokirano
SPREMEMBE: <datoteke, commit>
DOKAZ: <test, meritev pred/po, izpis iz resničnega teka>
OMEJITVE: <kaj še ne dela in zakaj>
NASLEDNJI KORAK: <konkretno>
```

Brez te oblike poročilo ni sprejeto.

---

## 8. Prvi korak, ki ga naredi takoj

1. Preberi `CLAUDE.md`, `SKILL.md`, `README.md`, `onchain_scripts/auto_pipeline.py`
   in `src/evm/host.rs`.
2. Preveri **vsako** od 9 vrzeli iz razdelka 0 v kodi — in zapiši, kje
   točno je (datoteka:vrstica).
3. Naredi `PLAN.md` z razčlenitvijo faz 1–8 po korakih, z oceno truda in
   odvisnostmi.
4. Začni s **FAZO 1** (gas metering), ker blokira vse ostalo.
5. Po vsaki fazi: testi, meritve, commit z dokazom v sporočilu.

Začni zdaj.
