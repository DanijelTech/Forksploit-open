# BLOKATORJI.md — zakaj ForkSploit (še) ne zmore "skrite globoke luknje"

> Pravilo R1: vsaka trditev ima ponovljivo meritev (ali simbol, ne krhko
> `datoteka:vrstica`). Pravilo R3: omejitev se zapiše, ne skrije.
> Namen: to je **načrt dela** za P1–P5, ne opravičilo.

---

## 0. Diagnoza v eni povedi

ForkSploit ima **močno in pošteno dokazovalno plast** (dokaz = merjen
porast salda recovery denarnice na pravi verigi) in **šibko iskalno plast**
(eno-transakcijski, vzorčno-usmerjen fuzzer z ročnim setupom in ozkim
concolic-om). Dokaz je dober; iskanje je ozko. Zato scenarij
"na videz čista pogodba s skrito globoko luknjo" **ni zanesljivo pokrit**.

---

## 1. Kaj JE dobro (da ne popravljamo po nepotrebnem)

- **Dokaz je konzervativen in merjen.** `auto_pipeline.execute_plan`
  (`if delta > 0 or gained_tokens`) prizna `PLAN_CONFIRMED` **samo**, če se
  saldo *recovery* denarnice **dejansko poveča** na pravi verigi; sicer
  `EXECUTED, NO PROFIT` ali `NOT CONFIRMED`. To je pravi "proof-before-claim"
  standard.
- **`chain-verified` je izpeljan, ne deklariran.** `auto_pipeline.is_chain_verified`
  (`status, recovery_delta_wei`).
- **Strukturiran `Proof`** z `blockers`. `auto_pipeline.build_proof`.

Te plasti **ne** spreminjamo — nanje se naslanjamo.

---

## 2. Blokatorji (z dokazi)

### B1. Vhod je ENA transakcija (največji blokator)
`struct EVMInput` (`src/evm/input.rs`) opisuje **eno** transakcijo
(`caller`, `contract`, `data`, `txn_value`, `env`). Večkoračnost nastane le
posredno skozi genealogijo korpusa (`sstate`), nikoli kot načrtovana
sekvenca. Scenarij "nastavi → financiraj → napadni" je zato **verjetnostni**,
ne **usmerjen**.

**Meritev (P2, 2026-11-07):** mehanizem genealogije (`TxnTrace::from_idx` +
`cov_stage` replay) **dela in je privzeto vklopljen** (`full_trace` +
`print_txn_corpus`). Na generatorju zaporednih lukenj
(`onchain_scripts/gen_chain_fixture.py`) najdemo zaporedja do **16 korakov**
zanesljivo (glej P2 spodaj za tabelo). Blokator torej ni "večkoračnost ne
dela", ampak: (a) zaporedje je **posledica evolucije**, ne načrt; (b) z
vsemi orakli je prepustnost nizka, zato so globoke verige počasne.

### B2. `setup.json` je ROČNO napisan (in dosegljiv le iz fixture)
`src/evm/setup.rs` dokumentira namen, a `setup.json` se naloži **samo**,
ko je v mapi fixture: `contract_utils.rs` (`path_str.ends_with("setup.json")`),
uporabi pa se prek `loader.setup_spec` v `corpus_initializer.rs`. Pot
`--target 0x...` (živa tarča) tega **nima**: `from_address`
(`contract_utils.rs`) nastavi `setup_spec: None`.

**Pomembna niansa (popravek prve ocene):** pot `--target` **ne** starta iz
praznega stanja — SLOAD se **fork-a leno iz RPC** (`StorageFetchingMode::OneByOne`,
`src/evm/onchain/mod.rs`), zato je *obstoječe* stanje resnično.
Vrzel torej **ni** "napačno stanje", ampak **odsotnost pred-pogojev**:
fuzzer ne more sam izvesti zaporedja dejanj, ki šele *ustvarijo* stanje,
potrebno za luknjo (npr. "najprej deponiraj, nato napadni").
**Dokaz razlike:** v `README.md` (§Samodejna izpeljava predpogojev) — na
`tests/evm/erc4626/` brez `setup.json` **986k izvedb ne najde nič**, z njim
oracle sproži.

### B3. Concolic (Z3) je ozek
`src/evm/concolic/concolic_host.rs` modelira simbolično le
`BALANCE`, `CALLVALUE`, `CALLER`, `ORIGIN`, `calldata` in memory. SLOAD/SSTORE
(opcode `0x54`/`0x55`) bereta/pišeta v
`symbolic_state`. **FAZA 2.1 (2026-11-07, delno):** `symbolic_state` je zdaj
`HashMap<EVMAddress, SymbolicStorage>` — ključen po **naslovu** in obstojen
čez okvire — s simboličnim ključem (`SymbolicStorage::load`/`store`), in
zamenjava operandov SSTORE je odpravljena (revm: ključ na vrhu). Merjeno:
slot, ki ga pogodba zapiše v **prejšnjem klicu**, je zdaj rešljiv z concolic
(izmerjeno v prejšnji seji: concolic 1, brez 0). **FAZA 2.5 (2026-11-07):** simbolične
**vrnjene vrednosti** klica so zdaj pokrite — `RETURN` (0xf3) shrani
callee-jev simbolični memory v okvir, `on_return` ga vstavi v klicočev memory
na `return_offset` CALL-a, `RETURNDATASIZE`/`RETURNDATACOPY` (0x3d/0x3e) ju
izpostavita. Bistvo: vstavljene bajte so **callee-jev lastni** simbolični
memory (vezan na klicočev vhod prek calldata), zato solver invertira callee-jev
izračun, ne ugiba konstante; če `RETURN` ni popolnoma sleden, pade nazaj na
**konkretno**. Merjeno (pred→po, isti `--seed`): `this.helper(y)` vrne `y*2`,
vrata `require(r == SODO)` → pred 0 najdb, po `sim-confirmed`; negativna
kontrola (vrata zahtevajo LIHO, nedosegljivo) → 0 najdb (brez lažnega
pozitiva). **Kaj ostaja (R3):** ni simboličnih `CALL` ciljev (FAZA 2.2) niti
simboličnih **bilanc**; `keccak256` se ne obrne, zato mapping vnos iz
**uvoženega** stanja ostaja nedosegljiv (izmerjeno: 0 z in brez concolic).
Vrednostno pogojene luknje (`require(f(x)==C)` znotraj enega okvira) so bile
in ostajajo dosegljive; **stanjsko** pogojene čez okvire so zdaj prav tako,
razen prek hasha; **vrnjeno-vrednostno** pogojene čez klic so zdaj tudi.
Fiksna fixture-a: `tests/evm/concolic_retval/` (pozitivni) in
`tests/evm_never_pass/concolic_retval_unsat/` (negativni); opomba: velika
konstanta zahteva `--concolic-timeout` > privzetih 1000 ms (glej OMEJITVE 3c).

### B4. Ekonomski orakli so, a VSAKI je ozko vezan na VZOREC
`src/evm/oracles/` ima 47 datotek. **Obstajajo** invariantni orakli, a vsak
preverja **en konkreten, ozko prepoznan vzorec**:
`eth_backing.rs` (vsota `balances(addr)` > nativno stanje; zahteva
`totalSupply()` fingerprint), `unbacked_mint.rs` (`totalSupply()` raste brez
nativnega priliva), `token_accounting_mismatch.rs` (`transferFrom` +
SSTORE z neverificiranim zneskom), `arb_transfer.rs` (neupravičen
`transferFrom`). **Popravek (P4, 2026-11-07):** zdaj OBSTAJA splošen,
konfigurabilen invariant — deklarativen orakel `--invariants <file.json>`
(`src/evm/oracles/invariant.rs`), kjer uporabnik zapiše invariant v JSON
(operandi `native_balance`, `literal`, `call`, `sum_over_callers`), brez
Rusta. **Kaj še manjka (R3):** vgrajeni ekonomski orakli ostajajo
vzorec-vezani; deklarativni invariant pokriva le oblike, izrazljive s temi
operandi (npr. `sum_over_callers(balanceOf)` vs. `native_balance`), ne
poljubne pogodbeno-specifične logike.

### B5. Control leak med iskanjem (za concolic zaprt, FAZA 2.4)
`src/evm/host.rs` `call_allow_control_leak`; razveja izbire je zdaj
`control_leak_bypassed()` (`host.rs`). Za **ne-concolic** iskanje fuzzer
**sme** uporabiti lažno vrnjeno vrednost; taka sled je označena
(`input.call_leak != u32::MAX`) in jo pre-flight zavrne kot NOT EXTRACTABLE,
a med iskanjem še vedno ustvarja šum (namerno — pomaga najti globoke poti).

**FAZA 2.4 (2026-11-07): za concolic je leak med iskanjem IZKLOPLJEN.**
`concolic_stage.rs` dvigne `CONCOLIC_NO_CONTROL_LEAK` za trajanje
`vm.execute` vsakega testcase-a, zato vsak klic med concolic izvedbo steče
skozi resnično kodo callee-ja (`call_forbid_control_leak`) — natanko kot na
verigi. Concolic torej ne more več "rešiti" veje, dosegljive le skozi
ponarejeno vrnjeno vrednost. Dokaz: enotni test
`host::control_leak_bypass_tests::concolic_flag_forces_control_leak_bypass`
+ E2E `tests/evm/concolic-2/` (medpogodbeni `CALL`) še vedno najde
`sim-confirmed` `0x3322`; primerjava z baseline pri istem `--seed` brez
regresije. **Kaj ostaja (R3):** za ne-concolic iskanje leak ostaja (namerno);
tam oznaka + downgrade še vedno preprečita `sim-confirmed` predstavitev.

### B6. Ni časa / vrstnega reda / mempoola
`src/evm/oracle.rs` (opomba o modelu). Sandwich, backrun, JIT, MEV in
več-blokovni hrošči (TWAP, staleness) so izven modela.

### B7. Empirični dokaz "našel + dokazal" — DELNO izmerjen (zunaj sandboxa)

V **čistem** sandboxu tega repozitorija ni RPC egressa, zato tam noben tek ne
more demonstrirati "našel resničen hrošč na živi tarči in ga dokazal".

**A dokaz JE bil izmerjen zunaj sandboxa:** `benchmarks/forksploit_full_live_mordor/`
je **polni** ForkSploit tek neposredno na živi ETC Mordor (`CyberScratchLottery`,
brez anvil forka), dva neodvisna seed-a po 300 s, in
`benchmarks/echidna_vs_forksploit/` primerja ForkSploit z Echidno na **isti**
pravi pogodbi — oba neodvisno najdeta isti resnični hrošč (slaba naključnost,
SWC-120). To je pravi "našel + dokazal" dokaz na živi tarči; glej tudi
`OMEJITVE.md` §C2.

---

## 3. Načrt popravkov (po prioriteti)

| # | Popravek | Naslavlja | Zahtevnost | Status |
|---|---|---|---|---|
| **P1** | Avtomatska izpeljava `setup.json` iz žive tarče | B2 | srednja | **DONE (delno)** |
| **P2** | Planner večkoračnih sekvenc (nastavi→napadni) | B1 | visoka | **DONE (delno)** |
| **P3** | Concolic na storage + vrnjene vrednosti | B3 | visoka | **DONE (delno, 2026-11-07)** — simbolični storage po naslovu, obstojen čez okvire (FAZA 2.1); simbolične vrnjene vrednosti klica (FAZA 2.5); bilance in `CALL` cilj še TODO |
| **P4** | Splošen, konfigurabilen invariantni orakel (ne le nov vzorec) | B4 | srednja | **DONE** |
| **P6** | Concolic brez control leak-a med iskanjem | B5 | nizka | **DONE (FAZA 2.4, 2026-11-07)** — `CONCOLIC_NO_CONTROL_LEAK`; simbolični `CALL` cilj (FAZA 2.2) ostaja TODO |
| **P5** | Empirični dokaz (našel + dokazal) na tarči | B7 | srednja | **DELNO — izmerjen zunaj sandboxa** (`benchmarks/`) |

**Vrstni red izvajanja:** P1 → P4 → P2 → P3 → P5.
Obrazložitev: P1 odklene praktično uporabo na živi tarči; P4 doda najbolj
pogrešano slepo pego (invariante); P2 in P3 sta jedrni Rust spremembi;
P5 je zaključna meritev.

### P1 — izvedeno (delno, 2026-11-07)

`--auto-setup` (`src/evm/auto_setup.rs`) izpelje *povezovalne* predpogoje
(`setX(address)` med deployanimi pogodbami) neposredno iz deployanega nabora
pogodb -- brez ročnega `setup.json` in tudi na poti `--target 0x...`, ki mape
fixture nima. Naslov se izbere: najprej tisti, ki ga pogodba že vsebuje
(`PUSH20`, preskoči precompile `0x01..0x0a`/ničlo), sicer druga deployana
pogodba. Eksplicitni `setup.json`/`--setup-file` ima vedno prednost.

**Dokaz (E2E, resnični binarni program, brez mockov)** —
`python -m unittest onchain_scripts/test_auto_setup.py -v` (2/2 OK):
- na `tests/evm/erc4626/` **brez** `setup.json` izpelje natanko
  `Vault.setAsset(address)` in ga izvede pred fuzzingom;
- brez zastavice ne izpelje nič (izključi lažni pozitiv).

5 offline unit testov v `src/evm/auto_setup.rs` (PUSH20 skener, izbira
naslova, zavrnitev view/ne-address setterjev).

**Omejitev (R3):** NE izpelje klicev, ki premikajo vrednost (`mint`,
`deposit`) -- uganjen napačen predpogoj bi bil zavajajoč; take tarče še
vedno potrebujejo ročni `setup.json`. Izpelje le `set*(address)` z natanko
enim `address` argumentom. Glej `OMEJITVE.md §I` (točka 18).

### P2 — izvedeno (delno, 2026-11-07)

**Izid meritve:** večkoračno iskanje **že deluje** prek genealogije korpusa
(`TxnTrace::from_idx` zapisan v `src/fuzzer.rs`, privzeto pod `full_trace` +
`print_txn_corpus`; `cov_stage`/`minimizer` zaporedje reproducira). P2 zato
**ni** dodal novega mehanizma, ampak ga je **izmeril in dokazal**, ter pošteno
zapisal, kje meja je.

**Dokaz za 2 koraka** -- `onchain_scripts/test_multistep_planner.py` (3/3 OK)
na `tests/evm/two_step/` (`arm()` nato `fire()`; ena transakcija nikoli ne
zlomi `value() <= 1`):
- pozitivno sproži **in** izpisana sled vsebuje oba `arm()` in `fire()`
  (dokaz, da je bil najden pravi *par*, ne ena transakcija);
- negativno (meja `value() <= 2`) ne sproži;
- sonda sproži (dokaz, da negativni izid ni tiho ne-izvajanje).

**Izmerjena globina** (`onchain_scripts/gen_chain_fixture.py <N> <mapa>`,
`-d invariant`, 30 s/tek):

| N | 2 | 3 | 4 | 5 | 6 | 8 | 10 | 12 | 16 |
|---|---|---|---|---|---|---|---|---|---|
| Najdeno | 8/8 | 8/8 | 8/8 | 8/8 | 8/8 | 6/6 | 4/4 | 4/4 | 4/4 |

**Omejitve (R3):** zaporedje je posledica **evolucije korpusa**, ne načrt --
ni ciljne gradnje predpogojev; z **vsemi** orakli je vsaka transakcija dražja,
zato so globoke verige počasne (**neizmerjeno**, koliko manj kot z
`-d invariant`); brez `full_trace`/`print_txn_corpus` genealogije ni. Glej
`OMEJITVE.md §I` (točka 19).

### P4 — izvedeno (2026-11-07)

Dodan deklarativen, uporabniško nastavljiv invariantni orakel:
`src/evm/oracles/invariant.rs`, zagon z `--invariants <file.json>`.
Uporabnik zapiše invariant v JSON (brez Rust): operandi `native_balance`,
`literal`, `call`, `sum_over_callers`; operatorji `le/lt/ge/gt/eq/ne`.
Kršitev se poroča kot `Invariant Violation` pri stopnji `sim-confirmed`.

**Dokaz (E2E, resnični binarni program, brez mockov)** —
`python -m unittest onchain_scripts/test_invariant_oracle.py -v`. Izvirni P4
dokaz je bil **3-scenarijski** nabor; datoteka ima danes **9** testov
(dodani so bili concolic regresijski testi za A6 in FAZO 2.5):
- pozitivno: `tests/evm/eth_backing/` (`creditMyself` brez priliva) → invariant
  sproži (`lhs=1 Le rhs=0 ne drži`);
- negativno: `tests/evm_never_pass/invariant_safe/` (pravilno zavarovana
  banka) → invariant **ne** sproži (ni lažnega alarma);
- sonda: namerno napačen invariant sproži na **isti** varni fixture →
  dokazuje, da je negativni izid pravi "true negative", ne tiho ne-izvajanje.

5 novih offline unit testov v `invariant.rs`; skupni `cargo test --release`
zdaj **140 passed, 10 failed** (10 = obstoječi omrežno/stanjsko odvisni testi).

---

## 4. Merila uspeha (kako vemo, da je popravek resničen)

- P1: `--target 0x...` brez ročnega `setup.json` izdela pred-fuzz klice iz
  živega stanja; merjeno na fixture, kjer prej nič ni našlo.
- P4: vsaj en nov orakel sproži na znanem testnem primeru (regresijski test).
- P2: fuzzer najde par (nastavi, napadni), ki ga eno-transakcijski model ne.
  **IZPOLNJENO (2026-11-07):** `test_multistep_planner.py` (2-koračni par) +
  izmerjena globina do 16 korakov.
- P3: z3 reši `require(sload(k)==C)` pogoj v testu.
- P5: en ponovljiv "našel + dokazal" tek na tarči (ali dokumentirana,
  poštena ovira, če okolje tega ne dopušča).

**R1/R4:** vsak korak se zaključi šele, ko je izmerjen. Kar ni izmerjeno,
ostane označeno kot **neizmerjeno**.

---


## 5. Natančna analiza in načrt popravil za VSE blokatorje (P1–P5)

**Vse v tem poglavju je zapisano z odebeljenim tekstom (zahteva naloge).**

**Poglavje NE spreminja kode — je izključno analiza in načrt.**

**Vse številke truda so INŽENIRSKE OCENE, ne meritve; označene so kot [OCENA]. Kar je preverjeno iz kode, je označeno kot [KODA].**

---

### 5.1 Metodologija ocenjevanja

**Vsak blokator je razbit na konkretne podnaloge. Vsaka podnaloga ima: (a) kaj točno je treba narediti, (b) kje v kodi se dotakne, (c) oceno truda [OCENA], (d) tveganje, (e) odvisnosti, (f) dokaz uspeha (R1). Podnaloge so razvrščene v tri razrede: INŽENIRING (znan recept, ocenljivo), RAZISKAVA (odprt problem, visoko tveganje) in OPERACIJE (izvedba na živi tarči).**

**Skupna koda, ki jo blokatorji zadevajo [KODA]: concolic_host.rs (2195 vrstic), host.rs (2877), fuzzer.rs (797), setup.rs (360), auto_setup.rs (253), invariant.rs (435), multicore.rs (419), concolic_stage.rs (343). Skupaj repozitorij: 49.318 vrstic Rusta + 13.677 vrstic Pythona [KODA].**

---

### 5.2 B1 — Vhod je ENA transakcija (največji blokator)

**Trenutno stanje [KODA]: struct EVMInput (src/evm/input.rs) opisuje eno transakcijo. Večkoračnost nastane posredno prek genealogije korpusa (TxnTrace::from_idx v fuzzer.rs, privzeto pod full_trace + print_txn_corpus). Izmerjena globina: do 16 korakov na generiranem fixture-u. Ni načrtovalnika, ki bi ciljno gradil predpogoje.**

**Razčlenitev na podnaloge:**

**B1.1 [INŽENIRING] — Izrecni "sequence planner" za ZNANE družine odvisnosti. Kaj: v strategy_layer.py (Python) že obstaja order_steps_by_dependencies (approve→transferFrom, deposit→withdraw); Rust stran bi potrebovala isto logiko pri generiranju plana, da bi predpogoje postavila V ISTI plan, ne šele pri združevanju. Kje: src/evm/solution/script_generator.rs, onchain_scripts/strategy_layer.py. Trud: [OCENA] 3–4 tedne. Tveganje: srednje. Dokaz: nov fixture, kjer je uspeh mogoč le s ciljnim vrstnim redom; regresijski test test_multistep_planner.py razširjen.**

**B1.2 [RAZISKAVA] — Splošen načrtovalec s podatkovnim tokom med argumenti (izhod koraka A → vhod koraka B). Kaj: model, ki sledi, kako se vrednost (naslov, količina) prenese iz enega koraka v naslednjega, ne le vrstni red selektorjev. Kje: nova komponenta v Rustu + strategy_layer._thread_address_arguments razširjen. Trud: [OCENA] 4–8 tednov za "lite" (omejene družine); ODPRTO za splošno. Tveganje: zelo visoko. Dokaz: fixture, kjer mora biti izhod A (npr. novo deployan naslov) res vstavljen v calldata B.**

**Načrt popravila B1: najprej B1.1 (znane družine) — to pokrije večino realnih večkoračnih napadov (unlock→use→drain, approve→transferFrom, deposit→withdraw); B1.2 (splošen podatkovni tok) se NE obljublja, ampak dokumentira kot dolgoročno raziskavo. Merilo uspeha: en združen plan, ki sam zlomi invariant, kjer posamezna transakcija ne more.**

---

### 5.3 B2 — setup.json je ROČNO napisan

**Trenutno stanje [KODA]: setup.json se naloži samo iz mape fixture (contract_utils.rs, path_str.ends_with("setup.json")); pot --target 0x… nastavi setup_spec: None. --auto-setup (auto_setup.rs) izpelje LE set*(address) z natanko enim address argumentom (filtri: is_static, is_payable, is_constructor izločeni; abi == "(address)"; ime se začne s set). NE izpelje vrednostnih seed-ov (mint, deposit) niti konstruktorskih argumentov; auto_pipeline.py nima --constructor-args (ima ga le Rust EvmArgs).**

**Razčlenitev na podnaloge:**

**B2.1 [INŽENIRING] — Izpeljava vrednostnih seed-ov iz ABI + stanja. Kaj: za mint(address,uint256)/deposit(uint256,address) izpelji količino iz obstoječega stanja (npr. totalSupply(), balanceOf), ne ugibaj. Kje: src/evm/auto_setup.rs (derive_setup_spec). Trud: [OCENA] 1–2 tedna. Tveganje: srednje (uganjen napačen predpogoj je slabši od nič — zato koda to namerno preskakuje). Dokaz: na tests/evm/erc4626/ z --auto-setup (brez ročnega setup.json) oracle sproži.**

**B2.2 [INŽENIRING] — Konstruktorski argumenti na poti --target. Kaj: auto_pipeline.py naj podpre --constructor-args (že obstaja v Rust EvmArgs, manjka v Python orkestraciji). Kje: onchain_scripts/auto_pipeline.py (build_parser, deploy). Trud: [OCENA] 2–4 dni. Tveganje: nizko. Dokaz: deploy fixture-a z ne-tivialnim konstruktorjem.**

**B2.3 [INŽENIRING] — Izpeljava povezav onkraj set*(address). Kaj: podpri initialize(address,address), setPair(token0,token1) z dvema naslovoma. Kje: auto_setup.rs. Trud: [OCENA] 1 teden. Tveganje: srednje. Dokaz: fixture z dvema naslovnima argumentoma.**

**Načrt popravila B2: B2.1 + B2.2 + B2.3 skupaj ≈ 2–3 tedne; to zapre praktično večino "povezovanje + financiranje" predpogojev. Ostane ročni setup.json le za povsem specifične protokolske sekvence.**

---

### 5.4 B3 — Concolic (Z3) je ozek

**Trenutno stanje [KODA]: simbolični so calldata, callvalue, caller, origin, memory, storage (simbolični ključ, obstojen čez okvire) in vrnjene vrednosti klica (FAZA 2.1/2.5). V concolic_host.rs: SHA3 (0x20) je concrete_eval!(2, 1) → keccak256 se NE obrne; BALANCE (0x31) je concrete_eval!(1, 1) → bilance niso simbolične; push_ctx bere naslov iz konkretnega stacka → CALL target ni simboličen.**

**Razčlenitev na podnaloge:**

**B3.1 [INŽENIRING] — Simbolični CALL target (FAZA 2.2). Kaj: če je naslov na stacku simboličen, ga modeliraj kot BV in ga omeji na "deployan kontrakt / znan naslov". Kje: concolic_host.rs (push_ctx, construct_input_from_abi). Trud: [OCENA] 1–2 tedna. Tveganje: srednje (kombinatorna eksplozija možnih tarč). Dokaz: vrata, ki zahtevajo klic točno določene pogodbe izmed več; concolic reši.**

**B3.2 [INŽENIRING] — Simbolične bilance (FAZA 2.6). Kaj: BALANCE (0x31) naj vrne simbolično BV vezano na symbolic_state/balance_cache, ne konkreten. Kje: concolic_host.rs opcode 0x31. Trud: [OCENA] ~1 teden. Tveganje: nizko–srednje. Dokaz: vrata require(self.balance == C); concolic reši.**

**B3.3 [RAZISKAVA] — keccak256 predslika (mapping vnos iz uvoženega stanja). Kaj: Z3 nima nativnega keccaka; modeliranje kot bitno vezje je eksplozivno. Kje: concolic_host.rs opcode 0x20. Trud: [OCENA] meseci / morda NEDOSEGLJIVO. Tveganje: zelo visoko. Priporočilo: NE obljubljati; dokumentirati kot trajno omejitev (že v OMEJITVE.md §A5). Alternativa [OCENA] 2–3 tedne: posebna obravnava branja znanega (contract, slot) para iz uvoženega stanja prek storage-layout (FAZA 4), ne prek inverzije hasha.**

**Načrt popravila B3: B3.1 + B3.2 ≈ 2–3 tedne in odpirata medpogodbene poti (največja praktična vrednost). B3.3 se NE načrtuje kot inženirski popravek — je raziskovalni problem; namesto tega storage-layout alternativa (FAZA 4) pokrije najpogostejši realni primer.**

---

### 5.5 B4 — Ekonomski orakli so vzorec-vezani

**Trenutno stanje [KODA]: 47 oraklov, vsak preverja en vzorec (eth_backing, unbacked_mint, token_accounting_mismatch, arb_transfer). Deklarativni invariant (invariant.rs, --invariants) je dodan (P4), a podpira le operande native_balance, literal, call, sum_over_callers — ni operanda za branje poljubnega storage slota niti za več-koračne izraze.**

**Razčlenitev na podnaloge:**

**B4.1 [INŽENIRING] — Nov operand storage_slot(contract, slot). Kaj: invariant naj bere poljuben storage slot kot operand. Kje: src/evm/oracles/invariant.rs (Operand, evaluacija). Trud: [OCENA] ~1 teden. Tveganje: nizko. Dokaz: invariant, ki primerja slot z totalSupply().**

**B4.2 [INŽENIRING] — Aritmetični izrazi med operandi (seštevanje, množenje). Kaj: npr. sum_over_callers(balanceOf) * price <= native_balance. Kje: invariant.rs (nov Expr sloj). Trud: [OCENA] 1–2 tedna. Tveganje: srednje. Dokaz: invariant z zmnožkom.**

**B4.3 [RAZISKAVA] — Splošno semantično razumevanje protokola. Kaj: zahtevalo bi razumevanje SPECIFIČNEGA protokola (Aave collateral factor vs. Compound) — v nasprotju z identiteto "bytecode-only". Trud: [OCENA] odprto. Priporočilo: NE (izven obsega po nove-oracle-roadmap.md).**

**Načrt popravila B4: B4.1 + B4.2 ≈ 2–3 tedne; to razširi deklarativni invariant na večino ekonomskih oblik, brez da bi šli v protokol-specifično semantiko (B4.3 se zavrne kot izven obsega).**

---

### 5.6 B5 — Control leak med iskanjem

**Trenutno stanje [KODA]: za concolic je leak izklopljen (CONCOLIC_NO_CONTROL_LEAK, FAZA 2.4); za ne-concolic iskanje ostaja (namerno), a je označen (input.call_leak != u32::MAX) in pre-flight ga zavrne kot NOT EXTRACTABLE, sim-confirmed se nikoli ne nasloni nanj (FAZA 2.3).**

**Razčlenitev na podnaloge:**

**B5.1 [INŽENIRING] — Preusmeritev "leak" poti v materializacijo. Kaj: ko iskanje uporabi leak, samodejno sproži materialize_plan.py logiko (že obstaja), da se ponarejen klic nadomesti z resnično spremembo stanja. Kje: onchain_scripts/auto_pipeline.py + materialize_plan.py. Trud: [OCENA] 1–2 tedna. Tveganje: srednje. Dokaz: plan z leak-om, ki se uspešno materializira in potrdi.**

**B5.2 [INŽENIRING] — Zmanjšanje šuma pri ne-concolic iskanju. Kaj: omejitev globine/hitrega izstopa, da leak ne ustvarja preveč planov. Kje: concolic_stage.rs, host.rs. Trud: [OCENA] 1 teden. Tveganje: nizko. Dokaz: merjenje upada števila leak-planov.**

**Načrt popravila B5: B5.1 (avtomatska materializacija) je ključna — spremeni "leak = neuporabno" v "leak = kandidat za materializacijo". B5.2 je kakovost življenja. ≈ 2–3 tedne.**

---

### 5.7 B6 — Ni časa / vrstnega reda / mempoola

**Trenutno stanje [KODA]: revm model nima mempoola, vrstnega reda, front-runninga, več-blokovnega časa. Sandwich, backrun, JIT, MEV in več-blokovni hrošči (TWAP, staleness) so izven modela.**

**Razčlenitev na podnaloge:**

**B6.1 [RAZISKAVA] — Model več-blokovnega časa. Kaj: omogoči, da fuzzer variira block.timestamp/block.number čez bloke (za TWAP/staleness). Kje: src/evm/input.rs (Env), host.rs. Trud: [OCENA] 2–3 tedne. Tveganje: srednje. Dokaz: TWAP oracle se sproži šele z variacijo časa.**

**B6.2 [RAZISKAVA] — Mempool/front-running model. Kaj: simulacija tekmovalnih transakcij v istem bloku. Trud: [OCENA] 4–6 tednov. Tveganje: visoko. Priporočilo: NIZKA prioriteta (nalog tega ne zahteva; oracle.rs to že označuje kot izven modela).**

**Načrt popravila B6: B6.1 (čas) je smiseln za TWAP/staleness orakle; B6.2 (mempool) je velik, nizko-prioriteten projekt — dokumentirati, ne načrtovati takoj.**

---

### 5.8 B7 — Empirični dokaz "našel + dokazal"

**Trenutno stanje [KODA]: v čistem sandboxu ni RPC egressa; zunaj sandboxa JE izmerjen (benchmarks/forksploit_full_live_mordor/ — polni tek na živi ETC Mordor; benchmarks/echidna_vs_forksploit/ — primerjava z Echidno, oba najdeta isti resnični hrošč SWC-120).**

**Razčlenitev na podnaloge:**

**B7.1 [OPERACIJE] — Ponovljiv "našel + dokazal" na testnetu (Sepolia/Mordor). Kaj: skriptiran E2E tek z znano ranljivo demo pogodbo. Kje: nov skript v benchmarks/. Trud: [OCENA] ~1 teden. Tveganje: srednje (zahteva financirano denarnico). Dokaz: izmerjen dvig recovery denarnice.**

**B7.2 [OPERACIJE] — Avtomatizirano poročilo dokaza. Kaj: agregat Proof čez cel tek (že obstaja per-plan build_proof). Kje: auto_pipeline.py. Trud: [OCENA] 3–5 dni. Tveganje: nizko.**

**Načrt popravila B7: B7.1 + B7.2 ≈ 1–1,5 tedna; to zapre "dokaz je bil izmerjen" v ponovljiv, skriptiran artefakt.**

---

### 5.9 Zbirni načrt popravil in prioritete

**Tabela spodaj je v celoti odebeljena.**

| **Blokator** | **Razred** | **Trud [OCENA]** | **Prioriteta** |
|---|---|---|---|
| **B2.1–B2.3** | **INŽENIRING** | **2–3 tedne** | **1 (najvišja — praktična vrednost)** |
| **B3.1 + B3.2** | **INŽENIRING** | **2–3 tedne** | **2** |
| **B1.1** | **INŽENIRING** | **3–4 tedne** | **3** |
| **B4.1 + B4.2** | **INŽENIRING** | **2–3 tedne** | **4** |
| **B5.1 + B5.2** | **INŽENIRING** | **2–3 tedne** | **5** |
| **B7.1 + B7.2** | **OPERACIJE** | **1–1,5 tedna** | **6** |
| **B6.1** | **RAZISKAVA** | **2–3 tedne** | **7** |
| **B1.2** | **RAZISKAVA** | **4–8 tednov / odprto** | **8** |
| **B6.2** | **RAZISKAVA** | **4–6 tednov** | **9 (nizka)** |
| **B3.3 (keccak)** | **RAZISKAVA** | **meseci / odprto** | **10 (dokumentirati, ne načrtovati)** |
| **B4.3** | **RAZISKAVA** | **odprto** | **zavrnjeno (izven obsega)** |

**Skupna ocena [OCENA] za celoten inženirski del (B2, B3.1–B3.2, B1.1, B4.1–B4.2, B5, B7): ≈ 12–17 tednov fokusiranega dela enega inženirja. Raziskovalni del (B1.2, B6.2, B3.3) je ODPRT in ga ni mogoče pošteno časovno zavezati.**

---

### 5.10 Utemeljitev (zakaj ta vrstni red)

**1. B2 prvi, ker odklene praktično uporabo na ŽIVI tarči (brez ročnega setup.json), kjer je trenutno največja ovira. 2. B3.1+B3.2 drugi, ker odpreta medpogodbene poti — najpogostejši realni napadi so cross-contract. 3. B1.1 tretji, ker večkoračnost že deluje (do 16 korakov), le "usmerjena" gradnja predpogojev manjka. 4. B4 razširi deklarativni invariant — poceni, visoka vrednost. 5. B5 spremeni leak iz "neuporabno" v "materializiraj". 6. B7 zapre dokaz v ponovljiv artefakt. 7. Raziskovalni (B6.2, B1.2, B3.3) se NE obljublja; dokumentira se kot dolgoročno.**

---

### 5.11 Opomba o zanesljivosti ocen (R1)

**VSE številke truda v tem poglavju so [OCENA] — inženirska presoja, NE meritve. Nobenega od teh blokatorjev še nisem poskusil dokončati, zato jih označujem kot ocene. Za natančnejšo oceno bi bilo treba vsako podnalogo razbiti še na pod-podnaloge in jo dejansko implementirati (šele takrat bi bila ocena [IZMERJENO]). Kar je v tem poglavju [KODA], je preverjeno v izvirni kodi in je dejstvo.**
