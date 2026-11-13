# OMEJITVE.md — kaj ForkSploit še ne zna (in zakaj)

> Pravilo R3: omejitev se **zapiše**, ne skrije. Kar ni izmerjeno, je označeno
> kot **neizmerjeno**. Namernih referenc `datoteka:vrstica` tu ni (zastarijo);
> kjer je pomembno, je naveden **simbol** (ime funkcije/konstante), ki se ne
> premakne tako zlahka.

Ta dokument je **seznam omejitev**, ne seznam dosežkov. Za dosežke glej
`README.md` in `CHANGELOG.md`. Vsaka točka pove: kaj ne deluje, zakaj, in kaj
bi jo zaprlo.

---

## A. Izvedbeni model

**A1. `revm` fork ne meri gasa.** Model izvaja pogodbe brez gas meteringa
(`no_gas_measuring`). Posledica: plan, ki v simulaciji uspe, lahko na pravi
verigi prekorači `block.gasLimit`.
*Omilitev:* Python plast uporablja avtoritativni `eth_estimateGas` + živi
`block.gasLimit` (`gas_utils.estimate_gas_limit`), pre-flight vrata
(`gas_oversized_reason`) pa plan, ki ne gre v blok, označijo z ločenim
statusom `oversized_gas` (`PLAN_OVERSIZED_GAS`). Enako merjenje je tudi v
`batch_pipeline.py`.
*Kaj manjka:* merjenje je še vedno na **Python** strani, ne v modelu `revm`,
zato je odvisno od dosegljivega fork-a; brez fork-a meritve ni in plana **ne**
označimo (`None`, ne ugibamo). Regresijski test:
`test_gas_oversized_gate.py`.

**A2. Ni mempoola / vrstnega reda / front-runninga.** Sandwich, backrun, JIT
likvidnost in MEV so **izven modela**. Ni načrtovanega popravila.

**A3. Concolic (Z3) je ozek.** Simbolični so calldata, `callvalue`, `caller`,
`origin` in memory. **Zaprto (FAZA 2.1, 2026-11-07):** simbolični storage
(`SymbolicStorage`) je zdaj ključen po **naslovu pogodbe** in **obstojen čez
klice** (prej per-frame); popravljena je tudi zamenjava operandov SSTORE.
**Merjeno:** slot, ki ga pogodba zapiše v **prejšnjem klicu**, concolic zdaj
reši (`violations:1`), brez concolic ne (`violations:0`).
**Zaprto (FAZA 2.5):** simbolične vrnjene vrednosti klica (glej A4).
**ŠE ODPRTO:** simbolični `CALL` target (FAZA 2.2) in simbolične bilance.
`keccak256` se **ne obrne**, zato mapping vnos, ki je bil v stanju **že pred
transakcijo** (`require(m[k]==1)`), ostaja nedosegljiv — glej A5.

**A4. Simbolične vrnjene vrednosti klica (FAZA 2.5) — zaprto.** Prej je bil
rezultat `CALL`-a vedno konkreten, zato vrat oblike
`(ok, ret) = target.call(...); require(abi.decode(ret) == SECRET)` concolic ni
mogel rešiti. Zdaj `RETURN` vzame simbolični memory callee-ja, `on_return` ga
vstavi v klicočev memory na `return_offset`, `RETURNDATASIZE`/`RETURNDATACOPY`
pa bereta `last_return_bytes`. Bistvo: vstavljene bajte so **callee-jev lastni
simbolični memory**, vezan na klicočev vhod — solver torej invertira
callee-jev izračun (`y*2 == SECRET`), ne ugiba proste konstante. Če callee-jev
`RETURN` ni popolnoma simbolično sleden, se uporabi **konkretna** vrednost
(nikoli izmišljena). Meja: pokriva le **sinhrona** `CALL`/`STATICCALL`/
`DELEGATECALL` v isti transakciji. Regresijska testa:
`tests/evm/concolic_retval/` (pozitivno) in
`tests/evm_never_pass/concolic_retval_unsat/` (negativno, lihi secret).
*Zanesljivost:* pri VELIKI konstanti rešitev potrebuje več kot privzetih
1000 ms; deterministično pri `--concolic-timeout 5000`.

**A5. Mapping vnos iz uvoženega stanja ostaja nedosegljiv (FAZA 2.1
nepopolna).** Simbolični storage reši slot, ki ga pogodba **zapiše** med
transakcijo s simboličnim ključem. Ne reši branja `m[k]`, kjer vnos `m[k]` že
obstaja v uvoženem stanju: naslov slota je `keccak256(k . p)`, concolic pa
`keccak256` **ne obrne**. *Kaj bi jo zaprlo:* model `keccak256` v Z3 (drago)
ali posebna obravnava branja znanega `(contract, slot)` para iz uvoženega
stanja (zahteva storage-layout, ne heuristike).

**A6. Lažen pozitiv invariantnega orakla na neinicializiranem concolic stanju
— najdeno in odpravljeno (2026-11-07).** Concolic stage je tekel tudi na
surovih semenskih vnosih korpusa, ki nosijo prazno svetovno stanje (vsak slot
bere 0); vrata `require(x*x == secret)` so prestala z `x = 0`, concolic
rešitve pa so podedovale to prazno stanje in orakel je videl zapis v
post-state, čeprav prava transakcija reverta. Popravek: stage **preskoči**
testcase z `!initialized` (`concolic_stage.rs`). Dokaz: fixture
`tests/evm_never_pass/concolic_uninit_state/` (pred: `violations:1`; po: `0`)
+ par regresijskih testov v `test_invariant_oracle.py` (drugi prepreči
vakuumski uspeh prvega).

---

## B. Napadalec vs. privilegirana stranka (FAZA 3)

**B1. Harvest heuristika ostaja** (namerno). Označena je z
`owner_impersonation`, razširjena v strukturiran zapis
`owner_impersonation_detail` (`{caller, harvested_from_contract,
harvested_from_slot}`) in v **semantični** test `owner_gated` (korak kliče
pogodbo KOT identiteto, prebrano iz **lastnega** storage-a te pogodbe — točno
`require(msg.sender == owner)`). Plan z `owner_gated`/`owner_impersonation` se
v poročilu označi z blockerjem in se **nikoli ne predstavi kot napad**
(`build_proof`). *Kaj manjka:* splošnejši semantični test poljubnega
privilegiranega pogoja, ne le "naslov iz lastnega storage-a".

---

## C. Dokaz izvedljivosti (FAZA 5)

**C1. Strukturiran dokaz obstaja** (`build_proof` → `Proof` z `replayed`,
`gas_used`, `net_profit_wei`, `blockers`). Signali so združeni v en objekt na
plan. *Kaj manjka:* enotna shema na nivoju **celega teka** (agregat čez vse
plane) — trenutno je dokaz per-plan.

**C2. Merilo uspeha (vsaj en plan prestane tri vrata na testni tarči z
izmerjenim neto dobičkom) je bilo preverjeno v okoljih z RPC dostopom, a v
čistem sandboxu ostaja NEPREVERJENO.** V tem okolju ni živega RPC-ja do
tarče. Izmerjeno: 10 od 10 omrežno/stanjsko odvisnih Rust testov pade **tudi z
egressom** (`onchain_pair_discovery::*`, `uniswap::{test_get_pair,
test_fetch_uniswap_path}`, `endpoints::tests::test_get_balance`), ker se
opirajo na žive javne RPC-je oz. pripeto živo stanje. To ni napaka v kodi,
ampak omejitev okolja in narave teh testov.

---

## D. Zanesljivost (FAZA 6)

**D1. Panic-prone `.unwrap()`/`.expect()` na zunanjih podatkih — pretežno
odpravljeno.** Meje zunanjih podatkov (RPC odgovor, solc/forge izhod, ABI,
storage, presets) so utrjene v `onchain/endpoints.rs`,
`blaz/offchain_artifacts.rs`, `corpus_initializer.rs`, `contract_utils.rs`,
`abi.rs`, `blaz/linking.rs`. Ostanek **ni** na zunanjih podatkih:
`.parse().unwrap()` na statične literale, `lock().unwrap()` in `#[cfg(test)]`.
*Kaj manjka:* `clippy::unwrap_used` kot lint v CI, da ostanek ne raste nazaj.

**D2. Multi-core (FAZA 6.2) — implementiran.** `src/evm/multicore.rs`
(`run_supervisor`) razdeli semenski prostor na `--jobs N` **ločenih
procesov** (ne niti) z izoliranim stanjem; `--jobs` je clampan na število
jeder. Procesna izolacija je izbrana, ker `EVMFuzzState` ni `Send`, pokritost
in cmp mape pa so procesno-globalne `RacyCell` (varne le pod eno-nitno
predpostavko).
*Kaj manjka (R1):* meritev "N jeder → ~N-krat več primerov/s" na pravi tarči;
hitrostni faktor ostaja **neizmerjen**.

**D3. Concolic teče na omejenem, kampanjsko skupnem bazenu delavcev.**
Vsako reševanje teče na svoji OS niti, v procesno-globalnem bazenu
`ALL_WORKER_THREADS` pa je hkrati živih največ `num_threads` reševalcev;
`threaded_solve` ob polnem bazenu najprej `join`-a najstarejšega delavca.
`--concolic-num-threads` **ni ignoriran**: `resolve_concolic_num_threads`
vrednost razreši proti stropu `min(MAX_CONCOLIC_THREADS, cores)`
(`MAX_CONCOLIC_THREADS = 2`). `0`/nenastavljeno = strop; `1` = en zaporedni
reševalec; več se odreže z opozorilom. `--jobs N --concolic` si strop **deli**
(`per_job_concolic_threads(jobs) = max(1, cap / jobs)`), ne množi.
Dokaz: `evm::test::concolic_threads_are_bounded_by_the_campaign_cap`,
`evm::test::concolic_cap_never_exceeds_two_or_cores`,
`evm::multicore::tests::per_job_concolic_threads_never_multiplies_the_cap`.
*Opomba (R3):* pri več jobih kot je strop (npr. `--jobs 4`, strop 2) ima vsak
delavec še vedno vsaj enega reševalca, zato je skupno število enako številu
jobov, ne `N * strop`.

---

## E. Poročanje (FAZA 7)

**E1. Ni `severity` / CVSS.** Obstajajo `confidence`
(`sim-confirmed`/`sim-review`), `net_profit_wei`, `gas_spent_wei`,
`recovery_delta_wei` in predikat **`chain-verified`**
(`is_chain_verified(status, recovery_delta_wei)`), ki se podeli **samo** ob
`PLAN_CONFIRMED` in izmerjenem pozitivnem delti (test
`test_chain_verified.py`). *Kaj manjka:* strukturirano polje `severity`/CVSS.

---

## F. Znanstvena poštenost: česa namenoma NE trdimo

- **Ne trdimo, da je pogodba brez ranljivosti**, kadar ni najdb. "Ni najdeno"
  pomeni "ni najdeno v tem proračunu s temi orakli".
- **Ne trdimo, da je najdba resnična, dokler se sredstva ne premaknejo.**
  Raven `sim-confirmed` je **simulacija**; šele `CONFIRMED` (izmerjen dvig
  recovery denarnice) je dokaz.
- **Ne trdimo, da control-leak sled odraža realno verigo.** Taka sled se
  nikoli ne predstavi kot `sim-confirmed` (FAZA 2.3/2.4).
- **Ne trdimo hitrosti več-jedrnega teka**, ker je nismo izmerili (D2).

---

## G. Blokatorji (povzetek iz `BLOKATORJI.md`)

Največji strukturni blokator je, da je **enota fuzzinga ena transakcija**
(`EVMInput`); večkoračno vedenje nastane šele čez genealogijo korpusa. Za
razrede, ki zahtevajo natančno sekvenco (nastavi → financiraj → napadi), je
doseg verjetnosten. Podrobno in z meritvami v `BLOKATORJI.md`.

---

## H. Zapis popravkov (za ravnotežje)

Nekdanje omejitve, ki so bile zaprte (z dokazom):

- Simbolični storage (FAZA 2.1) — slot, pisan v prejšnjem klicu, je rešljiv.
- Simbolične vrnjene vrednosti klica (FAZA 2.5).
- Lažen pozitiv invariantnega orakla na neinicializiranem stanju (A6).
- Control leak izklopljen med concolic iskanjem (FAZA 2.4).
- `sim-confirmed` se nikoli ne nasloni na control leak (FAZA 2.3).
- Napačni proxy slot konstanti (`BEACON_SLOT`, `UUPS_SLOT`) — beacon in
  EIP-1822 proxy se zdaj razrešita.
- Zastarel negativni oracle cache na control-leak vmesnem stanju (orakel je
  trajno potlačil kasnejšo resnično prijavo) — popravljeno v `feedback.rs`.
- Fuzzer panic "File name too long" pri zelo dolgem imenu najdbe (X1).
- Napačna klasifikacija reverta pri `eth_estimateGas` kot `INCONCLUSIVE`
  (X2 → zdaj `NOT_CONFIRMED`).
- Concolic bazen (D3) in `--jobs` clamp na jedra.
