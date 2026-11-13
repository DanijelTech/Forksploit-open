# Načrt razširitve: nove oracle vrste (2026-11-02, za nadaljevanje "jutri")

## Obseg -- razjasnjeno 2026-11-02 (pomembno, ne spreglej)

Uporabnik je po pregledu zunanjega (ChatGPT) predloga za "70 oraklejev"
eksplicitno razjasnil cilj: **lending/liquidation/governance/bridge/
staking-specifični oraklji (predlagana skupina #48-70 v tistem zunanjem
dokumentu) NISO cilj** -- to bi zahtevalo semantično razumevanje
SPECIFIČNEGA protokola (kaj JE "collateral factor" pri Aave vs Compound vs
Euler), kar nasprotuje ForkSploit-ovi lastni, namerni identiteti: "EVM-only,
bytecode-only, brez potrebe po viru" (glej `CLAUDE.md`). To bi bila druga
kategorija orodja (ročni audit-checklist za znan protokol), ne razširitev
istega bytecode fuzzerja.

**Prava, razjasnjena naloga**: doseči **polno, temeljito, zanesljivo
pokritost znotraj obstoječega obsega** -- torej (a) implementirati FAZO
A/B/C spodaj (13 kandidatov, vsi protokol-agnostični, čisto EVM-nivojski
vzorci, enako kot obstoječi oraklji), IN (b) sistematično poiskati vrzeli
ZNOTRAJ in MED obstoječimi oraklji -- torej mesta, kjer en oracle
delno pokriva nekaj, kar bi moral pokrivati popolno, ali kjer se dva
oraklja prekrivata/imata nejasno ločeno odgovornost (primer A2 spodaj:
"ali `reentrancy.rs` že pokriva ERC721/1155 hook reentrancy, preden
pišemo nov middleware" je TOČNO ta tip naloge). Cilj ni večje število
oraklejev zaradi števila samega -- cilj je, da noben bytecode-nivojski,
protokol-agnostičen vzorec iz dobro uveljavljenih taksonomij (SWC
Registry, znani DeFi heki) ne ostane nepokrit ali polovično pokrit.

> **Posodobitev 2026-11-07**: ta dokument je bil napisan 2026-11-02, ko je
> bilo orakljev 31. Od takrat je bilo dodanih več (danes jih je **46**;
> štej `OracleType` variante v `src/evm/mod.rs`), prazen stub
> `src/evm/oracles/function.rs` pa je bil **izbrisan** (skupaj z mrtvo
> konstanto `FUNCTION_BUG_IDX`) -- glej spodnji odstavek "Kontekst".

## Kontekst

Trenutno ForkSploit pokriva **46 dejanskih oraklejev** (`src/evm/oracles/*.rs`;
štej `OracleType` variante v `src/evm/mod.rs`). Prazen stub
`function.rs` (1 bajt, brez vsebine) je bil **izbrisan 2026-11-07** skupaj
z mrtvo konstanto `FUNCTION_BUG_IDX` -- nikoli ni bil žičen v `OracleType`
in ga ni referenciral noben drug modul, zato je bil mrtev tehnični dolg,
ne kandidat za dopolnitev. Ta dokument je rezultat sistematičnega pregleda SWC Registry
(Smart Contract Weakness Classification) in znanih, resničnih DeFi hekov,
primerjanega proti obstoječemu seznamu, da se najde KONKRETNE, resnične
vrzeli — ne generičen "dodaj še nekaj" seznam.

**Izključeno namenoma**: vse, kar je čisto statična/izvorno-kodna analiza
(floating pragma, poimenovanje spremenljivk, privzeta vidljivost funkcij,
vrstni red dedovanja) — ForkSploit deluje na BYTECODE nivoju, to že pokriva
Slither v `onchain_scripts/auto_pipeline.py`'s `run_static_analysis()`.
Spodaj so SAMO vzorci, ki jih je smiselno zaznati dinamično, med fuzzing
izvajanjem (opcode-level sledenje, taint tracking, pred/po primerjava stanja).

**Vsak kandidat spodaj potrebuje**: nov middleware (sledenje opcode-om) +
nov oracle (interpretacija + `bug_type` niz + confidence tier) + žično v
`src/evm/mod.rs`'s `OracleType` enum + `src/evm/evm_fuzzer.rs`'s oracle
registracija + testni fixture v `tests/evm/<ime>/` + živa verifikacija
(lokalni fuzz tek, preveri da se sproži na fixture-ju in NE na kontrolnem
primeru brez hrošča) + dokumentacija v `zmogljivosti.md`. Enaka disciplina
kot za vse obstoječe oraklje — nobena bližnjica.

## FAZA A — Že potrjeno s strani uporabnika (2026-11-02), prva na vrsti

Ti štirje so bili eksplicitno izbrani prejšnji večer, preden se je seja
razširila na "vse manjkajoče". Začeti je treba TU, po vrstnem redu:

### A1. Read-only reentrancy (najvišja prioriteta)
- **Kaj**: `view`/`pure` funkcija vrne manipulirano/neskladno stanje MED
  reentrant callback-om (preden se stanje "popravi" po koncu zunanjega
  klica), in to prebere ZUNANJI integrator (drug contract), ki temu
  zaupa kot pravemu stanju. Vzrok resničnih hekov: Curve (januar 2023,
  ~$70M tveganih sredstev pri integratorjih), Sturdy Finance (2023).
- **Zakaj ni pokrito**: obstoječi `reentrancy.rs`/`ReentrancyTracer`
  (middleware, SLOAD/SSTORE read-before-write vzorec na ISTI pogodbi)
  lovi SAMO spremembo STANJA (SSTORE) med leak-om — ne lovi primera, ko
  je edina "škoda" to, da je VIEW funkcija med leak-om vrnila napačen
  rezultat, ki ga NIHČE znotraj te transakcije ne zapiše nazaj, ampak ga
  prebere ZUNANJA pogodba (torej navzkrižno-pogodbeno, ne navzkrižno-
  funkcijsko znotraj ene).
- **Mehanizem zaznave (skica)**: nov middleware sledi, kdaj je pogodba A
  sredi "control leak" stanja (glej `host.rs`'s `leak_ctx`/`ControlLeak`)
  IN je v tem oknu neka DRUGA pogodba B poklicala STATICCALL/CALL na
  pogodbo A na view-stilno funkcijo (selektor brez stanja-spremembe), KI
  vrne vrednost, ki se RAZLIKUJE od vrednosti, ki bi jo ista funkcija
  vrnila PRED/PO celotni transakciji. To je `arb_call.rs`-stilen "kdo je
  klical med leak-om" + primerjava rezultata pred/po.
- **Confidence tier**: Review najprej (heuristika, lahko legitimni vzorci
  obstajajo) — Confirmed šele, če se dokaže profit na strani B.
- **Testni fixture**: minimalen ERC4626-stilen vault s `pricePerShare()`
  view funkcijo, ki med `withdraw()`-jevim ETH-send reentrance oknom vrne
  napihnjeno ceno, + ločena "integrator" pogodba, ki to prebere.

### A2. ERC721/1155 safe-transfer hook reentrancy
- **Kaj**: `onERC721Received`/`onERC1155Received`/`onERC1155BatchReceived`
  callback med `safeTransferFrom()` je reentrance vektor, ločen od
  navadnega ETH-send reentrancy (NFT standard EKSPLICITNO zahteva ta
  callback, torej je "varnostna" prednost standarda hkrati napadni
  vektor).
- **Preveri najprej**: ali `reentrancy.rs`'s obstoječi mehanizem (depth-
  based SLOAD/SSTORE sledenje) to ŽE zazna posredno, ker je callback
  mehanizem na nivoju EVM-ja enak navadnemu CALL-u (samo drugačen
  klicatelj/trigger). Če DA, ni novega oraklja treba — samo nov TEST
  FIXTURE, da se dokaže pokritost in doda regression test. Če NE
  (morda ker ReentrancyTracer kako filtrira po tem, da je šlo za ETH-
  transfer specifično), potreben ločen mehanizem.
- **To je torej najprej RAZISKOVALNA naloga** ("ali je to že pokrito"),
  šele nato morebitna implementacija.

### A3. Šibka naključnost (blockhash/timestamp kot entropija)
- **Kaj** (SWC-120): branje `block.timestamp`/`blockhash(...)`/
  `block.number`/`block.difficulty`/`block.basefee` in uporaba
  REZULTATA v primerjavi/modulo operaciji, ki določa izplačilo/zmagovalca/
  dodelitev (npr. lootbox, loterija, "random" NFT mint).
- **Mehanizem zaznave**: sledi opcode-om `0x42` (TIMESTAMP), `0x40`
  (BLOCKHASH), `0x43` (NUMBER), `0x44` (DIFFICULTY/PREVRANDAO), `0x48`
  (BASEFEE) — zapomni si (addr, pc, vrednost na skladu), nato preveri,
  ali je ta vrednost (ali njen MOD/AND rezultat) kasneje uporabljena kot
  operand EQ/LT/GT/MOD tik pred vejitvijo, ki vpliva na SSTORE
  povezanega z izplačilom/balance. Precej podoben vzorec kot `tx_origin.rs`
  (sledi viru → preveri uporabo v pogoju).
- **Confidence tier**: Review (lahko legitimna uporaba za NE-kritično
  logiko, npr. caching timestamp brez varnostnega pomena).
- **Testni fixture**: preprost "lottery" contract, `winner = blockhash(
  block.number-1) % participants.length`.

### A4. DoS prek revert-a v zanki (push-payment vzorec, SWC-113)
- **Kaj**: zanka, ki znotraj vsake iteracije izvede CALL (pogosto ETH
  pošiljanje več prejemnikom), in NI `try/catch`-ane niti ne preveri
  rezultata z `continue` ob neuspehu — torej EN zavrnjen/pokvarjen
  prejemnik (npr. pogodba brez `receive()`, ali namenoma revertira)
  zablokira CELOTNO funkcijo za VSE ostale prejemnike za vedno.
- **Razlika od `unchecked_call.rs`**: ta obstoječi oracle lovi NASPROTNO
  stvar — klic, ki MOLČE spodleti in se nadaljuje (rezultat se ignorira).
  Nov oracle lovi klic v zanki, čigar neuspeh VODI V REVERT cele
  transakcije (`JUMPI` na revert path, pogojen na CALL-ovim success bit-
  om, znotraj zaznane zanke — `unbounded_loop.rs` že ima zaznavanje
  zank, ta oracle lahko deli isto JUMPDEST-loop-detekcijo infrastrukturo).
- **Confidence tier**: Review (lahko legitimen design, če je znano malo
  prejemnikov).
- **Testni fixture**: `distributeDividends(address[] recipients)`, ki
  znotraj `for` zanke dela `recipients[i].transfer(amount)` brez try/catch.

## FAZA B — Dodatni kandidati iz SWC Registry (sistematičen pregled)

Prešteto proti VSEM SWC-100 do SWC-136 — spodaj SAMO tisti, ki (a) niso že
pokriti in (b) so smiselni za bytecode-level dinamično zaznavo:

### B1. Write to Arbitrary Storage Location (SWC-124)
- `SSTORE`, čigar SLOT argument je (deloma) izpeljan iz CALLDATA
  (taint-tracking, podoben vzorec kot `delegatecall_target.rs`'s resnično
  taint sledenje) — NE le statična primerjava layout-a kot
  `storage_collision.rs`. Resnično, ločeno, visoko-tveganje: napadalec
  lahko PREPIŠE poljuben slot (owner, implementation naslov, balance
  mapping) prek nenadzorovanega indeksa v `mapping`/`array` dostopu.
- Confirmed-tier kandidat (zelo nizka false-positive stopnja, če je
  taint resnično dokazan, enako kot delegatecall_target.rs).

### B2. Hardcoded Gas Stipend Reliance (SWC-134)
- **To SMO ŽE NAŠLI V TEJ SEJI kot resnično pogodbo-specifično napako**
  (WETH9's `transfer()` 2300-gas stipend, ki je razbil `AttackWallet`-ov
  `receive()`). To dokazuje, da je vzorec resničen in pomemben.
  Zaznava: `CALL`/`STATICCALL`/`SEND` z eksplicitno gas vrednostjo na
  skladu == natanko 2300 (ali drug nizek hardcoded konstanten znesek),
  kombinirano z `.transfer()`/`.send()`-stilno bytecode obliko.
- Confirmed-tier (deterministično, enostavno za preveriti).

### B3. Unexpected Ether Balance / Force-Fed ETH Assumption (SWC-132)
- Pogodba primerja `address(this).balance` z notranjim računovodstvom
  (`totalDeposits`/vsota mapping-a) in PREDVIDEVA enakost — `selfdestruct`
  katerekoli pogodbe na TO naslov, ali `block.coinbase` nagrada, lahko
  prisili ETH mimo vsakega `receive()`/`payable` preverjanja, kar pokvari
  to predpostavko. Delno sorodno `eth_backing.rs` (ki že lovi "obljubljeno
  > pravo"), a ta je ožji: SAMO primer, ko je vzrok NEPRIČAKOVANO
  vsiljen ETH (ne samo splošna insolvenca).
- Review-tier (eth_backing.rs morda že zadostuje — preveri prekrivanje
  PRED novo implementacijo, podobno kot A2 zgoraj).

### B4. Assert Violation / Reachable INVALID z napadalčevim vnosom (SWC-110)
- `assert()` (INVALID opcode `0xfe`, ne navaden REVERT) dosežen z
  napadalcem-nadzorovanim vnosom namesto interne invariante — pomeni, da
  je razvijalec uporabil `assert` za VALIDACIJO VNOSA namesto za internega
  preverjanja, kar troši VSO gas namesto refundiranja ostanka (in je
  signal slabe prakse/morebitnega logičnega hrošča tam, kjer bi moral
  biti `require`).
- Nizka prioriteta, review-tier, enostavna zaznava (samo `0xfe` dosežen
  brez reverta prej, z taint na vhodu).

## FAZA C — DeFi-specifični kandidati (iz resničnih hekov, ne SWC)

### C1. Flashloan-omogočena price/governance manipulacija v ENI transakciji
- Generalizacija obstoječega `twap_manipulation.rs`/`v2_pair.rs`: zaznaj
  VELIK flashloan-financiran swap/deposit + GLASOVANJE ali CENOVNO-
  ODVISNA odločitev + repay, VSE v ENI transakciji. Vzorec za Beanstalk
  ($182M, april 2022), bZx (2020). Delno pokrito posredno prek
  `erc20.rs`'s Fund Loss + `v2_pair.rs`, a NIHČE od obstoječih
  EKSPLICITNO ne povezuje "flashloan v tej transakciji" + "glasovanje/
  governance klic" kot svoj lasten bug_type.
- Visoka vrednost, a kompleksnejša implementacija (potrebuje sledenje
  "ali je bil ta klic financiran s flashloan-om", kar `auto_pipeline.py`
  že delno ve iz `execute_flat_plan_via_flashloan`, a to je Python-
  stran, ne Rust oracle).

### C2. Manjkajoč slippage/deadline check pri swap funkcijah
- Funkcija, ki izvede swap/trade BREZ preverjanja `minAmountOut`/
  `deadline` parametra (ali ju sprejme, a jih NIKOLI uporabi v
  primerjavi/`require`) — klasičen "sandwich attack" omogočevalec.
  Taint-sledenje: je `minOut`-stilen parameter prisoten v calldata, a
  nikoli ne doseže nobene `LT`/`GT`/`require` primerjave pred
  izvedbo swap-a.
- Review-tier (lahko legitimno, če je deadline/slippage preverjen VIŠJE
  v klicni verigi, npr. router nivo).

### C3. Fee-on-transfer / rebasing token neskladje
- Pogodba predvideva `amountReceived == amountSent` pri ERC20 transferju
  (shrani `amount` argument neposredno v accounting, namesto da preveri
  DEJANSKO spremembo lastnega balance-a pred/po transferju) — fee-on-
  transfer in rebasing tokeni (resnični, pogosti v produkciji) to
  predpostavko pokvarijo, kar vodi v accounting drift/drenažo.
- Zaznava: `TRANSFERFROM`/`TRANSFER` klic, katerega povratna vrednost
  (ali argument `amount`) se neposredno SSTORE-a v accounting mapping,
  BREZ vmesnega branja `balanceOf(address(this))` pred/po.

### C4. Manjkajoč ničelni-naslov preverek na kritičnih setter funkcijah
- `setOwner(address)`/`setAdmin(address)`/`upgradeTo(address)` brez
  `require(newAddr != address(0))` — enostavna, a resnično pogosta
  napaka, ki lahko nepovratno "zacementira" pogodbo (owner = address(0),
  nihče je ne more več upravljati). Enostavna, deterministična zaznava:
  SSTORE v slot, ki ga `access_control.rs` že prepozna kot owner/admin
  slot, z vrednostjo `0x0`, brez predhodnega `ISZERO`+`REVERT`-JUMPI
  preverka na argumentu.
- Confirmed-tier kandidat (nizka false-positive stopnja).

### C5. Precision loss: deljenje pred množenjem
- Bytecode vzorec `DIV` neposredno sledi `MUL` na ISTI vrednosti brez
  vmesnega SSTORE/uporabe (torej `(a / b) * c` namesto `(a * c) / b`) —
  klasična, dobro dokumentirana napaka pri obrestnih/deležnih
  računih, ki vodi v zaokroževanje v škodo uporabnika ali protokola.
  Čisto bytecode-vzorčno zaznavljiv (opcode zaporedje), brez potrebe po
  taint sledenju.
- Review-tier (lahko namerno, npr. za gas optimizacijo kjer izguba ni
  pomembna).

## Status: B1 (Arbitrary Storage Write) dokončan (2026-11-03)

Implementiran in živo preverjen -- nov middleware
(`middlewares/arbitrary_storage_write.rs`, razširi obstoječi `0x35`
CALLDATALOAD primer v `host.rs` z generičnim, ne samo naslovno-filtriranim
`current_calldata_words`) + nov oracle (`oracles/arbitrary_storage_write.rs`,
grajen s `pre_state`/`post_state` diff OD ZAČETKA, ne kot kasnejši popravek).
Žično v `OracleType` enum, `all`/`high_confidence` sezname,
`CONFIRMED_EXPLOITABLE_BUG_TYPES`, `classify_confidence`. Test: pozitiven
fixture (`tests/evm/arbitrary_storage_write/main.sol`, raw `assembly {
sstore(slot, value) }`) se pravilno sproži; kontrolni fixture (navaden
`mapping[key]=value`, ki vedno gre skozi KECCAK256) se PRAVILNO NE sproži --
preverjeno, ne samo trjeno.

Mimogrede najdeno in popravljeno PRED tem delom: sistematičen pregled vseh
11 `.chain(self.host.current_X...)` mest v `vm.rs` je razkril 4 DODATNE,
prejšnji dan spregledane instance istega "nikoli resetiran" bug-a
(`uninitialized_memory_reads`, `unchecked_call`, `tx_origin_checks`,
`delegatecall_targets_seen`) -- glej SKILL.md "Plast 4".

## Status: C3 (Token Accounting Mismatch) dokončan (2026-11-03)

Implementiran in živo preverjen -- `transferFrom(from, address(this),
amount)` + takojšen SSTORE, ki doda NEPREVERJENO `amount` na SLOAD-ano
staro vrednost, se zazna neposredno v `host.rs`'s `call()`/`0x55` kodi (ne
ločen middleware -- potreben je dekodiran `CallInputs.input`, ki ga samo
`call()` sam vidi). Review-tier. Testni fixture (`tests/evm/
token_accounting_mismatch/Vault.sol`) namenoma POKLIČE SAMO SEBE s
transferFrom-oblikovano calldata (prazen `fallback()`), da se izogne
nerealnemu "fuzzer mora uganiti naslov druge naključno-deployane
pogodbe" problemu -- detekcija sama ni odvisna od tega, kateri naslov je
dejansko poklican, samo od oblike odhodnega klica in SSTORE-ja, ki mu
sledi. Pozitiven fixture se sproži takoj; kontrolni primer (navaden ETH
`deposit()` brez zunanjega klica) se pravilno NE sproži.

## Status: B3 (Forced Native Value Accounting) dokončan (2026-11-03)

Implementiran in živo preverjen -- EQ primerjava proti
SELFBALANCE/BALANCE(address(this)) (SWC-132, DoS smer, nasprotno od
`eth_backing.rs`'s insolventnost-smeri). Pri tem je bila najdena
POMEMBNA, SPLOŠNA arhitekturna lastnost (glej SKILL.md): izhodni klic, ki
prenaša vrednost, KASNEJE v isti transakciji lahko izloči poročanje VSEH
hroščev iz te transakcije prek `feedback.rs`'s `has_post_exec` preverjanja
(control-leak), NE GLEDE na to, kje v transakciji je hrošč zaznan. Testni
fixture mora biti brez takega klica, da se to izogne.

## Status: C1 (Flashloan Manipulation) PREKLICAN (2026-11-03)

Po raziskavi preklicano kot neizvedljiv/redundanten v obstoječem EVM-generičnem,
bytecode-only obsegu -- razlikovanje "legitimna arbitraža" od "manipulacija"
znotraj enega flashloan-ovitega bloka transakcij zahteva protokol-specifično
semantično razumevanje (katera pogodba je pravi oracle/pool, kaj je "pravična"
cena), kar je v direktnem nasprotju s ForkSploit-ovo lastno, namerno omejitvijo
na EVM-only/bytecode-only detekcijo brez poslovne logike. Obstoječi
`twap_manipulation.rs`/`curve_virtual_price.rs` (oba z "Profit Confirmed"
varianto) že pokrivata dejansko dokazljiv del tega vzorca (cenovni skok +
dokazan profit klicatelja znotraj ene transakcije), ne glede na to, ali je
kapital za napad prišel iz flashloan-a ali lastnih sredstev -- flashloan je
samo mehanizem financiranja, ne nov detekcijski signal.

## Status: A1 (Read-Only Reentrancy) implementiran, a redko poroča -- arhitekturna omejitev, ne hrošč (2026-11-03)

Oracle (`readonly_reentrancy.rs`, bug_idx 39) je implementiran, zahteval je
persistenten `view_call_baseline` host field (isti vzorec kot
`slot_write_contexts`), in host-level detekcija je dokazano pravilna (debug
teki potrdijo tisoče pravilnih zadetkov). Kljub temu se najdba v praksi
skoraj nikoli ne poroča -- korenski vzrok NI v oraklju niti v `feedback.rs`
(ta je preverjen kot pravilno delujoč: klasični `Reentrancy` ga redno
prehaja), ampak v fuzzer-jevi mutacijski/kontinuacijski strategiji
(`mutator.rs`/`evm_fuzzer.rs`), ki med odprtim control-leak oknom skoraj
nikoli ne poskusi natanko "pokliči nazaj `getPrice()` zdaj, nato zaključi
normalno". Polna analiza in podatki: `SKILL.md` (razdelek 2026-11-03),
`zmogljivosti.md` (Review-tier dodatek). Uporabnik se je odločil poglobiti
v `mutator.rs`/`evm_fuzzer.rs` neposredno -- NI zaključeno v tej seji
(bližajoč se limit seje), nadaljevanje v naslednji seji. Velja za opozorilo
pri VSEH bodočih control-leak-odvisnih orakljih (npr. A2 spodaj).

## Status: obstoječi delegatecall_target.rs popravljen in živo potrjen (2026-11-03)

Ločeno od novih oraclejev zgoraj: na uporabnikovo zahtevo je bil pregledan
že obstoječi `delegatecall_target.rs` (dodan 2026-11-02) za isti razred
cross-leak-resumpcijskega bug-a kot `readonly_reentrancy.rs`. Najdena in
popravljena DVA resnična bug-a (glej SKILL.md za celotno analizo): (1)
`calldata_addresses`/`returndata_addresses`/`paid_calldata_addresses` niso
preživeli nadaljevanja control-leak kontinuacije -- popravljeno varneje
kot `view_call_baseline` (semenjeno iz `vm_state`, ne persistent za vedno,
da se izogne lažnim pozitivnim na Confirmed-tier oraclju); (2)
`calldata.len() < 20` preverjanje je napačno blokiralo tudi Confirmed-tier
signale, ki od `calldata` niso odvisni -- omejeno samo na šibkejši
fallback. **Za razliko od A1 zgoraj, ta popravek je bil USPEŠNO živo
potrjen** (nov namenski fixture, `tests/evm/delegatecall_target/`) --
oracle zdaj pravilno poroča, ko sta RETURNDATACOPY-dekodiranje tarče in
DELEGATECALL razdeljena čez leak mejo. Dokaz, da je A1-jeva ovira res
specifična za fuzzer-jevo mutacijsko strategijo (kateri kontinuaciji
sploh poskusi), ne splošna arhitekturna nezmožnost poročanja čez
leak mejo nasploh -- tukaj je bila ovira v dveh lokaliziranih kodnih
napakah, ki sta ju bilo mogoče neposredno popraviti.

## Povzetek prioritete za jutri

1. **FAZA A (4 že potrjeni)** — začni tu, po vrstnem redu A1→A4.
   A2 je deloma RAZISKOVALNA (preveri pokritost, šele nato kodiraj).
2. **B1 (Arbitrary Storage Write) in B2 (Hardcoded Gas Stipend)** —
   naslednja najvišja vrednost: oba Confirmed-tier, oba nizka
   false-positive stopnja, B2 je dobesedno dokazan resničen bug v tej
   seji (WETH9), B1 je isti taint-sledenje vzorec kot že obstoječi
   `delegatecall_target.rs` (torej manj tveganja pri implementaciji).
3. **C4 (ničelni naslov na setter-jih)** — zelo enostaven, hitra zmaga.
4. Preostanek (A3, A4, B3, B4, C1, C2, C3, C5) po dogovoru, glede na
   razpoložljiv čas — vsak zahteva enako disciplino (middleware + oracle
   + fixture + živa verifikacija), nobena bližnjica.

**Ni v tem seznamu** (namenoma izpuščeno, ker je čisto statično/izvorno-
kodno, ne bytecode-dinamično): SWC-100, 102, 103, 108, 111, 118, 119, 125,
129, 130, 131, 135, 136 — te že (ali bi morale) pokriti Slither/statična
analiza v Python plasti, ne ForkSploit-ov bytecode fuzzer.

---

## FAZA D — Podatkovno vodene vrzeli iz 2025-2026 incidentov (2026-11-05)

Vir: DefiLlama `api.llama.fi/hacks` (1339 zapisov, 696 od 2024+) + rekt.news
leaderboard, obdelano po tehniki in USD. Spodaj SAMO tisto, kar je (a) v
2025-2026 dejansko povzročilo izgube, (b) bytecode-nivojsko, protokol-
agnostično zaznavno, in (c) NI že pokrito z obstoječimi 43 bug_type-i.

### Ključni kontekst: kje je denar sploh izginil (2025+)
- **Off-chain (ključi/phishing/supply-chain): ~$7.4 mrd** — ForkSploit TO
  namenoma NE pokriva (ni koda; `zmogljivosti.md` §9 že pravi, da je to
  izven obsega). Ne dodajaj orakljev za to.
- **Code-level: ~$4.1 mrd**, od tega trije največji razredi:
  **Proxy Upgrade Hijack $366M**, **Unbacked Cross-Chain Mint $334M**,
  **Cross-Chain Message Spoofing $308M**.

### D1. Proxy Upgrade Hijack (najvišji USD v code-level, $366M)
- Obstoj: `proxy_integrity.rs` lovi REINITIALIZATION in STORAGE COLLISION,
  a NE lovi samega **upgrade hijack** vzorca: `upgradeTo`/`_authorizeUpgrade`
  /UUPS `upgradeToAndCall` dosežen od klicatelja, ki NI bil avtoriziran ob
  času klica (npr. `onlyOwner` obide prek `initialize()` front-run-a ali
  `delegatecall` v `receive()`). To je isti razred kot Gala ($216M, 2024)
  in Balancer-forks (2025).
- Mehanizem: `access_control.rs` že prepozna owner/proxy slot; tu dodaj
  vezavo "slot, ki ga je zapisal `upgradeTo`-stil selektor" → "je bil ta
  selektor kdaj dosežen brez predhodnega uspešnega `onlyOwner` preverka v
  isti transakciji". Confirmed-tier kandidat.
- Prioritetno: **najvišja** (največ USD, najbližje obstoječi infrastrukturi).

### D2. Unbacked Mint / Missing Supply Accounting ($334M + $21M Infinite Mint)
- Obstoj: `erc20.rs` pokriva "Fund Loss" (odliv iz pogodbe), a NE pokriva
  **mintanja, ki ni krita s protivrednostjo** — npr. `mint()`/`_mint()`
  dvigne `totalSupply`, a pripadajoči deposit/collateral mapping NI
  povečan. Vzorec: Liquid Network (2026, ~$320M, "unbacked L-BTC"),
  Cashio ($48M), številni 2025 infinite-mint heki.
- Mehanizem: sledi `totalSupply`-slot zapisom (SSTORE v slot, ki ga bere
  `totalSupply()` selektor) → primerjaj z zapisi v "backing" mapping/slot
  v isti transakciji. Če supply naraste brez sorazmernega backing zapisa →
  bug. Delno sorodno `eth_backing.rs`, a ta je ožji (native ETH le) in
  obrnjen (insolventnost, ne mint).
- Confirmed-tier kandidat.

### D3. Cross-Chain Message Spoofing / Forged Proof ($308M + $44M Forged Proof)
- Obstoj: `signature_replay.rs` pokriva replay podpisov, a NE pokriva
  **ponarejene cross-chain sporočilne dokaze** (Merkle proof / message hash
  verifikacija, kjer napadalec podtakne `(root, proof)` ali obide
  `verifyMessage`). Vzorec: KelpDAO/LayerZero (2026, $290M), Nomad ($190M,
  "trusted root = 0x0"), BNB Bridge ($586M).
- Mehanizem: `verify`-stil zunanji klic, katerega povratna vrednost
  odloča o nadaljevanju (mint/release), kjer je argument `root`/`message`
  iz calldata in NI bil nikoli primerjan z avtoritativnim stanjem. Zelo
  blizu obstoječemu `unchecked_call.rs` + `signature_replay.rs` — morda
  zadošča razširitev, ne nov oracle (enaka "preveri prekrivanje PRED
  implementacijo" disciplina kot A2).
- Review→Confirmed (odvisno od tega, ali je forged proof dokazljiv).

### D4. Donation Attack / Balance-vs-Accounting Drift ($145M + $137M Rounding)
- Obstoj: `erc4626.rs` pokriva share-inflation, `forced_eth_accounting.rs`
  pokriva forced-ETH. Manjka **splošen "donation" vzorec na NE-ERC4626
  pogodbah**: `token.balanceOf(address(this))` kot vir resnice, kjer
  neposreden `transfer()` v pogodbo (mimo `deposit()`) spremeni ceno/delež.
  Vzorec: Balancer II (2025, $128M, "rounding down"), 2025 donation heki.
- To je TOČNO tisto, kar je LLM-plast (`llm_poc/`) v testu že zadela po
  OBLIKI (donacija prek `transfer()`), a ne po natančnem numeričnem triku —
  torej realna, potrjena vrzel v bytecode orakljih.

### D5. EIP-1153 transient-storage reentrancy guard (Uniswap V4 era)
- Obstoj: `host.rs` ima `transient_storage`, a **noben oracle ne preverja
  guard-a v TSTORE/TLOAD prostoru** — `reentrancy.rs`/`stale_guard.rs`
  gledata SSTORE/JUMPI. Sodobne pogodbe (V4 hooks, novejši reentrancy
  guard-i) uporabljajo transient storage; guard, ki se resetira ob koncu
  transakcije, je lahko ranljiv če je `TSTORE` v napačnem kontekstu.
- Mehanizem: razširi `stale_guard.rs` na TSTORE/TLOAD (isti JUMPI-fed-by-slot
  vzorec, drug prostor). Manjša, ciljna razširitev.

### D6. EIP-7702 delegation / ERC-4337 account-abstraction (popolnoma prazno)
- Obstoj: **NIČ** (`grep 7702|4337|userop|paymaster` = 0 zadetkov).
- To je edini popolnoma nepokrit NOV napadni prostor iz 2025-2026
  (7702 je šel na mainnet Pectra, maj 2025). Bytecode-nivojsko zaznavno:
  `EXTCODECOPY`/delegation-designator vzorec, `validateUserOp`-stil
  selektor, paymaster `validatePaymasterUserOp` tok.
- Višji napor (nov podsistem), a edini, ki pokriva kategorijo, ki je
  danes 0 % pokrita.
- **Delno pokrito (2026-11-07):** delegacijski designator `0xef0100 ||
  delegate` je zdaj prepoznan v OBEH plasteh (`src/evm/contract_utils.rs`'s
  `eip7702_delegate` + `onchain_scripts/proxy_resolver.py`'s
  `eip7702_delegate`) in umeščen v obstoječo proxy-razrešitveno pot, tako da
  je delegirani kontrakt fuzzan (ne le designator). **Še manjka:** ERC-4337
  `validateUserOp`/paymaster tok in oracle za 7702-specifične zlorabe
  (npr. delegacija na zlonamerni kontrakt) — to je še vedno ločen projekt.

### Ne dodajaj (namenoma izpuščeno iz te faze)
- Off-chain razredi (Private Key Compromised, Phishing, Supply Chain,
  DNS Hijack) — izven ForkSploit-ove identitete.
- Protocol-specifični lending/liquidation/governance oraklji — že
  izključeni v tej isti datoteki zgoraj (zahtevali bi poslovno logiko).
- `Oracle Misconfiguration` ($11M) in `Aave liquidation` (2026) — to je
  config/ops napaka, ne bytecode vzorec; ni za fuzzer.

### Predlagan vrstni red
1. **D1 (proxy upgrade hijack)** — največ USD, najbližje obstoječi kodi.
2. **D2 (unbacked mint)** — največ USD med "čistimi" mint vzorci.
3. **D5 (transient-storage guard)** — majhna, ciljna razširitev.
4. **D4 (donation, ne-ERC4626)** — potrjena vrzel iz LLM-plast testa.
5. **D3 (cross-chain proof)** — najprej PREVERI prekrivanje s
   `signature_replay.rs`/`unchecked_call.rs`.
6. **D6 (7702/4337)** — največji nov obseg; ločen projekt.

## Status: D1 (Proxy Upgrade Hijack) DOKONČAN (2026-11-05)

Implementiran in živo preverjen -- nov oracle
(`oracles/proxy_upgrade_hijack.rs`, bug_idx 46), brez novega middleware-a
(detekcija v celoti v oraklju: bere EIP-1967 slota iz `pre_state`/`post_state`
+ `fast_static_call(owner())` na `pre_state`).

**Vrzel, dokazana empirično PRED implementacijo** (ne ugibanje):
obstoječa binarka na novem fixture-u `tests/evm/proxy_upgrade_hijack/`
(UUPS `upgradeTo` brez guard-a, admin slot nikoli nastavljen) je prijavila
SAMO `Zero Address Setter` (sim-review) -- in to zgolj zato, ker je fuzzer
slučajno poklical `upgradeTo(address(0))`. Prava ranljivost (manjkajoč
access control) NI bila nikoli javljena; realističen zlonamerni NENIČELNI
naslov implementacije ni sprožil NIČ, `confirmed_exploitable: false`.
Koda to pojasni: `access_control.rs` zahteva NENIČELN EIP-1967 admin slot
(da ima s čim primerjati klicatelja), `proxy_integrity.rs` pa upgrade
selektorje NAMENOMA preskoči. UUPS med njima pade v obe vrzeli.

**Po implementaciji**: isti fixture zdaj javi
`[Unprotected Proxy Upgrade (UUPS)] (sim-confirmed)`, `confirmed_exploitable:
true`, in zgenerira se `*Exploit.s.sol` (potrjeno: datoteka obstaja, ker je
najdba en-identitetna/atomska).

**Negativni fixture** (`tests/evm/proxy_upgrade_hijack_guard/`, `onlyOwner`
guard): oracle je TIŠI -- in dokazano ni tiho zaradi tega, ker fuzzer ne bi
klical `upgradeTo`: sledi (`traces/1.json`, `traces/2.json` od ne-lastnika,
`traces/3.json` od lastnika) potrjujejo, da je fuzzer selektor `3659cfe6`
dejansko izvajal; guard ga je revertal, zato ni bilo spremembe slota.

**Regresija**: obstoječi `proxy_reinit`/`proxy_collision`/`access_control`
fixture-i še javljajo točno svoje obstoječe bug_type-e, noben ne javlja
novega (ni lažnih pozitivov). Rust test suite: 67 passed / 11 failed --
IDENTIČNO baseline-u pred spremembo (vseh 11 je omrežno-odvisnih,
potrebujejo Anvil na `localhost:8545`).

**Omejitev, ki ostaja**: detekcija zahteva berljiv `owner()` prek proxy-ja
(non-zero, != caller). Role-based guard (`hasRole`) brez `owner()` je videti
enako kot manjkajoč guard od zunaj, zato oracle tam ostane tiho raje kot da
ugiba -- to je namerna izbira (Confirmed-tier zahteva dokaz, ne suma).

## Status: D2 (Unbacked Mint / Missing Supply Accounting) DOKONČAN (2026-11-05)

Implementiran (`oracles/unbacked_mint.rs`, bug_idx 47, Review-tier) --
namerno Review, ne Confirmed: javno `mint()` je včasih legitimno
(faucet/rebase/inflacijski žeton, ali žeton, ki SPLOH ni mišljen kot
native-backed), zato končno presojo potrebuje človek. Detekcija sama je
deterministična (brez heuristike), vseh 6 vrat:

1. `totalSupply()` odgovori v pre- IN post-stanju (ERC20-oblika).
2. post supply > pre supply (v tej tx se je zgodil mint).
3. klicatelj ni plačal nič (`txn_value == 0`).
4. native balance pogodbe se NI povečal (ni pritoka, ki bi kril nov supply
   -- npr. normalen `deposit()`).
5. pogodba je ŽE držala native ETH in ŽE imela supply>0 (obstaja obstoječi
   backed pool, ki se ga dilutira; izloči prvi mint in čiste ERC20/LP žetone).
6. klicatelj ni `owner()` (admin mint je običajno legitimen).

**Zakaj to ni podvojeno**:
- `erc20.rs` javlja "Fund Loss" (odliv) -- mint je nasprotna smer.
- `eth_backing.rs` javlja INSOLVENTNOST oblike `balances(address)` in
  NAMENOMA izloči ERC20-obliko (takoj ko `totalSupply()` odgovori, gre v
  `not_applicable`). Žeton s `totalSupply()` je TOČNO tisto, kar preskoči.

**Preverjeno živo**:
- `tests/evm/unbacked_mint/` (`deposit()` honest + `mint()` free): javi
  `[Unbacked Mint (Supply Growth Without Backing)] (sim-review)`. Sled
  potrjuje `deposit{value} -> deposit{value} -> mint(big)` -- pravi vzorec.
- `tests/evm/unbacked_mint_guard/` (supply raste SAMO prek plačanega
  `deposit()`): oracle je TIŠI, in sledi (`d0e30db0`) dokazujejo, da je
  fuzzer `deposit` res klical -- tišina je smiselna, ne prazna.
- `-d high_confidence` NE vključi tega oraklja (Review-tier ostane izven
  visoko-zanesljive množice; preverjeno, da na pozitivnem fixture-u
  `high_confidence` ne javi unbacked minta).
- Regresija: `eth_backing`/`erc4626`/`token_accounting_mismatch` še javljajo
  točno svoje obstoječe bug_type-e, nihče ne javlja "Unbacked Mint".
- `cargo test`: 67 passed / 11 failed == baseline (vseh 11 omrežnih).

## Status: D3 (Cross-Chain Message Spoofing / Forged Proof) DOKONČAN (2026-11-05)

Implementiran (`oracles/forged_proof.rs`, bug_idx 48, Review-tier).
Roadmap je predlagal "preveri prekrivanje PRED implementacijo" -- preverjeno
EMPIRIČNO na novem fixture-u `tests/evm/forged_proof/` z OBSTOJEČO binarko:
obstoječi oraklji javijo le nepovezane `Centralization Risk`/`Zero Address
Setter`/`Arbitrary Storage Write`, NITI EDEN ne javi forged proof-a. Vrzel
potrjena.

**Zakaj NOV oracle, ne razširitev** (odgovor na roadmap dvom):
- `signature_replay.rs` pokriva REPLAY istih podpisnih bajtov; tu ni podpisa
  in ni replay-a (vsak `(root, proof)` je unikaten).
- `unchecked_call.rs` pokriva NEUSPEL zunanji klic, katerega rezultat je
  ignoriran; tu je klic/verifikacija USPEŠNA in sprejeta.
- Noben obstoječi oracle ne sledi "lokalno izračunan hash == klicateljeva
  calldata beseda, sprejeto, brez primerjave s shranjenim stanjem".

**Mehanizem (pravi dataflow, ne proximity)**:
1. `host.rs` 0x20 (SHA3): izračuna TOČNO tisti hash, ki ga bo revm pravkar
   izračunal, in ga zapiše (`current_last_sha3`).
2. 0x14 (EQ): če je en operand ta hash in drugi surova calldata beseda
   (`current_calldata_words`), zapomni par. Ločeno beleži vsako calldata
   besedo, ki je bila kdaj primerjana s SLOAD-ano vrednostjo
   (`current_calldata_sload_compared`) -- VARNA oblika `root == trustedRoot`.
3. 0x57 (JUMPI): par zabeleži le, če je bila veja SPREJETA
   (`current_proof_accepted`).
4. Oracle izloči vsak par, katerega root je bil tudi SLOAD-primerjan
   (pogodba ga JE vezala na stanje).

Dodatna zaščita pred lažnimi pozitivi (najdena med regresijo): primerjava
mora imeti DVA RAZLIČNA operanda in izračunani hash ne sme biti kar ena od
klicateljevih besed -- brez tega solc-ova mapping-slot aritmetika (primerjava
calldata-ključa samega s seboj) sproži lažni pozitiv (potrjeno na
`eth_backing`).

**Preverjeno živo**:
- `tests/evm/forged_proof/` (root iz calldata, nikoli primerjan s
  `trustedRoot`): javi `[Forged Proof (Caller-Supplied Root Accepted)]
  (sim-review)`, pc 2858, s klicateljevo besedo.
- `tests/evm/forged_proof_guard/` (isti vzorec, a `require(root ==
  trustedRoot)` pred pripisom): oracle je TIŠI.
- Regresija (lažni pozitivi): `eth_backing`, `token_accounting_mismatch`
  sta po dodatnih filtrih ČISTA; `signature_replay`, `ecrecover`,
  `storage_collision`, `arbitrary_storage_write`, `erc4626`, `erc1155_batch`,
  `nft_transfer`, `twap_manipulation`, `curve_virtual_price`,
  `olympus-simple`, `proxy_collision`, `proxy_reinit`, `readonly_reentrancy`,
  `delegatecall_target` -- vsi brez Forged Proof lažnega pozitiva.
- `-d high_confidence` NE vključi tega oraklja (Review-tier).

## Status: D5 (EIP-1153 transient-storage reentrancy guard) DOKONČAN (2026-11-05)

Implementiran (`oracles/transient_guard.rs`, bug_idx 49, Review-tier).

**Vrzel, dokazana EMPIRIČNO PRED implementacijo** (ne ugibanje):
`host.rs` `step()` v obstoječi binarki SPLOH NI dekodiral `0x5c` (TLOAD) /
`0x5d` (TSTORE) -- preverjeno z `grep -c "0x5c =>\|0x5d =>"` = **0**. Edini
obstoječi reentrancy/stale-guard oraklji gledajo `0x54/0x55` (SSTORE/SLOAD),
zato je EIP-1153 guard popolnoma neviden. Na novem fixture-u
`tests/evm/transient_guard/` (guard sproščen PRED klicem) obstoječa binarka
javi le SSTORE-sledni `Reentrancy` prek `balances` -- NITI EDEN oracle ne
pokaže, da je prav TRANSIENTNI guard sproščen prezgodaj.

**Zakaj signal odstopa od roadmapovega predloga**: roadmap je predlagal
"isti JUMPI-fed-by-slot vzorec kot stale_guard". To bi bilo NAPAČNO --
transient storage se resetira ob koncu vsake transakcije, zato bi "slot se
nikoli ne spremeni" sprožilo na VSAKEM pravilnem guard-u (vsak `tload(0)`
prebere 0 na začetku vsake tx). Pravi, determinističen signal je namesto
tega: **guard je bil odklenjen (TSTORE 0 na slot, ki je bil v tej transakciji
TLOAD-an in prej zaklenjen) PRED zunanjim CALL-om** -- checks-effects-
interactions kršitev v transient prostoru.

**Mehanizem (pravi dataflow)**:
1. `host.rs` 0x5c (TLOAD): zabeleži slot kot kandidata za guard
   (`current_transient_loaded`).
2. 0x5d (TSTORE): ne-nič zapiše = zaklep; nič na prej zaklenjen slot =
   "pending unlock" (`current_transient_unlock`); ponoven zaklep ga prekliče.
3. CALL/STATICCALL arm (0xf1/0xf2): če se izvede, medtem ko je TLOAD-an slot
   v odklenjenem stanju, zabeleži hit (`current_transient_unlock_calls`).
4. Oracle (Review-tier) poroča vsak tak par (addr, tstore pc, slot).

**Preverjeno živo**:
- `tests/evm/transient_guard/` (guard sproščen PRED klicem): javi
  `[Transient Guard Released Before External Call]`.
- `tests/evm/transient_guard_safe/` (isti guard, sproščen PO klicu -- pravilen
  checks-effects-interactions): oracle je TIŠI.
- `-d high_confidence` NE vključi tega oraklja (Review-tier); preverjeno, da
  na pozitivnem fixture-u `high_confidence` ne javi Transient Guard.
- Regresija (lažni pozitivi): `reentrancy`, `stale_guard`, `eth_backing`,
  `erc4626`, `proxy_upgrade_hijack`, `unbacked_mint`, `forged_proof` -- vsi
  brez Transient lažnega pozitiva. Samo novi fixture-i uporabljajo
  TSTORE/TLOAD (`grep -rl tstore tests/evm`).
- `cargo test`: 67 passed / 11 failed == baseline (vseh 11 omrežnih).

## Status: D4 (Donation / balance-vs-accounting drift, ne-ERC4626) ODLOŽEN (2026-11-05)

Poskus implementacije (nov oracle `oracles/donation.rs`, bug_idx 50) je bil
UMAKNJEN pred commitom, ker pozitivnega fixture-a NI bilo mogoče doseči z
obstoječim fuzzerjem -- v skladu s projektnim pravilom "(sim-review) najdba
mora biti dokazano reproducirana v simulaciji", oraklja brez živega
pozitivnega dokaza ne commitamo.

**Kaj je bilo narejeno in kaj je dokazano**:
- Vrzel v KODI je resnična: obstoječa binarka na novem fixture-u
  `tests/evm/donation_non4626/` (Vault brez `totalAssets()`/`totalSupply()`,
  ki ceni prek `asset.balanceOf(address(this))`) NE javi donation napada --
  samo `Stale Guard Counter` / `Reentrancy` / `Zero Address Setter`. Torej
  `erc4626.rs` (ki zahteva `totalAssets()`) tega res ne pokriva.
- Implementiran je bil determinističen dvodelni latch v `host.rs`:
  `T.balanceOf(C)` kjer je C pogodba sama (`current_self_token_reads`) IN
  `T.transfer(X,...)` kjer klicatelj NI X (`current_token_donations`); oracle
  se sproži, ko je isti `(C, T)` par v obeh.
- **Zakaj ni bilo mogoče dokazati živo**: oba latcha se polnita (potrjeno z
  instrumentacijo: `self_read` 144x, `donation` 3x), a fuzzer donacijo
  usmeri na NAKLJUČNE naslove, ne na vault; `Vault.setAsset()` + `deposit()`
  + tuj `Token.transfer(vault,...)` v pravi sekvenci ni dosežen v razumnem
  času. Enako omejitev ima že obstoječi `erc4626` oracle -- na SVOJEM
  fixture-u `tests/evm/erc4626/` se prav tako NE sproži (samo Stale Guard
  itd.), kar potrjuje, da je to omejitev harness-a (multi-step cross-contract
  wiring), ne specifika D4.

**Zaključek**: D4 ostaja vzzel, a zahteva najprej izboljšavo harness-a
(usmerjeno zaporedje klicev / seed corpus z nastavljenim `setAsset`), šele
nato oracle. Predlagan vrstni red: D6 (7702/4337) ali harness-work, ne D4.

---

## Harness izboljšava #2 (2026-11-05): biasing naslovnega pool-a -- DONE

Implementirano in commitano (530c1f4): `state.rs` dobi `contract_addresses_pool`
(polnjen SAMO iz `add_contract_address`, ki ga kličeta `corpus_initializer.rs`
in `onchain/mod.rs`), `get_rand_address` pa preferira te naslove 75% časa
(zrcali obstoječi `get_rand_caller_excluding`). Ostalih 25% + primer "še ni
kontrakta" ostane uniformen, da svež EOA/`0x0`/tretje osebe niso izstradani.

**Živo izmerjeno** (instrumentacija, `tests/evm/erc4626/` in `donation_non4626/`):
- Pred: `addresses_pool` = 34 naslovov, od tega le 2 kontrakta -> argumenti so
  redko kazali na kontrakte.
- Po: `contract_addresses_pool = [Token, Vault]`; Vault dejansko izvaja
  `asset.balanceOf(self)`.
- Vsi pozitivni oraklji (D1 proxy_upgrade_hijack, D2 unbacked_mint, D3
  forged_proof, D5 transient_guard, reentrancy, eth_backing) še vedno poženejo;
  `cargo test` 67/11 == baseline.

**Omejitev**: #2 je potreben, a NE zadosten za D4/erc4626 -- fuzzer še vedno ne
zadene `setAsset(realToken)` + `Token.transfer(vault,...)` v pravi sekvenci.
Naslednji korak za D4 je #1 (setup/seed transakcije, glej zgoraj).

Preostale predlagane izboljšave harness-a (po ROI):
1. **#1 setup.json** (LOW-MEDIUM, najvišji ROI): deklarativne inicializacijske
   klice izvesti v `initial_state` pred fuzzingom -- odblokira D4 + erc4626.
3. **#3 koreliran cross-contract seeding** (MEDIUM): za vsak par (A,B) dodaj
   `A.transfer(B,x)`/`A.approve(B,max)` v corpus.
4. **#4 prava multi-tx sekvenca v vhodu** (HIGH): `EVMInput` -> `Vec<Tx>`;
   invazivno (mutator, scheduler, minimizer, executor, serializacija).
5. **#5 semantični donation mutator** (MEDIUM, ozko): ko oracle vidi
   `balanceOf(self)`, mutator injicira `transfer(vault, amount)`.

---

## Harness izboljšava #1 (2026-11-05): `setup.json` seed transakcije -- DONE

Implementirano in commitano: nov modul `src/evm/setup.rs` (+ polje
`setup_spec` na `ContractLoader`, klic v `EVMCorpusInitializer::initialize`
med `initialize_contract` in `initialize_corpus`).

**Format** (`tests/evm/<fixture>/setup.json`):
```json
{ "calls": [
  { "to": "Vault", "sig": "setAsset(address)",        "args": ["Asset"] },
  { "to": "Asset", "sig": "mint(address,uint256)",    "args": ["$caller", "1000000000000000000000"] },
  { "to": "Vault", "sig": "deposit(uint256,address)", "args": ["100000000000000000000", "$caller"] }
] }
```

- `to` je ime deployanega kontrakta (file-stem iz fixture-a) ali `$deployer`.
- Argumenti tipa `address` sprejmejo ime kontrakta ali `$caller`/`$deployer`;
  ostali se predajo ABI-enkoderju kot literal.
- Signature se parsirajo z `alloy_json_abi::Function::parse`, argumenti pa
  `coerce_str` + `abi_encode_input` (že obstoječe odvisnosti, nič novega).
- Klici se izvedejo z `EVMExecutor::fast_call_` na sveže-deployanem stanju;
  vsak klic je best-effort (revert se zabeleži, nikoli usoden).

**Živo izmerjeno** (`tests/evm/erc4626/`): brez `setup.json` 986k izvedb -> 0
zadetkov ERC4626; z `setup.json` zadetek v ~1.5M izvedb (Vault price-per-share
1e9 -> 1.2e47). To zapre vrzel, ki je D4 blokirala (glej zgoraj): harness zdaj
zna vzpostaviti predpogoj `setAsset` + `deposit` pred fuzzingom.

**Omejitev**: #1 rešuje predpogoj (wiring), ne pa še samega vrstnega reda
napada; za polno pokritost D4 (ne-ERC4626 "balance-vs-accounting drift") je
še vedno potreben #5 (semantični mutator) ali #4 (prava multi-tx sekvenca).

