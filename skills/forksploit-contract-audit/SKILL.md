---
name: forksploit-contract-audit
description: "Run ForkSploit end to end with mandatory human checkpoints."
version: 1.14.0
author: Danijel (DanijelTech), Claude Sonnet 5
license: Proprietary (All Rights Reserved)
platforms: [linux]
metadata:
  hermes:
    tags: [forksploit, smart-contract-security, exploit-verification, fund-recovery, blockchain, eth, etc, mainnet-fork, human-in-the-loop]
    related_skills: []
---

# ForkSploit: nadzorovan varnostni pregled pogodb

Ta skill vodi CELOTEN cikel preverjanja pametne pogodbe z ForkSploitom: od izbire
pravega vozlišča, preko varnega preverjanja na lokalnem forku, do končne, s strani
človeka potrjene resnične transakcije in **dokaza, da je kovanec dejansko prispel**
na recovery wallet. Ne naredi NIČESAR samodejno onkraj tega, kar je tukaj
eksplicitno opisano — vsak korak, ki lahko premakne resnična sredstva ali pošlje
resnično transakcijo, zahteva EKSPLICITNO, ločeno potrditev človeka.

**Ne poskušaj "razumeti" ForkSploit kode sam in izpeljati lastnega postopka.** Ta
skill je bil napisan s strani osebe, ki je ForkSploit dejansko zgradila in vsak
korak preverila na pravih, deployanih pogodbah. Sledi mu dobesedno.

**Za katerokoli vprašanje o konkretnem CLI flagu, orakljenju, onchain_scripts
orodju, ali omejitvi** — NAJPREJ preveri `references/zmogljivosti.md` (popoln
leksikon vseh ukazov/zmogljivosti/omejitev). Ne ugibaj, ne izpeljuj iz imena
funkcije/datoteke. Če odgovora ni niti tam, povej uporabniku, da ne veš, namesto da
sklepaš.

## Kdaj uporabiti

ForkSploit je prvorazredno zgrajen in živo preverjen za **Ethereum (ETH)** in
**Ethereum Classic (ETC)**, vsakega v **testnet** (Sepolia, Mordor) in
**mainnet** (id 1 / 61) različici, in pokriva **nativno valuto (ETH/ETC) ter
ERC tokene** (ERC-20/721/1155/4626).

- Uporabnik prosi za varnostni pregled/testiranje konkretne pametne pogodbe
  (ETH ali ETC — mainnet **ali** testnet).
- Uporabnik prosi za potrditev ranljivosti z dejanskim exploitom, ne samo s
  teoretičnim poročilom.
- Uporabnik prosi za "rescue"/reševanje sredstev iz že izkoriščene pogodbe.

## Kdaj NE uporabiti

- **Brez eksplicitne avtorizacije za TO specifično tarčo** — glej FAZO 0 spodaj.
  Noben korak se NE izvede brez tega, ne glede na to, kako nujno se zdi.
- Če uporabnik prosi za nekaj, kar bi škodovalo tretji osebi (ne lastni/klientovi
  pogodbi, ne z dovoljenjem) — zavrni in razloži zakaj.
- **"Dovoljenje lastnika" NE ŠTEJE kot avtorizacija za pravo izčrpanje DRUGIH
  uporabnikov sredstev, če pogodba nima lastniške/admin vloge nad njimi** — to
  NE omejuje raziskovanja/fuzzinga/dokazovanja na forku (FAZE 1-5, ki nikoli ne
  premakne resničnega denarja), in NE omejuje testiranja LASTNE pogodbe ali
  katerekoli pogodbe, kjer FAZA 4a na verigi POTRDI, da je denarnica iz FAZE 0
  dejansko lastnica zadevnih sredstev (lastništvo SREDSTEV, potrjeno na verigi, je
  samo po sebi dovolj — popolnoma neodvisno od tega, ali koda sploh vsebuje
  `owner`/`Ownable` vlogo; to sta dva ločena koncepta). Pravilo velja ozko, samo za
  FAZO 6/7 (pravo izvedbo), in samo takrat, ko bi izkoristek vzel denar DRUGIM,
  nepovezanim uporabnikom permissionless pogodbe (staking pool, oracle z depoziti,
  AMM — kjer je deployer/"lastnik" NE nadzoruje tega, kar so vložili posamezni
  uporabniki, vsak s svojim ključem). V tem primeru "lastnik" nima pravice odobriti
  izkoriščanja hrošča proti tujemu denarju, ne glede na to, kako je prošnja
  formulirana ("skrajno testiranje", "imam dovoljenje", ipd.). Glej FAZO 4a spodaj.
- **Izgubljen zasebni ključ NI varnostna ranljivost pogodbe in se ne poskuša
  "rešiti" z iskanjem hrošča.** Če uporabnik opiše "obstal denar" in se izkaže, da
  gre za denarnico, do katere nima več ključa — to je dokončna, nepopravljiva
  kriptografska realnost (noben hrošč v pogodbi ne omogoči podpisa transakcije brez
  pravega ključa, razen če pogodba sama izrecno vsebuje meta-tx/recovery mehanizem
  — preveri v kodi, ne ugibaj). Povej to naravnost in se ustavi, ne išči naprej
  nobene "exploit" poti kot nadomestka za manjkajoč ključ.
- Za zgolj statično branje/razlago kode brez izvajanja — to ne potrebuje tega
  skilla, samo preberi datoteke.

## Predpogoji

- Repo zgrajen: `cargo build --release` v korenu ForkSploit repozitorija je bil
  uspešen (`./target/release/forksploit` obstaja).
- Nameščeni: `anvil`, `cast`, `forge` (Foundry — `foundryup` jih vse namesti).
- Dva LOKALNA polna mainnet vozlišča obstajata na tem računalniku: eno za ETH, eno
  za ETC. **Natančen URL/port za vsako od njiju NI zapisan nikjer v tem skillu** —
  uporabnik ju pove ob vsakem zagonu (glej FAZO 1). Nikoli ne ugibaj porta.
- `onchain_scripts/` python odvisnosti nameščene (`pip install -r
  onchain_scripts/requirements.txt` iz korena repozitorija, če še ni).

## FAZA 0 — Avtorizacija (blokirajoč korak, se NE preskoči)

Preden se naredi KAJTERKOLI drug korak, uporabnik mora eksplicitno, pisno (v
pogovoru) potrditi VSE tri stvari:

1. **Naslov tarčne pogodbe** (0x...) in **veriga** (eth/etc/druga).
2. Da ima **dovoljenje** testirati to specifično pogodbo (lastna pogodba, pogodba
   klienta z pisnim dovoljenjem, ali javni bug-bounty program).
3. **Recovery wallet naslov** (0x...), kamor naj gre vse, kar se med pregledom
   "izkoristi" kot dokaz.

Če kateri od teh treh manjka ali je nejasen — **USTAVI se in vprašaj**. Ne
nadaljuj na podlagi domneve.

## FAZA 1 — Izbira in preverjanje PRAVEGA vozlišča

ETH in ETC mainnet sta en znak narazen v imenu in OBA sta resnična omrežja z
resnično vrednostjo — zamenjava ju je najpogostejša in najnevarnejša napaka, ki jo
lahko naredi avtomatiziran agent.

1. Vprašaj uporabnika za **natančen RPC URL** lokalnega vozlišča za verigo iz FAZE
   0 (npr. `http://127.0.0.1:XXXX`) — ne predpostavljaj porta.
   - Če uporabnik ni prepričan ali vozlišče teče v Dockerju: `docker ps` pokaže
     dejanski port, mapiran na gostitelja (`PORTS` stolpec, npr.
     `0.0.0.0:8546->8546/tcp` — port, ki je samo `8545/tcp` BREZ `0.0.0.0:...->`
     predpone, NI dosegljiv iz gostitelja, tudi če je "privzeti" port za to
     orodje). Preverjeno v praksi: core-geth ETC vozlišče je imelo notranji port
     8545, a dosegljiv samo preko mapiranega 8546.
2. **Preveri ga neposredno**, preden mu zaupaš:
   ```
   terminal(command="curl -s -X POST -H 'Content-Type: application/json' --data '{\"jsonrpc\":\"2.0\",\"method\":\"eth_chainId\",\"params\":[],\"id\":1}' <URL>")
   ```
   Pričakovan odziv: `"result":"0x1"` za ETH mainnet, `"result":"0x3d"` za ETC
   mainnet. **Če se ne ujema s verigo iz FAZE 0 — USTAVI se**, povej uporabniku
   natančno, kaj se je zgodilo, in ne nadaljuj.
3. Preveri, da vozlišče dejansko napreduje (ni obstalo):
   ```
   terminal(command="curl -s -X POST -H 'Content-Type: application/json' --data '{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}' <URL>")
   ```
   Počakaj nekaj sekund, ponovi, številka bloka se mora premakniti (ali vsaj biti
   svež/razumen blok, ne `0x0`).

**Zaključek FAZE 1**: imaš preverjen, pravi RPC URL za pravo verigo. Shrani si ga
samo za to sejo — ne zapisuj ga v noben trajen datotečni sistem.

## FAZA 2 — Vzpostavitev VARNEGA forka (vedno privzeto, nikoli direktno na pravo vozlišče za raziskovanje)

Vsako raziskovanje, fuzzing in PRVO preverjanje exploita se zgodi na LOKALNEM
forku pravega vozlišča — NIKOLI direktno proti pravemu vozlišču iz FAZE 1 v tej
fazi. Fork je brezplačen, popolnoma reverzibilen posnetek resničnega stanja.

```
terminal(command="anvil --fork-url <PREVERJEN_URL_IZ_FAZE_1> --port 8555 --hardfork shanghai &", timeout=10)
```

**Pomembno za ETC (in verjetno druge ne-ETH verige)**: `anvil` privzeto (`--hardfork
latest`) predpostavi post-Cancun blok-glavo (EIP-4844 "blob gas"). Pravo ETC vozlišče
(pred-Cancun) te glave nikoli ne vrne, zato VSAK `eth_call`/`eth_estimateGas` na forku
spodleti z `{"code":-32602,"message":"Excess blob gas not set."}` — videti je kot
pokvarjen fork, čeprav `eth_chainId`/`eth_blockNumber` delujeta normalno. Popravek:
EKSPLICITNO podaj `--hardfork shanghai` (najbližji pravi nivo za ETC, glej razdelek 8 v
`references/zmogljivosti.md`) ob zagonu anvil forka. Če po tem popravku `eth_call`
vrne normalen EVM revert namesto te RPC napake, je fork pravilno konfiguriran.

Preveri, da fork dejansko posnema pravo stanje (tarčna pogodba mora imeti kodo):

```
terminal(command="cast code <NASLOV_TARCE> --rpc-url http://127.0.0.1:8555")
```

Prazen odziv (`0x`) pomeni, da fork ni pravilno povezan ali da naslov ne obstaja na
tej verigi — **USTAVI se**, preveri FAZO 0/1 ponovno.

**Zaključek FAZE 2**: `http://127.0.0.1:8555` je potrjen, delujoč fork z
identičnim stanjem kot pravo vozlišče.

## FAZA 3 — Zagon ForkSploit na forku

Nastavi RPC override na FORK (ne na pravo vozlišče) za čas celotnega preverjanja:

```
terminal(command="cd onchain_scripts && python3 -c \"from chains import set_rpc_override; set_rpc_override('<eth|etc>', 'http://127.0.0.1:8555')\"")
```

Zaženi `auto_pipeline.py` — to je ŽE obstoječ, celoten cikel (register → fund →
fuzz → zaznaj → exploit preko ponovno-uporabljenega AttackWallet → sweep na
recovery wallet), ne piši svojega:

```
terminal(command="cd onchain_scripts && python3 auto_pipeline.py --target <NASLOV_TARCE> --recovery-wallet <RECOVERY_WALLET_IZ_FAZE_0> --key <POT_DO_KLJUCA_TESTNEGA_RACUNA> --chain <eth|etc> --confirm-mainnet --fund-eth 0.01 --fuzz-seconds 300 --detectors all", timeout=400)
```

Opomba: `--confirm-mainnet` je tukaj potreben, ker `auto_pipeline.py` ETH/ETC vedno
šteje za "mainnet" (`chains.require_mainnet_confirmation`) — TUDI ko dejansko
cilja na FORK preko RPC override-a zgoraj. To je namerno in varno: fork JE na
`eth`/`etc` chain-id, zato orodje ne razlikuje "fork" od "pravega" po chain-id-u,
samo po RPC URL-u, ki smo ga sami preverili v FAZI 1-2. Ključ (`--key`), ki ga tu
uporabiš, naj bo **testni/throwaway ključ** (npr. en izmed anvil-ovih znanih
privzetih dev ključev), NIKOLI pravi ključ uporabnika — na forku ni pomembno, kdo
plača gas.

**Zaključek FAZE 3**: dnevnik v `onchain_scripts/logs/` kaže, ali je bila najdena
ranljivost, in če je bil generiran `.plan.json`/`.s.sol` exploit.

## FAZA 4 — Pregled najdb: ČLOVEK izbere cilj

Preberi dnevnik in vsako najdbo predstavi uporabniku z:
- `bug_type` in oznako **`(sim-confirmed)`** ali **`(sim-review)`** — ta predpona
  `sim-` je namerna in NI okrajšava, ki se jo lahko ignorira: to je ZGOLJ
  simulacijska (revm, brez merjenja gasa — glej `CLAUDE.md`) ocena vzorca, nikoli
  dokaz o resnični on-chain izvedbi. Pred 2026-11-02 je Rust stran tu izpisovala
  golo `(confirmed)`/`(review)`, kar je bilo nevarno dvoumno: `auto_pipeline.py`'s
  `run_fuzzer()` to vrstico (s predpono `[fuzzer] `) zapiše v ISTO log datoteko kot
  svoj lastni, resnično on-chain preverjen `CONFIRMED`/`NOT CONFIRMED` status
  (glej FAZA 7/8 spodaj) — zlahka bi ju kdo zamenjal. Preimenovano po resnični
  najdbi na ETC mainnet-u (plan `C9f53_2`): Rust stran je rekla "Confirmed", prava
  veriga pa je rekla "ne" (presežen `block.gasLimit`, ker revm gasa ne meri).
- Ali JE bil generiran exploit skript (`*.Exploit.s.sol`) — to je res samo za
  `(sim-confirmed)` najdbe (glej `src/evm/solution/mod.rs`'s `is_confirmed_exploitable_bug`
  v ForkSploit repoju za natančen trenutni seznam).
- `(sim-review)` najdbe NIKOLI ne predstavi kot "dokazan napad" — to so samo sumi, ki
  potrebujejo človeško presojo.
- **Nikoli ne reči stranki/uporabniku samo "CONFIRMED" na podlagi tega koraka.**
  `(sim-confirmed)` pomeni "vzorec je resničen v simulaciji", NE "denar je
  dejansko premaknjen". Edina beseda "CONFIRMED" (brez `sim-` predpone), ki jo je
  dovoljeno uporabiti v poročilu stranki, je tista, ki jo vrne `execute_plan()` v
  FAZI 7/8 (`auto_pipeline.PLAN_CONFIRMED`) — zahteva resnično spremembo salda
  recovery denarnice na pravi verigi.

**Vprašaj uporabnika**, katero najdbo (če je več) naj se dejansko preveri/izkoristi
naprej. Ne nadaljuj samodejno na prvo najdbo.

## FAZA 4a — Preveri DEJANSKO lastništvo sredstev (blokirajoč korak pri "pooled"/staking pogodbah)

**Pred vsakim nadaljevanjem proti najdbi, ki bi "izvlekla denar" iz pogodbe s skupnim
skladom (staking, lending, pooled vault, oracle z depoziti, AMM) — preveri na forku,
ali denarnica iz FAZE 0 DEJANSKO ima pozicijo v tej pogodbi**, preden karkoli
predpostaviš o tem, čigav je denar v njej. Konkreten primer (2026-11-02, resnična
ETC pogodba): uporabnik je trdil "10 ETC v pogodbi je moj denar" — direkten
`cast call` na pogodbin `stakes(address)`/`mana(address)` (ali ekvivalentno glede na
specifično pogodbo: `balanceOf`, `deposits`, lastna mapping funkcija) za OBE
denarnici iz FAZE 0 je vrnil `0` — denar je pripadal DRUGIM, nepovezanim
uporabnikom pogodbe. Brez tega koraka bi se nadaljevalo naravnost proti izkoriščanju
tujih sredstev.

```
terminal(command="cast call <NASLOV_TARCE> \"<ustrezna_getter_funkcija>(address)(uint256)\" <NASLOV_DENARNICE_IZ_FAZE_0> --rpc-url http://127.0.0.1:8555")
```

Če rezultat je `0` (ali kako drugače kaže, da denarnica iz FAZE 0 nima pozicije) —
**USTAVI se in vprašaj uporabnika neposredno**, ali ima DRUGO denarnico s to pozicijo
(in če da, preveri NJO enako, preden nadaljuješ), ali je prišlo do nesporazuma. Ne
predpostavljaj "saldo pogodbe = uporabnikov denar" samo zato, ker ima uporabnik
dovoljenje za TESTIRANJE pogodbe — dovoljenje za testiranje ni isto kot lastništvo
sredstev v njej.

**Če rezultat NI `0`, torej denarnica iz FAZE 0 dejansko ima pozicijo** — ta korak je
USPEŠNO opravljen, nadaljuj normalno proti FAZI 5-9. Ta faza NI splošna blokada
testiranja permissionless/staking pogodb, niti pogodb brez `owner` vloge v kodi —
lastništvo sredstev, potrjeno tukaj na verigi, je samo po sebi popolnoma zadostna
avtorizacija za pravo izvedbo, ne glede na to, ali koda sploh ima admin vlogo. Prav
tako ta faza NIKOLI ne omejuje FAZ 1-3 (raziskovanje/fuzzing na forku) — tiste se
lahko vedno izvedejo na kateremkoli naslovu, ker nikoli ne premaknejo resničnega
denarja; ta preverba je relevantna šele, ko se najdba obravnava kot "denar za
vrnitev" nekomu.

**Če se izkaže, da je prava denarnica tista, do katere je uporabnik izgubil zasebni
ključ** — glej opozorilo v "Kdaj NE uporabiti" zgoraj. To je dokončno, ne glede na
morebitne hrošče v pogodbi; ustavi se tukaj, ne iskati "exploit" nadomestka.

## FAZA 5 — Preverjanje DOKAZA na forku ("je kovanec prispel" — prvič, varno)

`auto_pipeline.py` je že izvedel sweep na recovery wallet NA FORKU v FAZI 3. Zdaj
to DOKAŽI, ne samo predpostavljaj:

```
terminal(command="cast balance <RECOVERY_WALLET> --rpc-url http://127.0.0.1:8555")
```

Primerjaj s stanjem PRED tekom (če ni bilo zapisano, zaženi ponovno na svežem
forku in zapiši stanje pred in po). **Samo če se saldo dejansko dvigne za
pričakovan znesek**, šteje FAZA 5 kot uspešna. Če se ne dvigne — to NI dokazana
ranljivost, ne glede na to, kaj pravi terminalski izpis "Found vulnerabilities" —
povej uporabniku natančno to in se ustavi tukaj.

## FAZA 6 — KONČNA potrditev pred PRAVO izvedbo (ločen, eksplicitni korak)

To je najpomembnejša varovalka v celotnem skillu. Preden se karkoli iz FAZE 7
zažene, uporabniku jasno, eksplicitno povej VSE naslednje in počakaj na
EKSPLICITNO pritrditev (ne tiho nadaljevanje):

1. "Zdaj bom izvedel PRAVO transakcijo na [ETH/ETC] MAINNET, z resničnimi sredstvi."
2. "Tarča: [naslov]. Recovery wallet: [naslov]. Pričakovan znesek: [znesek]."
3. "To je NEPOVRATNO. Ali eksplicitno potrjuješ, da naj nadaljujem?"

Če uporabnik ne odgovori z nedvoumnim DA — **USTAVI se**. Nikoli ne razlagaj
molka ali prejšnjega splošnega dovoljenja (FAZA 0) kot zadostno za TO specifično
pravo izvedbo — FAZA 0 je avtorizacija za TESTIRANJE, FAZA 6 je ločena potrditev
za PRAVO TRANSAKCIJO.

## FAZA 7 — Resnična izvedba (šele po FAZI 6)

Preklopi RPC override na PRAVO vozlišče iz FAZE 1 (ne na fork):

```
terminal(command="cd onchain_scripts && python3 -c \"from chains import set_rpc_override; set_rpc_override('<eth|etc>', '<PRAVI_URL_IZ_FAZE_1>')\"")
```

Zaženi **identičen** `auto_pipeline.py` ukaz kot v FAZI 3, le s **pravim** ključem
uporabnika (uporabnik ga poda sveže, zdaj — glej "Varnost ključev" spodaj), ne s
testnim:

```
terminal(command="cd onchain_scripts && python3 auto_pipeline.py --target <NASLOV_TARCE> --recovery-wallet <RECOVERY_WALLET> --key <POT_DO_PRAVEGA_KLJUCA> --chain <eth|etc> --confirm-mainnet --fund-eth <ZNESEK> --fuzz-seconds 300 --detectors all", timeout=400)
```

## FAZA 8 — KONČNO preverjanje: je kovanec DEJANSKO prispel (pravo vozlišče)

**To je dokaz, ne "se je skript izvedel brez napake".**

```
terminal(command="cast balance <RECOVERY_WALLET> --rpc-url <PRAVI_URL_IZ_FAZE_1>")
```

Primerjaj s stanjem PRED FAZO 7 (zapiši ga PRED zagonom FAZE 7, ne šele zdaj).
Povej uporabniku natančno razliko v ETH/token. Samo TA primerjava šteje kot dokaz
uspeha — ne izpis "ONCHAIN EXECUTION COMPLETE & SUCCESSFUL" iz `forge script`, ki
pomeni samo "transakcija ni revertirala", ne "denar je prispel tja, kamor naj bi".

## FAZA 8a — Če ni bila najdena NOBENA ranljivost: formalna "negativna" trditev

**To je enako pomembno kot FAZA 8 in se NIKOLI ne sme izpustiti.** En sam fuzzer
tek, ki ne najde ničesar, sam po sebi NI dovolj za trditev "pogodba je varna" —
ne za ForkSploit, ne za katerokoli drugo fuzz/varnostno orodje na svetu (odsotnost
dokaza ni dokaz odsotnosti). Zato `auto_pipeline.py`/`batch_pipeline.py` zdaj
avtomatsko izračunata formalno **omejeno** trditev namesto golega molka, vsakič
ko `work_dir/vulnerabilities/*.plan.json` ostane prazen IN `vuln_info.jsonl` nima
niti ene (tudi ne `sim-review`) najdbe (`determine_negative_result_verdict()` v
`auto_pipeline.py`, dodano 2026-11-02 kot direkten odgovor na zahtevo po
"dokazljivem orodju z garancijo", ne demonstracijski kodi):

- **`VERDICT: NO VULNERABILITY FOUND (bounded)`** — izda se SAMO, če so
  izpolnjeni VSI trije pogoji: ≥80% instruction coverage (najmanjša vrednost med
  VSEMI pogodbami v `coverage.txt`, ne povprečje), ≥300s dejanskega fuzz časa
  (resnično pretečen, ne zahtevan), in `--detectors all` (ne ožji nabor). Poročilo
  stranki mora vedno navesti natančen % pokritosti, čas in verigo — NIKOLI samo
  "varno".
- **`VERDICT: INSUFFICIENT COVERAGE`** — izda se, če KATERIKOLI od treh pogojev
  ni izpolnjen. To pomeni "ne vemo", NE "varno". Poročilo stranki mora to jasno
  povedati in priporočiti daljši tek/`--detectors all`, preden se sme izdati
  karkoli o odsotnosti ranljivosti.
- Če je bila najdena VSAJ ENA `(sim-review)` najdba (tudi brez `.plan.json`), se
  ta formalna trditev NE izda — `report_unexecuted_findings()` že pokrije ta
  primer ("najdeno nekaj resničnega, a ni avtomatsko izkoristljivo"), in izdati
  ob tem ŠE "NO VULNERABILITY FOUND" bi bilo neposredno v nasprotju s tem.
- **Pravilo za poročanje stranki**: "ni ranljivosti" se SME reči SAMO skupaj s
  točnim obsegom (% pokritosti, čas, verzija detektorjev) — nikoli kot golo,
  nekvalificirano "varno". Enako velja v obratni smeri kot `(sim-confirmed)`
  preimenovanje (FAZA 4 zgoraj): beseda "CONFIRMED"/"varno" brez natančnega
  obsega je prav tisto, kar to podjetje ne sme nikoli izreči.

## FAZA 9 — Čiščenje in zapis v rastočo knjižnico

1. **Vedno, ne glede na uspeh**: počisti RPC override, da naslednja seja privzeto
   ne kaže na pravo vozlišče po nesreči:
   ```
   terminal(command="cd onchain_scripts && python3 -c \"from chains import clear_rpc_override; clear_rpc_override('<eth|etc>')\"")
   ```
   Ustavi anvil fork (`kill %1` ali po PID-u).
2. **Samo če je FAZA 8 potrdila uspeh**: dodaj vnos v
   `references/potrjene_tehnike.md` (glej ta skill-ov `references/` imenik) — datum,
   veriga, naslov pogodbe, `bug_type`, kratek povzetek, kaj je dejansko delovalo.
   To je "rastoča knjižnica", NE "model se je naučil" — gre za dejanski, berljiv
   zapisnik, ki ga lahko naslednja seja prebere kot referenco, ne za spremembo
   samega modela.

## Varnost ključev (nespremenljivo pravilo)

- Zasebni ključi NIKOLI ne gredo v ta skill, v kodo, v trajno shrambo, ali v
  katerikoli zapis, ki preživi to sejo. Uporabnik jih poda sveže, ob vsakem
  dejanskem potrebnem koraku (FAZA 3: testni ključ, FAZA 7: pravi ključ).
- Testni ključ (FAZA 3, fork) in pravi ključ (FAZA 7, pravo vozlišče) sta VEDNO
  različna. Nikoli ne uporabi pravega ključa na forku "ker je vseeno" — navada
  ubija disciplino.

## Napake (Pitfalls)

- **ETH in ETC mainnet sta en znak narazen.** `require_mainnet_confirmation` v
  `onchain_scripts/chains.py` ju obe obravnava enako (obe zahtevata
  `--confirm-mainnet`) — NE razlikuje tipkarske napake med njima. Edina zaščita je
  FAZA 1 (preveri `eth_chainId` neposredno, ne zaupaj samo imenu).
- `--confirm-mainnet` zastavica se uporablja TUDI na forku (glej opombo v FAZI 3)
  — to ni napaka, je posledica tega, da `chains.py` ne loči forka od resnične
  verige po chain-id-u.
- Če `auto_pipeline.py` poroča "Found vulnerabilities" to NE pomeni avtomatsko, da
  je bil denar dejansko prenešen — vedno preveri FAZO 5/8 neposredno.
- Review-tier najdbe (`(sim-review)` oznaka) NIMAJO generiranega exploit skripta po
  dizajnu — to ni napaka ForkSploita, glej `src/evm/oracle.rs`'s `classify_confidence`
  v repoju za natančen razlog za vsak primer.
- `anvil --fork-url` na ETC (ali drugi pred-Cancun verigi) BREZ `--hardfork shanghai`
  vrže `"Excess blob gas not set."` na VSAK `eth_call` — glej FAZO 2.
- **Popravljeno 2026-11-02** (prej veljavna past, zdaj zaprta za ETH): `execute_plan()`
  v `auto_pipeline.py` je prej vrnil `CONFIRMED`, če noben korak ni revertiral, TUDI
  če je `AttackWallet balance after plan: 0 ETH` — torej hrošč, ki uspe brez
  reverta, a ne iztrži nič denarja (fuzzer je našel SAMO primitiv, ne najbolj
  profitabilno varianto). Zdaj `execute_plan()` zajame pravo ETH stanje recovery
  denarnice tik pred in tik po tem konkretnem planu, in vrne `CONFIRMED` SAMO, če je
  saldo dejansko narasel — sicer nov status `EXECUTED_NO_PROFIT`, ki se NIKOLI ne
  poroča kot dokazan napad. To ne nadomešča FAZE 5/8 (tisti dve še vedno preverjata
  CELOTEN tek na pravem vozlišču, ne samo en plan, in sta edini neodvisni, s strani
  človeka izvedeni preverbi), a zdaj pomeni, da niz `CONFIRMED` v samem izpisu
  pipeline-a dejansko pomeni "denar je pristal na recovery denarnici za TA plan",
  ne le "koraki niso revertirali". **Posodobljeno 2026-11-02 (isti dan, drugi
  korak): zdaj pokriva tudi ERC20** — `plan.json` nosi `stolen_asset` za raw
  ERC20 korake (glej `erc20_token_touched` v `src/evm/solution/mod.rs`),
  `execute_plan()` po planu preveri/pobere vsak tak token preko `sweepToken()`
  z istim pred/po preverjanjem na recovery denarnici. Primer, ki je to
  past prvič razkril (2026-11-02): ForkSploit je potrdil reentrancy v
  `withdraw()`-stilu klicu z 38% pokritostjo v 300s, a resnična profitabilna pot (v
  `claim()`, druga funkcija z enako ranljivostjo) je zahtevala ROČNO branje
  verificirane izvorne kode (Blockscout), ne samo zaupanje avtomatskemu teku.
- **Verificirana izvorna koda na Blockscout je brezplačna in brez API ključa**:
  `https://etc.blockscout.com/api/v2/smart-contracts/<naslov>` (ETC) oz. ustrezen
  `<veriga>.blockscout.com` za druge podprte verige — vrne `is_verified`,
  `source_code`, `abi`, `constructor_args` v JSON-u, če je pogodba verificirana. Za
  pravo, že deployano mainnet tarčo je to VEDNO prvi korak pred branjem raw
  bytecode-a ali zanašanjem izključno na ForkSploitove heuristike — prava izvorna
  koda razloči resnično ranljivo funkcijo od lažno-pozitivnih najdb v knjižnicah
  (npr. gas-optimizirane assembly-based matematične knjižnice sprožijo "Integer
  Overflow (sim-review)" na raw SUB opcode-ih, ki NISO resnični hrošči).
- **WETH9's `withdraw()` ima trdo-kodiran 2300 gas limit na povratni pošiljki —
  ujeto šele z živim testom na Anvil forku, ne s statičnim branjem kode**
  (2026-11-02): ko je `AttackWallet` znotraj `executeOperation()` poklical
  `WETH.withdraw(amount)` za odvitje izposojenega WETH v raw ETH (flashloan
  financiranjska pot), je WETH9 interno uporabil `msg.sender.transfer(wad)` —
  Solidity-jev klasičen vzorec s trdo-kodiranim 2300 gas stipend-om za klic v
  `receive()`. `AttackWallet.receive()` samo prebere `pendingCallbackTarget`
  (cold SLOAD, ~2100 gas po EIP-2929) preden se odloči, ali naj kaj naredi —
  to SAMO po sebi skoraj izčrpa celoten 2300 gas budget, in transakcija je
  zanesljivo (ne občasno) padla z `OutOfGas` znotraj `receive()`. Preverjeno z
  `cast run <tx_hash> -vvvv` na pravem Anvil forku ETH mainnet-a — brez tega
  orodja bi bil root cause skoraj nemogoče najti samo iz "AttackWallet:
  flashLoanSimple failed" sporočila na vrhu sledi, ki pravi vzrok prekrije.
  Popravek: `executeOperation()` zdaj na svojem začetku segreje (warm) to
  shrambeno mesto prek `emit SlotWarmed(pendingCallbackTarget)` (NE bare
  branje — to bi `--via-ir` optimizator lahko odstranil kot "brez učinka").
  Živo ponovno preverjeno po popravku: cel cikel (izposoja→odvitje→korak→
  zavitje→vračilo) je uspel, stanja se ujemajo do zadnjega wei-ja. Lekcija: ta
  past je NEVIDNA za `cargo build`/`solc` (oba uspeta brez opozorila) in za
  statični code review — samo dejanska izvedba na forku jo pokaže.
- **MEV zaščita za flashloan pot + resnična napaka v `sign_step()`, ujeta šele
  z dejanskim klicem** (2026-11-02): `armFlashloanActions` sama po sebi
  razkrije CEL seznam korakov (tarčo, calldata, vrednost) kot ločeno, javno
  vidno transakcijo PRED `startFlashLoan` — brez zaščite bi to dalo
  mempool-botu dovolj časa, da isti hrošč izkoristi prej (hujše kot pri
  ostalih plan-vrstah, ker sta arm in start LOČENI transakciji, ne ena). Zdaj
  obe skupaj, atomsko, prek Flashbots bundle (enaka odločitev `use_bundle` kot
  za ostale plane). Med prvim dejanskim klicem `sign_step()` za ta dve
  transakciji se je pokazala NAPAKA, ki je obstajala že prej za VSAK bundle
  (nihče je očitno še ni dejansko pogonil): `tx = {..., **fee_fields}` pusti
  `is_legacy` ključ v slovarju, kar `eth_account.sign_transaction` zavrne
  (`"Transaction had invalid fields: {'is_legacy': False}"`). Popravljeno z
  istim dispatch-om kot `gas_utils.build_precise_tx` (legacy → `gasPrice`,
  sicer `maxFeePerGas`/`maxPriorityFeePerGas`/`type=2`, NIKOLI `is_legacy`
  samega). Po popravku: obe transakciji se pravilno pred-podpišeta.
- **DRUGA, resnejša napaka, ujeta in POPRAVLJENA istega dne — prejšnja
  domneva "datacenter-IP blokada" je bila NAPAČNA**: dejanska oddaja na
  `relay.flashbots.net` je vračala `403` + `{"code":-32025,"message":"invalid
  flashbots signature"}` — ne network blokada, pravi podpis je bil
  NEVELJAVEN. `sign_request()` v `flashbots_bundle.py` je manjkal `0x`
  prefiks na SAMEM PODPISU v `X-Flashbots-Signature` glavi (hash digest je
  bil pravilen). Uradni Python primer na docs.flashbots.net ima ISTO napako
  (`signature.hex()` brez `0x`, ker `hexbytes>=2` ne doda prefiksa
  samodejno) — Go primer v isti dokumentaciji ga vedno doda prek
  `hexutil.Encode`. Sistematično testirano vseh 4 kombinacij `0x` na
  (hash, podpis) neposredno proti PRAVEMU produkcijskem relay-ju: samo
  (hash=0x+hex, podpis=0x+hex) je dalo čist premik iz "invalid flashbots
  signature" v normalno `{"code":-32003,"message":"insufficient funds..."}`
  — dokaz, da relay podpis sprejme in dejansko simulira transakcijo.
  Popravljeno v `sign_request()`. **Lekcija**: ne verjemi uradni dokumentaciji
  dobesedno v vseh jezikih hkrati — Python in Go primera na isti strani sta
  si nasprotovala, in samo živi test proti pravemu relay-ju (ne samo "ujema
  se z referenčno implementacijo") je razkril, kateri je dejansko pravilen.
- **Spremenjen podpis skupne funkcije pokvaril DRUG, ločen skript — ujeto
  šele, ko je uporabnik vprašal o `dex_arbitrage_scanner.py`** (2026-11-02):
  ko je `AttackWallet.sol`'s `armFlashloanActions` dobil tretji parameter
  (`values`) za flashloan-financiranjsko pot v `auto_pipeline.py`, je
  `dex_arbitrage_scanner.py` — ki NEODVISNO kliče isto funkcijo za cross-DEX
  arbitražo, zgrajeno PRED tem popravkom — ostal pri stari 2-argumentni
  obliki (`selector("armFlashloanActions(address[],bytes[])")`). Ta
  selector po spremembi pogodbe ne obstaja več, torej bi vsak `--execute`
  tek zanesljivo padel. **Lekcija**: sprememba podpisa skupne/deljene
  funkcije (`AttackWallet.sol`, poklicane iz VEČ neodvisnih
  `onchain_scripts/*.py` datotek) zahteva `grep -rn "<ime_funkcije>"
  onchain_scripts/` PRED, ne po, spremembi — enostaven `cargo build`/`solc`
  test ne pokrije Python klicateljev sploh. Ob tej priložnosti je
  `dex_arbitrage_scanner.py`'s `--execute` pot tudi prvič dobila Flashbots
  bundle MEV zaščito (prej je pošiljala `armFlashloanActions`/
  `startFlashLoan` kot dve ločeni javni transakciji — hujše tveganje kot pri
  exploit-planih, ker gre arbitraža v zanki, VEDNO tekmuje z drugimi boti,
  ne glede na prag vrednosti). Živo preverjeno: profitabilnostni račun proti
  pravim Uniswap V2/SushiSwap V2 WETH/USDC pool-om na forku (pravilno
  poroča "ni profitabilno" — realen trg je učinkovito arbitražiran), in
  `execute_arbitrage()`'s bundle pot proti PRAVEMU `relay.flashbots.net`
  (doseže normalno "insufficient funds", ne napako podpisa).
- **Razmerje med `dex_arbitrage_scanner.py` in Rust TWAP/cenovnimi oraklji
  (`src/evm/oracles/twap_manipulation.rs`, `v2_pair.rs`) — pomembno, a
  NAMERNO brez tehnične varovalke** (2026-11-02, na uporabnikovo izrecno
  zahtevo): ta Python skript NIKOLI ne kliče Rust orakljev — to sta povsem
  ločena sistema (Rust oraklji tečejo samo znotraj `forksploit evm`
  fuzzing teka, prek `src/feedback.rs`'s `OracleFeedback`). A FIZIČNI
  primitiv je IDENTIČEN: `TwapManipulationOracle` zazna premik razmerja
  rezerv >2x znotraj ENE transakcije; `build_arbitrage_steps()`'s
  transfer+swap na poimenovan pool, s poljubno izbranim `x`, atomsko ovit
  v flashloan, je NATANKO ta primitiv. Edina razlika med "legitimno
  arbitražo" in "napad na oracle" je NAMEN izbire `x` — optimizator ga
  izbere za zapiranje realne vrzeli (samo-omejujoče, majhen `x` na
  učinkovitem trgu), napadalec bi ga izbral namerno velikega. `max_x =
  min(ra_a, ra_b) // 2` je edina velikostna omejitev — NI "ostani pod X%
  vpliva na ceno" varovalka. **Uporabnik je eksplicitno zahteval, da to
  ostane izključno na človeški presoji, BREZ avtomatske tehnične blokade**
  — ne dodajaj je sam v prihodnji seji, razen če uporabnik to izrecno
  spremeni.
- **Dopolnjeno isti dan**: "človeška presoja" brez dejanskega prikaza
  številke ni presoja, samo upanje. Dodano: `price_impact_pct()` (ista
  metrika kot zgoraj) se zdaj izpiše v dnevniku pri VSAKEM pregledu
  (tudi samo-opozorilnem) za OBA pool-a, in `--execute` VEDNO ustavi ter
  vpraša človeka za natančno besedo "DA" (glej `ask_human_confirmation()`
  v `dex_arbitrage_scanner.py`) preden karkoli pošlje — brez zastavice za
  izklop. Vsak drug odgovor (napaka, prazen vnos, EOF) je zavrnitev;
  nikjer ni privzete poti za odobritev. Preverjeno z vsemi 4 primeri
  (DA/narobe/prazno/EOF) in s formulo na namerno velikem (-75%) in
  majhnem (-0.02%) primeru, da je metrika dejansko smiselna, ne samo
  prisotna.
- **Dve resnični napaki v `onchain_scripts/dashboard_server.py` (novo,
  lokalni web dashboard), ujeti šele z dejanskim e2e testom** (2026-11-02):
  (1) Python-ovo `input("poziv")` NIKOLI ne zapiše zaključnega `\n`
  (čaka na človeka v isti vrstici) — vrstično-bazirano branje subprocess
  stdout-a (`for line in stdout`) ta poziv nikoli ne vidi kot vrstico,
  dokler se kasneje ne pojavi nek DRUG `\n`, ki oba spoji — popravljeno s
  branjem znak-za-znakom in sprostitvijo takoj, ko se znan niz pojavi v
  medpomnilniku. (2) Ko je subprocess-ov `stdout` cevovod (vedno, ko ga
  Python zažene kot podproces, nikoli terminal), Python privzeto preklopi
  `print()`/`tee.log()` na BLOČNO (ne vrstično) shranjevanje izhoda —
  vrstice tiho obtičijo v notranjem predpomnilniku poljubno dolgo.
  Popravljeno z `-u` zastavico pri `subprocess.Popen([sys.executable,
  "-u", ...])`. Obe napaki bi bili NEVIDNI brez dejanskega pogona celotne
  verige (subprocess → zaznava poziva → zapis v stdin → pravi odgovor) —
  statično branje kode ali `py_compile` ju ne bi ujel.

## Preverbeni seznam (Verification)

- [ ] FAZA 0: naslov, avtorizacija, recovery wallet vsi eksplicitno potrjeni
- [ ] FAZA 1: `eth_chainId` ujema s pričakovano verigo, blok napreduje
- [ ] FAZA 2: fork vrača pravo kodo tarče
- [ ] FAZA 3-5: najdba + saldo na forku DEJANSKO preverjen, ne samo predpostavljen
- [ ] FAZA 4a: za "pooled"/staking pogodbe, lastništvo sredstev DEJANSKO preverjeno
      na verigi (ne predpostavljeno iz uporabnikove izjave)
- [ ] FAZA 6: eksplicitna, nedvoumna potrditev uporabnika za PRAVO izvedbo obstaja
- [ ] FAZA 7-8: saldo recovery wallet-a na PRAVEM vozlišču primerjan pred/po
- [ ] FAZA 9: RPC override počiščen, anvil ustavljen, (če uspeh) vnos zapisan

## Referenčne datoteke v tem skillu

- `references/zmogljivosti.md` — **POPOLN leksikon** vseh CLI flagov, vseh ~37
  orakljev (s confidence tier), vseh `onchain_scripts/` orodij, varnostnih
  mehanizmov in znanih omejitev. Preveri TUKAJ najprej za katerokoli faktično
  vprašanje o sistemu.
- `references/ukazi.md` — zbirka natančnih ukazov za hitro iskanje med delom.
- `references/potrjene_tehnike.md` — rastoč dnevnik dejansko potrjenih uspehov
  (glej FAZO 9).
- `references/nove-oracle-roadmap.md` — **ODPRT NAČRT (2026-11-02), nadaljevanje
  naslednjo sejo**: ~15 konkretnih, dobro utemeljenih kandidatov za nove oracle
  vrste (read-only reentrancy, ERC721/1155 hook reentrancy, šibka naključnost,
  DoS prek revert-a v zanki, arbitrary storage write, hardcoded gas stipend, in
  več), prioritizirano. Uporabnik je rekel, da bo sam dodatno raziskal kandidate
  — uskladi PRED kodiranjem, ne predvidevaj da je ta seznam dokončen.

## Dashboard: živo preverjena omrežna identiteta (2026-11-02)

`dashboard_server.py`'s `GET /api/verify-chain` NIKOLI ne zaupa imenu iz
`--chain` spustnega seznama — pokliče pravi, trenutno konfigurirani RPC
(`chains.make_w3`, upošteva aktiven `rpc_overrides.json`) in primerja
dejanski `eth_chainId` proti `chains.CHAIN_IDS` (preneseno iz
`src/evm/onchain/endpoints.rs`'s avtoritativne tabele, ne uganjeno).
Watermark (vijoličen ETH diamant / zelen ETC diamant) in barvna oznaka v
GUI-ju se preklopita izključno na podlagi TEGA živega rezultata, nikoli na
podlagi besedila v spustnem seznamu. Živo preverjeno med gradnjo proti
uporabnikovim resničnim lokalnim vozliščem: `rpc_overrides.json`'s `eth`
je kazal na mrtev RPC (port 8545, povezava zavrnjena) — dashboard je to
pravilno pokazal kot rdeče opozorilo "RPC nedosegljiv", NE kot tiho
napačno ETH oznako. `etc` override (port 8555, Anvil fork od uporabnikovega
pravega lokalnega ETC mainnet vozlišča na portu 8546 — potrjeno s strani
uporabnika) je pravilno vrnil chain ID 61 in zeleno ETC oznako. To je
dejanski dokaz koncepta "eth in etc sta eno črko narazen, nikoli ne
zaupaj imenu" — isto vodilo kot `chain_banner()`/FAZA 1 zgoraj, zdaj tudi
v GUI-ju, ne samo v CLI-ju.

## Dashboard Faza 2 dokončana (2026-11-02)

Vseh 5 Python `onchain_scripts/*.py` skript z `build_parser()` (dodano
tudi `monitor.py`, `batch_pipeline.py`, `aave_flashloan_runner.py`, enak
vzorec kot `auto_pipeline.py`/`dex_arbitrage_scanner.py` prej), PLUS
direkten Rust fuzzer zagon (`RUST_FUZZER_FIELDS` — ROČNO vzdrževana shema,
ker Rust clap parser ni introspektibilen iz Pythona tako kot `argparse`;
to je EDINO mesto v dashboard-u, kjer obrazec ni samodejno sinhroniziran s
pravim CLI-jem — če se Rust `evm` zastavice spremenijo, je treba to
ročno posodobiti), PLUS `POST /api/rpc-override`/`DELETE
/api/rpc-override/{chain}` (tanek ovitek okoli `chains.set_rpc_override`/
`clear_rpc_override`) in `POST /api/wallet-policy` (tanek ovitek okoli
`wallet_policy.register_policy`, ista anti-tipkarska `--confirm-chain`
dvojna potrditev — preverjeno, da napačna potrditev NIČESAR ne zapiše).
Pomembno za naslednjo sejo: **spremembe na `dashboard_server.py` (Python)
zahtevajo ponoven zagon procesa**, ne samo osvežitev brskalnika — za
razliko od `dashboard_static/*` (CSS/JS/HTML), ki se berejo sveže iz
diska ob vsaki zahtevi.

## Poslovni model: recovery_wallet = lastnik testirane pogodbe (2026-11-02)

Pomembna razjasnitev uporabnika: `recovery_wallet` NI fiksna
ForkSploit-ova denarnica — je **vedno denarnica lastnika/stranke, čigavo
pogodbo ravno testiraš**. Uspešno izkoriščena ranljivost izčrpa sredstva
NEPOSREDNO na naslov stranke — to JE determinističen dokaz ranljivosti
(glej zgodnejši del te seje o "edina zanesljiva pot"). Ker se recovery
denarnica spreminja PO STRANKI/ANGAŽMAJU, `wallet_policy.register_policy()`
zdaj sprejme opcijski `client_note` (CLI: `--client-note`, dashboard: polje
"Stranka / opomba" v wallet-policy panelu) — čisto informativno, NIKOLI
brano s strani `enforce_wallet_policy()` ali katere koli poti podpisovanja,
samo da je na prvi pogled jasno, ZA KOGA je trenutna recovery denarnica na
posamezni verigi zaklenjena, ne samo gol hex naslov. Obstoječi vnosi (npr.
`etc` v `wallets.json`) nimajo še nazaj-vpisane opombe — to prepusti
uporabniku, ki pozna pravi kontekst, ne ugibaj je sam.

**Ločeno, pomembno odkritje isti dan**: AttackWallet naslov, zapisan za
`etc` v `attack_wallets.json` (`0x5FbDB2315678afecb367f032d93F642f64180aa3`)
je **dobro znan Anvil/Hardhat privzeti naslov** ("prva pogodba, deployana
iz privzetega dev računa na nonce 0") — kar pomeni, da gre za ostanek
LOKALNEGA fork-testiranja, NE prave pogodbe na resničnem ETC mainnet-u.
Zato kaže saldo 0 in zato je poizvedba prej vrgla "missing trie node".
Lekcija za naslednjo sejo: `attack_wallets.json` vnosi niso avtomatsko
"pravi" samo zato, ker obstajajo — preveri naslovni vzorec/izvor, preden
mu zaupaš, enaka disciplina kot za vse drugo v tem projektu.

## Splošna najdba: control-leak lahko izloči VSE najdbe v transakciji, ne glede kje se zgodijo (2026-11-03)

Pri testiranju `forced_eth_accounting.rs` se najdba NI nikoli poročala,
čeprav je detekcijska logika v `host.rs` nedvoumno pravilno delovala
(preverjeno s začasnim debug izpisom: tisoče pravilnih zadetkov). Vzrok
ni bil v oraklju — je v `feedback.rs`'s `is_interesting()`:

```rust
if metadata.known_bugs.contains(&bug_idx) || has_post_exec {
    continue;
}
```

`has_post_exec` pove, ali je ta CELOTNA transakcija (kot celota, ne samo
del, kjer je hrošč zaznan) končala z NEREŠENO "control leak" kontinuacijo
(glej `host.rs`'s `call_allow_control_leak`/`CALL_UNTIL`). Če DA, se
VSI bug_idx-i iz te transakcije izločijo iz poročanja — tudi če je bil
hrošč zaznan PREJ, popolnoma neodvisno od klica, ki je povzročil leak.

Testni fixture je imel `require(EQ preverjanje); ... payable(x).transfer(
amount);` — EQ (hrošč) se zgodi PRVI, `.transfer()` (ki povzroči leak)
PRIDE ŠELE KASNEJE, a je VSEENO izločil poročilo za EQ. **Vsak izhodni
klic, ki prenaša vrednost, je natanko tista oblika, ki jo fuzzer-jev
lastni raziskovalni mehanizem najbolj agresivno poskuša prestreči** (za
raziskovanje reentrancy scenarijev) — zato lahko POLJUBEN oracle, čigar
zaznava se zgodi v FUNKCIJI, ki tudi pošlje ETH/vrednost KASNEJE v isti
transakciji, redko ali nikoli poroča, ČEPRAV je detekcija sama pravilna.

**To ni hrošč v posameznem oraklju — je arhitekturna lastnost, vredna
zavedanja pri VSAKEM novem oraklju in pri interpretaciji "0 najdb" na
pravih pogodbah, ki imajo funkcije z izhodnimi ETH prenosi.** Testni
fixture-ji za take vzorce morajo biti brez izhodnega klica, ki prenaša
vrednost (glej `forced_eth_accounting.rs`'s test opombo), da dokažejo
vzorec brez tega nepovezanega šuma.

## Resen Rust-side bug: 5 oraklejev je napačno pripisovalo hrošče nepovezanim klicom (2026-11-02)

Na pravi ETC mainnet pogodbi (`0x9f5304DA62A5408416Ea58A17a92611019bD5ce3`, plan
`C9f53_5`) je bila `[Unchecked ecrecover(0)] (sim-confirmed)` najdba pripisana
klicu `0x64dab283()` — a neodvisno preverjeno z `cast disassemble` IN z
`debug_traceCall` na lokalnem anvil forku: ta klic je navaden `address`
getter (0 CALL-tipa opcode-ov, pc doseže največ 1314), ki NIKOLI ne pokliče
`ecrecover`. Opisani `pc=1927` je bil v CELO DRUGI funkciji (`0xe3ce9714`,
pravi "claim s podpisom" klic s 5 argumenti) — preverjeno z istim
`debug_traceCall`: ta DEJANSKO pokliče `ecrecover` precompile (`CALL` na
`0x1`) natanko na pc=1927.

**Korenski vzrok** (preverjen v Rust kodi, `src/evm/vm.rs`): detektorji kot
`ecrecover_zero`, `integer_overflow`, `delegatecall_injections`,
`storage_collisions`, `arbitrary_calls` se UNIJAJO (`old.chain(current)`)
naprej skozi CELOTNO genealogijo corpus-a, NIKOLI se ne počistijo. Oracle
(`ctx.post_state.X.iter()`) je iteriral ta CELOTEN akumuliran set, ne samo
NOVE vnose iz TE transakcije — zato je enkrat najden hrošč na enem naslovu/pc
"ostal priklopljen" na VSAKO poznejšo, nepovezano transakcijo, zgrajeno na
istem corpus veji, tudi če ta transakcija sploh ni dosegla te kode. Minimizer
(`src/evm/minimizer.rs`) je zato lahko "minimiziral" sled na eno samo,
popolnoma nepovezano transakcijo, in `objective.reproduces()` je še vedno
vrnil `true`, ker je začetno stanje minimizacije že podedovalo stari zastavek.

**Prizadeti oraklji** (vsi imajo IDENTIČEN vzorec, preverjeno z grep čez
celoten `src/evm/oracles/`): `ecrecover.rs`, `overflow.rs`,
`delegatecall.rs`, `storage_collision.rs`, `arb_call.rs` — od tega SO
Confirmed-tier (torej avtomatsko generirajo `*Exploit.s.sol`): Unchecked
ecrecover(0), Delegatecall Injection, Storage Collision, Arbitrary Call.

**Popravek**: vsak od teh petih `oracle()` zdaj filtrira na
`ctx.post_state.X.difference(ctx.pre_state.X)` — `OracleCtx` že ima ločen
`pre_state`/`post_state` (dokumentirano v `src/oracle.rs` kot "state
pred/po IZVEDBI TE transakcije"), zato je to natančno pravo mesto za
popravek, brez vpliva na pravo multi-tx logiko (korak, ki DEJANSKO prvič
sproži hrošč, se še vedno pravilno ujame na SVOJEM lastnem `oracle()`
klicu, ker je takrat `pre_state` še brez njega).

**Živo preverjeno** (lokalen anvil fork, brez tveganja, 2x `debug_traceCall`
kot neodvisen dokaz pred in po popravku): pred popravkom je bil hrošč
napačno pripisan `0x64dab283()`; po popravku (rebuild + ponovni fuzz tek na
istem cilju) je bil pravilno pripisan `0xe3ce9714(...)`, kar je neodvisno
potrjeno z `debug_traceCall` (CALL na `0x1` precompile na natanko tistem pc).

**Zakaj je to pomembno za poslovni model**: to ni "najden primitiv, ni
profita" (kot pri `C9f53_5` prej mislili) — to je bil primer, kjer je
ForkSploit TRDIL, da se določen klic obnaša na določen način, kar
NI BILO RESNICA niti v simulaciji. Brez tega popravka bi `auto_pipeline.py`
lahko generiral in (če bi gas/profit pogoji ustrezali) celo PODPISAL
transakcijo za exploit, ki sploh ne obstaja na opisanem naslovu/pc.

## Dve nadaljnji plasti istega problema, najdeni isti dan (2026-11-02)

Po zgornjem popravku se je na PRAVEM mainnet teku (isti cilj, 7 planov,
vseh 7 dejansko podpisanih in poslanih) pokazalo, da zgornji popravek
NI zadosten -- `Unchecked ecrecover(0)` je bil še naprej pripisan
nepovezanim selektorjem (`02ef6c86`, `f3fef3a3`), neodvisno zavrnjeno z
`debug_traceCall` (max doseženi pc 2050, trdjen pc 2214 nikoli dosežen).
Dve ločeni, globlji plasti:

**Plast 2 -- `host.current_*` se nikoli ni resetiral med transakcijami**
(`src/evm/vm.rs`): `current_arbitrary_calls` se je pravilno resetiral na
treh mestih pred vsako transakcijo, `current_ecrecover_zero`/
`current_integer_overflow`/`current_delegatecall_injections`/
`current_storage_collisions` pa NIKOLI -- rastli so čez CELOTNO življenjsko
dobo fuzz procesa (ne samo znotraj ene transakcije). Zato je plast-1
popravek (primerjava `pre_state`/`post_state` v oraklju) pomagal le delno:
`current_X` je bil že od prej "umazan" iz NEPOVEZANE veje raziskovanja, še
preden je `pre_state` za NOVO vejo sploh bil zgrajen. Popravljeno: dodano
resetiranje vseh štirih manjkajočih `current_*` HashSet-ov na vseh treh
mestih (`init_host!` makro + 2 ročna bloka), kjer se `current_arbitrary_calls`
že resetira.

**Plast 3 -- "control leak" simulacija brez preverjanja proti pravi verigi**
(`src/evm/host.rs`'s `call_allow_control_leak`, `src/evm/solution/mod.rs`):
fuzzer lahko med raziskovanjem PRESTREŽE klic (po `call_leak` številu
klicev) in namesto pravega izvajanja INJICIRA lastno, izmišljeno vrnjeno
vrednost, nato nadaljuje z ločeno, NIKJER SERIALIZIRANO kontinuacijo. Sled,
najdena na ta način, lahko "dokaže" oracle v simulaciji z vrednostjo, ki je
PRAVA veriga NIKOLI ne bo vrnila. AttackWallet nima načina, da bi
replikiral "lažno vrni X za ta klic" -- samo Reentrancy-jev `armCallback`
(PRAVI ponovljen klic, ne lažna vrnjena vrednost) je zanesljiv atomski
primitiv. Popravljeno: `Tx` (in `SolutionTx` trait, `ConciseEVMInput`) zdaj
nosi `call_leak: u32` naprej do generatorja; `trace_depends_on_control_leak()`
v `solution/mod.rs` OPUSTI generiranje atomičnega `.plan.json`/`.s.sol` za
tak primer (ostane samo `.t.sol`, z jasnim debug sporočilom zakaj) -- enak
vzorec kot že obstoječi `has_multiple_distinct_callers` preskok. NE velja
za pot Reentrancy (ta ostaja zanesljiva, ker `armCallback` ne injicira
ničesar lažnega).

**Pomembna, poštena omejitev, ugotovljena pri tem**: ForkSploit-ovi oraklji
prepoznajo samo ~37 vnaprej kodiranih bytecode vzorcev. "0 Confirmed
hroščev" na dani pogodbi NE pomeni "pogodba je varna" -- pomeni samo, da se
noben od TEH SPECIFIČNIH vzorcev ni ujel znotraj danega fuzz okna/pokritosti.
Poslovna logika, ekonomski/cenovni exploiti, admin-key tveganja in sistemske
napake med več pogodbami niso in ne morejo biti pokrite s čisto bytecode-level
vzorčnim prepoznavanjem -- to je meja te kategorije orodja, ne hrošč v
ForkSploit-u. Glej FAZA 8a zgoraj za formalno "omejeno" trditev, ki to
razmejuje.

## Plast 4 -- še 4 spregledane instance istega bug-a, najdene sistematično (2026-11-03)

Pred začetkom dela na novih oraklejih je bil narejen sistematičen pregled
VSEH `.chain(self.host.current_X...)` klicev v `src/evm/vm.rs` (11 skupaj),
ne samo tistih 4-5, ki jih je prejšnji dan konkretna najdba na ETC mainnet-u
pokazala. Rezultat: samo 3 od 11 (`self_destructs`, `arbitrary_calls`,
`typed_bug`) so bila pravilno resetirana; 4 so bila popravljena prejšnji dan
(`integer_overflow`, `delegatecall_injections`, `ecrecover_zero`,
`storage_collisions`); **4 so bila spregledana, ker prejšnji dnevni grep ni
zajel teh imen polj**: `current_uninitialized_memory_reads`,
`current_unchecked_call`, `current_tx_origin_checks`,
`current_delegatecall_targets_seen`. Popravljeno enako kot prejšnji dan:
resetiranje na vseh treh mestih v `vm.rs` + primerjava `pre_state`/`post_state`
v `uninitialized_memory.rs`, `unchecked_call.rs`, `tx_origin.rs`,
`delegatecall_target.rs`. Opomba: `calldata_addresses`/`returndata_addresses`/
`paid_calldata_addresses` (ki jih `delegatecall_target.rs` in
`self_referral.rs` tudi berejo) NISO prizadeta -- ta dva se vsako transakcijo
PRESTAVITA (`=`), ne UNIJATA (`.chain()`), torej sta bila od začetka pravilna.

**Lekcija za naprej**: pred dodajanjem NOVEGA oraklja s "current_X"
akumuliranim poljem, VEDNO preveri z `grep -n "\.chain(self\.host\.current_"
src/evm/vm.rs`, ali je število ujemanj enako številu resetiranih polj na VSEH
treh mestih (`init_host!` makro + 2 ročna bloka) -- ne zanašaj se na to, da je
bil prejšnji popravek izčrpen.

## Najdba na pravem ETC mainnet-u: simulacija brez merjenja gasa lahko potrdi neizvedljivo sled (2026-11-02)

Med izvajanjem resničnega, še ne preizkušenega plana `C9f53_2` proti pravi
ETC mainnet pogodbi `0x9f5304DA62A5408416Ea58A17a92611019bD5ce3` je
`execute_plan()` padel z `Web3RPCError: {'code': -32000, 'message':
'exceeds block gas limit'}`. Neposredno preverjeno z `eth_estimateGas`/
`eth_getBlock('latest')`: ocenjeni gas za ta klic je bil ~50 milijonov,
resnični ETC `block.gasLimit` pa natanko 8.000.000. Korenski vzrok: Rust
fuzzer simulira na `revm`, ki (glej `CLAUDE.md`) **nima merjenja gasa** —
zato lahko "potrdi" sled, ki je v idealizirani brezmejni simulaciji
veljavna, na pravi verigi pa je fizično nikoli ne moreš oddati v enem
bloku. Napaka se je prej pojavila šele kot surova RPC zavrnitev PO
podpisu transakcije.

**Popravek**: `gas_utils.estimate_gas_limit()` zdaj PRED vrnitvijo oceno
primerja z resničnim, sveže prebranim `w3.eth.get_block('latest')
['gasLimit']` in vrže `GasExceedsBlockLimitError`, če ocena presega block
limit — to je edino mesto, kjer se to preverja, ker VSI klicatelji
(`auto_pipeline.py`, `aave_flashloan_runner.py`, `batch_pipeline.py`,
`dex_arbitrage_scanner.py`) gredo prek `build_precise_tx`/
`estimate_gas_limit`. `execute_plan()` v `auto_pipeline.py` to izjemo
zdaj ujame ob prvi oceni gasa (prej izven vsakega `try`/`except` bloka —
od tod neukrotjena izjema) in vrne čist `PLAN_NOT_CONFIRMED` z berljivim
sporočilom, enako za bundle-pot (`execute_flat_plan_via_flashloan`) in
zaporedno pot. **Živo preverjeno na pravi ETC mainnet verigi po popravku in merge-u v
`main`** (ponovni zagon istega `C9f53_2` plana, isti dan): ocena gasa
49.610.942 proti resničnemu `block.gasLimit` 8.000.000 → čist
`NOT CONFIRMED: potreben gas presega block limit`, `status=not_confirmed,
recovery_delta_wei=0`, BREZ poskusa podpisa/pošiljanja transakcije (plan
je imel `total_value=0`, zato tudi funding-korak ni bil dosežen pred
preverbo gasa). Potrjuje dvoje: (1) popravek deluje točno kot
predvideno, in (2) ta konkretna fuzzer-jeva najdba NI realno izkoristljiva
na pravi verigi kljub `CONFIRMED`-videzu v simulaciji — natanko primer
blind spot-a, ki ga ta popravek zajame.

## Najdba: logi so trdo izpisovali "ETH" tudi na ETC/BSC/Polygon/... (2026-11-02)

Uporabnik je ob branju resničnega ETC-mainnet izpisa vprašal "zakaj meša
ETH z ETC?" — upravičeno: `auto_pipeline.py`, `batch_pipeline.py`,
`aave_flashloan_runner.py` in `gas_utils.describe_actual_cost()` so imeli
povsod trdo zakodiran priponek `" ETH"` za vsak `w3.from_wei(...,
'ether')`, NE GLEDE na to, katera veriga dejansko teče — torej je tudi
pravi ETC-mainnet tek izpisoval zneske kot "ETH", ne "ETC" (podobno bi
veljalo za BSC → BNB, Polygon → POL, Avalanche → AVAX, Gnosis → xDAI na
poteh, ki te verige dejansko podpirajo, npr. `aave_flashloan_runner.py`).

**Popravek**: `chains.py` dobi `NATIVE_SYMBOL` (chain string → ticker) in
`native_symbol_for_w3(w3)`, ki simbol izpelje iz RESNIČNEGA, živo
povezanega `w3.eth.chain_id` (ne iz morebiti napačnega `--chain` niza —
ista "nikoli ne zaupaj samo imenu" disciplina kot `chain_banner()`/
`require_mainnet_confirmation()`, tu uporabljena za izpis namesto za
izbiro verige). Vsi prizadeti klicni mesta zdaj kličejo
`native_symbol_for_w3(w3)` namesto trdega `"ETH"`. `dex_arbitrage_scanner.py`
je bil namenoma izpuščen — trenutno deluje izključno na `eth`
(`DEX_PAIRS_BY_CHAIN` ima samo `"eth"` ključ), zato je tam `"ETH"` dejansko
pravilen, dokler se scanner ne razširi na druge verige.

## `readonly_reentrancy.rs`: pravilna detekcija, a `has_post_exec` jo skoraj nikoli spusti skozi — korenski vzrok NI v `feedback.rs` (2026-11-03)

Novi oracle `readonly_reentrancy.rs` (bug_idx 39, SWC read-only
reentrancy: `view` funkcija vrne nekonsistentno vmesno stanje med odprtim
reentrancy oknom) je zahteval dodatni popravek, preden je sploh lahko
pravilno zaznaval:

**Popravek 1 — `view_call_baseline` mora biti persistenten.** Standarden
vzorec "`current_*`, počisti ob vsakem klicu" (glej Plast 2-4 zgoraj) se
izkaže za PREVEČ agresivnega tudi za ta primer: polje se je pobrisalo
tudi ob RESUMPCIJI control-leak kontinuacije, ne samo ob resnično NOVI
top-level transakciji. Posledica: `baseline_present=false` natanko v
trenutku, ko ga oracle potrebuje. Popravek: `current_view_call_baseline`
→ preimenovan v persistentni `view_call_baseline` (NIKOLI počiščen na 3
reset mestih), po istem vzorcu kot že obstoječi `slot_write_contexts`.
Po popravku je debug instrumentacija potrdila `baseline_present=true` in
pravilne `HIT INSERTED` dogodke (21562+-krat v enem teku).

**Popravek 2 ni bil mogoč — druga plast istega `has_post_exec` problema,
a tokrat nerešljiva s preoblikovanjem test fixture-ja.** Pri
`forced_eth_accounting.rs` (glej razdelek zgoraj) je bilo mogoče
preprosto odstraniti nepotreben izhodni `.transfer()` klic iz test
fixture-ja, ker vzorec hrošča tega klica sploh ni potreboval. Pri
read-only reentrancy pa je control-leak klic (zunanji klic, ki odpre
reentrancy okno) SAM MEHANIZEM hrošča — ni ga mogoče odstraniti, ne da bi
odstranili sam scenarij, ki ga oracle preverja.

Na uporabnikovo eksplicitno zahtevo ("Poglobi se v `feedback.rs` in
poskusi rešiti `has_post_exec` problem na splošni ravni") je bila
dodana začasna debug instrumentacija v `feedback.rs`'s `is_interesting()`
(odstranjena pred commit-om), in zagnan 20s tek na
`tests/evm/readonly_reentrancy/*`. Rezultat:

```
120305 has_post_exec=false
 99444 has_post_exec=true
---per bug_idx, has_post_exec=false count---
2579933380265121289   <- samo klasični Reentrancy, NIČ drugega
```

Od **120.305** popolnoma razrešenih transakcij v celotnem teku je SAMO
EN bug_idx (klasični `Reentrancy`) kadarkoli dosegel `has_post_exec=false`.
`readonly_reentrancy`-jeva dva bug_idx-a (`4330118404053422103`,
`10675110855689788199`) se nista pojavila niti enkrat med ~220.000
skupnimi preverjanji — kljub temu, da je host-level detekcija dokazano
pravilna in se sproži tisočkrat.

**Sklep: `feedback.rs`'s `has_post_exec` vrata NISO hrošč — delujejo
natanko po načrtu.** Klasični reentrancy dokazuje, da fuzzer OBČASNO
NAJDE popolnoma razrešeno pot za control-leak-odvisen hrošč — torej
mehanizem sam po sebi deluje. Prava ovira je v tem, KATERE kontinuacije
fuzzer-jeva mutacijska/izbirna strategija (`src/evm/mutator.rs`,
`src/fuzzers/evm_fuzzer.rs`) sploh poskusi med odprtim control-leak
oknom — "pokliči nazaj `getPrice()` MED oknom, nato pusti zunanjo
sekvenco normalno zaključiti" je precej ožji, specifičnejši cilj kot
klasični "prenesi vrednost nazaj", zato ga trenutna strategija le redko
zadane.

**Posledica za VSE bodoče control-leak-odvisne orakle** (ne samo za
tega): nizka stopnja dejanskega poročanja na pravih pogodbah ni nujno
znak napačne detekcijske logike — lahko je znak, da fuzzer preprosto
redko poskusi natanko pravo kontinuacijo. To je arhitekturna omejitev
mutacijske strategije, ne oracle-specifičen hrošč, in popravek bi moral
cilja biti v `mutator.rs`/`evm_fuzzer.rs` (vpliva na VSE control-leak
odvisne orakle hkrati, torej tvegan, večji posel), ne v `feedback.rs`.
Uporabnik se je odločil za to poglobitev; ni bila zaključena v tej seji
zaradi bližajočega se limita seje — nadaljevanje v naslednji seji.

## `delegatecall_target.rs`: dva resnična popravka, USPEŠNO živo potrjena (2026-11-03)

Na uporabnikovo zahtevo ("dokončaj zgornje popravilo in še tega
delegatecall_target.rs") je bila najprej preverjena hipoteza, da
`current_calldata_addresses`/`current_returndata_addresses`/
`current_paid_calldata_addresses` trpijo za ISTIM cross-leak-resumpcijskim
problemom kot `view_call_baseline` (glej razdelek zgoraj). Potrjeno v
kodi: `execute_abi`'s `is_step` zanka (`vm.rs`) kliče `execute_from_pc` s
`cleanup=true` ŽE ZA PRVI resumiran segment, in `post_exec` parameter je
`Some(pe)` natanko in SAMO za resumpcijo (nikoli za pravo novo
transakcijo, ki vedno prejme `None`) — to je natančen, zanesljiv signal
za razlikovanje med "prava nova transakcija" (potreben pravi reset, da se
prepreči cross-transaction onesnaženje, enak razlog kot "Plast 1-4" zgoraj)
in "nadaljevanje istega leak-a" (potreben OHRANJEN taint izpred leak-a).

**Popravek (varnejši od "persistent za vedno")**: namesto da bi ta tri
polja NIKOLI ponastavili (tveganje: naslovne vrednosti se veliko pogosteje
po naključju ponovijo med nepovezanimi transakcijami kot ozko-ključan
`view_call_baseline`, kar bi na Confirmed-tier oraclju lahko sprožilo
lažne pozitivne), se ob `post_exec.is_some()` namesto ponastavitve na
`empty` SEMENIJO iz `vm_state`-a same lineage (ki je BIL pravilno
izračunan tik pred leak-om in je na voljo kot parameter `execute_from_pc`-ju)
— natančno, brez tveganja cross-lineage onesnaženja, ker gre za PRAVO,
že-pravilno-izračunano stanje te specifične veje, ne za globalno
persistentno stanje na host objektu.

**Druga, ločena najdba med živim preverjanjem**: zgrajen namenski test
fixture (`tests/evm/delegatecall_target/main.sol`), ki RETURNDATACOPY
dekodiranje tarče (self-call na `getTarget()`, izpeljana vrednost iz
shranjenega `x`, da se izogne kakršnikoli koliziji s calldata/byte-coincidence
signalom) in ranljiv DELEGATECALL namerno razdeli čez control-leak mejo
(`Someone(x).something()`). Debug instrumentacija je pokazala, da
`delegatecall_targets_seen`-ov pre/post diff PRAVILNO zazna nov zadetek
(deset-tisoče primerov `pre=0 post=1 equal=false`), a `calldata.len() < 20`
preverjanje VEDNO prezgodaj vrne `vec![]` za TAK segment — korenski vzrok:
`set_as_post_exec()` (`src/evm/input.rs`) ob "step" mutaciji PREPIŠE
`input.data` s sintetičnim placeholder-jem (predstavlja injicirano
vrnjeno vrednost leak-callback-a), zato `ctx.input.to_bytes()` za
resumiran segment vrne samo 4 bajte (gol selector), NIKOLI prave argumente
originalne transakcije — preverjeno živo.

**Ta preverek je bil nepravilno postavljen kot blanket early-return za
CELO funkcijo**, čeprav je resnično relevanten SAMO za šibkejši
"byte coincidence" fallback — Confirmed-tier `via_calldata_taint`/
`via_returndata_taint` sploh ne uporabljata `calldata`, slonita izključno
na (zdaj pravilno persistentnih) `calldata_addresses`/`returndata_addresses`.
Popravek: `calldata.len() < 20` preverjanje premaknjeno iz zgodnjega
`return` v sam `via_byte_coincidence` izračun znotraj zanke — Confirmed-tier
signali zdaj tečejo neodvisno od dolžine `calldata`, fallback pa preprosto
ne velja, ko je `calldata` prekratka (enako praktično vedenje kot prej,
a pravilno omejeno samo na signal, ki od tega dejansko je odvisen).

**Živo potrjeno po obeh popravkih**: fuzzer je na novem fixture-ju v 15s
poročal natanko EN `[Delegatecall Target From Calldata] (sim-confirmed)`
zadetek, pravilno opisan kot "read back from a PRIOR call's return data
within this same transaction" — in generiral `Delegatecall_target_0.t.sol`
v `work_dir/vulnerabilities/`. **To je PRVI primer v tej seji, kjer je bil
control-leak-odvisen oracle USPEŠNO popravljen in živo potrjen do konca**
(za razliko od `readonly_reentrancy.rs` zgoraj, kjer ovira ostaja v
fuzzer-jevi mutacijski strategiji) — razlika: tu je bila ovira v DVEH
konkretnih, lokaliziranih kodnih napakah (persistenca stanja + napačen
obseg preverjanja dolžine), ne v tem, KATERE kontinuacije fuzzer sploh
poskusi.

## Strategy Layer: dvo-koračno verigenje najdb, živo potrjeno (2026-11-03)

Uporabnik je identificiral resnično vrzel: `auto_pipeline.py`/`batch_pipeline.py`
vsako `.plan.json` najdbo na isti tarči izvajata POPOLNOMA NEODVISNO, v
leksikografskem vrstnem redu datotečnih imen (celo ne numeričnem). Nikjer v
kodi ni obstajal koncept "ta najdba omogoči drugo" — če oracle A (npr.
`ecrecover.rs`) odkrije ponarejanje podpisa, ki odklene `authorized[caller]`,
in oracle B (npr. `erc20.rs`) ločeno odkrije `withdraw()`, ki to zastavico
zahteva, pravi fuzz tek pa NI slučajno nadaljeval iz A-ja v B znotraj ene
linije — se ta compound napad NIKOLI ni poskusil na pravi verigi, čeprav sta
OBE polovici že samostojno odkriti.

**Nov modul**: `onchain_scripts/strategy_layer.py`. Dve ločeni izboljšavi:

1. **`ordering_key()`** — zamenja golo `sorted(plan_files)` (leksikografsko
   ime) s smiselnim vrstnim redom: UNLOCK-tipa najdbe (ponarejanje podpisa,
   auth bypass, delegatecall/storage hijack, ...) pred OBJECTIVE-tipa
   (Fund Loss, nepooblaščeni prenosi, insolventnost, ...), z NUMERIČNIM (ne
   leksikografskim) razvrščanjem znotraj istega razreda. Klasifikacija
   temelji IZKLJUČNO na že obstoječem, že pregledanem bug_type taksonomiju
   (`src/evm/oracle.rs`'s `classify_confidence`) — brez kakršnega koli
   novega semantičnega razumevanja kode, samo druga os nad isto tabelo.
2. **`run_chain_attempts()`** — po obstoječem neodvisnem teku (ki se NE
   spremeni, ničelno tveganje regresije) poskusi pare (UNLOCK najdba A,
   OBJECTIVE najdba B na ISTI tarči), kjer B še ni sam potrdil. Sestavi
   sintetičen plan (`merge_plans()`: `A.steps + B.steps`, `kind:"flat"`) in
   ga pošlje skozi POPOLNOMA OBSTOJEČ `execute_plan()` — brez podvajanja
   gas-limit/mainnet-confirmation varnostne logike.

**Namerno OZEK obseg prve verzije** (dokumentirano, ne tiho izpuščeno):
samo `kind=="flat"` plani (reentrancy-tipa ima en sam `repeat_step` slot,
ki ne pokrije dveh ločenih najdb); samo pari, ne 3+ verige; samo ista tarča;
izključeni financirani (`needs_funding`) plani; brez prenosa resnične
on-chain vrnjene vrednosti kot argumenta (samo PREDVAJANJE korakov po
vrsti — pokrije "A spremeni stanje/pooblastilo, ki ga B potrebuje", ne "B
potrebuje A-jev točen izhodni bajt kot argument").

**Tehnična podrobnost**: `plan.json` sam nima polja `bug_type`/`confidence`
(preverjeno v `src/evm/solution/script_generator.rs`'s `ExploitPlan`
strukturi) — `strategy_layer.py` ga pridobi iz istoimenskega `.t.sol`
Description bloka (`[bug_type] (confirmed): ...` vrstice, regex toleranten
na `sim-` predpono), ker ga `generate_test()`/`generate_exploit_plan()`
pišeta iz ISTE `TemplateArgs` z istim `contract_name`.

**Živo potrjeno** na lokalnem anvil forku z namenskim dvo-pogodbenim
fixture-jem, ki natanko ponazarja uporabnikov primer: `Vault.claim(v,r,s)`
ima nepreverjen `ecrecover(bytes32(0),...)`, ki ob `signer==address(0)`
nastavi `authorized[msg.sender]=true`; LOČEN `Vault.withdraw()` zahteva to
zastavico in nakaže celoten saldo. Rezultat:
- `withdraw()` SAM (brez `claim()`): `EXECUTED_NO_PROFIT`, 0 ETH (ne
  `NOT_CONFIRMED` — `AttackWallet.execute()` ne razveljavi zunanje
  transakcije, ko notranji klic revert-ira, zato se to pravilno pokaže kot
  "izvedeno, brez profita", ne kot neuspeh same transakcije).
- `strategy_layer.merge_plans(claim, withdraw)`, poslan skozi
  `execute_plan()`: **`CONFIRMED`**, recovery denarnica pridobi ~1 ETH
  (natančen znesek minus plin, ker je bil signer v tem testu isti naslov
  kot recovery denarnica — v pravi uporabi, kjer so ločeni, bi bil znesek
  natančno 1 ETH).

To je prvi neposreden dokaz, da verigenje DVEH ločeno odkritih najdb v EN
resničen, izvršen compound izkoristek deluje — ne samo teoretično načrtovano.

## Resen zaupanja-vreden popravek: oraclji so trdo izpisovali "ETH" tudi na ETC/BSC/... (2026-11-03)

Uporabnik je poročal **resnično poslovno škodo**: stranka je na ETC reviziji
videla besedo "ETH" v imenu/opisu hrošča in sklepala, da ForkSploit ne loči
ETH (dražji kovanec) od ETC (~500x cenejši) — izguba zaupanja, izgubljen
posel. To je BILO resnično, a LOČENO od že popravljenega Python-ovega
`native_symbol_for_w3()` popravka (2026-11-02, glej spodaj) — TA popravek je
pokril samo `onchain_scripts/*.py`, NE same Rust fuzzer binarke.

**Najdeno** (preverjeno z grep čez `src/evm/oracles/*.rs`): `eth_backing.rs`,
`forced_eth_accounting.rs`, `curve_virtual_price.rs`, `twap_manipulation.rs`,
`erc20.rs`, `unchecked_call.rs` so imeli trdo zapisano besedo "ETH" v
`bug_type` imenu in/ali `bug_info` opisu, NE GLEDE na pravo verigo. Te
nize gredo neposredno v `.t.sol`, `vuln_info.jsonl` in dashboard — torej
jih stranka dejansko vidi.

**Zakaj ni bilo mogoče dinamično vstaviti PRAVEGA tickerja** (npr. "ETC"
namesto generičnega): preverjeno v kodi (`src/evm/oracle.rs`'s
`EVMOracleCtx`), da aktivna veriga NI zanesljivo dosegljiva znotraj
`oracle()` klica — edina pot je `chain_id` kot STRANSKI UČINEK `CHAINID`
opcode-a (`onchain/mod.rs`'s `OnChain::step`), ki je `None`, dokler
pogodba dejansko ne pokliče `CHAINID`. Pri OFFCHAIN fuzzanju (brez
`--onchain-*` zastavic) sploh NI pravega chain konteksta. Pravilna, edina
univerzalno pravilna rešitev: **genericizacija** — "native value"/
"native-token balance" namesto katerekoli konkretne kratice, kar je
pravilno TAKO za onchain KOT offchain fuzzanje.

**Popravek** (bug_type STRINGI, ki so matching key, posodobljeni V LOCKSTEP
na vseh mestih): `"Insolvent: Promised ETH Exceeds Real Balance"` →
`"Insolvent: Promised Native Value Exceeds Real Balance"` (3 mesta:
`eth_backing.rs`, `oracle.rs`'s `classify_confidence`,
`solution/mod.rs`'s `CONFIRMED_EXPLOITABLE_BUG_TYPES`, PLUS
`onchain_scripts/strategy_layer.py`'s klasifikacijske tabele, ker je ta
isti niz uporabljen kot UNLOCK/OBJECTIVE klasifikacijski ključ);
`"Forced ETH Accounting"` → `"Forced Native Value Accounting"` (brez
lockstep tveganja v Rustu, a enako posodobljeno v `strategy_layer.py`).
Prosta besedila (ne matching key) v preostalih 4 datotekah preprosto
preimenovana ("net ETH balance increase" → "net native-token balance
increase" ipd.).

**Živo potrjeno** na obstoječih test fixture-jih (`tests/evm/eth_backing/*`,
`tests/evm/forced_eth_accounting/*`): novi nizi se pravilno izpišejo
(`[Insolvent: Promised Native Value Exceeds Real Balance] (sim-confirmed)`,
`[Forced Native Value Accounting] (sim-review)`), in confidence tier se
NI spremenil (lockstep popravek deloval pravilno).

## Resen najden gap na pravi stranki pogodbi: resna Confirmed najdba, 0 planov generiranih -- delno popravljeno, NI dokončno (2026-11-03)

Uporabnik je poročal resno poslovno škodo: na stranki pogodbi, znani kot
"90% ranljiva", je ForkSploit našel resne hrošče, a `AttackWallet` ni
izvedel NIČESA -- ne napačno, ampak ker **noben plan sploh ni bil
generiran**. Živo preverjeno na uporabnikovi pravi ETC pogodbi
(`0x9f5304DA62A5408416Ea58A17a92611019bD5ce3`, ista kot v prejšnjih
najdbah te seje): 300s tek, 90.90% instruction coverage, **4037 ločenih
najdb, 0 `.plan.json` datotek**.

Med njimi: `[Fund Loss] (sim-confirmed)` -- "Anyone can earn 1,277,262
native tokens" (skoraj CEL saldo pogodbe), ponovljeno 4x z realistično
(ne fuzzer-napihnjeno) vrednostjo. Sled: `Sender → target.call(0x1554611f)
→ Sender.fallback() → target.call(0x00000000)` -- klasičen
control-leak/callback vzorec. `trace_depends_on_control_leak()` ga je
pravilno zavrnila (varnostna varovalka deluje), A `solution/mod.rs` je
callback-zmožen generator (`armCallback`/`repeat_step`) prej uporabil
SAMO, če je `bug_type` dobesedno "Reentrancy" -- oraclj-poimenovalna
nesreča, ne resnična razlika v tem, kaj AttackWallet potrebuje storiti.

**Popravek 1 (dokončan, varen, commitan)**: `trace_depends_on_control_leak`
veja zdaj poskusi `split_reentrant_trace` za VSAKO Confirmed najdbo, ne
samo za "Reentrancy" -- enak mehanizem, širši pogoj sprožitve, brez
podvajanja za primere, ki jih je "Reentrancy" veja že obdelala.

**A ta konkreten primer S TEM popravkom ŠE VEDNO ni rešen** -- živo
ponovno preverjeno na isti pogodbi po popravku: **še vedno 0 planov**.
Korenski vzrok, natančno: `split_reentrant_trace()` zahteva, da napadalec
isto (contract, selector) par pokliče DVAKRAT (klasičen "pokliči isto
funkcijo spet" reentrancy vzorec). Ta sled ima DRUGAČEN selector v
callback oknu (`0x00000000`) kot zunanji klic (`0x1554611f`) -- ni
ponovitev, je DRUGAČEN klic med oknom. `split_reentrant_trace` zato
pravilno vrne `None`, in popravek se ne sproži.

**Prava rešitev, odložena na naslednjo sejo zaradi časovne stiske**:
razširiti `armCallback`/`repeat_step` mehanizem (ali zgraditi vzporeden),
da lahko AttackWallet med callback oknom predvaja DRUGAČEN, fuzzer-
odkrit klic (ne samo isti klic ponovno) -- to je večji, tveganejši posel
(vpliva na generiranje planov za VSE control-leak-odvisne Confirmed
najdbe), ki potrebuje lastno, skrbno načrtovanje in živo preverjanje,
preden se ga šteje za rešenega.

**Pomembno vodilo za naprej** (uporabnikova eksplicitna zahteva, glej
[[feedback_literal_execution]] v spominu): dokler ta konkreten primer na
tej konkretni pogodbi dejansko ne doseže pravega premika sredstev, se to
NE sme šteti ali poročati kot "rešeno". Ta razdelek ostaja odprt dokler
ni to dokazano.

## Resna napaka v gas-limit preverjanju: "presega block limit" je bila LAŽNA (2026-11-03)

Po prejšnjem popravku (control-leak routing) je uporabnik ponovno pognal
na ISTI pravi ETC pogodbi — tokrat STA se generirala 2 plana (napredek!),
a OBA sta padla z `NOT CONFIRMED: potreben gas (49610942) presega resnicni
block gas limit (8000000)`. Isto natanko število za DVA popolnoma
različna, nepovezana klica (`3e2640d6...` in `c01c1ca3`) je bilo sumljivo.

**Preverjeno neposredno proti pravemu lokalnemu ETC vozlišču** (`eth_call`,
ne samo zaupanje `eth_estimateGas`-u): z EXAKTNO pravo blok-mejo
(8.000.000 gasa) OBA klica **uspeta brez revert-a** — tudi povsem trivialen
klic (prazna calldata) skozi AttackWallet vrne IDENTIČNO "potrebno" oceno
49.610.942. To dokončno dokaže: **ocena gasa je bila napačna, ne resnica
o neizvedljivosti**. Znan EVM/geth pojav: `eth_estimateGas`-ov binarni
iskalnik lahko vrne popolnoma napačno, napihnjeno število, če je prava
poraba gasa NEMONOTONA glede na razpoložljiv gas (npr. nekje v verigi
klicev `gasleft()`-odvisno vejanje) — binarno iskanje takrat ne konvergira
pravilno.

**To je bila ISTA pogodba in ISTA vrsta napake kot v prvotnem popravku
tega preverjanja (2026-11-02, plan C9f53_2)** — kar pomeni, da je bil
ŽE TISTI prvotni "exceeds block gas limit" primer MOREBITI tudi lažen
negativ, nikoli preverjen s pravim `eth_call`.

**Popravek** (`gas_utils.py`'s `estimate_gas_limit()`): preden obupa, zdaj
naredi PRAVO preverbo — `eth_call` z natanko pravo blok-mejo kot gas. Če
TA ne revert-ira, je ocena preprosto napačna, in se uporabi prava
`block_gas_limit` vrednost neposredno (brez margin-a, ker bi ta spet
presegel strop). `GasExceedsBlockLimitError` se zdaj sproži SAMO, če tudi
ta neposredna proba revert-ira -- torej samo, ko je sled RESNIČNO
neizvedljiva, ne samo "estimateGas je vrnil veliko število".

**Živo potrjeno** (neposreden Python klic `estimate_gas_limit()` proti
pravemu lokalnemu ETC vozlišču, z EKSAKTNO calldato obeh padlih planov):
oba zdaj vrneta `8000000` namesto da bi vrgla napako. **Uporabnik bo zdaj
ponovno pognal `auto_pipeline.py` na isti pogodbi** — šele TA tek pove,
ali ta dva plana po tem popravku dejansko premakneta prava sredstva. Dokler
to ni potrjeno, to OSTAJA odprto, enako kot zgornji razdelek.

## Triaža + materializacija: 4664 planov -> 241 površin -> 21 pravih (2026-11-07)

Uporabnik je pognal triažni sloj (`triage_findings.py`) na svojih pravih
podatkih: **4664 planov se je sesedlo na 241 površin**, od tega 2 RUNNABLE,
19 NEEDS_MATERIALIZATION in 220 HEURISTIC_ONLY. Iz agregata ponarejenih
klicev je takoj razvidno dvoje: (a) vseh 19 materializacijskih površin je
na ISTI tarči `0x9f5304DA62A5408416Ea58A17a92611019bD5ce3`, (b) prevladujejo
selektorji `escapeHatch`, `proxyWithdraw`, `withdraw`, `claimRemaining` in
`extendClosingTime` -- torej gre za ENO pogodbo, ne za 19 hroščev.

`materialize_plan.py` je bil dodan kot naslednji korak: vsak ponak klic
razvrsti v razred (`AUTH_GUARD`, `SIGNATURE`, `TOKEN_BALANCE`,
`PRICE_ORACLE`, `REENTRANCY_CALLBACK`, ...) in mu pripiše recept. Ponak klic
v DRUGO pogodbo (ne v tarčo) se razvrsti kot `REENTRANCY_CALLBACK`, ker je to
callback oblika, ne branje stanja.

### Živo preverjeno na lokalnem anvil forku ETC (NIKOLI na mainnetu)

Tarča `0x9f53...5ce3` drži **1.277.262 ETC** (`getTotalFunds` 8.44M ETC).
Vseh 14 selektorjev iz dispatcha razrešenih prek 4byte: `escapeHatch()`,
`proxyWithdraw(address,uint256,uint8,bytes32,bytes32)`,
`withdraw(address,uint256)`, `claimRemaining()`, `extendClosingTime(uint256)`,
`changeOwner`, `addOwner/removeOwner/changeRequirement`, `setDailyLimit`,
`resetSpentToday`, `seal`, `fill`, `deposit`.

**Vsaka funkcija reverta za ne-lastnika (`InvalidJump` = solc 0.4.x
`require`), RAZEN `deposit()` in `proxyWithdraw` z majhno vsoto.**

`escapeHatch()` je `require(msg.sender == slot0)` (lastnik
`0xe79aca...`); na lastniški poti prenese `slot8` (fiksni 100 wei), NE
celotnega salda. Fuzzerjev "Fund Loss" na `escapeHatch` je torej
control-leak artefakt: nobena ne-lastniška pot ne premakne vrednosti.

**Resnična najdba -- `proxyWithdraw` (Unchecked ecrecover(0)):** funkcija
zgradi sporočilo `"Withdraw DAOETC to " + <20-bajtni naslov> + <32-bajtna
vsota>` (preverjeno z rekonstrukcijo keccak predpone), ga KLIČE ecrecover
precompile (CALL na `0x1`, pc=1927), a **rezultata ne preveri, da bi bil
ne-ničeln**. Z `v=27, r=0x1111..., s=0x2222...` (ponarejena signatura)
funkcija **USPE (status 1, 64122 gas)**. Z `v=0, r=0, s=0` ecrecover vrne
`0x0`, a funkcija se ustavi PRIJ vsoto `> 100` (drugo preverjanje); z
vsoto `<= 100` gre skozi.

**A resnični premik sredstev NI dokazan:** ob uspehu `proxyWithdraw(ME,1)`
in `proxyWithdraw(ME,100)` se saldo tarče, napadalca IN lastnika **ne
spremeni** (vse delte 0). Izplačilo gre prek `slot7` (lastnik
`0xe79aca...`) z količino, ki jo določa nekaj, kar je v tem stanju 0 --
zato je "Fund Loss" tu NEPOTRJEN. Kar JE potrjeno, je ranljivost sama:
signatura se ne preverja pravilno (ecrecover(0) se ne zavrne) -- kar je
klasičen `Unchecked ecrecover` razred, a sam po sebi v tem stanju ne
izprazni pogodbe.

**Druga RUNNABLE tarča `0xD096...9ff7` je standardni WETH9** ("Wrapped
Ether"): nima nobenega klica ecrecover precompile, zato je "Unchecked
ecrecover(0)" tam LAŽNO POZITIVEN. `deposit()/withdraw()` se obnašata
točno kot pri WETH (withdraw ne-držanega salda reverta).

### Zaključek

Triaža je bila pravilna: 220 od 241 površin je šum, 21 je pravih, a **nobena
od 21 (v tem stanju) ne premakne sredstev** -- RUNNABLE je potreben, ne
zadosten pogoj. To je natanko "dokaži, ne trdi" pravilo: šele resnična tx
na forku, ki premakne vrednost, šteje. Materializacijski recept za
`proxyWithdraw` (SIGNATURE) je pravi, a materializacija SAMA po sebi ne
ustvari vrednosti, ki je v pogodbi ni na voljo prek te poti.

## Sledenje denarju na 0x9f53...5ce3: nobena ne-lastniška pot ne izplača (2026-11-07)

Nadaljevanje prejšnje sekcije. Po globljem sledenju (anvil fork ETC, nikoli
mainnet) je slika popolna in NEGATIVNA glede izpraznitve pogodbe:

**Pomemben popravek prejšnje meritve:** `withdraw(address,uint256)` NI
nepredvajljiv. Pri 3M gasa je OOG, a pri 8M (RESNICNI ETC block limit,
potrjen na mainnetu: gasLimit=8.000.000) **USPE** (status 1, 37064 gas) z
`amount=1`. Prejšnji OOG je bil posledica premajhnega gasa, ne logike
pogodbe -- to je natanko past "simulacija brez merjenja gasa".

**A izplačilo je 0, ker je `balanceOf(uporabnik)` 0.** Sled `withdraw`:
1. SLOAD slot1 -> naslov ledgerja `0x180826b05452ce96e157f0708c43381fee64a6b8`
2. CALL ledger.`balanceOf(msg.sender)` (0x70a08231)
3. SLOAD `keccak(uporabnik, slot0)` -> interni saldo (0)
4. CALL ledger.`totalSupply()` (0x18160ddd) -> 1.15e25
5. SLOAD slot2, slot4, slot `keccak(adr, ...)` -> vse 0
Pogodba torej preveri `balanceOf` + shranjeni saldo; ker je oboje 0, prenese
0. `RETURN` vmesnih korakov je `0x00...00`.

**Ledger `0x180826...` ima `totalSupply` 11538165987024671407837618, a
`balanceOf` je 0 za VSAK preverjen naslov** (owner, WHG donation, slot8,
tarča, zero address) -- tudi neposredno prek `cast index` po mapiranju v
slot0. Distribucija saldov torej ni bila izvedena (ali pa so saldi drugje in
pot do njih ni prek teh selektorjev).

**`deposit()` sprejme ETH, a NE pripiše per-user salda:** po depozitu 1 ETC
se saldo tarče poveča (+1 ETC), a `getMyBalance(ME)` ostane **0**; depozit
doda le v slot4 (skupni pool) in izda LOG1. Zato `deposit -> withdraw` ne
vrne nič deponentu. `withdraw` z `amount=1e18` po depozitu celo OOG-a (zanka
je odvisna od zneska), z `amount=1` pa uspe z 0 izplačila.

**V uspešnih poteh NI nobenega prenosa vrednosti:** opcode histogram
`withdraw`/`proxyWithdraw` vsebuje samo 3 CALL-e z `value=0` (ecrecover,
balanceOf, totalSupply), `SELFDESTRUCT: 0`, `CREATE: 0`, zadnji opcode STOP.
`sealed() == true`, `totalAccounts == 22092`.

**Zaključek:** vseh 21 resničnih površin je strukturirano NEIZKORISTLJIVIH v
trenutnem stanju pogodbe -- bodisi so `AUTH_GUARD` (lastniške), bodisi
izplačajo 0, ker je ledger brez saldov. Edini potrjeni hrošč ostaja
`proxyWithdraw` `Unchecked ecrecover(0)` (ponarejena signatura USPE), a sam
ne premakne sredstev. Pogodba je verjetno "DAOETC" slog refund/claim sistema,
kjer so saldi nastavljeni v drugem (upravljanem) koraku, ki ga ne-lastnik ne
doseže.

## Koncni dokaz: ledger ima totalSupply, a NIČ bilanc (2026-11-07)

Zadnji kamen je odkrit in zapira celotno preiskavo 0x9f53...5ce3.

Ledger `0x180826b05452ce96e157f0708c43381fee64a6b8` ima natanko 7 funkcij:
`totalSupply()`, `seal()`, `totalAccounts()`, `balanceOf(address)`,
`fill(uint256[])`, `owner()`, `sealed()`. **NI `mint` ali `setBalance`** --
saldi so fiksni v storage in se ne morejo povečati prek katerega koli
selektorja.

`balanceOf(a)` bere `storage[keccak(a, slot0)]` (potrjeno s sledjo:
KECCAK inputs [0x40, 0x0] -> SLOAD key 0x88d0184361... = `cast index address
0x941D... 0`). Ta je **0 za vsak preverjen naslov**. Struktura ledgerja:
slot0=0 (mapping), slot1=owner 0x941D..., slot2=totalSupply 1.153e25,
slot3=22092 (totalAccounts), slot4=1 (sealed), owner()=0x941D..., sealed=true.

**Posledica:** fuzzerjev "Fund Loss" na `withdraw`/`proxyWithdraw` temelji
IZKLJUČNO na ponarejenem `balanceOf` (leak `0x70a08231`/`0x7e3ef7cd`), ne na
resničnem premiku. Recept `TOKEN_BALANCE` v materializacijskem seznamu je
teoretično pravilen, a **fizično neizvedljiv za to pogodbo**: naložiti
napadalcu neničeln saldo v ledgerju ni mogoče, ker ledger nima poti za
pisanje bilanc in je njegov `fill`/`seal` lastniško zaklenjen.

Zato je končni odgovor na vprašanje "ali kateri od 21 resničnih površin
izprazni pogodbo?" **NE**, in to z dokazom, ne z domnevo. Edini potrjeni
hrošč ostaja `proxyWithdraw` Unchecked ecrecover(0) (ponarejena signatura
USPE, status 1), ki pa sam ne premakne vrednosti.

To je hkrati meja samega fuzzerja: control-leak (ponarejen `balanceOf`) je
USTVARIL prehod skozi `require`, ki na resnični verigi ne obstaja. Triaža +
materializacijski sloj to pravilno označita kot NEEDS_MATERIALIZATION; šele
resnična tx na forku (ki premakne 0) pokaže, da materializacija ni mogoča.

## Plast 5 -- `owner_impersonation`: ločevanje lastnika-od-napadalca (2026-11-07)

**Problem, ugotovljen v živo** (ETC tarča `0x9f5304DA62...5ce3`): tek je vrnil
1201–2072 planov, **vseh 2072 `SKIPPED, NOT EXTRACTABLE`, 0 potrjenih**. To
ni bil hrošč pipeline-a -- fuzzer je delal točno po načrtu, a je večino najdb
ustvaril tako, da je **postal lastnik tarče**.

`src/evm/host.rs` pri `SLOAD` namerno pobira konkretne naslove iz storage-a v
bazen klicateljev (brez tega owner-gated koda ni dosegljiva). A ko iz slota 0
prebere `owner`, lahko pokliče `escapeHatch()` (`require(msg.sender==owner)`)
**kot lastnik** -- in to javi kot "Fund Loss". Preverjeno na forku:
`escapeHatch` kot OWNER → OK; kot RANDOM → REVERT (InvalidJump). Ni vdora,
samo privilegirana stranka uporablja svojo pravico.

**Popravek (poštena oznaka, ne skrivanje):**
- `host.rs`: nov `HARVESTED_STORAGE_ADDRESSES` (`lazy_static RwLock<HashSet<String>>`,
  checksumirani naslovi) + `record_harvested_storage_address()` na harvest mestu
  + `is_harvested_storage_address()`.
- `solution/script_generator.rs`: `PlanMeta.owner_impersonation` = `callers.iter().any(...)`.
  Namenoma `any`, ne `all`: živi lažni pozitiv je imel DVA klicatelja (generični
  fuzzer naslov + lastnikov multisig), lastnik pa je bil tisti, ki je zadostil
  `require`. `all` bi zgrešil natanko ta primer.
- `auto_pipeline.py` / `batch_pipeline.py`: `metadata_skip_reason` zdaj take
  plane preskoči z jasnim razlogom ("owner/admin/multisig impersonation"), in
  povzetek izpiše, koliko jih je. Preverjeno zaporedje: review-tier razlog ima
  prednost pred owner-impersonation (heuristična najdba s harvestanim naslovom
  ostane "heuristika", ne "impersonation").

**Zakaj oznaka, ne odstranitev:** uporaba harvestanih naslovov je za fuzzer
koristna in namerna. Odstranitev bi zmanjšala pokritost owner-gated kode.
Oznaka ohrani pokritost, a prepreči, da bi pipeline predstavljal 2000+
neizvedljivih planov kot napade.

**Testi:** `test_preflight_gate.py` +3 (`test_owner_impersonation_is_skipped`,
`test_missing_owner_impersonation_defaults_to_not_flagged`,
`test_review_tier_wins_over_owner_impersonation`). Skupaj 31/31 PASS.
