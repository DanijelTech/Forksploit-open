# Popoln referenčni priročnik: zmogljivosti ForkSploit sistema

Ta dokument je **popoln seznam dejstev o ForkSploit sistemu**, preverjen neposredno
v izvorni kodi (ne iz spomina), namenjen temu, da Hermes (ali kateri drugi agent, ki
upravlja ta sistem) pozna VSE točke — ukaze, zmogljivosti, omejitve — brez potrebe,
da bi sam interpretiral ali ugibal iz kode. Za POSTOPEK (kako varno izvesti pregled)
glej `../SKILL.md`. Ta dokument je LEKSIKON, ne postopek.

## 1. Arhitektura v dveh plasteh

1. **Rust fuzzer** (`./target/release/forksploit`, zgrajen iz `src/`) — jedro:
   coverage-guided fuzzing + concolic (Z3) reševanje nad EVM bytecode-om (revm).
   Najde in DOKAŽE hrošče z dejansko izvedljivo transakcijsko sledjo.
2. **Python orkestracijska plast** (`onchain_scripts/*.py`) — kliče Rust binarko,
   upravlja denarnice, verige, exploit generacijo/izvedbo na pravih omrežjih.

ForkSploit **ni** formalna verifikacija in **ne** razume poslovne logike pogodbe —
je vzorčni detektor + fuzzer. Glej razdelek 9 (Znane omejitve) spodaj.

## 2. Popoln CLI referenc: `./target/release/forksploit evm`

Ukaz se zažene iz korena repozitorija. Najpomembnejši flagi (vsi flagi preverjeni iz
`evm --help` na trenutni verziji):

| Flag | Pomen |
|---|---|
| `-t, --target <TARGET>` | Glob vzorec do lokalne `.bin`/`.abi` datoteke, ALI `0x...` naslov že deployane pogodbe. |
| `-c, --chain-type <CHAIN>` | Veriga za onchain cilj: `eth,goerli,sepolia,bsc,chapel,polygon,mumbai,fantom,avalanche,optimism,arbitrum,gnosis,base,celo,zkevm,zkevm_testnet,blast,linea,iotex,scroll,vana,story,etc,mordor,local`. |
| `-u, --onchain-url <URL>` | RPC URL za `-c` verigo. Privzeto izpeljan iz `-c`, a VEDNO podaj eksplicitno pri lokalnih/forkanih vozliščih — glej FAZO 1 v `../SKILL.md`. |
| `-b, --onchain-block-number <N>` | Blok, na katerem se fork/branje stanja zgodi. Privzeto najnovejši. |
| `-k, --onchain-etherscan-api-key <KEY>` | API ključ za pridobitev verificiranega ABI-ja. Brez njega se fuzzer prestavi na EVMole dekompilacijo (deluje, a manj natančno). |
| `-f, --flashloan` | Omogoči flashloan simulacijo (Aave V3/Balancer V2 na podprtih verigah) — fuzzer si lahko sam "izposodi" realne tokene med raziskovanjem. |
| `--run-forever` | NE ustavi se po prvi najdbi — nadaljuje iskati druge hrošče do izteka `--fuzz-seconds`-ekvivalenta (časovne omejitve preko `timeout` ukaza). Brez tega flaga se ustavi na PRVI najdbi. |
| `-d, --detectors <LIST>` | Kateri oraklji so aktivni. `all` (privzeto) = vseh 47. `high_confidence` = samo podskupina z nizko lažno-pozitivno stopnjo (glej razdelek 3). Lahko tudi posamezen oraklj po imenu (npr. `reentrancy`). |
| `--concolic` + `--concolic-caller` | Omogoči Z3-podprto simbolično reševanje (počasnejše, a globlje) + obravnava klicatelja kot simboličnega. |
| `--concolic-timeout <MS>` | Časovna omejitev za eno Z3 reševanje (privzeto 1000ms). |
| `--max-call-depth <N>` | Kako globoko v verigo klicev (ugnezdeni proxyji, reentrancy) analiza sega (privzeto 32). |
| `--sha3-bypass` | Simbolično obravnava SHA3/keccak primerjave — lahko PODRE originalno logiko pogodbe (eksperimentalno), uporabi samo za taint analizo, ne za končno potrditev. |
| `-w, --work-dir <PATH>` | Kam se zapišejo corpus, dnevniki, najdbe. Privzeto `work_dir`. |
| `--constructor-args <STR>` | Konstruktorski argumenti za LOKALNO deployanje (`ImeKontrakta:arg1,arg2,...`, ločeno s `;` za več pogodb). Zadnji argument lahko konča na `wei`/`gwei`/`ether` (Z PRESLEDKOM pred enoto, npr. `"10 ether"`) za nastavitev začetnega ETH salda pogodbe. |
| `--only-fuzz <ADDR,...>` | Omeji fuzzing SAMO na navedene naslove (koristno pri multi-contract setupih). |
| `setup.json` (v fixture-u) | Deklarativne inicializacijske klice (`{"calls":[{"to","sig","args"}]}`) izvede na sveže-deployanem stanju PRED fuzzingom, da kampanja starta iz že povezanih pogodb (npr. `Vault.setAsset(token)`, `Token.mint`). `to`/`address` argumenti sprejmejo ime kontrakta ali `$caller`/`$deployer`. Odblokira razrede, ki zahtevajo predpogoj (ERC4626 donation, initializirani pari). |
| `--spec-id <ID>` | EVM hardfork pravila (`Frontier`...`Cancun`,`Latest`). Za ETC VEDNO uporabi `Shanghai` eksplicitno (glej razdelek 8, ETC posebnost). |
| `-m, --deployment-script <Pot:Kontrakt>` | Namesto `.bin`/`.abi` uporabi Foundry setup skript za deploy (npr. za `forge test --mc` nadomestitev invariant testov). |
| `--force-abi <naslov:pot_do_abi,...>` | Prisili uporabo danega ABI-ja za naslov (koristno pri kompleksnih proxyjih, ki jih dekompilator napačno prebere). |
| `--replay-file <PATH>` / `-r` | Ponovno predvaja že posneto sled namesto novega fuzzing teka. |

Izhod (v `<work-dir>/vulnerabilities/`):
- `<Ime>.t.sol` — Foundry TEST reprodukcija. Generira se za VSAKO najdbo, brez izjeme.
- `<Ime>.plan.json` — strukturiran seznam korakov exploita (uporablja `auto_pipeline.py`).
- `<Ime>Exploit.s.sol` — dejanski IZVEDLJIV Foundry SCRIPT. Generira se SAMO za
  `(sim-confirmed)` vrste hroščev (glej natančen seznam v razdelku 4) — razen Reentrancy,
  ki ima svoj ločen generator (`<Ime>Exploit.s.sol` z `attack()`/`receive()` vzorcem).

## 3. Vsi detektorji ("oraklji") — popoln seznam

ForkSploit ima **46 oracle tipov** (`OracleType` v `src/evm/mod.rs`). Vsak je BYTECODE-LEVEL vzorčni detektor — ne
razume poslovne logike, samo prepozna vnaprej kodiran vzorec. Oznaka v izpisu
(`(sim-confirmed)` / `(sim-review)`) pove, ali je najdba dokazano resnična ZNOTRAJ
SIMULACIJE ali samo sum, ki potrebuje človeško presojo (glej natančno logiko v
`src/evm/oracle.rs`'s `classify_confidence`, preverjeno 2026-11-02). **Predpona
`sim-` je bila dodana 2026-11-02** (prej golo `confirmed`/`review`) — ker se je na
pravem ETC mainnet-u (plan `C9f53_2`) izkazalo, da je revm (brez merjenja gasa)
nekaj označil kot "Confirmed", resnična veriga pa je zavrnila (presežen
`block.gasLimit`). Ta oznaka torej NIKOLI ne pomeni "denar se je dejansko
premaknil na pravi verigi" — samo `auto_pipeline.py`'s `PLAN_CONFIRMED` (FAZA 7/8,
zahteva resnično spremembo salda) to pomeni.

### Confirmed-tier (31 bug_type vzorcev v `classify_confidence`, iz 47 oraklejev + "Bug" generičen invariant)

| Oraklj (datoteka) | bug_type niz | Kaj zazna |
|---|---|---|
| `access_control.rs` | Unauthorized Owner Change / Pause Toggle / Proxy Upgrade | Nepooblaščena sprememba lastnika/pause/proxy upgrade. |
| `arb_call.rs` | Arbitrary Call | Poljuben klic na napadalcu-nadzorovan naslov. |
| `erc20.rs` | Fund Loss | Izguba ERC20 sredstev iz pogodbe. |
| `delegatecall.rs` | Delegatecall Injection | Delegatecall na naslov, ki narašča skozi kampanjo (neomejen). |
| `delegatecall_target.rs` | Delegatecall Target From Calldata | Delegatecall tarča izvira iz calldata ALI vrnjenih podatkov prejšnjega klica (resnično taint sledenje, ne naključno ujemanje bajtov — glej razdelek 6). **Popravljeno in živo potrjeno 2026-11-03** za primer, ko sta RETURNDATACOPY-dekodiranje in sam DELEGATECALL razdeljena čez control-leak mejo: (1) `calldata_addresses`/`returndata_addresses`/`paid_calldata_addresses` zdaj ob nadaljevanju leak-a semenijo iz `vm_state`-a te veje namesto da bi se ponastavili na empty (isti razred bug-a kot `view_call_baseline`, varnejši popravek — glej SKILL.md); (2) `calldata.len() < 20` preverjanje je bilo napačno blanket early-return za CELO oracle (blokiralo je tudi Confirmed-tier signale, ki od `calldata` niso odvisni), zdaj omejeno samo na šibkejši byte-coincidence fallback. |
| `ecrecover.rs` | Unchecked ecrecover(0) | `ecrecover` vrne naslov 0 (neveljaven podpis), a koda to ne preveri. |
| `erc4626.rs` | ERC4626 Share Inflation | Napačno računanje deležev pri standardnem ERC4626 vaultu. |
| `eth_backing.rs` | Insolvent: Promised Native Value Exceeds Real Balance | Obljubljena sredstva (notranje računovodstvo) presegajo pravi ETH saldo. |
| `initializer_front_run.rs` | Initializer Front-Running | Kdorkoli lahko pokliče `initialize()` pred pravim lastnikom. |
| `nft_transfer.rs` | Unauthorized ERC721/ERC1155 Transfer | Nepooblaščen prenos NFT. |
| `preview_rounding.rs` | ERC4626 Rounding Favors User | Napaka pri rounding v standardnem ERC4626 preview funkcijah. |
| `proxy_integrity.rs` | Proxy Reinitialization / Proxy Storage Collision | Ponovna inicializacija proxy-ja; STATIČNA primerjava proxy/implementation storage layoutov (glej razdelek 6). |
| `proxy_upgrade_hijack.rs` | Unprotected Proxy Upgrade (UUPS) | Upgrade selektor (`upgradeTo`/`upgradeToAndCall`/`changeAdmin`/`diamondCut`) je SPREMENIL EIP-1967 implementation/admin slot, klicatelj NI `owner()`, IN admin slot je nič (UUPS primer, ki ga `access_control.rs` ne doseže). Največji code-level USD razred 2025-2026 (~$366M: USPD, Rari Fuse, UPCX). |
| `forged_proof.rs` | Forged Proof (Caller-Supplied Root Accepted) | Tx je SAM izračunal hash (SHA3) in ga primerjal za enakost s klicateljevo calldata besedo, JUMPI je primerjavo SPREJEL, ta beseda pa NIKOLI ni bila primerjana z lastno shranjeno vrednostjo pogodbe (`root == trustedRoot`). Pravi dataflow (SHA3 -> EQ -> JUMPI), ne ugibanje. Review-tier: verifier, ki legitimno vzame root kot parameter (stateless, klican le s strani zaupanja vrednega relay-a), je dobro oblikovan. Nomad/KelpDAO $308M+$44M, BNB Bridge. |
| `transient_guard.rs` | Transient Guard Released Before External Call | EIP-1153 reentrancy guard (TLOAD/TSTORE, 0x5c/0x5d) je bil ODKLENJEN (TSTORE 0 na TLOAD-an slot) PRED zunanjim CALL/STATICCALL-om -- zaščitno okno se zapre prezgodaj. Edini oracle, ki dekodira TSTORE/TLOAD (SSTORE oraklji jih sploh ne vidijo). Review-tier: transient storage je lahko ne-guard namen, a opozori na točno lokacijo unlock-then-call. Uniswap V4-era vzorec. |
| `reentrancy.rs` | Reentrancy | Klasičen reentrancy (ima SVOJ exploit generator, glej razdelek 4). |
| `selfdestruct.rs` | Selfdestruct | Dosegljiv selfdestruct. |
| `signature_malleability.rs` / `signature_replay.rs` | Signature Malleability / Replay | Ponovna uporaba ali malleable ECDSA podpis. |
| `storage_collision.rs` | Storage Collision | Dinamično zaznan storage slot, zapisan tako "domače" kot preko delegatecall-a. |
| `tx_origin.rs` | Tx.Origin Phishing Bypass | `tx.origin` preverjanje, ki ga posrednik lahko zaobide. |
| `typed_bug.rs` | Bug | Generičen, uporabniško definiran Foundry invariant (iz `-m` setup skripta). |
| `v2_pair.rs` | Imbalanced Uniswap Pair | Nenormalna sprememba ene rezerve v V2-stilnem paru. |
| `arb_transfer.rs` | Unauthorized ERC20 Transfer | Nepooblaščen ERC20 prenos. |
| `self_referral.rs` | Validation-Independent Payment | Plačilo se izvede NE GLEDE na to, ali argument prestane lastno validacijo pogodbe (zahteva opazovanje OBEH izidov preverjanja — zato Confirmed, ne Review). |
| `arbitrary_storage_write.rs` | Arbitrary Storage Write | SWC-124: `SSTORE`, čigar slot argument je surova (nehashirana) vrednost iz calldata-e — NE normalen `mapping[key]=value` (ta vedno gre skozi KECCAK256), ampak raw `assembly { sstore(slot, value) }` z napadalcu-izbranim slotom (2017 Parity multisig library vzorec). Dodano 2026-11-03, prvi novi oracle od roadmapa. |

Review-tier dodatek (2026-11-03): `forced_eth_accounting.rs` (SWC-132) --
EQ primerjava, ki uporabi `SELFBALANCE`/`BALANCE(address(this))` kot
operand (torej EXACT equality proti lastnemu pravemu ETH stanju). To je
NASPROTNA smer od `eth_backing.rs` (ta preveri `sum(balances) > real
balance`, insolventnost) -- tu gre za DoS: `SELFDESTRUCT` z 1 wei lahko
TRAJNO podre tako preverjanje, ker nobena legitimna transakcija ne more
odstraniti nezaželenega ETH. **Pomembna najdba pri testiranju**: testni
fixture z izhodnim `.transfer()` klicem po EQ preverjanju NIKOLI ni
poročal najdbe -- ne zaradi napake v oraklju, ampak ker fuzzer-jev lasten
control-leak mehanizem (`host.rs`'s `call_allow_control_leak`) skoraj
vedno prestreže klice, ki prenašajo vrednost, kar `feedback.rs`'s
`has_post_exec` preverjanje v celoti izloči iz poročanja -- NE GLEDE na
to, da je hrošč zaznan PREJ v isti transakciji. Popravek: testni fixture
mora biti brez izhodnega klica, ki prenaša vrednost, da dokaže vzorec
brez tega nepovezanega šuma.

Review-tier dodatek (2026-11-03): `readonly_reentrancy.rs` — `view`
funkcija (npr. cenovni getter), ki med odprtim reentrancy oknom vrne
nekonsistentno vmesno stanje (SWC read-only reentrancy vzorec). Zahteva
persistenten `view_call_baseline` host field (isti razlog kot
`slot_write_contexts`: standardni "počisti ob vsakem klicu" vzorec se
pobriše tudi ob resumpciji control-leak kontinuacije, ne samo ob
resnično novi top-level transakciji). **Pomembna, širša najdba**: tudi
po tem popravku se ta najdba v praksi SKORAJ NIKOLI ne poroča, čeprav je
host-level detekcija dokazano pravilna (tisoče potrjenih zadetkov v
debug teku) — vzrok ni v `feedback.rs`'s `has_post_exec` vratih (ta so
preverjena kot pravilno delujoča: klasični `Reentrancy` jih redno
prehaja), ampak v fuzzer-jevi mutacijski/kontinuacijski strategiji
(`mutator.rs`/`evm_fuzzer.rs`), ki med odprtim control-leak oknom skoraj
nikoli ne poskusi natanko "pokliči nazaj `getPrice()` zdaj". Za VSAK
control-leak-odvisen oracle (ta in bodoče, npr. ERC721/1155 hook
reentrancy) velja: nizka stopnja poročanja na pravih pogodbah ni nujno
znak slabe detekcije — glej `SKILL.md`-jev razdelek o tem (2026-11-03)
za celotno analizo in podatke.

Review-tier dodatek (2026-11-03): `token_accounting_mismatch.rs` — uspešen
`transferFrom(from, address(this), amount)`, takoj sledi SSTORE, ki doda
NEPREVERJENO `amount` (ne pravo opaženo spremembo salda) na prejšnjo SLOAD-ano
vrednost na istem slotu. Fee-on-transfer/rebasing token to predpostavko
podre. Zaznava je v `host.rs`'s `call()`/`0x55` primeru (ne ločen middleware,
ker potrebuje dekodiran `CallInputs`, ki ga samo `call()` sam vidi), heuristika
na proximity (ne polno dataflow), zato Review ne Confirmed — veliko pravih
tokenov nima fee/rebase, kjer je ta vzorec povsem varen.
| `twap_manipulation.rs` | TWAP Manipulation (Profit Confirmed) | Cenovni skok >2x V ISTI transakciji, IN klicatelj je dokazano profitiral (ETH saldo narasel). |
| `curve_virtual_price.rs` | Curve Virtual Price Decrease (Profit Confirmed) | Padec `get_virtual_price()`, IN klicatelj dokazano profitiral. |

### Review-tier (negotovo, potrebuje človeško presojo — NIKOLI ne dobi exploit skripta)

| Oraklj | bug_type niz | Zakaj negotovo |
|---|---|---|
| `centralization_risk.rs` | Centralization Risk: Owner-Only Function | To NI hrošč — je inventar tega, kar lastnik PO DIZAJNU lahko naredi. |
| `curve_virtual_price.rs` | Curve Virtual Price Decrease (BREZ "Profit Confirmed") | Padec cene zaznan, a NI dokazano, da je TA klicatelj profitiral. |
| `price_feed_staleness.rs` | Price Feed Staleness | Samo PREDPOGOJ za napad, ne dokazan izkoristek. |
| `twap_manipulation.rs` | TWAP Manipulation Precondition (BREZ "Profit Confirmed") | Isto — samo predpogoj. |
| `unbounded_loop.rs` | Unbounded Loop | DoS/gas-griefing signal, ne tatvina — rastoča zanka brez omejitve. |
| `stale_guard.rs` | Stale Guard Counter | Lahko je legitimen admin flag, ne nujno hrošč. |
| `unbacked_mint.rs` | Unbacked Mint (Supply Growth Without Backing) | `totalSupply()` naraste v tx brez plačila IN brez pritoka native ETH, na pogodbi, ki ŽE drži native ETH in ŽE ima supply>0. Javno `mint()` je včasih namerno (faucet/rebase/inflacijski žeton), zato Review -- človek presodi, ali naj bi bil žeton sploh native-backed. |
| `unchecked_call.rs` | Unchecked Low-Level Call | Lahko sproži TUDI na kodi, ki namerno preveri rezultat in nadaljuje. |
| `uninitialized_memory.rs` | Uninitialized Memory Read | EVM branje nič je lahko popolnoma normalno. |
| `state_comp.rs` | state_comp | Semantika je POPOLNOMA odvisna od uporabniške definicije "želenega stanja". |
| `overflow.rs` | Integer Overflow | VEDNO aktiven (ni vezan na `-d` izbiro) — znano visoka stopnja lažnih pozitivnih (sproži na compiler-generated selector aritmetiki). |
| `delegatecall_target.rs` | Delegatecall Target From Calldata (Unconfirmed) | Šibkejša varianta — naslov se samo NAKLJUČNO pojavi v calldata bajtih, ni resnično taint-sledenje. |

**Pravilo brez izjem**: `(sim-review)` najdba NIKOLI ne pomeni "dokazan napad". Vsaka
`(sim-review)` najdba JE dokazano reproducirana V SIMULACIJI (`.t.sol` obstaja), a NI
dokazano IZKORISTLJIVA v smislu dejanskega profita na pravi verigi.

## 4. Katere najdbe dobijo dejanski exploit skript

Samo `(sim-confirmed)` najdbe (razdelek 3, zgornja tabela) dobijo `*Exploit.s.sol` — s
TREMA izjemami/posebnostmi:

1. **Reentrancy** ima SVOJ ločen generator (`generate_reentrancy_script`), ker je
   oblika napada (`attack()` sproži enkrat, `receive()` ponavlja) drugačna od
   ostalih (ki samo ravno-predvajajo zaporedje klicev).
2. **Multi-caller sledi se NIKOLI ne pretvorijo v exploit skript**, tudi če je
   bug_type Confirmed — `has_multiple_distinct_callers()` preverjanje v
   `src/evm/solution/mod.rs` to prepreči, ker je bilo PRAVO, v tej seji potrjeno
   dokazano, da poskus "poravnave" več identitet v eno producira SKRIPT, KI SE
   DEJANSKO ZRUŠI ob zagonu (preverjeno na realni ERC4626 pogodbi). V tem primeru
   se generira SAMO `.t.sol` (test), ne `.s.sol` (skript).
3. **Review-tier NIKOLI ne dobi skripta**, ne glede na to, kako prepričljivo izgleda
   najdba — to je namerna, nepogajateljiva varovalka, ne manjkajoča funkcija.

## 5. Vsa `onchain_scripts/*.py` orodja

| Datoteka | Namen |
|---|---|
| `auto_pipeline.py` | GLAVNI cikel: register→fund→fuzz→zaznaj→exploit (preko ponovno-uporabljenega `AttackWallet.sol`)→sweep na recovery wallet. En ukaz, eno zagon. `execute_plan()` zajame pravo ETH IN ERC20 stanje recovery denarnice tik pred/po VSAKEM planu — `CONFIRMED` vrne samo, če je saldo DEJANSKO narasel (ETH preko `recovery_delta_wei`, ERC20 preko `stolen_asset` v `plan.json` + `sweepToken()`), sicer nov status `EXECUTED_NO_PROFIT`. Za `kind=="flat"` plane na `eth`/`sepolia`, ko signer nima dovolj ETH, poskusi resnično Aave V3 WETH flashloan namesto `INCONCLUSIVE` (`execute_flat_plan_via_flashloan`) — živo preverjeno na Anvil forku ETH mainnet-a 2026-11-02 (glej Napake spodaj za `SlotWarmed` popravek, ki je bil potreben, da to deluje). Po neodvisnem teku zdaj tudi pokliče `strategy_layer.run_chain_attempts()` (glej lastno vrstico spodaj in `../SKILL.md` 2026-11-03). Glej `../SKILL.md` za varno uporabo. |
| `strategy_layer.py` | **Nov 2026-11-03.** Pametno razvrsti najdbe (UNLOCK pred OBJECTIVE, numerično ne leksikografsko) namesto golega `sorted(plan_files)`, in po neodvisnem teku poskusi verigenje (UNLOCK najdba + OBJECTIVE najdba na isti tarči → en sestavljen plan skozi OBSTOJEČ `execute_plan()`) za primere kot "ponaredi podpis → pokliči withdraw()", ki ju noben posamezen oracle sam ne poveže. Živo potrjeno na Anvil forku. Samo `kind=="flat"`, samo pari, brez financiranih planov — glej `../SKILL.md` za celoten obseg/omejitve. Uvožen iz `auto_pipeline.py` IN `batch_pipeline.py`, nikoli obratno (brez cikličnega importa). |
| `batch_pipeline.py` | Isto kot zgoraj, a za VEČ tarč naenkrat (nisem še podrobno preveril to sejo — preveri `--help` pred uporabo). |
| `chains.py` | Edini vir resnice za RPC naslove/override-e vseh verig. `require_mainnet_confirmation()` tu živi — glej razdelek 8. |
| `monitor.py` | NEPREKINJEN nadzor že deployane pogodbe (ne enkraten pregled) — opozori na nenavadne selektorje/padce salda, lahko AVTOMATSKO sproži reševanje sredstev ob zaznani krizi (`--key`+`--safe-wallet`). |
| `wallet_policy.py` | Validacija/registracija denarnic po verigah (prepreči tipkarsko napako med naslovi). |
| `aave_flashloan_runner.py` | Resnična (ne simulirana) izvedba flashloan napada preko Aave V3 — za REPRODUKCIJO že najdenega hrošča z resničnim brezkapitalskim kapitalom, ne za ODKRIVANJE. |
| `gas_utils.py` | Natančno računanje gas cene/limita za transakcije (nikoli flat guess). |
| `dex_arbitrage_scanner.py` | Cross-DEX arbitražni skener na **seznamu** vnaprej določenih parov (ne splošen "najdi katerikoli par" scanner): na `eth` zdaj 5 živo preverjenih WETH-parov (USDC/USDT/DAI/WBTC, vsak z resničnimi nenaznimi rezervami na OBEH DEX-ih, preverjeno 2026-11-02) na natanko DVEH trdo-kodiranih DEX-ih (Uniswap V2, SushiSwap V2). `--token-a`/`--token-b` omeji na en ročen par namesto celotnega seznama. Profitabilnost: ternary search, samo-testirano proti brute-force (`--self-test`). `--execute` na `eth` zdaj VEDNO pošlje `armFlashloanActions`+`startFlashLoan` kot en atomski Flashbots bundle (ne nad pragom — arbitraža tekmuje z boti ne glede na velikost), živo preverjeno proti pravemu `relay.flashbots.net` 2026-11-02. **Druge verige iz `KNOWN_V2_FACTORIES`** (ETC, BSC, Polygon, Arbitrum, Celo) **imajo samo EN živo preverjen V2 factory vsaka** — cross-DEX arbitraža jih potrebuje DVA; drugi DEX ni bil najden/preverjen (poskus za BSC Biswap ni uspel — brez zanesljivega vira naslova, zato ni bil ugibano vpisan). Splošno odkrivanje POPOLNOMA novih parov (`allPairsLength`/`allPairs(i)` po factory-jih) ostaja ločen, večji projekt. |
| `dashboard_server.py` | Lahek lokalni FastAPI web dashboard, zaženi iz `forksploit/` korena z `python3 onchain_scripts/dashboard_server.py` (ALI iz `onchain_scripts/` z `python3 dashboard_server.py` — nikoli oboje skupaj, `onchain_scripts/onchain_scripts/...` ne obstaja), `http://127.0.0.1:8765` samo — projicira wallet policy/RPC override-e/AttackWallet salde/zgodovino tekov, in sproža `auto_pipeline.py`/`dex_arbitrage_scanner.py` z obrazcem zgrajenim iz `build_parser()` (ne ročno podvojeno). Poziv za potrditev v GUI je navadno besedilno polje (ne gumb) — isto "DA" zahteva kot CLI. Nobena varnostna logika ni podvojena — vsak tek je isti CLI skript kot subprocess. **Živo preverjena omrežna identiteta**: `GET /api/verify-chain` pokliče pravi `eth_chainId` (upošteva aktiven RPC override) in primerja proti `chains.CHAIN_IDS` — temna grafitna tema z ETH (vijoličen)/ETC (zelen) watermark logotipom in barvno oznako, ki se preklopi IZKLJUČNO na podlagi tega živega rezultata, nikoli na podlagi besedila v `--chain` spustnem seznamu; neujemanje ali nedosegljiv RPC proži glasen rdeč opozorilni pas. **Faza 2 DOKONČANA (2026-11-02)**: vseh 5 Python skript sprožljivih (dodana `monitor.py`/`batch_pipeline.py`/`aave_flashloan_runner.py`), `POST/DELETE /api/rpc-override` in `POST /api/wallet-policy` (ista `--confirm-chain` dvojna potrditev), direkten Rust fuzzer zagon (`forksploit evm`, ROČNO vzdrževana shema `RUST_FUZZER_FIELDS` — edino mesto v GUI-ju brez samodejne sinhronizacije s CLI-jem, ker clap ni introspektibilen kot argparse). **Python spremembe na `dashboard_server.py` zahtevajo ponoven zagon procesa** (ne samo osvežitev brskalnika) — za razliko od `dashboard_static/*`, ki se berejo sveže ob vsaki zahtevi. |
| `debug_file_generator.py`, `evaluate.py`, `immunefi.py`, `deploy_sepolia_demo.py` | NISO bili podrobno preverjeni/dokumentirani v prejšnjih sejah te seje — PREVERI `--help` vsakega pred uporabo, ne predpostavljaj namena iz imena. |

## 6. Zunanji vir resnice za PRAVO, že deployano tarčo: Blockscout verificirana koda

Za KATEROKOLI realno, že deployano mainnet pogodbo (ne lokalno `.sol`/`.bin`), preveri
NAJPREJ, ali obstaja verificirana izvorna koda — brezplačno, brez API ključa:

```
curl -s "https://<veriga>.blockscout.com/api/v2/smart-contracts/<0xNASLOV>"
```

(za ETC: `etc.blockscout.com`; drugi podprti Blockscout-instanci obstajajo za več
verig — preveri, ali obstaja za to specifično verigo, preden predpostaviš da ne).
Odgovor vsebuje `is_verified` (bool), `source_code` (polni Solidity vir, če
verificirano), `abi`, `compiler_version`, `constructor_args` (ABI-enkodirano — lahko
vsebuje berljive nize, npr. opis namena pogodbe, kot je bilo odkrito 2026-11-02 na
realni ETC oracle pogodbi).

**Zakaj je to pomembno, ne samo "lepo imeti"**: ForkSploitovi oraklji delujejo na
RAW BYTECODE nivoju in NE razumejo poslovne logike (razdelek 9). Resnična izvorna
koda razloči:
- Katera funkcija je DEJANSKO ranljiva (npr. `claim()` vs. videti-podobna, a
  pravilno napisana `withdraw()` v isti pogodbi — oba lahko sprožita isti generičen
  "Reentrancy" oraklj, a samo ena je dejansko profitabilna).
- Lažno-pozitivne review-tier najdbe v KNJIŽNICAH (npr. gas-optimizirane
  assembly-based matematične knjižnice, kot Solmate/Solady `FixedPointMathLib`,
  uporabljajo raw `SUB` opcode brez Solidity-jevega overflow-checka PO DIZAJNU — to
  bo sprožilo "Integer Overflow (sim-review)" na vsakem takem klicu, kar JE pravilno
  bytecode-level zaznavanje, a NI dejanski hrošč v knjižnici sami).
- Natančen, s kodo podprt odgovor na FAZO 4a (čigavi so sredstva, kako je
  dostop do njih gated — `msg.sender`-only? obstaja admin override?).

## 7. Kaj je ForkSploit DEJANSKO popravil to sejo (konkretni dokazi, ne obljube)

- Resnično (ne naključno ujemanje bajtov) sledenje izvora delegatecall tarče
  (CALLDATALOAD + RETURNDATACOPY opazovanje v `host.rs`).
- Statična primerjava proxy/implementation storage layoutov BREZ potrebe, da
  fuzzer dejansko sproži trk (`bytecode_analyzer::find_literal_sstore_slots`).
- Sekundarna potrditev profita za TWAP/Curve (ne samo "cena se je premaknila", ampak
  "klicatelj je DEJANSKO profitiral v isti transakciji").
- Razširjena exploit-generacija z 6 na 25+ potrjenih vrst hroščev.
- VEČ resničnih popravljenih napak med preverjanjem (padajoč `msg.value`, enkratna
  zaznamba, ki je blokirala kasnejše najdbe, "control leak" zavrnitve, panika na
  malformiranih `--constructor-args`).

## 8. Varnostni mehanizmi (preverjeno v trenutni kodi, NE iz spomina)

- `onchain_scripts/chains.py`'s `require_mainnet_confirmation(chain, confirmed)` —
  kliče se TAKOJ po parsanju `--chain`, PRED kakršnim koli podpisovanjem. Zavrne
  (`SystemExit`) VSAKO verigo, ki ni v `TESTNET_CHAINS = {"sepolia", "chapel",
  "mordor"}`, RAZEN če je podan `--confirm-mainnet`. ETH in ETC sta OBA "mainnet" po
  tej logiki (en znak narazen v imenu — najpogostejša napaka).
- **Stara, zastarela informacija (NE uporabi)**: `tui.py` in interaktivni
  "POTRJUJEM" poziv STA BILA ODSTRANJENA iz projekta — če kjerkoli vidiš sklicevanje
  nanju, je to zastarelo. Edini trenutni mehanizem je `--confirm-mainnet` CLI
  zastavica.
- ETC posebnost: `revm`-ov `SpecId` nima pravega ETC varianta. `Shanghai` je
  najbližji pravilen, a ETC namerno NI sprejel Merge-related EIP-jev — `DIFFICULTY`
  opcode (0x44) na ETC vrača pravo PoW težavnost, ne `Shanghai`-jevo
  PREVRANDAO-stilno vrednost. Vedno uporabi `--spec-id Shanghai` eksplicitno pri
  ciljanju ETC.
- Aave in Balancer NE OBSTAJATA na ETC — `-f` (flashloan) na ETC ne bo imel iz česa
  izposoditi.
- **`anvil --fork-url` na ETC potrebuje `--hardfork shanghai` eksplicitno.** Privzeti
  `--hardfork latest` povzroči, da anvil pričakuje post-Cancun (EIP-4844 blob gas)
  blok-glave, ki jih pravo pred-Cancun ETC vozlišče nikoli ne vrne — vsak `eth_call`
  na takem forku spodleti z `{"code":-32602,"message":"Excess blob gas not set."}`,
  medtem ko `eth_chainId`/`eth_blockNumber` še naprej delujeta normalno (zato je
  lahko zavajajoče — fork je "živ", a neuporaben). Preverjeno in popravljeno
  2026-11-02.
- **Lokalna vozlišča pogosto tečejo v Dockerju** — notranji port znotraj containerja
  (npr. `8545/tcp`) NI nujno dosegljiv na gostitelju; `docker ps` pokaže dejanski
  mapiran port (`PORTS` stolpec, oblika `0.0.0.0:XXXX->notranji_port/tcp`). Vedno
  preveri to, preden predpostaviš "privzeti" port za geth/core-geth/besu itd.

## 9. Znane, trajne omejitve (ne poskušaj jih "rešiti" z ugibanjem)

- ForkSploit NE razume poslovne logike — samo prepozna vnaprej kodirane vzorce
  (razdelek 3). Nov, kontekstno-specifičen napad, ki ne ustreza nobenemu od 46
  vzorcev, je NEVIDEN. To je natanko motivacija za LLM-hipoteza plast,
  `onchain_scripts/llm_poc/` (ZGRAJENO in testirano 2026-11-02, ne več "v gradnji"):
  `hypothesis_engine.py` vpraša lokalni Hermes (llama-server), naj prebere izvorno
  kodo pogodbe in predlaga konkreten napad kot strog JSON; `confirm_engine.py`
  (v celoti avtorjeva, ne LLM-ova koda) ta predlog DEJANSKO izvede na svežem Anvil
  forku in razsodi CONFIRMED/REFUTED izključno iz merjenih sprememb stanja —
  "LLM predlaga, simulator razsoja", LLM nikoli sam ne odloči o uspehu;
  `run_loop.py` povezuje oba za do N krogov predlog→potrditev→(če REFUTED)
  izboljšava. Resnični test (lokalni 35B model, 3 kroge): model je takoj pravilno
  uganil OBLIKO napada (donacija prek `transfer()` mimo `deposit()`, da se napihne
  delež), a v nobenem krogu ni odkril natančnega numeričnega trika (minimalen prvi
  lastni vložek, da zaokroževanje navzdol prizadene žrtev) — realna, dokumentirana
  meja zmogljivosti majhnega modela, ne izmišljen uspeh. Motor za potrditev je bil
  preverjen, da NE pritrjuje avtomatsko: hkrati pravilna ročno napisana hipoteza
  (CONFIRMED) in namerno napačna kontrolna hipoteza (REFUTED, profit=0).
- **Popravljeno 2026-11-02 (prej veljavna past)**: ERC20 token sweep je zdaj
  priklopljen v avtomatiziran pipeline. `plan.json` nosi `stolen_asset` za raw
  ERC20 korake (`erc20_token_touched` v `src/evm/solution/mod.rs`, reuse
  `make_erc20_calls`-selector logike), `auto_pipeline.py`'s `execute_plan()` po
  vsakem planu preveri/pobere vsak tak token preko `sweepToken()`. Živo
  preverjeno na Anvil forku: `AttackWallet.execute(WETH.deposit, 0.05 ETH)` →
  `sweepToken(WETH, 0.05 ETH)` → recovery denarnica prejela natanko 0.05 WETH.
  **Omejitev, ki ostaja**: zajame samo RAW ERC20 klice (transfer/transferFrom/
  mint/burn/skim/approve neposredno na token pogodbi) — "Fund Loss" najdbe, ki
  gredo skozi buy/sell swap-router mehanizem (`Tx.swap_data`), že pretvorijo
  profit nazaj v ETH kot del same sledi (glej `foundry_script.hbs`), zato jih
  ETH-based preverjanje že pokriva; ta polje je za primere, ki NIKOLI ne gredo
  skozi swap.
- **Flashloan "ničen kapital" je zdaj priklopljen in živo preverjen** (zaprta
  past, 2026-11-02): prej je `auto_pipeline.py` vedno obupal (`INCONCLUSIVE`),
  ko signer ni imel dovolj ETH za financiranje plana. Zdaj za `kind=="flat"`
  plane na `eth`/`sepolia` poskusi resnično Aave V3 WETH flashloan
  (`execute_flat_plan_via_flashloan`): izposodi WETH, odvij v raw ETH znotraj
  `executeOperation()`, poženi exploit korake, zavij nazaj za vračilo — vse
  atomsko. **Resnično ujeta napaka med testiranjem na Anvil forku ETH
  mainnet-a**: WETH9's `withdraw()` interno uporabi `msg.sender.transfer()`
  (trdo 2300 gas) za pošiljko, kar je ZANESLJIVO sprožilo `OutOfGas` v
  `AttackWallet.receive()` (cold SLOAD `pendingCallbackTarget` sam porabi
  ~2100 gas). Popravljeno z `emit SlotWarmed(pendingCallbackTarget)` na
  začetku `executeOperation()`, ki segreje to shrambeno mesto PREDEN karkoli
  lahko sproži povratni klic. Po popravku: cel cikel potrjen uspešen na
  forku, stanja ujemajo do zadnjega wei-ja. **Omejitev, ki ostaja**: samo
  "flat" plani (ne "reentrancy" — kombinacija z `armCallback` ni bila
  načrtovana), samo `eth`/`sepolia` (edini verigi z živo preverjenim Aave
  pool-om IN WETH naslovom — glej `chains.py`; ETC nima Aave-ja, resnična
  omejitev omrežja).
- **MEV zaščita za flashloan pot dodana, + resnična `sign_step()` napaka
  popravljena** (2026-11-02): `execute_flat_plan_via_flashloan` zdaj sprejme
  `use_bundle`/`submit_w3` od `execute_plan` (ista odločitev, isti
  `FLASHBOTS_THRESHOLD_ETH` prag) — na ETH mainnet-u nad pragom sta
  `armFlashloanActions` in `startFlashLoan` pred-podpisana in oddana SKUPAJ
  kot en atomski Flashbots bundle, namesto kot dve ločeni javni transakciji
  (kar bi razkrilo cel exploit mempool-botu pred `startFlashLoan`). Pri prvem
  dejanskem klicu `sign_step()` za to je bila odkrita resnična, PREJ
  OBSTOJEČA napaka (prizadela bi vsak bundle, ne samo flashloan): `**fee_fields`
  pusti `is_legacy` ključ v tx slovarju, kar `eth_account` zavrže. Popravljeno
  z istim legacy/1559 dispatch-om kot `gas_utils.build_precise_tx`. Živo
  preverjeno na Anvil forku: obe transakciji se zdaj pravilno pred-podpišeta.
  **Druga, resnejša napaka je bila odkrita in POPRAVLJENA isti dan — prejšnja
  domneva "403 = datacenter-IP blokada relay-ja" je bila NAPAČNA**: dejanski
  vzrok je bil `sign_request()` v `flashbots_bundle.py`, kateremu je manjkal
  `0x` prefiks na SAMEM PODPISU (ne na hash-u) v `X-Flashbots-Signature`
  glavi — uradni Python primer na docs.flashbots.net ima isto napako (Go
  primer na isti strani jo nima, ker `hexutil.Encode` vedno doda `0x`).
  Sistematično testirano vseh 4 kombinacij `0x` neposredno proti PRAVEMU
  `relay.flashbots.net`: samo (hash=0x+hex, podpis=0x+hex) je dalo čist
  premik iz `-32025 "invalid flashbots signature"` v normalno `-32003
  "insufficient funds"` — dokaz, da relay podpis zdaj sprejme. Popravljeno v
  `sign_request()`; Flashbots bundle pot je zdaj dejansko preverjena proti
  produkcijskemu relay-ju, ne samo proti forku.
- `(sim-review)` najdba brez dodatnega preverjanja NI dokaz izkoristljivosti. In
  `(sim-confirmed)` NI dokaz, da je karkoli dejansko izvedljivo na pravi verigi --
  samo `PLAN_CONFIRMED` iz `execute_plan()` (resnična sprememba salda) je to.
- Noben fuzzing pristop ne more dokazati ODSOTNOSTI hroščev — samo njihovo
  PRISOTNOST, če jih najde v času, ki ga ima na voljo.
