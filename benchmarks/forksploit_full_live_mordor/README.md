# ForkSploit — polni tek neposredno na živi Mordor (brez anvil forka)

Cilj: **celoten** ForkSploit (vse zmogljivosti) na **točno tej pogodbi** in
**točno tem omrežju**, kot je zahtevano — brez anvil forka, neposredno na javni
Mordor RPC.

- Pogodba: `CyberScratchLottery`
  `0x1FD07693355ac7f1c29d2FC2BbC390fc0D5Ad2Ee`
- Omrežje: ETC Mordor, `https://rpc.mordor.etccooperative.org` (chainId 63)
- Blok: `17353046` (`0x108c9dd`)
- Bajtkod tarče: 4427 B (`eth_getCode`)

## Ukaz (polni tek)

```bash
./target/release/forksploit evm \
  -t 0x1FD07693355ac7f1c29d2FC2BbC390fc0D5Ad2Ee \
  -c mordor -u https://rpc.mordor.etccooperative.org \
  --spec-id Shanghai \
  --concolic --concolic-caller --concolic-num-threads 3 \
  -f \
  --jobs 3 --fuzz-seconds 300 \
  --invariants benchmarks/forksploit_full_live_mordor/invariants.json \
  --auto-setup --run-forever \
  -w <workdir>
```

Vklopljeno: concolic + concolic-caller, flashloan (`-f`), 3 vzporedna delavca
(concolic strop deljen: `--concolic-num-threads 1` na delavca), invariants,
auto-setup, `--run-forever`, Shanghai spec (ETC Mordor).

## Ponovljivost (R1)

Dva **neodvisna** teka z različnima seedoma (`1667840158231589000` in
`987654321`), vsak 300 s, 3 delavci:

| Tek | Izvršitev | Najdene datoteke | Množica tipov najdb |
|-----|-----------|------------------|---------------------|
| 1 | 385.865.153 | 91 | 9 tipov |
| 2 | 430.108.236 | 103 | **isti 9 tipov** |

Množica tipov najdb je **100 % ponovljiva** med tekoma.

## Resnica vs. šum — preverjeno proti verificirani izvorni kodi

Nameščeni bajtkod **se ujema** z verificirano izvorno kodo
(`deployed_bytecode` iz Blockscout == `eth_getCode`, 4427 B, solc
0.8.20+commit.a1b79de6, optimizacija **izklopljena**). Zato lahko vsako
najdbo preverimo neposredno.

Izvor: `CyberScratchLottery.sol` (shranjen v tem imeniku). Ključno: vir
**nima** `ecrecover`, `unchecked` ali `assembly`.

| # | Najdba (tier) | Verdikt | Dokaz |
|---|---------------|---------|-------|
| 1 | **Weak Randomness** (sim-review) | **RESNIČNA** | vir: `keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender)) % 100` (SWC-120); pc 2084 |
| 2 | Centralization Risk (sim-review) | resnična, po namenu | `onlyOwner` na `withdrawFunds`/`setTicketPrice` |
| 3 | **Invariant Violation** (sim-confirmed) | **LAŽNI POZITIV** | operand `native_balance` v Address načinu bere `post_state.balance[target]` = 0 (`contract_utils.rs:820`); živa bilanca je 1.06e19. `rhs=0` → invariant trivialno pade. Na verigi `totalPayouts(1.3e18) <= balance(1.06e19)` DRŽI |
| 4 | **Fund Loss** (sim-confirmed) | **zavajajoče / FP** | sled: `withdrawFunds()` kliče **lastnik** (slot 1 = `0xfF0f5263…`), torej privilegiran dvig po namenu, ne "anyone can earn" |
| 5 | **Arbitrary Storage Write** (sim-confirmed) | **LAŽNI POZITIV** | pc 962 = `PUSH1 0x02; … SSTORE` → slot je **konstanta 2** (`ticketPrice`), ne attacker-chosen. Sproži se, ker argument `setTicketPrice(2)` sovpade s konstantnim indeksom slota |
| 6 | **Unchecked ecrecover(0)** (sim-confirmed) | **LAŽNI POZITIV** | vir nima `ecrecover`. Sled: `[Sender] 0x…01` → `buyTicket` → `payable(msg.sender).call{value:…}` cilja `0x…01` (naslov ecrecover precompila), ker fuzzer uporabi `0x01` kot klicatelja |
| 7 | **Integer Overflow** (sim-review) | **LAŽNI POZITIV** | pc 2616 = ReentrancyGuard `_status == ENTERED` primerjava (selector `0x3ee5aeb5`); pc 3666 = compiler checked-math helper. Solidity 0.8.20 ima preverjeno aritmetiko, v viru ni `unchecked` |
| 8 | **Zero Address Setter** (sim-review) | **LAŽNI POZITIV** | pc 962, slot 2 = `ticketPrice` (številka, ne naslov). `setTicketPrice(0)` vpiše 0 v numerični slot, ki je zaradi majhne vrednosti "address-shaped" |
| 9 | **Stale Guard Counter** (sim-review) | benigno | stražarji berejo `_status` (slot 0), `winProbability` (slot 5 = 65) — po namenu konstantni |
| 10 | **Unbounded Loop** (sim-review) | benigno | `getWinners(count)`: zanka je omejena s klicateljevim `count`, ne z `winners.length` |

## Sklep

- **En resničen bug**: Weak Randomness (SWC-120) — potrjen z izvorno kodo in
  neodvisno z Echidno.
- **Dodatnih 8 "najdb"** na `sim-confirmed`/`sim-review` ravni je v tem teku
  **lažnih pozitivov ali zavajajočih oznak** (6 FP + 2 benigna heuristika),
  preverjeno proti verificirani kodi.

To je pošten, izmerjen rezultat **polnega** cevovoda na živi verigi. Prejšnja
"minimalna" primerjava je poročala le podmnožico (Weak Randomness + Fund Loss)
in je zato **podcenila** šum; polni tek pokaže, da oraklji na `sim-confirmed`
ravni proizvedejo več lažnih pozitivov, ki jih je treba ročno preveriti.

Omejitev tega okolja: `--invariants` operand `native_balance` v Address načinu
ni napolnjen z živo bilanco (točka 3) — to je napaka orodja, ne tarče.

## Artefakti

- `run1_*.log`, `run2_*.log` — surovi dnevnik delavcev (oba teka)
- `run{1,2}_supervisor.log` — nadzornik (združevanje najdb)
- `CyberScratchLottery.sol` — verificirana izvorna koda
- `invariants.json` — uporabljeni invarianti
- `runtime_disasm.txt` — disassembler nameščenega bajtkoda
