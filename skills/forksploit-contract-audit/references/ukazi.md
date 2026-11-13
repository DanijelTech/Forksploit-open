# Referenca ukazov za ForkSploit nadzorovan pregled

Zbirka natančnih ukazov, uporabljenih skozi `../SKILL.md`, za hitro kopiranje med
delom. Vse poti so relativne glede na koren ForkSploit repozitorija, razen kjer je
drugače navedeno. Nadomesti `<...>` placeholderje z dejanskimi vrednostmi — nikoli
jih ne pusti dobesedno v ukazu.

## Preverjanje vozlišča (FAZA 1)

```bash
# Chain ID (0x1 = ETH mainnet, 0x3d = ETC mainnet)
curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
  <RPC_URL>

# Trenutni blok (preveri, da se premika)
curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  <RPC_URL>
```

## Preverjanje lokalnega vozlišča v Dockerju (FAZA 1, če uporabnik ni prepričan o portu)

```bash
# Pokaže dejanski port, mapiran na gostitelja (PORTS stolpec) -- notranji port
# v containerju (npr. 8545/tcp brez "0.0.0.0:...->" predpone) NI dosegljiv od zunaj
docker ps
```

## Vzpostavitev forka (FAZA 2)

```bash
# Zaženi fork na ločenem portu (8555), NE na 8545 (izogibanje koliziji)
# --hardfork shanghai je OBVEZEN za ETC (in verjetno druge pred-Cancun verige) --
# brez njega VSAK eth_call na forku spodleti z "Excess blob gas not set."
anvil --fork-url <PREVERJEN_PRAVI_RPC_URL> --port 8555 --hardfork shanghai &

# Potrdi, da fork vidi pravo kodo tarče
cast code <NASLOV_TARCE> --rpc-url http://127.0.0.1:8555

# Potrdi, da eth_call dejansko deluje (pricakovan navaden EVM revert, NE RPC napaka)
cast call <NASLOV_TARCE> "owner()(address)" --rpc-url http://127.0.0.1:8555
```

## Iskanje verificirane izvorne kode za pravo, že deployano tarčo (pred FAZO 4)

```bash
# Brezplačno, brez API kljuca. Zamenjaj "etc" z ustrezno Blockscout instanco verige.
curl -s "https://etc.blockscout.com/api/v2/smart-contracts/<NASLOV_TARCE>" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print('is_verified:', d.get('is_verified')); open('target_source.sol','w').write(d.get('source_code','')); json.dump(d.get('abi'), open('target_abi.json','w'))"
```

## Preverjanje DEJANSKEGA lastništva sredstev (FAZA 4a, pri pooled/staking pogodbah)

```bash
# Zamenjaj "stakes"/"mana" z dejansko getter funkcijo TE pogodbe (balanceOf,
# deposits, ipd. -- preveri v ABI-ju/izvorni kodi iz prejsnjega koraka)
cast call <NASLOV_TARCE> "stakes(address)(uint256)" <DENARNICA_IZ_FAZE_0> --rpc-url http://127.0.0.1:8555
cast call <NASLOV_TARCE> "mana(address)(uint256)" <DENARNICA_IZ_FAZE_0> --rpc-url http://127.0.0.1:8555
```

## RPC override (FAZA 3 in FAZA 7)

Zaganja se iz `onchain_scripts/` imenika (ali z `PYTHONPATH` nastavljenim nanj).

```bash
# Nastavi override na FORK (varno raziskovanje)
python3 -c "from chains import set_rpc_override; set_rpc_override('eth', 'http://127.0.0.1:8555')"

# Nastavi override na PRAVO vozlišče (šele po FAZI 6!)
python3 -c "from chains import set_rpc_override; set_rpc_override('eth', '<PRAVI_URL>')"

# Počisti override (FAZA 9, vedno na koncu)
python3 -c "from chains import clear_rpc_override; clear_rpc_override('eth')"

# Preveri, kam trenutno kaže override
python3 -c "from chains import get_rpc_url; print(get_rpc_url('eth'))"
```

Zamenjaj `'eth'` z `'etc'` za Ethereum Classic.

## Glavni cikel (FAZA 3 in FAZA 7)

```bash
python3 onchain_scripts/auto_pipeline.py \
  --target <NASLOV_TARCE_ALI_POT_DO_.bin> \
  --recovery-wallet <RECOVERY_WALLET> \
  --key <POT_DO_DATOTEKE_S_KLJUCEM> \
  --chain <eth|etc> \
  --confirm-mainnet \
  --fund-eth 0.01 \
  --fuzz-seconds 300 \
  --detectors all
```

Opombe:
- `--confirm-mainnet` je OBVEZEN za `eth`/`etc` tudi na forku (glej SKILL.md FAZA 3).
- `--key` v FAZI 3 (fork) = testni/throwaway ključ. `--key` v FAZI 7 (pravo
  vozlišče) = uporabnikov pravi ključ, podan sveže v tistem trenutku.
- `--fuzz-seconds 300` je razumen začetek; za kompleksnejše pogodbe lahko traja
  dlje (glej `--detectors`/`--concolic` opcije neposredno v
  `./target/release/forksploit evm --help`, če `auto_pipeline.py` ne najde
  ničesar v 300s).

## Neposreden zagon ForkSploit (če `auto_pipeline.py` ni primeren, npr. samo
## analiza brez izvedbe exploita)

```bash
./target/release/forksploit evm \
  -t <NASLOV_TARCE> \
  -c <eth|etc> \
  -u <RPC_URL_FORKA_ALI_PRAVEGA_VOZLISCA> \
  -f --run-forever \
  -d all \
  -w <DELOVNI_IMENIK>
```

Izhod: `<DELOVNI_IMENIK>/vulnerabilities/*.t.sol` (dokaz za VSAKO najdbo),
`*.plan.json` (strukturiran exploit plan), `*Exploit.s.sol` (SAMO za `(sim-confirmed)`
vrste hroščev — glej `src/evm/solution/mod.rs`'s `is_confirmed_exploitable_bug`).
`(sim-confirmed)`/`(sim-review)` sta ZGOLJ simulacijski oznaki (glej `src/evm/oracle.rs`) —
NIKOLI ne enači ju z resnično on-chain potrditvijo (`PLAN_CONFIRMED` v `auto_pipeline.py`,
FAZA 7/8).

## Preverjanje saldov (FAZA 5 in FAZA 8)

```bash
cast balance <RECOVERY_WALLET> --rpc-url <RPC_URL_FORKA_ALI_PRAVEGA_VOZLISCA>
```

Vedno primerjaj PRED in PO — zapiši vrednost PRED zagonom FAZE 3/7, ne šele po.

## Ročni zagon generiranega exploit skripta (če potrebno izven `auto_pipeline.py`)

```bash
forge script <POT_DO_XExploit.s.sol> \
  --tc <ImeKontrakta>ExploitRunner \
  --rpc-url <RPC_URL_FORKA_ALI_PRAVEGA_VOZLISCA> \
  --private-key <KLJUC> \
  --broadcast
```
