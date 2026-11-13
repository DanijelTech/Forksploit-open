# PYTHON PLAST — izvršilna plast po modulih

> Samostojen dokument. Sorodno: [ARHITEKTURA.md](ARHITEKTURA.md),
> [OZICENJE_RUST_PYTHON.md](OZICENJE_RUST_PYTHON.md),
> [ATTACKWALLET.md](ATTACKWALLET.md), [TOK_PODATKOV.md](TOK_PODATKOV.md).

Vse poti so pod `onchain_scripts/`. Vsaka trditev je preverjena v kodi.

---

## 1. Pregled modulov

```
onchain_scripts/
├── auto_pipeline.py          orkestracija enega cilja (3108 vrstic)
├── batch_pipeline.py         isti tok za več ciljev (464)
├── strategy_layer.py         branje/združevanje planov (592)
├── chains.py                 verige, RPC, identiteta (485)
├── wallet_policy.py          zaklep denarnic (322)
├── gas_utils.py              plin: meje, proračun (484)
├── gas_oracle.py             uradni gas-price oracle (483)
├── proxy_resolver.py         proxy razširitev (217)
├── flashbots_bundle.py       atomični bundle (162)
├── monitor.py                površinski nadzor po izdaji (478)
├── dashboard_server.py       GUI strežnik (552)
├── materialize_plan.py       delovni seznam materializacije (425)
├── triage_findings.py        razvrščanje po površinah (273)
├── dex_arbitrage_scanner.py  iskalnik DEX arbitraže (671)
├── aave_flashloan_runner.py  validacija flashloan (281)
├── gen_chain_fixture.py      generator verižnih fixture-ov (95)
├── deploy_sepolia_demo.py    razporeditev demo pogodb (118)
├── evaluate.py               množično vrednotenje (63)
├── immunefi.py, debug_file_generator.py   pomožna orodja
├── server_run.sh             zagon GUI (186)
├── contracts/AttackWallet.sol   on-chain primitiv (346)
├── contracts/proof_w1_w2_w3.sh  dokazni skript
├── dashboard_static/         index.html, app.js, style.css
└── test_*.py                 22 testnih datotek
```

---

## 2. `auto_pipeline.py`

### Namen
Register → fund → fuzz → exploit → recover za **en** cilj. Vse, razen
identifikatorja cilja in recovery denarnice, se izvede brez nadaljnjega
vnosa.

### Ključne funkcije

| Simbol | Namen | Vhod | Izhod |
|--------|-------|------|-------|
| `main()` | celoten tok | CLI | `int` (exit koda) |
| `build_parser()` | CLI parser (introspekcija za dashboard) | — | `ArgumentParser` |
| `run_fuzzer(target_address, chain, detectors, fuzz_seconds, work_dir, tee, extra_targets)` | požene Rust binarij | naslovi, veriga | `float` (dejanske sekunde) |
| `execute_plan(w3, acct, nonce_box, attack_wallet, plan, recovery_wallet, tee, chain, return_units)` | izvede plan prek AttackWallet | plan | 4/5-terica statusov |
| `gated_execute_plan(...)` | `execute_plan` za pre-flight vrati | plan | 5-terica |
| `preflight_skip_reason(...)` | polna pre-flight vrata | finding | `str \| None` |
| `metadata_skip_reason(finding)` | sloj 1 (brez omrežja) | finding | `str \| None` |
| `gas_oversized_reason(plan)` | plinska vrata | plan | `str \| None` |
| `simulate_plan_on_fork(...)` | sloj 2 (anvil fork) | plan | `(delta, gas, reverted, tokens) \| None` |
| `estimate_plan_gas_on_fork(...)` | meritev plina | plan | `dict \| None` |
| `_start_fork(chain, tee)` | zažene anvil fork | veriga | `(proc, w3)` |
| `get_or_deploy_attack_wallet(...)` | enkrat na verigo | veriga | naslov |
| `send_call(...)` | podpiše+pošlje tx | — | `bool` |
| `deploy(...)`, `compile_contract(...)` | razporeditev/prevedba | — | naslov / bajtkod |
| `build_proof(...)` | strukturiran dokaz | signals | `Proof` |
| `is_chain_verified(status, delta)` | najvišji nivo | — | `bool` |
| `determine_negative_result_verdict(...)` | ocena "ni najdb" | coverage | `str` |
| `report_unexecuted_findings`, `report_surface_triage`, `report_coverage`, `report_materialization` | poročila | — | — |
| `run_static_analysis(sol_path, tee)` | Slither | — | — |
| `parse_pretty_wei`, `selector`, `encode_address`, `encode_uint256` | pomožno | — | — |
| `attack_wallet_*_calldata(...)` | gradnja calldata | — | `bytes` |
| `revert_reason`, `first_failing_step_index`, `erc20_balance_of`, `aave_flashloan_premium_bps` | diagnoza | — | — |

### Odvisnosti (importi)
`chains`, `flashbots_bundle`, `proxy_resolver`, `gas_utils`, `wallet_policy`,
`strategy_layer`, `eth_abi`, `eth_account`, `web3`.

### Konstante (iz kode)

| Konstanta | Vrednost | Pomen |
|-----------|----------|-------|
| `FLASHBOTS_THRESHOLD_ETH` | `10.0` | nad tem se uporabi atomični bundle |
| `BUNDLE_GAS_LIMIT` | `2_000_000` | fiksna meja plina v bundleu |
| `BUNDLE_BUILDER_TIP_BPS` | `400` | 4 % napitnina builderju |
| `GAS_BUDGET_MARGIN` | `1.10` | rezerva proračuna |
| `REPLACEMENT_FEE_BUMP` | `1.15` | dvig cene pri zamenjavi |
| `REPLACEMENT_MAX_ATTEMPTS` | `3` | poskusi zamenjave |
| `FORK_SIM_ENABLED_DEFAULT` | `True` | pre-flight privzeto vključen |
| `FORK_SIM_PORT` | `18545` | vrata anvil forka |
| `FORK_SIM_ETC_HARDFORK` | `"shanghai"` | hardfork za ETC |
| `FORK_SIM_STARTUP_TIMEOUT_S` | `20.0` | čakanje na anvil |
| `MIN_COVERAGE_PCT_FOR_NEGATIVE_RESULT` | `80.0` | prag za "ni najdb" |
| `MIN_FUZZ_SECONDS_FOR_NEGATIVE_RESULT` | `300` | prag časa |
| `PRIVACY_REDIRECT_RPC` | `{"bsc": {...}}` | zasebni mempool za BSC |

Statusi: `PLAN_CONFIRMED`, `PLAN_NOT_CONFIRMED`, `PLAN_INCONCLUSIVE`,
`PLAN_EXECUTED_NO_PROFIT`, `PLAN_SKIPPED_UNPROFITABLE`,
`PLAN_SKIPPED_NOT_EXTRACTABLE`, `PLAN_OVERSIZED_GAS` (glej
[OZICENJE_RUST_PYTHON.md](OZICENJE_RUST_PYTHON.md) §8).
Presoje "ni najdb": `SCAN_NO_BUG_BOUNDED`, `SCAN_INSUFFICIENT_COVERAGE`.

### Povratna pisanja
`main` prepiše `plan.json` z `gas_estimate`, `fits_block_gas_limit`,
`gas_headroom_pct`, `block_gas_limit` (po forku) in `gas_used` (po izvedbi).

### Dotik druge plasti
`run_fuzzer` je edini stik z Rust binarijem (Popen + `ETH_RPC_URL`).

---

## 3. `batch_pipeline.py`

* `main` enkrat prebere `--targets` datoteko, enkrat preveri denarnico
  (`enforce_wallet_policy`), nato za vsak cilj `run_one_target`.
* Napaka na enem cilju ne prekine serije (razen napake politike denarnice).
* Ponovno uporabi funkcije iz `auto_pipeline` (import na vrhu).
* Argumenti: `--targets`, `--recovery-wallet`, `--key`, `--chain`,
  `--confirm-mainnet`, `--fund-eth`, `--fuzz-seconds`, `--detectors`,
  `--no-preflight`, `--no-gas-oracle`.

---

## 4. `strategy_layer.py`

### Namen
Uredi najdbe in sestavi en koherenten, izvedljiv plan iz mnogih
neodvisnih planov.

### Ključne strukture

| Simbol | Pomen |
|--------|-------|
| `UNLOCK_BUG_TYPES` | `frozenset` bug tipov, ki dajo sposobnost (ne premaknejo sredstev) |
| `OBJECTIVE_BUG_TYPES` | `frozenset` bug tipov, ki že pomenijo premik sredstev |
| `_CONFIRMED_BUG_TYPE_RE` | regex za branje `.t.sol` kot fallback |
| `_APPROVE_SELECTORS` | `{0x095ea7b3, 0xa22cb465}` |
| `_TRANSFER_FROM_SELECTORS` | `{0x23b872dd}` |
| `_DEPOSIT_SELECTORS` | `{0xd0e30db0}` |
| `_WITHDRAW_SELECTORS` | `{0x2e1a7d4d, 0xba087652}` |

### Ključne funkcije

| Simbol | Namen |
|--------|-------|
| `load_findings(work_dir)` | prebere `*.plan.json` + metapodatke |
| `ordering_key(finding)` | razvrsti unlock → dvoumno → objective → neklasificirano |
| `_steps_of(finding)` | `full_trace_steps` pred `steps` |
| `_is_chainable(finding)` | `atomic_replayable` in `kind` v `("flat","reentrancy")` |
| `_dedup_steps(steps)` | odstrani podvojene korake |
| `order_steps_by_dependencies(steps)` | stabilen topološki red (approve→transferFrom, deposit→withdraw) |
| `_thread_address_arguments(steps, composed_caller)` | prepiše `from` v `transferFrom` na sestavljenega klicatelja |
| `compose_plan(findings, composed_caller)` | sestavi en plan |
| `build_composition_candidates(findings, max_attempts)` | kandidatne skupine |
| `run_chain_attempts(execute_plan_fn, ...)` | izvede sestavljene plane |

### Izhod
`compose_plan` vrne slovar z isto shemo, kot jo pričakuje `execute_plan`:
`contract_name`, `kind`, `needs_funding`, `total_value`, `steps`,
`repeat_step`, `composed_from`, `confirmed_exploitable`.

### Dotik druge plasti
Bere `plan.json` (Rust izhod). Ne importa `auto_pipeline` (izogib krožnemu
importu); prejme `execute_plan_fn` kot parameter.

---

## 5. `chains.py`

### Namen
Enotni vir za verige/RPC/identiteto.

### Ključni podatki

| Simbol | Pomen |
|--------|-------|
| `DEFAULT_RPC` | privzeti RPC po verigi (21 vnosov) |
| `TESTNET_CHAINS` | `{"sepolia", "chapel", "mordor"}` |
| `CHAIN_IDS` | ime → chain id (vključno `local: 31337`) |
| `AAVE_V3_POOLS` | veriga → Aave V3 Pool |
| `WETH_ADDRESSES` | veriga → WETH (`eth`, `sepolia`) |
| `CHAIN_TITLES` | kratka imena za meni |
| `NATIVE_SYMBOL` | ticker (ETH/ETC/BNB/...) |
| `OVERRIDES_FILE` | `rpc_overrides.json` |

### Ključne funkcije

| Simbol | Namen |
|--------|-------|
| `verify_rpc_identity(chain, tee, w3)` | prebere realni `eth_chainId`, primerja |
| `require_mainnet_confirmation(chain, confirmed, tee)` | `SystemExit` brez `--confirm-mainnet` |
| `NetworkProfile` | `chain`, `chain_id`, `family`, `is_testnet`, `native_symbol`, `supports_flashbots` |
| `network_profile_for_chain_name`, `_profile_from_id`, `network_family`, `chain_name_for_id` | profili |
| `native_symbol`, `native_symbol_for_w3` | oznake |
| `chain_banner`, `chain_title` | prikaz |
| `known_chains()`, `get_rpc_url(chain)`, `make_w3(chain)`, `set_rpc_override`, `clear_rpc_override` | RPC upravljanje |

`make_w3` vedno vbrizga `ExtraDataToPOAMiddleware` (za POA verige).

### Dotik druge plasti
Rust binarij dobi RPC prek `ETH_RPC_URL`, ki ga nastavi `run_fuzzer` iz
`get_rpc_url(chain)`. Rust stran ima svojo tabelo
(`src/evm/onchain/endpoints.rs::Chain::get_chain_rpc`), a bere `ETH_RPC_URL`
brezpogojno.

---

## 6. `wallet_policy.py`

### Namen
Strog zaklep vlog denarnic na verigo.

### Strukture
* `WALLETS_FILE` = `wallets.json`: natanko en funding + en recovery na verigo.
* `CONTRACTS_FILE` = `contracts.json`: dnevnik vseh pogodb.
* `_FILE_LOCK`: `threading.Lock` za read-modify-write.

### Ključne funkcije

| Simbol | Namen |
|--------|-------|
| `load_policy(chain)` | prebere politiko |
| `register_policy(chain, confirm_chain, funding_wallet, recovery_wallet, force, client_note)` | zapiše politiko |
| `enforce_wallet_policy(chain, signer_address, recovery_or_safe_wallet)` | `SystemExit` ob neujemanju |
| `register_contract(chain, address, source, run_id, script, funding_wallet, recovery_wallet)` | doda zapis |
| `_cmd_register`, `_cmd_show`, `_cmd_contracts`, `main` | CLI |

`register_policy` zahteva `--confirm-chain`, ki mora biti enak `--chain`
(anti-typo, ker sta `eth` in `etc` eno črko narazen).

### Dotik druge plasti
`auto_pipeline.main` in `monitor.watch_target` kličeta
`enforce_wallet_policy` **pred** vsakim podpisom.

---

## 7. `gas_utils.py`

| Simbol | Namen |
|--------|-------|
| `DEFAULT_GAS_LIMIT_MARGIN` = `0.10` | rezerva |
| `MAX_GAS_LIMIT` = `8_000_000` | trda meja plina na tx |
| `BASE_FEE_LOOKAHEAD_BLOCKS` = `2` | zaščita maxFeePerGas |
| `GasExceedsBlockLimitError` | izjema |
| `estimate_gas_limit(w3, tx, margin)` | precizna meja + cross-check |
| `get_fee_fields(w3, lookahead_blocks, chain, use_official)` | fee polja |
| `tx_worst_case_price(tx)` | najslabša cena |
| `build_precise_tx(...)` | sestavi tx |
| `describe_actual_cost(w3, receipt)` | opis stroška |
| `GasBudgetExceeded`, `GasBudget` | proračun |
| `GasLedger` | knjiga porabe |
| `net_profit_wei(gross, gas)`, `format_wei_signed(w3, wei)` | izračun/format |
| `gas_fit(gas_estimate, block_gas_limit, margin)` | `{gas_estimate, gas_limit_with_margin, block_gas_limit, fits_block_gas_limit, gas_headroom_pct}` |

---

## 8. `gas_oracle.py`

| Simbol | Namen |
|--------|-------|
| `BLOCKSCOUT_CHAINS` | `{"etc": ..., "mordor": ...}` |
| `ETHERSCAN_V2_URL` | `https://api.etherscan.io/v2/api` |
| `DEFAULT_TIMEOUT` = `12`, `DEFAULT_TTL_SECONDS` = `12`, `DEFAULT_LOOKAHEAD_BLOCKS` = `2` | — |
| `ENABLED`, `set_enabled(value)` | stikalo (`--no-gas-oracle`) |
| `GasQuote` | kvota |
| `etherscan_v2_gas_oracle(...)`, `blockscout_v2_gas_prices(...)`, `fetch_official_gas_quote(...)` | pridobivanje |
| `compute_fee_fields(...)`, `resolve_fee_fields(w3, chain, ...)` | izračun |
| `verify_gas_oracles(...)`, `main` | preverjanje/CLI |

Best-effort: vsaka napaka uradnega vira degradira na kvoto vozlišča.

---

## 9. `proxy_resolver.py`

| Simbol | Namen |
|--------|-------|
| `_slot(definition, minus_one)` | izračuna slot iz keccak |
| `BEACON_IMPLEMENTATION_SELECTOR` | `keccak("implementation()")[:4]` |
| `_address_from_word(word)` | razčleni 32-bajtno besedo v naslov |
| `minimal_proxy_implementation(code_hex)` | EIP-1167 |
| `eip7702_delegate(code_hex)` | EIP-7702 |
| `_read_slot_address(w3, address, slot)` | bere slot |
| `_call_implementation(w3, beacon, selector)` | kliče beacon |
| `discover_implementations(w3, address)` | seznam implementacij |
| `resolve_proxy_chain(w3, address, max_hops)` | slovar `{is_proxy, implementations, depth}` |

Slot konstante so izpeljane iz keccak in cross-checked z Rust literali v
`test_proxy_resolver.py`.

---

## 10. `flashbots_bundle.py`

| Simbol | Namen |
|--------|-------|
| `RELAY_URLS` | `{"eth": "https://relay.flashbots.net", "sepolia": "https://relay-sepolia.flashbots.net"}` |
| `sign_request(acct, payload)` | podpiše po spec |
| `_post(relay_url, acct, payload)` | POST |
| `call_bundle(relay_url, acct, raw_txs, target_block, state_block)` | `eth_callBundle` |
| `send_bundle(relay_url, acct, raw_txs, target_block)` | `eth_sendBundle` |
| `submit_bundle_and_wait(...)` | čakanje na vključitev |

Flashbots pokriva **samo** ETH mainnet + sepolia (glej `RELAY_URLS`).

---

## 11. `contracts/AttackWallet.sol`

Podrobno v [ATTACKWALLET.md](ATTACKWALLET.md).

---

## 12. `dashboard_server.py` in `dashboard_static/`

* FastAPI aplikacija, `uvicorn.run(app, host="127.0.0.1", port=args.port)`,
  privzeta vrata `4114` (`main`).
* Končne točke: `GET /api/actions`, `GET /api/verify-chain`, `GET /api/state`,
  `POST /api/run`, `POST /api/run/{id}/input`, `POST /api/run/{id}/stop`,
  `WS /api/run/{id}/stream`, `POST /api/rpc-override`,
  `DELETE /api/rpc-override/{chain}`, `POST /api/wallet-policy`.
* `/api/state` vrne `wallets`, `rpc_overrides`, `contracts`, `attack_wallets`,
  `recent_logs`, `vulnerabilities_found`, `dashboard_runs`,
  `external_processes`.
* `dashboard_static/index.html` ima stransko navigacijo s tremi skupinami
  (`Upravljanje`, `Nastavitve in konfiguracija`, `Rezultati`) in pogledi:
  `overview`, `run`, `runs`, `console`, `wallet`, `rpc`, `contracts`,
  `findings`, `logs`, `processes`.

---

## 13. `monitor.py`

| Simbol | Namen |
|--------|-------|
| `watch_target(chain, address, args, acct, nonce_locks, stop_event)` | nadzor enega cilja |
| `attempt_rescue(trigger, current_balance)` | poskus rešitve |
| `rescan(reason)` | periodično ponovno fuzzanje |
| `build_parser()`, `main` | CLI |
| `_load_targets(args)` | branje `--config` |

Zastavice: `--address`, `--chain`, `--config`, `--poll-interval`,
`--balance-drop-pct`, `--large-tx-eth`, `--rescan-interval`, `--rescan-seconds`,
`--rescan-detectors`, `--key`, `--safe-wallet`, `--confirm-mainnet`.

Avtomatska rešitev zahteva `--key` **in** `--safe-wallet`; sicer je nadzor
samo bralen.

---

## 14. `triage_findings.py`, `materialize_plan.py`

* `triage_findings`: `surface_key`, `classify`, `triage`, nivoji
  `RUNNABLE`, `NEEDS_MATERIALIZATION`, `NEEDS_MULTI_SENDER`,
  `AMOUNT_UNREALISTIC`, `HEURISTIC_ONLY`.
* `materialize_plan`: `classify_selector`, `leaked_steps`,
  `is_callback_leak`, `worklist`, `RECIPES` (preslikava razreda selectorja v
  recept), `SELECTOR_CLASS`.

---

## 15. `dex_arbitrage_scanner.py`, `aave_flashloan_runner.py`,
`gen_chain_fixture.py`, `deploy_sepolia_demo.py`, `evaluate.py`,
`immunefi.py`, `debug_file_generator.py`

* `dex_arbitrage_scanner`: `get_pair`, `get_reserves`, `find_optimal_arbitrage`,
  `check_once`, `ask_human_confirmation` — opozarja (ne izvaja samodejno).
* `aave_flashloan_runner`: validacija flashloan na `--chain`.
* `gen_chain_fixture`: generira N-stopenjsko verižno fixture.
* `deploy_sepolia_demo`: razporedi demo pogodbe na Sepolia.
* `evaluate`, `immunefi`, `debug_file_generator`: pomožna/legacy orodja.

---

## 16. `server_run.sh`

Zagon GUI. Vezan na `127.0.0.1`; izbere naslednja prosta vrata, če so
`4114` zasedena s **tujim** servisom; ponovno uporabi `4114`, če tam že
teče **naš** dashboard; počaka, da strežnik sprejme povezave, nato odpre
brskalnik.

---

## 17. Diagram odvisnosti Python modulov

```mermaid
graph TD
    ap[auto_pipeline.py] --> chains
    ap --> wp[wallet_policy.py]
    ap --> gu[gas_utils.py]
    ap --> go[gas_oracle.py]
    ap --> pr[proxy_resolver.py]
    ap --> fb[flashbots_bundle.py]
    ap --> sl[strategy_layer.py]
    bp[batch_pipeline.py] --> ap
    bp --> chains
    bp --> wp
    bp --> sl
    mon[monitor.py] --> chains
    mon --> wp
    mon --> gu
    ds[dashboard_server.py] --> ap
    ds --> chains
    ds --> wp
    gu --> chains
    sl -.bere plan.json.-> fs[(work_dir)]
    ap -.Popen.-> rust[Rust binarij]
    fb --> chains
```

---

## 18. Odprto / neizmerjeno

* **Nepreverjeno:** ali `dashboard_static/app.js` pokriva vse poglede —
  `test_dashboard_ui.py` to preverja, a ta dokument ne ponavlja rezultata.
* **Neizmerjeno:** število testov (232 passed v `requirements`-polnem okolju)
  ni del tega dokumenta; glej [TESTI.md](TESTI.md).
* `evaluate.py`, `immunefi.py`, `debug_file_generator.py` so pomožna orodja;
  njihova točna uporaba ni dokumentirana v kodi zunaj docstringov.
