# Author: DanyTech
"""chains.py -- shared chain/RPC configuration for every onchain_scripts/
tool (auto_pipeline.py, monitor.py).

Previously each of those three files kept its own hardcoded RPC dict,
which could silently drift out of sync. This is now the single source of
truth, with a small persisted override file (rpc_overrides.json,
gitignored like wallets.json/contracts.json) so a user can point any
chain at their own RPC endpoint (a paid/rate-limit-friendly one, a local
anvil fork, ...) without editing code.
"""
import dataclasses
import json
from pathlib import Path

HERE = Path(__file__).parent
OVERRIDES_FILE = HERE / "rpc_overrides.json"

# Defaults -- only the chains forksploit itself supports via -c/--chain-type
# (see src/evm/onchain/endpoints.rs) are listed here. TESTNET_CHAINS marks
# which of these are safe to deploy/fund/execute (anything that SIGNS a
# transaction) against without real-money consequences; callers should
# confirm explicitly before doing so on anything not in this set.
DEFAULT_RPC = {
    "sepolia": "https://ethereum-sepolia.publicnode.com",
    # Verified live 2026-11-01: eth.merkle.io (previous default) actively
    # rate-limits anonymous requests ("Rate limit exceeded" on
    # eth_chainId, reproduced after a 5s pause, not a cold-start fluke).
    # publicnode's Ethereum endpoint is free, no key required. Mirrors
    # the matching fix in src/evm/onchain/endpoints.rs.
    "eth": "https://ethereum-rpc.publicnode.com",
    "bsc": "https://bsc-rpc.publicnode.com",
    # Verified live 2026-10-28: polygon.llamarpc.com (previous default)
    # fails DNS resolution entirely; this publicnode endpoint is free,
    # no key required, confirmed serving real eth_call results. Mirrors
    # the matching fix in src/evm/onchain/endpoints.rs.
    "polygon": "https://polygon-bor-rpc.publicnode.com",
    # Verified live 2026-10-28: rpc.ankr.com/arbitrum (previous default)
    # now requires a paid API key ("Unauthorized" for anonymous
    # requests). Arbitrum's own official public RPC needs no key.
    # Mirrors the matching fix in src/evm/onchain/endpoints.rs.
    "arbitrum": "https://arb1.arbitrum.io/rpc",
    # Verified live 2026-10-28: rpc.ankr.com/optimism (previous default)
    # also requires a paid API key now, same as arbitrum's did. Optimism's
    # own official public RPC needs no key. NOTE: an earlier version of
    # this comment claimed this "mirrors the matching fix in
    # src/evm/onchain/endpoints.rs", but that Rust-side fix was never
    # actually applied until 2026-11-01 -- only this Python default was
    # ever updated, so the Rust binary's own default optimism RPC was
    # silently broken (API-key-required) the whole time. Don't trust a
    # "mirrors the other side" comment without checking the other side.
    "optimism": "https://mainnet.optimism.io",
    # Verified live 2026-11-01: developer-access-mainnet.base.org (previous
    # default) fails DNS resolution entirely -- dead/decommissioned, not a
    # rate limit. Base's own official public RPC needs no key. Mirrors
    # the matching fix in src/evm/onchain/endpoints.rs.
    "base": "https://mainnet.base.org",
    # Verified live 2026-10-28 (returns chain id 0x3d = 61; reliably serves
    # state at a pinned recent block, unlike drpc.org which was tried
    # first -- see the matching comment in src/evm/onchain/endpoints.rs).
    # No Etherscan coverage -- ABI fetching on the Rust side routes through
    # Blockscout (etc.blockscout.com) instead, see is_blockscout_api() in
    # src/evm/onchain/endpoints.rs.
    "etc": "https://geth-at.etc-network.info",
    # The 10 entries below were simply missing until now -- this dict only
    # ever had 8 of the 23 chains src/evm/onchain/endpoints.rs's Chain enum
    # supports, so e.g. --chain fantom raised KeyError in every
    # onchain_scripts/ tool despite the Rust binary itself supporting it
    # fine. All verified live 2026-10-28 (real eth_chainId response
    # matching the chain's real id, no key required). GOERLI, MUMBAI, and
    # ZKEVM_TESTNET are deliberately NOT added -- confirmed live that all
    # three are now dead/decommissioned testnets with no working public
    # RPC left (Goerli and Mumbai were officially sunset; the old zkEVM
    # testnet -- chain id 1442 -- was superseded by Cardona, a different
    # chain id); adding a non-working URL for a dead network isn't a real
    # fix.
    "avalanche": "https://api.avax.network/ext/bc/C/rpc",
    "fantom": "https://rpc.fantom.network",
    "gnosis": "https://rpc.gnosischain.com",
    "celo": "https://forno.celo.org",
    "scroll": "https://rpc.scroll.io",
    "blast": "https://rpc.blast.io",
    "linea": "https://rpc.linea.build",
    "iotex": "https://babel-api.mainnet.iotex.io",
    "vana": "https://rpc.vana.org",
    "story": "https://mainnet.storyrpc.io",
    "zkevm": "https://zkevm-rpc.com",
    # Testnet -- see TESTNET_CHAINS below.
    "chapel": "https://bsc-testnet-rpc.publicnode.com",
    # Mordor: ETC's real, live testnet (chain id 63 -- not the separate,
    # deprecated "Morden" testnet, chain id 62). Was missing entirely
    # until now, even though ETC mainnet itself was already supported --
    # meaning there was no way to test/fund anything ETC-shaped without
    # using real ETC. Verified live 2026-10-29 (eth_chainId == 0x3f,
    # eth_blockNumber a real, current, advancing block). Mirrors the
    # matching addition in src/evm/onchain/endpoints.rs.
    "mordor": "https://rpc.mordor.etccooperative.org",
}
# Chains safe to deploy/fund/execute (anything that SIGNS a transaction)
# against without real-money consequences. Enforced by
# require_mainnet_confirmation() below -- every onchain_scripts/ tool that
# signs transactions must call it right after parsing --chain, before
# touching a wallet or sending anything.
TESTNET_CHAINS = {"sepolia", "chapel", "mordor"}

# Ported directly from src/evm/onchain/endpoints.rs's Chain::get_chain_id()
# (the authoritative source -- not re-derived/guessed here) so Python side
# tools (currently: dashboard_server.py's live network-identity check) can
# verify a configured --chain name against the REAL chain ID an RPC
# endpoint actually answers with, the same "never trust the name alone"
# discipline chain_banner()/require_mainnet_confirmation() already apply
# elsewhere in this file. Keep in sync with that Rust match if it changes.
CHAIN_IDS = {
    "eth": 1, "goerli": 5, "sepolia": 11155111, "bsc": 56, "chapel": 97,
    "polygon": 137, "mumbai": 80001, "fantom": 250, "avalanche": 43114,
    "optimism": 10, "arbitrum": 42161, "gnosis": 100, "base": 8453,
    "celo": 42220, "zkevm": 1101, "zkevm_testnet": 1442, "blast": 81457,
    "linea": 59144, "iotex": 4689, "scroll": 534352, "vana": 1480,
    "story": 1514, "etc": 61, "mordor": 63, "local": 31337,
}

# Moved here from aave_flashloan_runner.py (2026-11-02) so auto_pipeline.py
# can read it too without a circular import (aave_flashloan_runner.py
# already imports from auto_pipeline.py). Every address below was taken
# from the official bgd-labs/aave-address-book repo and live-verified
# (real, non-trivial bytecode at that address on that chain, confirmed via
# eth_getCode) before being added -- the same discipline used for
# src/evm/tokens/aave_transformer.rs's own table, after a pasted address
# list for that file turned out to be entirely wrong. A chain not listed
# here simply isn't supported yet -- an honest gap, not a silent reuse of
# another chain's address. ETC/Mordor are deliberately absent: Aave does
# not exist on Ethereum Classic at all (verified against official Aave
# docs and directly on-chain), not merely "not yet added" here.
AAVE_V3_POOLS = {
    "sepolia": "0x6Ae43d3271ff6888e7Fc43Fd7321a503ff738951",
    "eth": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
    "polygon": "0x794a61358D6845594F94dc1DB02A252b5b4814aD",
    "arbitrum": "0x794a61358D6845594F94dc1DB02A252b5b4814aD",
    "optimism": "0x794a61358D6845594F94dc1DB02A252b5b4814aD",
    "avalanche": "0x794a61358D6845594F94dc1DB02A252b5b4814aD",
    "base": "0xA238Dd80C259a72e81d7e4664a9801593F98d1c5",
    "gnosis": "0xb50201558B00496A145fE76f7424749556E326D8",
    "scroll": "0x11fCfe756c05AD438e312a7fd934381537D3cFfe",
    "bsc": "0x6807dc923806fE8Fd134338EABCA509979a7e0cB",
}

# The wrapped-native-token reserve for each AAVE_V3_POOLS chain -- the
# ONLY asset a flashloan can usefully fund a plain ETH-value exploit
# plan with, since unwrapping it (WETH9-style `withdraw(uint256)`) is
# the one way to turn a borrowed ERC20 into real native currency
# AttackWallet.execute() can forward as msg.value. Deliberately scoped to
# ONLY the chains this project's own wallet_policy/skill workflow
# actually targets (eth, sepolia) -- NOT filled in by guessing a
# wrapped-native address for every AAVE_V3_POOLS chain from memory, per
# this file's own address-table discipline above. Each entry below was
# live-verified on 2026-11-02 by calling the real Aave V3 Pool's own
# getReservesList() and then symbol() on each returned reserve until one
# answered "WETH" -- not pasted from memory, not reused from any other
# project file. A chain missing here needs the same live lookup before
# being added, not a guess.
WETH_ADDRESSES = {
    "eth": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    "sepolia": "0xC558dBdd856501FCd9aaF1E62eae57A9F0629a3C",
}


# Ethereum (ETH) and Ethereum Classic (ETC) are one letter apart and
# BOTH real mainnets that pass the exact same --confirm-mainnet gate --
# nothing else in this codebase would catch a typo'd --chain between
# them (unlike, say, typo-ing a wallet address, which wallet_policy.py's
# own per-chain registry would reject outright). Spelled out loudly and
# unconditionally in require_mainnet_confirmation below specifically
# because of that, not for every chain equally.
_CHAIN_DISPLAY_NAMES = {
    "eth": "ETHEREUM (ETH) mainnet -- this is NOT Ethereum Classic (ETC)",
    "etc": "ETHEREUM CLASSIC (ETC) mainnet -- this is NOT Ethereum (ETH)",
    "sepolia": "Sepolia (an ETH testnet)",
    "mordor": "Mordor (an ETC testnet)",
}

# Short, human-friendly names for the interactive chain menu (forksploit.sh).
# Kept separate from _CHAIN_DISPLAY_NAMES above: that one is the long,
# unambiguous form used where the ETH/ETC mix-up actually matters (the final
# run summary), while this is a plain label a first-time user can scan at a
# glance. A chain missing here falls back to its own name.
CHAIN_TITLES = {
    "sepolia": "Sepolia",
    "mordor": "Mordor",
    "chapel": "Chapel",
    "eth": "Ethereum",
    "etc": "Ethereum Classic",
    "bsc": "BNB Chain",
    "polygon": "Polygon",
    "arbitrum": "Arbitrum",
    "optimism": "Optimism",
    "base": "Base",
    "avalanche": "Avalanche",
    "fantom": "Fantom",
    "gnosis": "Gnosis",
    "celo": "Celo",
    "scroll": "Scroll",
    "blast": "Blast",
    "linea": "Linea",
    "iotex": "IoTeX",
    "vana": "Vana",
    "story": "Story",
    "zkevm": "Polygon zkEVM",
}


# Found live 2026-11-02 (user noticed ETC-mainnet run logs literally
# saying "ETH"): every log line across auto_pipeline.py/batch_pipeline.py/
# aave_flashloan_runner.py/gas_utils.py hardcoded the unit suffix " ETH"
# after w3.from_wei(..., 'ether'), regardless of which chain was actually
# selected -- so a real ETC-mainnet run's own logs described ETC balances
# as "ETH". Exactly the ETH/ETC mix-up this file's own chain_banner()/
# require_mainnet_confirmation() exist to prevent, just in the log text
# instead of the chain-selection gate. Ticker, not full name (unlike
# _CHAIN_DISPLAY_NAMES above) -- this is for inline amounts like
# "0.5 {symbol}", not a banner line. A chain missing here falls back to
# "ETH" (web3.py's from_wei('ether') unit is literally Ethereum's, so that
# fallback is the least-wrong default for an unlisted EVM chain) rather
# than raising, since this is a log label, not a trust boundary.
NATIVE_SYMBOL = {
    "eth": "ETH", "goerli": "ETH", "sepolia": "ETH",
    "etc": "ETC", "mordor": "ETC",
    "bsc": "BNB", "chapel": "BNB",
    "polygon": "POL", "mumbai": "MATIC",
    "fantom": "FTM", "avalanche": "AVAX",
    "optimism": "ETH", "arbitrum": "ETH", "base": "ETH",
    "gnosis": "xDAI", "celo": "CELO",
    "zkevm": "ETH", "zkevm_testnet": "ETH", "blast": "ETH", "linea": "ETH",
    "scroll": "ETH", "iotex": "IOTX", "vana": "VANA", "story": "IP",
    "local": "ETH",
}


def native_symbol(chain: str) -> str:
    return NATIVE_SYMBOL.get(chain, "ETH")


# Reverse lookup by REAL chain id rather than the (possibly-wrong,
# possibly-absent) --chain string: every call site that logs an amount
# already has a connected `w3`, and w3.eth.chain_id reflects what the RPC
# endpoint is ACTUALLY serving right now, the same "never trust the name
# alone" discipline chain_banner()/require_mainnet_confirmation() apply to
# chain SELECTION -- here applied to chain DISPLAY instead, so no function
# signature anywhere needs its own extra `chain` parameter threaded
# through just to label a log line correctly.
_SYMBOL_BY_CHAIN_ID = {CHAIN_IDS[c]: NATIVE_SYMBOL.get(c, "ETH") for c in CHAIN_IDS}


def native_symbol_for_w3(w3) -> str:
    return _SYMBOL_BY_CHAIN_ID.get(w3.eth.chain_id, "ETH")


# Reverse map: REAL chain id -> canonical chain name, built from CHAIN_IDS
# (the authoritative table). Used to turn an RPC's own eth_chainId back into
# a name, so nothing has to trust the operator's --chain string to decide
# which network is actually connected.
_CHAIN_NAME_BY_ID: dict = {}
for _name, _cid in CHAIN_IDS.items():
    _CHAIN_NAME_BY_ID.setdefault(_cid, _name)


@dataclasses.dataclass(frozen=True)
class NetworkProfile:
    """What a connected RPC endpoint ACTUALLY is, resolved from its own
    eth_chainId rather than from the --chain name the operator typed.

    Every mechanism that behaves differently per network (bundle relay,
    mempool-privacy redirect, native-token label, mainnet confirmation)
    should read THIS instead of the raw --chain string, so a typo'd or
    stale --chain can never make a run apply the wrong chain's behaviour
    -- exactly the ETH/ETC mix-up this file's require_mainnet_confirmation
    already guards against, but for the whole run's mechanics rather than
    just the signing gate."""

    chain: str            # canonical name for the detected chain id
    chain_id: int
    family: str           # "eth" | "etc" | "other"
    is_testnet: bool
    native_symbol: str
    supports_flashbots: bool

    def describe(self) -> str:
        kind = "testnet" if self.is_testnet else "mainnet"
        return (
            f"{self.chain} (chain id {self.chain_id}, {self.family.upper()} {kind}, "
            f"native {self.native_symbol})"
        )


def chain_name_for_id(chain_id: int) -> "str | None":
    return _CHAIN_NAME_BY_ID.get(chain_id)


def network_family(chain_id: int) -> str:
    """Which of the two networks this project is centred on a given chain id
    belongs to -- Ethereum (1) vs Ethereum Classic (61 mainnet, 63 Mordor).
    One letter apart in every table, so this is deliberately its own named
    function rather than an inline comparison scattered around."""
    if chain_id == 1:
        return "eth"
    if chain_id in (61, 63):
        return "etc"
    return "other"


def _profile_from_id(chain_id: int) -> NetworkProfile:
    name = _CHAIN_NAME_BY_ID.get(chain_id)
    return NetworkProfile(
        chain=name or f"chain-{chain_id}",
        chain_id=chain_id,
        family=network_family(chain_id),
        is_testnet=(name in TESTNET_CHAINS) if name else False,
        native_symbol=_SYMBOL_BY_CHAIN_ID.get(chain_id, "ETH"),
        # Flashbots' auction is genuinely ETH-mainnet-only (see
        # auto_pipeline.py's own note): keyed on the real chain id, never
        # the name.
        supports_flashbots=(chain_id == 1),
    )


def network_profile_for_chain_name(chain: str) -> NetworkProfile:
    """Offline profile for a --chain NAME, with no RPC call -- the fallback
    for callers (and tests) that only have the name. A live run should
    prefer verify_rpc_identity()'s profile, which is derived from what the
    endpoint actually serves."""
    expected = CHAIN_IDS.get(chain)
    if expected is None:
        raise KeyError(f"unknown chain {chain!r} -- known chains: {', '.join(known_chains())}")
    return _profile_from_id(expected)


def verify_rpc_identity(chain: str, tee=None, w3=None) -> NetworkProfile:
    """Resolve what the configured RPC for `chain` REALLY is and refuse to
    continue on any mismatch.

    This is the runtime counterpart to require_mainnet_confirmation(): that
    gate checks the NAME is one that is safe to sign against; this one
    checks the ENDPOINT actually serves that name. Together they close the
    'eth' vs 'etc' hole from both ends -- a wrong name on a right RPC, and
    a right name on a wrong RPC (a stale rpc_overrides.json entry, a typo'd
    custom URL) -- before a single signature is produced, instead of
    discovering it from a wrong-chain broadcast. Returns the detected
    NetworkProfile so callers can adapt their mechanisms to it.

    `w3` lets a caller that already has a connected Web3 for this chain
    reuse it instead of opening a second connection.
    """
    expected = CHAIN_IDS.get(chain)
    if expected is None:
        raise SystemExit(
            f"unknown chain {chain!r} -- known chains: {', '.join(known_chains())}"
        )
    try:
        if w3 is None:
            w3 = make_w3(chain)
        actual = w3.eth.chain_id
    except Exception as e:
        raise SystemExit(
            f"cannot reach the configured RPC for '{chain}' to verify its identity: {e}"
        )
    if actual != expected:
        actual_name = _CHAIN_NAME_BY_ID.get(actual, f"chain id {actual}")
        raise SystemExit(
            f"RPC identity mismatch: --chain '{chain}' expects chain id {expected}, but the configured "
            f"RPC {get_rpc_url(chain)} is actually serving {actual_name} (chain id {actual}). Refusing to "
            "sign anything until --chain and the RPC agree -- 'eth' and 'etc' are one letter apart and "
            "both real mainnets. Fix --chain, or clear/fix the rpc_overrides.json entry, and re-run."
        )
    profile = _profile_from_id(actual)
    line = f"RPC identity verified: {profile.describe()}"
    if tee is not None:
        tee.log(line)
    else:
        print(line)
    return profile


def chain_banner(chain: str) -> str:
    return _CHAIN_DISPLAY_NAMES.get(chain, f"'{chain}'")


def chain_title(chain: str) -> str:
    """Short, plain-language name for the interactive menu."""
    return CHAIN_TITLES.get(chain, chain)


def require_mainnet_confirmation(chain: str, confirmed: bool, tee=None) -> None:
    """Call this immediately after parsing --chain, before any signing
    happens. Raises SystemExit with a clear message if `chain` is not a
    known testnet and the caller didn't pass --confirm-mainnet (or
    equivalent) to explicitly acknowledge that real funds are at stake.

    This existed only as an unenforced convention (a comment on
    TESTNET_CHAINS, and before that an interactive prompt in the now-removed
    tui.py) until this was wired up for real -- worth being strict about it
    now that Ethereum Classic (a real, non-testnet chain) is reachable here
    too.

    Also always prints (not just logs through `tee`, which usually
    doesn't exist yet this early -- every current call site calls this
    before creating its own Tee) which chain was actually selected,
    spelled out via chain_banner() above -- the whole reason this
    function exists is already "the first thing called right after
    parsing --chain", which makes it the earliest possible point to
    surface a --chain typo, before a wallet is even loaded.
    """
    print(f"Chain selected: {chain_banner(chain)}")
    if tee is not None:
        tee.log(f"Chain selected: {chain_banner(chain)}")
    if chain in TESTNET_CHAINS or confirmed:
        return
    message = (
        f"Refusing to sign transactions on '{chain}': it is not in TESTNET_CHAINS "
        f"({', '.join(sorted(TESTNET_CHAINS))}), so this is a real network with real value at "
        f"stake. Re-run with --confirm-mainnet if you genuinely mean to fund/deploy/execute "
        f"against '{chain}'."
    )
    if tee is not None:
        tee.log(f"ERROR: {message}")
    raise SystemExit(message)


def _load_overrides() -> dict:
    if not OVERRIDES_FILE.exists():
        return {}
    try:
        return json.loads(OVERRIDES_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def known_chains() -> list:
    """All chain names usable right now: every default plus any chain a
    user has only ever added via an override (no built-in default)."""
    return sorted(set(DEFAULT_RPC) | set(_load_overrides()))


def make_w3(chain: str) -> "Web3":
    """Builds a Web3 instance for `chain`, with the POA extraData
    middleware always injected. Several supported chains (BSC and its
    Chapel testnet, Polygon's Bor, others) are POA/IBFT-style and put
    more than the standard 32 bytes in a block header's `extraData` --
    without this, ANY call that fetches a full block (e.g. monitor.py's
    block-scanning loop) throws `ExtraDataLengthError` on those chains,
    confirmed live when this was first hit on BSC. The middleware is a
    permissive pass-through on non-POA chains (their extraData is always
    <=32 bytes already), so injecting it unconditionally here is safe
    everywhere rather than needing a hand-maintained "which chains are
    POA" list that would only ever be a guess and go stale."""
    from web3 import Web3
    from web3.middleware import ExtraDataToPOAMiddleware

    w3 = Web3(Web3.HTTPProvider(get_rpc_url(chain)))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return w3


def get_rpc_url(chain: str) -> str:
    overrides = _load_overrides()
    if chain in overrides:
        return overrides[chain]
    if chain in DEFAULT_RPC:
        return DEFAULT_RPC[chain]
    raise KeyError(f"unknown chain {chain!r} -- known chains: {', '.join(known_chains())}")


def set_rpc_override(chain: str, url: str) -> None:
    overrides = _load_overrides()
    overrides[chain] = url
    OVERRIDES_FILE.write_text(json.dumps(overrides, indent=2))


def clear_rpc_override(chain: str) -> bool:
    """Removes a chain's override, reverting it to the built-in default
    (or removing it entirely if it only ever existed as an override).
    Returns whether there was anything to clear."""
    overrides = _load_overrides()
    if chain not in overrides:
        return False
    del overrides[chain]
    OVERRIDES_FILE.write_text(json.dumps(overrides, indent=2))
    return True
