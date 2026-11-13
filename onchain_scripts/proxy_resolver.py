#!/usr/bin/env python3
"""proxy_resolver.py -- discover a target's proxy stack over RPC, from the
Python side, so the execution pipeline can fuzz and exploit the
IMPLEMENTATION of a proxy target and not just the proxy's tiny dispatcher.

The Rust layer already resolves proxies for the `--target <address>` path
(ContractLoader::expand_proxy_targets in src/evm/contract_utils.rs). This
module is the Python-side counterpart for the address/verification flow and
the dashboard, and is deliberately kept to the SAME conventions so the two
layers never disagree about what a target's implementation is:

  1. EIP-1967 -- implementation slot, and (for a beacon proxy) the beacon
     slot whose contract's `implementation()` is read next.
  2. EIP-1167 minimal proxy -- the 45-byte runtime that hardcodes the
     implementation as a PUSH20.
  3. EIP-1822 (UUPS) -- the `keccak256("PROXIABLE")` slot.
  4. EIP-7702 -- the `0xef0100 || delegate` delegation designator an EOA
     sets under Pectra (May 2025); functionally the same shape as the
     others (an account whose code forwards to another contract).

The slot constants are RE-DERIVED here from their keccak definitions (not
pasted), and test_proxy_resolver.py re-checks them against the Rust
constants' own values so a future drift is caught by a test rather than by
silently reading the wrong slot (a wrong slot read returns 0, which is
indistinguishable from "not a proxy").

Every RPC call is best-effort: any failure yields "no implementation found
here" rather than raising, so a proxy discovery problem degrades to fuzzing
the address the user named -- it never crashes a run.
"""
from typing import Optional

from eth_utils import keccak


def _slot(definition: str, minus_one: bool = True) -> bytes:
    h = keccak(text=definition)
    if minus_one:
        h = (int.from_bytes(h, "big") - 1).to_bytes(32, "big")
    return h


# EIP-1967: keccak256(name) - 1.
EIP1967_IMPLEMENTATION_SLOT = _slot("eip1967.proxy.implementation")
EIP1967_BEACON_SLOT = _slot("eip1967.proxy.beacon")
EIP1967_ADMIN_SLOT = _slot("eip1967.proxy.admin")
# EIP-1822 (UUPS): the "PROXIABLE" slot, NOT decremented.
EIP1822_UUPS_SLOT = _slot("PROXIABLE", minus_one=False)

# implementation() -- read on a beacon contract to get the impl it serves.
BEACON_IMPLEMENTATION_SELECTOR = keccak(text="implementation()")[:4]

# The canonical EIP-1167 minimal-proxy runtime, split around the embedded
# 20-byte implementation address (matches src/evm/contract_utils.rs's own
# minimal_proxy_implementation byte-for-byte).
_EIP1167_PREFIX = bytes.fromhex("363d3d373d3d3d363d73")
_EIP1167_SUFFIX = bytes.fromhex("5af43d82803e903d91602b57fd5bf3")

# EIP-7702 (Pectra, May 2025): an EOA that has delegated its code sets its
# account code to exactly `0xef0100 || <20-byte delegate>`, 23 bytes total.
# This is the newest, previously-uncovered delegation surface -- an EOA
# "becomes" a proxy whose implementation is the delegated contract, so it
# belongs in the SAME resolution path as the other proxy conventions.
EIP7702_DELEGATION_PREFIX = bytes.fromhex("ef0100")


def _address_from_word(word: bytes) -> Optional[str]:
    """A storage word holds an address in its low 20 bytes; anything with
    high bits set is ordinary data, not a pointer (same rule as the Rust
    slot_value_to_address)."""
    if len(word) != 32 or word == b"\x00" * 32:
        return None
    if word[:12] != b"\x00" * 12:
        return None
    return "0x" + word[12:].hex()


def minimal_proxy_implementation(code_hex: str) -> Optional[str]:
    """Detect the canonical EIP-1167 minimal-proxy runtime and return the
    implementation it hardcodes. Pure -- no RPC. None when `code_hex` isn't
    exactly that runtime."""
    try:
        code = bytes.fromhex(code_hex[2:] if code_hex.startswith("0x") else code_hex)
    except (ValueError, TypeError, AttributeError):
        return None
    if len(code) != len(_EIP1167_PREFIX) + 20 + len(_EIP1167_SUFFIX):
        return None
    if code[: len(_EIP1167_PREFIX)] != _EIP1167_PREFIX:
        return None
    if code[len(_EIP1167_PREFIX) + 20:] != _EIP1167_SUFFIX:
        return None
    impl = "0x" + code[len(_EIP1167_PREFIX):len(_EIP1167_PREFIX) + 20].hex()
    return None if impl == "0x" + "00" * 20 else impl


def eip7702_delegate(code_hex: str) -> Optional[str]:
    """Detect an EIP-7702 delegation designator (`0xef0100 || delegate`) and
    return the delegated contract address. Pure -- no RPC. None when
    `code_hex` is not exactly a 23-byte delegation designator."""
    try:
        code = bytes.fromhex(code_hex[2:] if code_hex.startswith("0x") else code_hex)
    except (ValueError, TypeError, AttributeError):
        return None
    if len(code) != 3 + 20 or code[:3] != EIP7702_DELEGATION_PREFIX:
        return None
    delegate = "0x" + code[3:].hex()
    return None if delegate == "0x" + "00" * 20 else delegate


def _read_slot_address(w3, address: str, slot: bytes) -> Optional[str]:
    try:
        word = w3.eth.get_storage_at(w3.to_checksum_address(address), int.from_bytes(slot, "big"))
    except Exception:
        return None
    if isinstance(word, int):
        word = word.to_bytes(32, "big")
    elif isinstance(word, (bytes, bytearray)):
        word = bytes(word)
        if len(word) < 32:
            word = word.rjust(32, b"\x00")
    else:
        return None
    return _address_from_word(word)


def _call_implementation(w3, beacon: str, selector: bytes = BEACON_IMPLEMENTATION_SELECTOR) -> Optional[str]:
    try:
        ret = w3.eth.call({"to": w3.to_checksum_address(beacon), "data": "0x" + selector.hex()})
    except Exception:
        return None
    if isinstance(ret, (bytes, bytearray)) and len(ret) >= 32:
        return _address_from_word(bytes(ret)[-32:])
    return None


def discover_implementations(w3, address: str) -> list:
    """Every implementation `address` currently points at, across all three
    recognized conventions. Empty when it isn't a recognized proxy. Order:
    EIP-1967 impl, UUPS impl, beacon impl, EIP-1167 impl (deduped)."""
    impls = []
    for slot in (EIP1967_IMPLEMENTATION_SLOT, EIP1822_UUPS_SLOT):
        a = _read_slot_address(w3, address, slot)
        if a:
            impls.append(a)

    beacon = _read_slot_address(w3, address, EIP1967_BEACON_SLOT)
    if beacon:
        impl = _call_implementation(w3, beacon)
        if impl:
            impls.append(impl)

    try:
        code = w3.eth.get_code(w3.to_checksum_address(address))
        code_hex = code.hex() if isinstance(code, (bytes, bytearray)) else str(code)
    except Exception:
        code_hex = ""
    if code_hex:
        a = minimal_proxy_implementation(code_hex)
        if a:
            impls.append(a)
        # EIP-7702 delegation designator: an EOA delegating to a contract.
        a = eip7702_delegate(code_hex)
        if a:
            impls.append(a)

    out, seen = [], set()
    for a in impls:
        key = a.lower()
        if a == "0x" + "00" * 20 or key in seen:
            continue
        seen.add(key)
        out.append(w3.to_checksum_address(a) if _looks_like_address(a) else a)
    return out


def _looks_like_address(a: str) -> bool:
    return isinstance(a, str) and a.startswith("0x") and len(a) == 42


def resolve_proxy_chain(w3, address: str, max_hops: int = 8) -> dict:
    """Bounded BFS from `address` over `discover_implementations`, so a
    proxy -> proxy -> implementation stack is fully resolved. Returns:

        {"target": <checksummed address>,
         "implementations": [<checksummed addr>, ...],   # BFS order, target excluded
         "depth": <int>,                                 # longest chain length
         "is_proxy": <bool>}

    Bounded by `max_hops` and a visited set, so a self-referential or cyclic
    proxy stack can never spin this into an unbounded walk (same discipline
    as the Rust expand_proxy_targets)."""
    target = w3.to_checksum_address(address)
    visited = {target.lower()}
    implementations = []
    depth = 0
    frontier = [target]
    hops = 0
    while frontier and hops < max_hops:
        next_frontier = []
        for addr in frontier:
            for impl in discover_implementations(w3, addr):
                key = impl.lower()
                if key in visited:
                    continue
                visited.add(key)
                implementations.append(impl)
                next_frontier.append(impl)
        if next_frontier:
            depth += 1
        frontier = next_frontier
        hops += 1
    return {
        "target": target,
        "implementations": implementations,
        "depth": depth,
        "is_proxy": bool(implementations),
    }
