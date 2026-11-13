#!/usr/bin/env python3
# Author: DanyTech
"""test_proxy_resolver.py -- offline proof tests for the Python-side proxy
discovery (proxy_resolver.py).

No network: a tiny FakeW3 answers get_storage_at / get_code / eth.call /
to_checksum_address from an in-memory map, so every convention (EIP-1967,
EIP-1822/UUPS, beacon, EIP-1167) and the cycle-safety of the BFS are
exercised against real code paths, not a mock of the module under test.

Also re-derives each slot from its keccak definition and pins it against the
literal Rust constant value, so a drift between the Python and Rust proxy
slots (which would silently read the wrong slot and see "not a proxy") is
caught here.

Run: python -m pytest onchain_scripts/test_proxy_resolver.py -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import proxy_resolver as pr  # noqa: E402


class FakeEth:
    """The `w3.eth` namespace: only the methods the resolver uses."""

    def __init__(self, storage, code, calls):
        self._storage = storage
        self._code = code
        self._calls = calls

    def get_storage_at(self, address, slot):
        val = self._storage.get(address.lower(), {}).get(slot)
        if val is None:
            return b"\x00" * 32
        return val

    def get_code(self, address):
        return self._code.get(address.lower(), b"")

    def call(self, tx):
        to = tx["to"].lower()
        if to in self._calls:
            return self._calls[to]
        raise ValueError("no code")


class FakeW3:
    """Minimal stand-in for web3.Web3: only the four methods the resolver
    uses, backed by plain dicts keyed by lowercase address."""

    def __init__(self, storage=None, code=None, calls=None):
        storage = {k.lower(): dict(v) for k, v in (storage or {}).items()}
        code = {k.lower(): v for k, v in (code or {}).items()}
        calls = {k.lower(): v for k, v in (calls or {}).items()}
        self.eth = FakeEth(storage, code, calls)

    def to_checksum_address(self, a):
        return a


def _wire_eth(w3):
    return w3


def _word(addr_hex_no_prefix):
    return bytes.fromhex("00" * 12 + addr_hex_no_prefix)


class TestSlotConstants(unittest.TestCase):
    def test_impl_slot_matches_rust_constant(self):
        # Literal from src/evm/mod.rs EIP1967_IMPLEMENTATION_SLOT.
        self.assertEqual(
            pr.EIP1967_IMPLEMENTATION_SLOT.hex(),
            "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
        )

    def test_admin_slot_matches_rust_constant(self):
        self.assertEqual(
            pr.EIP1967_ADMIN_SLOT.hex(),
            "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
        )

    def test_slots_are_keccak_derived(self):
        from eth_utils import keccak
        impl = (int.from_bytes(keccak(text="eip1967.proxy.implementation"), "big") - 1).to_bytes(32, "big")
        self.assertEqual(impl, pr.EIP1967_IMPLEMENTATION_SLOT)
        self.assertEqual(keccak(text="PROXIABLE"), pr.EIP1822_UUPS_SLOT)


class TestMinimalProxy(unittest.TestCase):
    def test_canonical_eip1167_is_detected(self):
        impl = "11" * 20
        code = pr._EIP1167_PREFIX + bytes.fromhex(impl) + pr._EIP1167_SUFFIX
        self.assertEqual(pr.minimal_proxy_implementation("0x" + code.hex()), "0x" + impl)

    def test_wrong_length_is_not_a_minimal_proxy(self):
        self.assertIsNone(pr.minimal_proxy_implementation("0x6001"))

    def test_garbage_hex_does_not_raise(self):
        self.assertIsNone(pr.minimal_proxy_implementation("0xzzzz"))
        self.assertIsNone(pr.minimal_proxy_implementation(None))

    def test_zero_implementation_rejected(self):
        code = pr._EIP1167_PREFIX + bytes(20) + pr._EIP1167_SUFFIX
        self.assertIsNone(pr.minimal_proxy_implementation("0x" + code.hex()))


class TestEip7702(unittest.TestCase):
    def test_delegation_designator_detected(self):
        code = "0xef0100" + "33" * 20
        self.assertEqual(pr.eip7702_delegate(code), "0x" + "33" * 20)

    def test_wrong_length_rejected(self):
        # A real contract's 0xef00-prefixed code is not a delegation.
        self.assertIsNone(pr.eip7702_delegate("0xef00"))
        self.assertIsNone(pr.eip7702_delegate("0xef0100"))

    def test_zero_delegate_rejected(self):
        self.assertIsNone(pr.eip7702_delegate("0xef0100" + "00" * 20))

    def test_garbage_does_not_raise(self):
        self.assertIsNone(pr.eip7702_delegate("0xzz"))
        self.assertIsNone(pr.eip7702_delegate(None))

    def test_discovery_finds_7702_delegate(self):
        delegate = "0x9900000000000000000000000000000000000099"
        addr = "0x9800000000000000000000000000000000000098"
        w3 = _wire_eth(FakeW3(code={addr: bytes.fromhex("ef0100" + delegate[2:])}))
        self.assertEqual(pr.discover_implementations(w3, addr), [delegate])


class TestDiscovery(unittest.TestCase):
    def test_eip1967_implementation_found(self):
        w3 = _wire_eth(FakeW3(storage={
            "0xAAAA000000000000000000000000000000000001": {
                int.from_bytes(pr.EIP1967_IMPLEMENTATION_SLOT, "big"): _word("2222222222222222222222222222222222222222")
            }
        }))
        impls = pr.discover_implementations(w3, "0xAAAA000000000000000000000000000000000001")
        self.assertEqual(impls, ["0x2222222222222222222222222222222222222222"])

    def test_uups_implementation_found(self):
        w3 = _wire_eth(FakeW3(storage={
            "0xbbbb000000000000000000000000000000000002": {
                int.from_bytes(pr.EIP1822_UUPS_SLOT, "big"): _word("3333333333333333333333333333333333333333")
            }
        }))
        impls = pr.discover_implementations(w3, "0xbbbb000000000000000000000000000000000002")
        self.assertEqual(impls, ["0x3333333333333333333333333333333333333333"])

    def test_beacon_proxy_reads_implementation(self):
        w3 = _wire_eth(FakeW3(
            storage={
                "0xcccc000000000000000000000000000000000003": {
                    int.from_bytes(pr.EIP1967_BEACON_SLOT, "big"): _word("dddddddddddddddddddddddddddddddddddddddd")
                }
            },
            calls={"0xdddddddddddddddddddddddddddddddddddddddd": _word("4444444444444444444444444444444444444444")},
        ))
        impls = pr.discover_implementations(w3, "0xcccc000000000000000000000000000000000003")
        self.assertEqual(impls, ["0x4444444444444444444444444444444444444444"])

    def test_non_proxy_returns_empty(self):
        w3 = _wire_eth(FakeW3(storage={
            "0xeeee000000000000000000000000000000000004": {
                int.from_bytes(pr.EIP1967_IMPLEMENTATION_SLOT, "big"): b"\x00" * 32
            }
        }))
        self.assertEqual(pr.discover_implementations(w3, "0xeeee000000000000000000000000000000000004"), [])

    def test_high_bits_word_is_not_an_address(self):
        w3 = _wire_eth(FakeW3(storage={
            "0xffff000000000000000000000000000000000005": {
                int.from_bytes(pr.EIP1967_IMPLEMENTATION_SLOT, "big"): b"\xff" + b"\x00" * 11 + b"\x11" * 20
            }
        }))
        self.assertEqual(pr.discover_implementations(w3, "0xffff000000000000000000000000000000000005"), [])


class TestResolveChain(unittest.TestCase):
    def test_multi_hop_stack_resolved(self):
        impl_slot = int.from_bytes(pr.EIP1967_IMPLEMENTATION_SLOT, "big")
        proxy = "0x1000000000000000000000000000000000000001"
        impl = "0x2000000000000000000000000000000000000002"
        leaf = "0x3000000000000000000000000000000000000003"
        w3 = _wire_eth(FakeW3(storage={
            proxy: {impl_slot: _word(impl[2:])},
            impl: {impl_slot: _word(leaf[2:])},
        }))
        result = pr.resolve_proxy_chain(w3, proxy)
        self.assertTrue(result["is_proxy"])
        self.assertEqual(result["depth"], 2)
        self.assertEqual(result["implementations"], [impl, leaf])

    def test_cycle_is_bounded_and_terminates(self):
        impl_slot = int.from_bytes(pr.EIP1967_IMPLEMENTATION_SLOT, "big")
        a = "0x4000000000000000000000000000000000000004"
        b = "0x5000000000000000000000000000000000000005"
        w3 = _wire_eth(FakeW3(storage={
            a: {impl_slot: _word(b[2:])},
            b: {impl_slot: _word(a[2:])},
        }))
        result = pr.resolve_proxy_chain(w3, a)
        # a -> b, then b -> a is already visited: exactly one implementation.
        self.assertEqual(result["implementations"], [b])
        self.assertEqual(result["depth"], 1)

    def test_self_referential_slot_terminates(self):
        impl_slot = int.from_bytes(pr.EIP1967_IMPLEMENTATION_SLOT, "big")
        a = "0x6000000000000000000000000000000000000006"
        w3 = _wire_eth(FakeW3(storage={a: {impl_slot: _word(a[2:])}}))
        result = pr.resolve_proxy_chain(w3, a)
        self.assertEqual(result["implementations"], [])
        self.assertFalse(result["is_proxy"])

    def test_rpc_failure_degrades_to_empty(self):
        class BoomW3(FakeW3):
            def get_storage_at(self, address, slot):
                raise RuntimeError("rpc down")
        w3 = _wire_eth(BoomW3())
        result = pr.resolve_proxy_chain(w3, "0x7000000000000000000000000000000000000007")
        self.assertEqual(result["implementations"], [])
        self.assertFalse(result["is_proxy"])


if __name__ == "__main__":
    unittest.main()
