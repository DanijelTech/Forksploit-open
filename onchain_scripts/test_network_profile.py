#!/usr/bin/env python3
# Author: DanyTech
"""test_network_profile.py -- offline proof tests for the runtime RPC
identity check (chains.verify_rpc_identity / NetworkProfile).

No network: verify_rpc_identity is given a fake `w3` whose eth.chain_id is
set to the value under test, so the mismatch/success branches are exercised
against the real function, not a reimplementation.

Run: python -m pytest onchain_scripts/test_network_profile.py -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import chains  # noqa: E402


class FakeEth:
    def __init__(self, chain_id):
        self.chain_id = chain_id


class FakeW3:
    def __init__(self, chain_id):
        self.eth = FakeEth(chain_id)


class TestNetworkProfile(unittest.TestCase):
    def test_etc_mainnet_profile(self):
        p = chains.network_profile_for_chain_name("etc")
        self.assertEqual(p.chain_id, 61)
        self.assertEqual(p.family, "etc")
        self.assertFalse(p.is_testnet)
        self.assertEqual(p.native_symbol, "ETC")
        self.assertFalse(p.supports_flashbots)

    def test_mordor_is_etc_testnet(self):
        p = chains.network_profile_for_chain_name("mordor")
        self.assertEqual(p.chain_id, 63)
        self.assertEqual(p.family, "etc")
        self.assertTrue(p.is_testnet)

    def test_eth_mainnet_profile(self):
        p = chains.network_profile_for_chain_name("eth")
        self.assertEqual(p.chain_id, 1)
        self.assertEqual(p.family, "eth")
        self.assertFalse(p.is_testnet)
        self.assertTrue(p.supports_flashbots)

    def test_sepolia_profile(self):
        p = chains.network_profile_for_chain_name("sepolia")
        self.assertTrue(p.is_testnet)
        self.assertFalse(p.supports_flashbots)

    def test_unknown_chain_raises(self):
        with self.assertRaises(KeyError):
            chains.network_profile_for_chain_name("not-a-chain")

    def test_network_family_boundaries(self):
        self.assertEqual(chains.network_family(1), "eth")
        self.assertEqual(chains.network_family(61), "etc")
        self.assertEqual(chains.network_family(63), "etc")
        self.assertEqual(chains.network_family(56), "other")


class TestVerifyRpcIdentity(unittest.TestCase):
    def test_matching_rpc_returns_profile(self):
        p = chains.verify_rpc_identity("etc", w3=FakeW3(61))
        self.assertEqual(p.chain_id, 61)
        self.assertEqual(p.family, "etc")

    def test_mismatched_rpc_aborts(self):
        # --chain etc (61) but the endpoint actually serves ETH (1).
        with self.assertRaises(SystemExit) as cm:
            chains.verify_rpc_identity("etc", w3=FakeW3(1))
        self.assertIn("identity mismatch", str(cm.exception))

    def test_eth_etc_confusion_is_caught_both_ways(self):
        with self.assertRaises(SystemExit):
            chains.verify_rpc_identity("eth", w3=FakeW3(61))
        with self.assertRaises(SystemExit):
            chains.verify_rpc_identity("etc", w3=FakeW3(1))

    def test_unknown_chain_aborts(self):
        with self.assertRaises(SystemExit):
            chains.verify_rpc_identity("nope", w3=FakeW3(1))

    def test_tee_receives_verification_line(self):
        class Tee:
            def __init__(self):
                self.lines = []

            def log(self, msg, **kw):
                self.lines.append(msg)

        tee = Tee()
        chains.verify_rpc_identity("etc", tee=tee, w3=FakeW3(61))
        self.assertTrue(any("RPC identity verified" in m for m in tee.lines))


if __name__ == "__main__":
    unittest.main()
