#!/usr/bin/env python3
"""test_send_call_reprice.py -- a send at a nonce that already holds an
un-mined tx is repriced, so geth accepts it as a replacement instead of
rejecting it as "replacement transaction underpriced".

Without this, one tx stuck in the mempool (see gas_utils.MAX_GAS_LIMIT) made
EVERY later send at that nonce fail, so the run could never make progress
again even after the gas-limit fix.

No network: a fake Web3 records the signed raw tx so the test can decode the
gas price it was actually signed with.

Run: python -m unittest onchain_scripts/test_send_call_reprice.py -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from eth_account import Account  # noqa: E402
from web3 import Web3  # noqa: E402
from web3.datastructures import AttributeDict  # noqa: E402

import gas_oracle  # noqa: E402
import auto_pipeline  # noqa: E402


class _FakeEth:
    chain_id = 61
    gas_price = 1_000_000_000

    def __init__(self, pending_count=None, reject_underpriced_times=0):
        self.sent_raw = []
        self._pending_count = pending_count
        self._reject_underpriced_times = reject_underpriced_times
        self.send_attempts = 0

    def get_block(self, which):
        return {"number": 1, "gasLimit": 8_000_000}

    def get_transaction_count(self, addr, block="latest"):
        # `pending` reports an un-mined tx left by an EARLIER run.
        if block == "pending" and self._pending_count is not None:
            return self._pending_count
        return 0

    def estimate_gas(self, tx):
        return 100_000

    def call(self, tx):
        return b"\x00" * 32

    def send_raw_transaction(self, raw):
        self.send_attempts += 1
        if self.send_attempts <= self._reject_underpriced_times:
            raise ValueError("replacement transaction underpriced")
        self.sent_raw.append(raw)
        return b"\xab" * 32

    def wait_for_transaction_receipt(self, tx_hash, timeout=None):
        return AttributeDict({"gasUsed": 100_000, "effectiveGasPrice": self.gas_price,
                              "status": 1, "contractAddress": None})


class _FakeW3:
    def __init__(self, pending_count=None, reject_underpriced_times=0):
        self.eth = _FakeEth(pending_count, reject_underpriced_times)

    from_wei = staticmethod(Web3.from_wei)
    to_wei = staticmethod(Web3.to_wei)
    to_checksum_address = staticmethod(Web3.to_checksum_address)


class _Tee:
    def __init__(self):
        self.lines = []

    def log(self, msg, alert=False):
        self.lines.append(str(msg))


def _signed_gas_price(raw) -> int:
    """The gasPrice a legacy tx was actually signed with, read back from its
    own signature -- not from anything the code under test reports."""
    from eth_account._utils.legacy_transactions import Transaction
    return Transaction.from_bytes(raw).gasPrice


class SendCallRepriceTest(unittest.TestCase):
    def setUp(self):
        gas_oracle.set_enabled(False)

    def tearDown(self):
        gas_oracle.set_enabled(True)

    def _send(self, nonce_box, pending_count=None, reject_underpriced_times=0):
        w3 = _FakeW3(pending_count, reject_underpriced_times)
        acct = Account.from_key("0x" + "11" * 32)
        tee = _Tee()
        ok = auto_pipeline.send_call(
            w3, acct, nonce_box, "0x" + "22" * 20, b"", tee, "step", value=0,
        )
        self.assertTrue(ok)
        return w3, tee

    def test_first_send_uses_node_price(self):
        nonce_box = {"nonce": 5}
        w3, _ = self._send(nonce_box)
        self.assertEqual(len(w3.eth.sent_raw), 1)
        self.assertEqual(_signed_gas_price(w3.eth.sent_raw[0]), _FakeEth.gas_price)
        self.assertNotIn("stuck_nonce", nonce_box)

    def test_stuck_nonce_send_is_repriced_higher(self):
        # After a TimeExhausted, nonce_box carries stuck_nonce; the next send
        # at that nonce must be signed with a strictly higher price.
        nonce_box = {"nonce": 5, "stuck_nonce": 5}
        w3, tee = self._send(nonce_box)
        price = _signed_gas_price(w3.eth.sent_raw[0])
        self.assertGreater(price, _FakeEth.gas_price)
        self.assertTrue(any("repricing" in line for line in tee.lines))

    def test_pending_tx_from_earlier_run_is_repriced(self):
        # nonce_box has NO stuck_nonce (fresh process, like a re-run after a
        # crash), but the node reports a pending tx at this nonce -- left by
        # an earlier run. Must still reprice, or geth rejects every send.
        nonce_box = {"nonce": 164}
        w3, tee = self._send(nonce_box, pending_count=165)
        price = _signed_gas_price(w3.eth.sent_raw[0])
        self.assertGreater(price, _FakeEth.gas_price)
        self.assertTrue(any("repricing" in line for line in tee.lines))

    def test_no_pending_tx_is_not_repriced(self):
        # Node's pending count equals our nonce: nothing stuck, no bump.
        nonce_box = {"nonce": 164}
        w3, tee = self._send(nonce_box, pending_count=164)
        self.assertEqual(_signed_gas_price(w3.eth.sent_raw[0]), _FakeEth.gas_price)
        self.assertFalse(any("repricing" in line for line in tee.lines))

    def test_underpriced_rejection_is_retried_higher(self):
        # Node rejects the first send as an underpriced replacement (market
        # price dropped since the stuck tx). The retry must be signed higher
        # and succeed -- never surface as a crash.
        nonce_box = {"nonce": 164}
        w3, tee = self._send(nonce_box, pending_count=165, reject_underpriced_times=1)
        self.assertEqual(w3.eth.send_attempts, 2)
        self.assertGreater(_signed_gas_price(w3.eth.sent_raw[0]), _FakeEth.gas_price)
        self.assertTrue(any("underpriced" in line for line in tee.lines))

    def test_underpriced_rejection_beyond_retry_limit_raises(self):
        # More rejections than REPLACEMENT_MAX_ATTEMPTS: the caller must see
        # the real error, not an infinite retry.
        nonce_box = {"nonce": 164}
        w3 = _FakeW3(pending_count=165, reject_underpriced_times=99)
        acct = Account.from_key("0x" + "11" * 32)
        with self.assertRaises(Exception):
            auto_pipeline.send_call(w3, acct, nonce_box, "0x" + "22" * 20, b"", _Tee(), "step", value=0)
        self.assertEqual(w3.eth.send_attempts, auto_pipeline.REPLACEMENT_MAX_ATTEMPTS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
