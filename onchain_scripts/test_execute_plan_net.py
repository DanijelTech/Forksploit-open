#!/usr/bin/env python3
# Author: DanyTech
"""test_execute_plan_net.py -- end-to-end test that execute_plan() reports
NET profit (gross recovery-wallet gain minus the real gas the funding wallet
paid), driving the REAL execute_plan() code path against a fake Web3.

No network and no chain: the fake object below implements only the Web3/eth
surface execute_plan actually touches, and returns real-shaped receipts whose
gasUsed * effectiveGasPrice is a known number -- so the assertions check the
actual wiring (GasLedger is fed every send, net = gross - gas), not a mock of
the logic under test. Only the transport is faked; execute_plan, send_call,
build_precise_tx, estimate_gas_limit, get_fee_fields and GasLedger all run for
real.

Run: python -m unittest onchain_scripts/test_execute_plan_net.py -v
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from eth_account import Account  # noqa: E402
from web3 import Web3  # noqa: E402
from web3.datastructures import AttributeDict  # noqa: E402

import auto_pipeline  # noqa: E402
import gas_oracle  # noqa: E402
from auto_pipeline import PLAN_CONFIRMED, execute_plan  # noqa: E402

RECOVERY = "0x" + "22" * 20
TARGET = "0x" + "33" * 20
ATTACK_WALLET = "0x" + "44" * 20
GAS_PRICE = 10**9
GAS_USED = 50_000
GAIN_WEI = 10**18  # what the exploit lands on the recovery wallet


class _FakeEth:
    def __init__(self, gain_wei=GAIN_WEI):
        self.gain_wei = gain_wei
        self.chain_id = 61
        self.gas_price = GAS_PRICE
        self._balances = {Web3.to_checksum_address(RECOVERY): 0}
        self._sent = 0

    def get_balance(self, addr, *args, **kwargs):
        return self._balances.get(Web3.to_checksum_address(addr), 0)

    def get_block(self, which):
        # Legacy chain: no baseFeePerGas, exactly like ETC mainnet.
        return {"number": 1, "gasLimit": 30_000_000}

    def estimate_gas(self, tx):
        return GAS_USED

    def call(self, tx):
        return b"\x00" * 32

    def get_transaction_count(self, addr, *args):
        return 0

    def send_raw_transaction(self, raw):
        self._sent += 1
        # The exploit step is the first (and only) send here -- once it lands,
        # the recovery wallet has gained GAIN_WEI.
        self._balances[Web3.to_checksum_address(RECOVERY)] = self.gain_wei
        return b"\xab" * 32

    def _receipt(self):
        # AttributeDict matches what web3 really returns (attribute access
        # for .status, item access for ["gasUsed"]).
        return AttributeDict({"gasUsed": GAS_USED, "effectiveGasPrice": GAS_PRICE,
                              "status": 1, "contractAddress": None})

    def wait_for_transaction_receipt(self, tx_hash, timeout=None):
        return self._receipt()

    def get_transaction_receipt(self, tx_hash):
        return self._receipt()


class _FakeW3:
    def __init__(self, gain_wei=GAIN_WEI):
        self.eth = _FakeEth(gain_wei)

    from_wei = staticmethod(Web3.from_wei)
    to_wei = staticmethod(Web3.to_wei)
    to_checksum_address = staticmethod(Web3.to_checksum_address)


class _Tee:
    def __init__(self):
        self.lines = []

    def log(self, msg, alert=False):
        self.lines.append(str(msg))


class ExecutePlanNetTest(unittest.TestCase):
    def setUp(self):
        # Keep the oracle offline/deterministic -- pricing is not what this
        # test is about, and it must not depend on a network.
        gas_oracle.set_enabled(False)

    def tearDown(self):
        gas_oracle.set_enabled(True)

    def _run(self):
        w3 = _FakeW3()
        acct = Account.from_key("0x" + "11" * 32)
        plan = {
            "contract_name": "fake",
            "kind": "flat",
            "steps": [{"contract": TARGET, "calldata": "deadbeef", "value": "0"}],
        }
        tee = _Tee()
        return execute_plan(w3, acct, {"nonce": 0}, ATTACK_WALLET, plan,
                            RECOVERY, tee, chain="etc"), tee

    def test_returns_four_values(self):
        result, _ = self._run()
        self.assertEqual(len(result), 4)

    def test_confirmed_with_gross_delta(self):
        (status, delta, _gas, _net), _ = self._run()
        self.assertEqual(status, PLAN_CONFIRMED)
        self.assertEqual(delta, GAIN_WEI)

    def test_gas_spent_is_recorded_from_real_receipt(self):
        (_s, _d, gas, _n), _ = self._run()
        self.assertEqual(gas, GAS_USED * GAS_PRICE)

    def test_net_is_gross_minus_gas(self):
        (_s, delta, gas, net), _ = self._run()
        self.assertEqual(net, delta - gas)
        self.assertEqual(net, GAIN_WEI - GAS_USED * GAS_PRICE)

    def test_confirmed_log_shows_net_and_gas(self):
        _res, tee = self._run()
        joined = "\n".join(tee.lines)
        self.assertIn("CONFIRMED", joined)
        self.assertIn("net", joined)
        self.assertIn("gas", joined)


class ExecutePlanNetLossTest(unittest.TestCase):
    """A confirmed plan whose gas bill exceeds its gain must report a
    negative net, never a clamped-to-zero or omitted one."""

    def setUp(self):
        gas_oracle.set_enabled(False)

    def tearDown(self):
        gas_oracle.set_enabled(True)

    def test_net_goes_negative_when_gas_exceeds_gain(self):
        # Gain (1e12) is below the gas bill (50k * 1 gwei = 5e13).
        w3 = _FakeW3(gain_wei=10**12)
        acct = Account.from_key("0x" + "11" * 32)
        plan = {
            "contract_name": "fake",
            "kind": "flat",
            "steps": [{"contract": TARGET, "calldata": "deadbeef", "value": "0"}],
        }
        status, delta, gas, net = execute_plan(
            w3, acct, {"nonce": 0}, ATTACK_WALLET, plan, RECOVERY, _Tee(), chain="etc"
        )
        self.assertEqual(status, PLAN_CONFIRMED)
        self.assertEqual(delta, 10**12)
        self.assertEqual(gas, GAS_USED * GAS_PRICE)
        self.assertLess(net, 0)


class ExecutePlanTokenCheckHonestyTest(unittest.TestCase):
    """P3 regression: the EXECUTED, NO PROFIT message must not claim a token
    was checked when the plan had no recognized ERC-20 money-mover step.

    `stolen_asset` is stamped by the Rust layer only for
    transfer/transferFrom/mint/burn/skim/approve steps (erc20_token_touched in
    src/evm/solution/mod.rs). A plan with none of those never inspects a token
    balance, so saying "no token this plan touched moved" would be false -- it
    would hide the fact that a token holding the target's value was never
    looked at.
    """

    def setUp(self):
        gas_oracle.set_enabled(False)

    def tearDown(self):
        gas_oracle.set_enabled(True)

    def _run_with(self, steps):
        # gain_wei=0 so the plan lands in the EXECUTED, NO PROFIT branch.
        w3 = _FakeW3(gain_wei=0)
        acct = Account.from_key("0x" + "11" * 32)
        plan = {"contract_name": "fake", "kind": "flat", "steps": steps}
        tee = _Tee()
        execute_plan(w3, acct, {"nonce": 0}, ATTACK_WALLET, plan, RECOVERY, tee, chain="etc")
        return "\n".join(tee.lines)

    def test_no_token_step_says_no_token_was_checked(self):
        out = self._run_with([{"contract": TARGET, "calldata": "deadbeef", "value": "0"}])
        self.assertIn("EXECUTED, NO PROFIT", out)
        self.assertIn("NO token balance was checked at all", out)
        self.assertNotIn("in any token this plan touched", out)

    def test_token_step_reports_it_checked_that_token(self):
        # A recognized ERC-20 money-mover step carries a `stolen_asset`.
        out = self._run_with([
            {"contract": TARGET, "calldata": "a9059cbb", "value": "0", "stolen_asset": TARGET}
        ])
        self.assertIn("EXECUTED, NO PROFIT", out)
        self.assertIn("in any token this plan touched", out)
        self.assertNotIn("NO token balance was checked at all", out)


class W4BatchExecutionTest(unittest.TestCase):
    """W4: a multi-step FLAT plan is executed ATOMICALLY through
    AttackWallet.executeBatch (one tx), and a failed step names its revert
    reason. Pins both the calldata shape and the real execute_plan wiring."""

    def setUp(self):
        gas_oracle.set_enabled(False)

    def tearDown(self):
        gas_oracle.set_enabled(True)

    def test_execute_batch_calldata_shape(self):
        from auto_pipeline import attack_wallet_execute_batch_calldata, selector
        cd = attack_wallet_execute_batch_calldata([TARGET, TARGET], [b"\xaa\xbb", b"\xcc"], [1, 0])
        self.assertTrue(cd.startswith(selector("executeBatch(address[],bytes[],uint256[])")))
        # Three dynamic arrays => three head words (offsets) after the selector.
        self.assertEqual(len(cd), 4 + 3 * 32 + len(cd[4 + 3 * 32:]))

    def test_multi_step_flat_plan_uses_execute_batch(self):
        # Two-step flat plan whose sends SUCCEED (gain 0 => NO PROFIT path);
        # the FIRST (and only) send must be an executeBatch call, not two
        # separate execute() calls.
        w3 = _FakeW3(gain_wei=0)
        sent = []
        orig = w3.eth.send_raw_transaction

        def spy(raw):
            sent.append(raw)
            return orig(raw)

        w3.eth.send_raw_transaction = spy
        acct = Account.from_key("0x" + "11" * 32)
        plan = {"contract_name": "fake", "kind": "flat", "steps": [
            {"contract": TARGET, "calldata": "deadbeef", "value": "0"},
            {"contract": TARGET, "calldata": "cafebabe", "value": "0"},
        ]}
        tee = _Tee()
        execute_plan(w3, acct, {"nonce": 0}, ATTACK_WALLET, plan, RECOVERY, tee, chain="etc")
        joined = "\n".join(tee.lines)
        self.assertIn("executeBatch (2 steps, atomic)", joined)
        self.assertEqual(len(sent), 1, "the atomic batch must be exactly ONE transaction")

    def test_single_step_plan_stays_plain_execute(self):
        w3 = _FakeW3(gain_wei=0)
        acct = Account.from_key("0x" + "11" * 32)
        plan = {"contract_name": "fake", "kind": "flat", "steps": [
            {"contract": TARGET, "calldata": "deadbeef", "value": "0"},
        ]}
        tee = _Tee()
        execute_plan(w3, acct, {"nonce": 0}, ATTACK_WALLET, plan, RECOVERY, tee, chain="etc")
        joined = "\n".join(tee.lines)
        self.assertNotIn("executeBatch", joined)


class W4FailingStepNamingTest(unittest.TestCase):
    """W4: when the atomic batch reverts, the report must name WHICH step
    broke, not just that 'the batch reverted'. Pins the best-effort prefix
    replay (first_failing_step_index) and its wiring into execute_plan."""

    def setUp(self):
        gas_oracle.set_enabled(False)

    def tearDown(self):
        gas_oracle.set_enabled(True)

    def test_first_failing_step_index_points_at_the_breaking_step(self):
        from web3.exceptions import ContractLogicError
        from auto_pipeline import first_failing_step_index

        steps = [
            {"contract": TARGET, "calldata": "deadbeef", "value": "0"},
            {"contract": TARGET, "calldata": "cafebabe", "value": "0"},
        ]

        class _Eth:
            def call(self, tx):
                # Only the 2-step prefix (containing the 2nd step) reverts.
                data = tx.get("data", b"")
                if b"\xca\xfe\xba\xbe" in data:
                    raise ContractLogicError("execution reverted: step 1 broke")
                return b"\x00" * 32

        class _W3:
            eth = _Eth()

        acct = Account.from_key("0x" + "11" * 32)
        self.assertEqual(first_failing_step_index(_W3(), acct, ATTACK_WALLET, steps), 1)

    def test_batch_revert_log_names_the_step(self):
        from web3.exceptions import ContractLogicError

        steps = [
            {"contract": TARGET, "calldata": "deadbeef", "value": "0"},
            {"contract": TARGET, "calldata": "cafebabe", "value": "0"},
        ]

        class _Eth(_FakeEth):
            def estimate_gas(self, tx):
                return GAS_USED

            def call(self, tx):
                data = tx.get("data", b"")
                if isinstance(data, str):
                    data = bytes.fromhex(data[2:] if data.startswith("0x") else data)
                if b"\xca\xfe\xba\xbe" in data:
                    raise ContractLogicError("execution reverted: step 1 broke")
                return b"\x00" * 32

            def _receipt(self):
                # The batch lands but REVERTED.
                return AttributeDict({"gasUsed": GAS_USED, "effectiveGasPrice": GAS_PRICE,
                                      "status": 0, "contractAddress": None})

        class _W3(_FakeW3):
            def __init__(self):
                self.eth = _Eth(gain_wei=0)

        acct = Account.from_key("0x" + "11" * 32)
        plan = {"contract_name": "fake", "kind": "flat", "steps": steps}
        tee = _Tee()
        (status, delta, gas, net) = execute_plan(
            _W3(), acct, {"nonce": 0}, ATTACK_WALLET, plan, RECOVERY, tee, chain="etc"
        )
        out = "\n".join(tee.lines)
        self.assertEqual(status, auto_pipeline.PLAN_NOT_CONFIRMED)
        self.assertIn("points at step 1/2", out)
        # The batch reverted, so no value moved (delta 0) -- but the reverted
        # tx still cost real gas, so net is that (negative) gas bill.
        self.assertEqual(delta, 0)
        self.assertEqual(gas, GAS_USED * GAS_PRICE)
        self.assertLess(net, 0)


class X2EstimateRevertClassificationTest(unittest.TestCase):
    """X2 regression: when the plan's FIRST step reverts, eth_estimateGas
    itself raises ContractLogicError. That is a NOT CONFIRMED plan (the
    fuzzer's simulated trace did not reproduce against real state) -- it used
    to escape to the generic per-plan handler and be mislabelled INCONCLUSIVE,
    hiding a genuine revert. W1 (execute() now bubbles the inner revert) is
    what made this reachable on a real run."""

    def setUp(self):
        gas_oracle.set_enabled(False)

    def tearDown(self):
        gas_oracle.set_enabled(True)

    def _run_with_estimate_error(self):
        from web3.exceptions import ContractLogicError

        w3 = _FakeW3(gain_wei=0)

        def raising_estimate_gas(tx):
            raise ContractLogicError(
                "execution reverted: AttackWallet: execute target call reverted with no reason"
            )

        w3.eth.estimate_gas = raising_estimate_gas
        acct = Account.from_key("0x" + "11" * 32)
        plan = {"contract_name": "fake", "kind": "flat", "steps": [
            {"contract": TARGET, "calldata": "deadbeef", "value": "0"},
        ]}
        tee = _Tee()
        result = execute_plan(w3, acct, {"nonce": 0}, ATTACK_WALLET, plan, RECOVERY, tee, chain="etc")
        return result, "\n".join(tee.lines)

    def test_estimate_revert_is_not_confirmed_not_inconclusive(self):
        (status, delta, gas, net), out = self._run_with_estimate_error()
        self.assertEqual(status, auto_pipeline.PLAN_NOT_CONFIRMED)
        self.assertNotEqual(status, auto_pipeline.PLAN_INCONCLUSIVE)
        self.assertIn("reverts against real chain state", out)
        self.assertEqual((delta, gas, net), (0, 0, 0))


if __name__ == "__main__":
    unittest.main()
