#!/usr/bin/env python3
"""test_chain_verified.py -- the `chain-verified` tier (FAZA 7 of
PROMPT_RESEN_SISTEM.md) must be awarded ONLY to a plan that was actually
executed on a real chain AND moved a strictly positive amount of real
assets. It is the one tier that must never be handed out on the strength
of a simulation, a fork replay, or a clean-but-zero execution.

No network: is_chain_verified is a pure predicate over the two signals a
CONFIRMED plan already carries (status + its own measured recovery delta),
so it is tested directly.

Run: python -m unittest onchain_scripts/test_chain_verified.py -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import auto_pipeline  # noqa: E402
from auto_pipeline import (  # noqa: E402
    PLAN_CONFIRMED,
    PLAN_EXECUTED_NO_PROFIT,
    PLAN_INCONCLUSIVE,
    PLAN_NOT_CONFIRMED,
    PLAN_SKIPPED_UNPROFITABLE,
    is_chain_verified,
)


class TestChainVerified(unittest.TestCase):
    def test_confirmed_with_positive_delta_is_chain_verified(self):
        self.assertTrue(is_chain_verified(PLAN_CONFIRMED, 1))

    def test_confirmed_with_zero_delta_is_not_chain_verified(self):
        # A CONFIRMED status with a zero measured delta is self-contradictory
        # (execute_plan only confirms on a positive balance move), but the
        # predicate must still refuse it rather than trust the label alone.
        self.assertFalse(is_chain_verified(PLAN_CONFIRMED, 0))

    def test_executed_no_profit_is_never_chain_verified(self):
        # Every step succeeded, no money moved: explicitly NOT chain-verified.
        self.assertFalse(is_chain_verified(PLAN_EXECUTED_NO_PROFIT, 0))

    def test_non_confirmed_statuses_are_never_chain_verified(self):
        for status in (
            PLAN_NOT_CONFIRMED,
            PLAN_INCONCLUSIVE,
            PLAN_SKIPPED_UNPROFITABLE,
        ):
            # Even with a positive delta (impossible in practice), a
            # non-CONFIRMED status must not earn the top tier.
            self.assertFalse(is_chain_verified(status, 10**18), msg=status)


if __name__ == "__main__":
    unittest.main()
