#!/usr/bin/env python3
"""Verification harness for WholeTroutMedia/oss-verification-sandbox#2 (_quorum_epoch_barrier_7c2b)."""

import unittest
import sys
import os

# Ensure package is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main() -> int:
    loader = unittest.TestLoader()
    suite = loader.discover("tests", pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print("\n[PASS] stream-quorum-flush (_quorum_epoch_barrier_7c2b) verified (exit code 0).")
        return 0
    print("\n[FAIL] Test failures encountered.")
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
