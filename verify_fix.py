#!/usr/bin/env python3
"""Verification harness for WholeTroutMedia/oss-verification-sandbox#1 (_rfc7239_forwarded_nonce_9f4a)."""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main() -> int:
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName("tests.test_forwarded")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print("\n[PASS] asgi-proxy-header-401 (_rfc7239_forwarded_nonce_9f4a) verified (exit code 0).")
        return 0
    print("\n[FAIL] Test failures encountered.")
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
