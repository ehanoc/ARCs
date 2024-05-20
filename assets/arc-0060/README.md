# ARC-60 Reference Implementation

## Overview

This is a reference implementation of the ARC-60 specification. It is written in TypeScript and uses the Jest testing framework.
The test suite shows the different use cases of the ARC-60 specification.

## Instructions

```bash
$ yarn
$ yarn test
```

## Sample Output

```bash
 PASS  ./arc60wallet.api.spec.ts
  Test Suite Name
    Reject unknown LSIGs
      ✓ (FAILS) Tries to sign with any scope if "Program" is present (34 ms)
    SCOPE == CHALLENGE32
      ✓ (OK) Signs random 32 byte challenge (3 ms)
      ✓ (FAILS) Tries to sign with bad size random data as CHALLENGE32 (1 ms)
    SCOPE == MX_RANDOM
      ✓ (OK) Signs random 32 byte challenge with MX prefix (2 ms)
      ✓ (FAILS) Tries to sign but no MX prefix is present (1 ms)
    SCOPE == INVALID
      ✓ (FAILS) Tries to sign with invalid scope (1 ms)
    SCOPE == LSIG_TEMPLATE
      ✓ (FAIL) Fails to sign LSIG_TEMPLATE program, templated program doesnt match known hashes (74 ms)
      ✓ (OK) Signs LSIG_TEMPLATE program, templated program is known, values replaced and signature produced (1026 ms)

Test Suites: 1 passed, 1 total
Tests:       8 passed, 8 total
Snapshots:   0 total
Time:        3.001 s, estimated 4 s
```