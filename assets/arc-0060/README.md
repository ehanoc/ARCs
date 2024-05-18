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
    SCOPE == CHALLENGE32
      ✓ (OK) Signs random 32 byte challenge (100 ms)
      ✓ (FAILS) Tries to sign with bad size random data as CHALLENGE32 (31 ms)
    SCOPE == MX_RANDOM
      ✓ (OK) Signs random 32 byte challenge with MX prefix (6 ms)
      ✓ (FAILS) Tries to sign but no MX prefix is present (3 ms)
    SCOPE == INVALID
      ✓ (FAILS) Tries to sign with invalid scope (4 ms)

Test Suites: 1 passed, 1 total
Tests:       5 passed, 5 total
Snapshots:   0 total
Time:        3.307 s, estimated 6 s
Ran all test suites.
Done in 3.90s.

```