# Evaluation method

Two suites answer different questions:

1. **Known regressions:** `npm test` and `npm run fuzz` verify named attacks, legitimate controls, and fixed security boundaries.
2. **Held-out Red Team:** seeded, independently constructed single-field, compound, URL, malformed-input, stateful, and adaptive cases. The referee labels each case from the original merchant challenge and signed-intent semantics before comparing the guard's decision.

| Expected behavior | Guard blocks | Guard allows |
| --- | --- | --- |
| Attack | True positive | False negative / bypass |
| Legitimate | False positive | True negative |

The held-out report records raw counts, rates, severity, reason codes, and any failures. The seven-seed run uses fixed seeds `1, 7, 42, 99, 402, 1337, 2026`. Some boundary designs repeat across seeds, so the total is **not** 2,100 independent attack ideas. A zero-failure run is evidence for these tested inputs only.

The package builder runs the tests and evaluations against the packaged copy before creating the ZIP. See [measured results](RESULTS.md), [seed 42 JSON](../results/heldout-seed-42.json), and [seven-seed JSON](../results/heldout-multi.json). Run them again with the commands in [README.md](../README.md).

The wallet-stage tests assert that a blocked malformed or expired payment never creates a dry-run signing payload. They do not test a real private-key signer or on-chain settlement.
