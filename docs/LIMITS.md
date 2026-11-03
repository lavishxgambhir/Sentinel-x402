# Scope and limits

- This is a **dry-run** locally and on Vercel. It uses x402-shaped HTTP 402 requirements and an EIP-3009-shaped authorization object, but broadcasts no transaction and does not prove on-chain settlement.
- The wallet relationship graph is synthetic demo data. Its loop signal is not a finding about real people or illicit funds.
- The Blue admin token protects demo controls. It is not production authentication. Do not expose this server as a public payment service.
- The authority key, wallet signer, and guard are trusted components in this prototype. The local ledger is in memory; the Vercel ledger uses a versioned Neon row for atomic updates. This is demo-scale storage, not a production payment ledger.
- The referee is independent of the guard's decision for its expected labels, but both run in one codebase. Results apply to these seeds, inputs, policy, and build; they do not prove universal security or zero false positives.
- The optional vulnerable permit issuer is a labeled arena-only fault injection. Its timeout bypass demonstrates detection and repair, not a discovered vulnerability in the default guard. The signer stage is simulated; no real key signs or broadcasts the attack.
- Sentinel does not verify merchant delivery, real-world wallet ownership, AML/KYC status, sanctions compliance, or facilitator honesty.

The project demonstrates a buyer-side authorization boundary and a controlled way to measure attacks and legitimate payments. Present it at that scope.
