# Architecture

```text
Owner / Blue policy authority
          │ signs a short-lived IntentPermit
          ▼
Agent → Merchant → HTTP 402 + PAYMENT-REQUIRED
                         │
                         ▼
                  Sentinel guard
            schema · signed intent · policy
            recipient · amount · time · replay
                         │
             BLOCK ◀──────┴──────▶ APPROVE
                                      │ reserve budget and permit use
                                      ▼
                              dry-run authorization
                                      │
                                      ▼
                           paid retry and receipt check
```

The merchant owns the requested payment terms. The owner or Blue authority owns spending permission. The guard compares them; it does not let the merchant define both.

The permit uses Ed25519 and binds the wallet, HTTP method, canonical URL and query, amount ceiling, recipient, network, asset, scheme, payment flow, transfer method, timeout ceiling, policy digest, time window, use count, and nonce. The guard evaluates all offered `accepts[]` entries and can choose a compliant later offer.

The single-use permission is consumed **when approval is created**, before any simulated wallet signing. A pending approval also reserves its amount against the daily budget. These state changes prevent two approvals from racing on one permission or the same remaining budget. A final check compares the approved authorization with the observed dry-run settlement fields.

The Red/Blue arena is a separate evaluation plane. It stores the original challenge on the server and gives Red a one-use challenge ID. The referee derives the expected result from that original; it does not read the guard's answer to decide whether a mutation was an attack. The Judge displays both answers and the execution trace.

| Module | Responsibility |
| --- | --- |
| `src/core/` | Strict x402 shape validation and canonical URLs |
| `src/security/` | Permit authority, policy checks, risk checks, approval and settlement checks |
| `src/state/` | Permit claims, nonce, budget reservations, challenge registry |
| `src/demo/` | Merchant baseline, attack cases, referee, scorekeeping |
| `src/research/` | Independent held-out cases and generated tests |
| `src/app/` | HTTP API, runtime, server-sent updates, audit log, state serialization |
| `api/` | Vercel Node Function with Neon Postgres persistence |

Locally, one Node process holds payment state in memory and writes the audit log to a local file. On Vercel, a Neon Postgres row stores the arena, ledger, challenges, and audit chain. Each write compares the row version and retries on a conflict; the browser polls for shared updates. The Ed25519 authority key and Blue admin token live in Vercel secrets. A production payment service would additionally need per-user authentication, managed key rotation, stronger operational controls, and a verified wallet integration.
