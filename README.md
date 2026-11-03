# KCC Sentinel

**Team KCC · x402 Red/Blue challenge**

A merchant's HTTP 402 response says what it wants to be paid. It does not say what the buyer authorized. Sentinel checks the merchant's payment terms against a short-lived, signed buyer permit before the wallet authorization stage.

[Live demo](https://kcc-x402-sentinel.vercel.app) · [Red console](https://kcc-x402-sentinel.vercel.app/red) · [Blue console](https://kcc-x402-sentinel.vercel.app/blue) · [Judge view](https://kcc-x402-sentinel.vercel.app/judge)

## What to show

1. In **Blue**, run the legitimate x402 control. The matching payment passes and the paid retry returns HTTP 200.
2. In **Red**, choose **Timeout +1 second**. The original offer allows 60 seconds; Red submits 61. In secure mode the guard blocks it with `INTENT_TIMEOUT` before the simulated signer.
3. In **Judge**, compare the server-held original, Red's submission, the signed permit, and the guard decision. The referee labels the expected outcome from the original offer, independently of the guard's answer.

The arena also includes a deliberately vulnerable permit issuer for a controlled Red win. Blue must enable it explicitly. The same 61-second attack then passes because the issuer signs Red's changed timeout. Restoring secure mode blocks it again. This is a fault-injection demonstration, not a bypass of the default guard. See [the demo steps](docs/DEMO.md).

## Run locally

Requires Node.js 20 or newer.

```bash
npm ci
npm start
```

Open `http://127.0.0.1:4173`. The local server prints a Blue admin token for policy changes and the training fixture. Do not commit or share the token. The hosted deployment has its own admin token in Vercel environment variables.

## Design

| Component | Job |
| --- | --- |
| `src/core` | Parse and validate x402 requirements; canonicalize resource URLs |
| `src/security` | Verify signed intent, policy, recipient, and settlement correspondence |
| `src/state` | Track one-use permits, challenges, nonces, and pending budget |
| `src/demo` | Run the merchant challenge, Red mutations, and independent referee |
| `src/research` | Generate seeded and held-out evaluation cases |
| `src/app` and `api` | Serve local and Vercel APIs; persist shared state on Neon |
| `public` | Red, Blue, Judge, and landing views |
| `tests` | Guard, state, referee, and legitimate-flow regressions |

The merchant cannot issue its own buyer permit. A permit binds the resource, recipient, network, asset, amount, timeout, and use count. Permission and budget are reserved when an approval is created, before the simulated wallet stage. [Architecture](docs/ARCHITECTURE.md) has the trust boundaries and deployment details.

## Reproduce the checks

```bash
npm test
npm run heldout -- --seed 42 --attacks 300 --legitimate 300
npm run heldout:multi -- --attacks 300 --legitimate 300
```

[Measured results](docs/RESULTS.md) and the raw reports in `results/` come from this packaged source. The test corpus is synthetic; passing it is not a claim of universal security. [Evaluation method](docs/EVALUATION.md) explains the labels and counts.

## Scope

This is a dry-run security prototype. It constructs x402-shaped requirements and a payment authorization payload, but does not use a real wallet key, broadcast a transaction, or verify on-chain settlement. The recipient relationship graph uses synthetic demo data. See [scope and limits](docs/LIMITS.md) and [references](docs/REFERENCES.md).

Teammates can use [CONTRIBUTING.md](CONTRIBUTING.md) to develop and submit changes. `main` deploys to the public Vercel site; the repo never contains database credentials or signing keys.
