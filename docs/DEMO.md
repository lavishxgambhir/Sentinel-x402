# Demo sequence

Use the same deployment for all three tabs: [Blue](https://kcc-x402-sentinel.vercel.app/blue), [Red](https://kcc-x402-sentinel.vercel.app/red), and [Judge](https://kcc-x402-sentinel.vercel.app/judge). For a local demo, run `npm ci && npm start` and use `http://127.0.0.1:4173` instead. Blue controls require the admin token. The local server prints its token at startup; the hosted token is stored separately in Vercel.

## Secure mode

1. **Blue:** Check that the mode badge says **Secure**. Click **Load baseline**, then **Run x402 control**. A matching offer should pass and the paid retry should return HTTP 200.
2. **Red:** Choose **Recipient binding** and click **Evaluate with referee**. Only the payee changes. The guard should block before the simulated signer.
3. **Red:** Choose **Timeout +1 second** and evaluate. The original merchant offer has a 60-second ceiling; Red submits 61 seconds. The wallet's general 120-second policy does not override the signed permit's 60-second limit. Judge should show `INTENT_TIMEOUT` and **ATTACK BLOCKED**.
4. **Judge:** Point to the original offer, Red submission, permit, expected decision, actual decision, and execution trace. These are the evidence behind the verdict.

## Controlled Red win

This step injects a fault into the arena's permit issuer. It is not a bypass of Sentinel's normal guard.

1. In Blue, enter the admin token and click **Enable vulnerable mode**. Confirm the banner changes on Red and Judge.
2. In Red, choose **Timeout +1 second** again and evaluate. Judge should show **TRUE BYPASS**: the referee expects a block from the original 60-second offer, but the weakened issuer signs Red's 61-second limit. The dry-run signer stage opens.
3. In Blue, click **Restore secure mode**. Repeat the same Red mutation; it should be blocked again.

The demo never uses a real wallet key or broadcasts a transaction. Each round records which mode it used, so an older vulnerable result remains labeled after secure mode is restored.

## Evaluation

In Judge, the **Known regression**, **Held-out Red**, and **Multi-seed** panels run reproducible suites. The admin token is required to execute them on the hosted site. The checked-in [results](RESULTS.md) and raw JSON reports are available if the live benchmark is slow or the network is unavailable. The held-out suite uses synthetic cases; its counts are observations, not a security proof.
