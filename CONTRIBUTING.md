# Contributing to KCC Sentinel

The GitHub repository is public. Anyone can read or fork it. To push changes directly, ask the owner for a collaborator invitation, accept it, and clone `https://github.com/Anubhav-2005/kcc-x402-sentinel.git`.

1. Run `npm ci` and `npm test` before editing.
2. Change the UI in `public/`, the local/serverless API in `src/app/` and `api/`, and payment rules in `src/security/`.
3. Create a branch, push it, and open a pull request. GitHub Actions runs the test and held-out checks.
4. After review, merge to `main`. Vercel is linked to this repository and builds the public production site from `main`.

The website uses a dedicated Neon database and Vercel environment secrets. Do not commit `.env.local`, admin tokens, database URLs, private keys, audit exports, or real wallet credentials. The demo does not broadcast funds.
