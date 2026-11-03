import {
  applicableResearchTests,
  capabilityProfile
} from '../research/paper-analysis.mjs';
import { readJson, sendJson } from './http.mjs';
import { validatePaymentRequiredShape } from '../core/x402.mjs';

function requiresAdmin(runtime, request, response) {
  if (runtime.isAdmin(request)) return true;
  sendJson(response, 403, { error: 'Blue admin token required' });
  return false;
}

/**
 * Creates the JSON API dispatcher.  It has no ownership of sockets, files, or
 * process configuration; those stay in the server composition root.
 */
export function createApiRouter({ runtime, audit, getRealStatus, research, publishArenaState }) {
  return async function routeApi(request, response, url) {
    const key = `${request.method} ${url.pathname}`;

    switch (key) {
      case 'GET /api/system':
        sendJson(response, 200, {
          name: 'KCC Sentinel',
          version: '1.0.0',
          x402Version: 2,
          network: 'eip155:84532',
          runtime: process.version,
          adminTokenRequired: true,
          authority: runtime.intentAuthority.publicInfo(),
          real: await getRealStatus(),
          research
        });
        return true;

      case 'GET /api/real/status':
        sendJson(response, 200, await getRealStatus());
        return true;

      case 'GET /api/research/papers':
        sendJson(response, 200, { papers: research });
        return true;

      case 'POST /api/research/profile': {
        const body = await readJson(request);
        const paymentRequired = body?.paymentRequired ?? body;
        validatePaymentRequiredShape(paymentRequired);
        sendJson(response, 200, {
          profile: capabilityProfile(paymentRequired),
          tests: applicableResearchTests(paymentRequired)
        });
        return true;
      }

      case 'POST /api/attack/fuzz': {
        if (!requiresAdmin(runtime, request, response)) return true;
        const report = runtime.runFuzz(await readJson(request));
        sendJson(response, 200, report);
        return true;
      }

      case 'POST /api/research/heldout': {
        if (!requiresAdmin(runtime, request, response)) return true;
        sendJson(response, 200, runtime.runHeldOut(await readJson(request)));
        return true;
      }

      case 'GET /api/research/evaluation':
        sendJson(response, 200, runtime.evaluationReports);
        return true;

      case 'POST /api/research/heldout/multi': {
        if (!requiresAdmin(runtime, request, response)) return true;
        sendJson(response, 200, runtime.runHeldOutMulti(await readJson(request)));
        return true;
      }

      case 'GET /api/merchant/challenge': {
        const challenge = runtime.issueArenaChallenge();
        sendJson(response, 200, {
          challengeId: challenge.challengeId,
          expiresAt: challenge.expiresAt,
          requestedUrl: challenge.paymentRequired.resource.url,
          paymentRequired: challenge.paymentRequired,
          paymentRequiredHeader: challenge.header
        });
        return true;
      }

      case 'GET /merchant/premium-data': {
        const result = runtime.merchantChallengeResponse(request.headers['payment-signature']);
        sendJson(response, result.status, result.body, result.headers);
        return true;
      }

      case 'POST /api/agent/run': {
        if (!requiresAdmin(runtime, request, response)) return true;
        const { status, result } = await runtime.runAgentFlow();
        sendJson(response, status, result);
        return true;
      }

      // A guest can exercise the normal 402 -> 200 path without receiving
      // authority to edit a wallet policy, issue permits, or enable fixtures.
      // The flow creates a fresh, signed dry-run approval on the server.
      case 'POST /api/demo/control': {
        const { status, result } = await runtime.runAgentFlow();
        // Keep permits, signatures, challenge headers, and raw merchant data
        // inside the trusted runtime. The guest UI only needs the outcome.
        sendJson(response, status, {
          ok: result.ok,
          stage: result.stage,
          http: {
            firstStatus: result.http?.firstStatus,
            secondStatus: result.http?.secondStatus
          },
          wallet: {
            signed: result.wallet?.signed === true,
            broadcast: result.wallet?.broadcast === true
          }
        });
        return true;
      }

      case 'POST /api/intent/issue': {
        if (!requiresAdmin(runtime, request, response)) return true;
        sendJson(response, 201, runtime.issueIntent(await readJson(request)));
        return true;
      }

      case 'GET /api/arena/state':
        sendJson(response, 200, runtime.arena.snapshot(
          url.searchParams.get('role') ?? 'judge',
          Number(url.searchParams.get('limit') ?? 60)
        ));
        return true;

      case 'POST /api/arena/submit': {
        const result = runtime.submitArenaChallenge(await readJson(request));
        if (!result.ok) {
          sendJson(response, result.status, { error: result.error });
          return true;
        }
        publishArenaState();
        sendJson(response, result.status, { ok: true, item: result.item, state: result.state });
        return true;
      }

      case 'POST /api/arena/policy': {
        if (!requiresAdmin(runtime, request, response)) return true;
        const policy = runtime.arena.setPolicy(await readJson(request));
        publishArenaState();
        sendJson(response, 200, { ok: true, policy });
        return true;
      }

      case 'POST /api/arena/training-mode': {
        if (!requiresAdmin(runtime, request, response)) return true;
        const body = await readJson(request);
        const mode = runtime.arena.setTrainingMode(body?.mode);
        publishArenaState();
        sendJson(response, 200, { ok: true, mode });
        return true;
      }

      case 'POST /api/arena/reset': {
        if (!requiresAdmin(runtime, request, response)) return true;
        const state = runtime.resetArena();
        publishArenaState();
        sendJson(response, 200, { ok: true, state });
        return true;
      }

      case 'POST /api/guard/evaluate':
        sendJson(response, 200, runtime.evaluateGuard(await readJson(request)));
        return true;

      case 'GET /api/audit':
        sendJson(response, 200, {
          entries: audit.list(Number(url.searchParams.get('limit') ?? 100)),
          integrity: audit.verifyChain()
        });
        return true;

      case 'GET /api/audit/export': {
        const body = JSON.stringify({
          exportedAt: new Date().toISOString(),
          product: 'x402 Sentinel',
          integrity: audit.verifyChain(),
          entries: audit.list(500)
        }, null, 2);
        response.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'content-disposition': 'attachment; filename="sentinel-audit.json"'
        });
        response.end(body);
        return true;
      }

      default:
        return false;
    }
  };
}
