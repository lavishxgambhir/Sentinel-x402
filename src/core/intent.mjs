import crypto from 'node:crypto';

export function createIntent(overrides = {}) {
  return {
    id: crypto.randomUUID(),
    createdAt: new Date().toISOString(),
    method: 'GET',
    resourceUrl: 'https://api.safe.test/premium-data',
    serviceName: 'Aperture Data',
    maxAmount: '50000',
    maxTimeoutSeconds: 60,
    expectedPayTo: '0x1111111111111111111111111111111111111111',
    network: 'eip155:84532',
    asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
    scheme: 'exact',
    paymentFlow: 'authorization',
    assetTransferMethod: 'eip3009',
    maxUses: 1,
    purpose: 'Purchase premium market snapshot',
    ...overrides
  };
}

export function publicIntent(intent) {
  return { ...intent };
}

export function intentFromPaymentRequired(paymentRequired, overrides = {}) {
  const offer = paymentRequired?.accepts?.[0];
  if (!offer) throw new Error('Cannot derive intent without a payment offer');
  return createIntent({
    resourceUrl: paymentRequired.resource.url,
    serviceName: paymentRequired.resource.serviceName ?? 'x402 Merchant',
    maxAmount: String(offer.amount),
    maxTimeoutSeconds: offer.maxTimeoutSeconds,
    expectedPayTo: String(offer.payTo),
    network: String(offer.network),
    asset: String(offer.asset),
    scheme: String(offer.scheme),
    paymentFlow: String(offer.extra?.paymentFlow ?? 'authorization'),
    assetTransferMethod: String(offer.extra?.assetTransferMethod ?? 'eip3009'),
    ...overrides
  });
}
