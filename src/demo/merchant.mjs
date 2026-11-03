import { encodePaymentRequiredHeader } from '../core/x402.mjs';

export const BASE_SEPOLIA_USDC = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';
export const DEMO_MERCHANT = '0x1111111111111111111111111111111111111111';

export function buildMerchantChallenge({ amount = '50000', payTo = DEMO_MERCHANT, resourceUrl = 'https://api.safe.test/premium-data' } = {}) {
  const paymentRequired = {
    x402Version: 2,
    error: 'PAYMENT-SIGNATURE header is required',
    resource: {
      url: resourceUrl,
      description: 'Premium market snapshot for an autonomous agent',
      mimeType: 'application/json',
      serviceName: 'Aperture Data',
      tags: ['market-data', 'agent-tool']
    },
    accepts: [{
      scheme: 'exact',
      network: 'eip155:84532',
      amount,
      asset: BASE_SEPOLIA_USDC,
      payTo,
      maxTimeoutSeconds: 60,
      extra: { name: 'USDC', version: '2', assetTransferMethod: 'eip3009', paymentFlow: 'authorization' }
    }],
    extensions: {}
  };
  return { paymentRequired, header: encodePaymentRequiredHeader(paymentRequired) };
}
