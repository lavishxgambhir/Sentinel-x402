const GOOD_PAYEE = '0x1111111111111111111111111111111111111111';
const EVIL_PAYEE = '0x9999999999999999999999999999999999999999';
const GOOD_ASSET = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';
const EVIL_ASSET = '0x8888888888888888888888888888888888888888';
const GOOD_NETWORK = 'eip155:84532';

export const scenarioCatalog = [
  { id: 'normal', label: 'Normal payment', kind: 'safe', expected: 'allow', summary: 'Correct amount, merchant, network and asset.' },
  { id: 'overpay', label: 'Overpayment', kind: 'attack', expected: 'block', summary: 'Merchant asks for 5 USDC when policy allows only 0.5 USDC for this merchant.' },
  { id: 'wrong-party', label: 'Wrong recipient', kind: 'attack', expected: 'block', summary: 'Price is normal but payTo is replaced with an attacker wallet.' },
  { id: 'wrong-network', label: 'Wrong network', kind: 'attack', expected: 'block', summary: 'Request tries to move payment from Base Sepolia to Ethereum mainnet.' },
  { id: 'wrong-asset', label: 'Wrong asset', kind: 'attack', expected: 'block', summary: 'Request swaps the approved token contract.' },
  { id: 'resource-swap', label: 'Resource swap', kind: 'attack', expected: 'block', summary: 'A 402 from one URL is replayed against a different protected resource.' },
  { id: 'unsupported-scheme', label: 'Scheme downgrade', kind: 'attack', expected: 'block', summary: 'Request proposes a scheme the wallet policy does not permit.' },
  { id: 'long-timeout', label: 'Excessive timeout', kind: 'attack', expected: 'block', summary: 'Authorization window is much longer than wallet policy allows.' },
  { id: 'payment-flow-swap', label: 'Payment-flow swap', kind: 'attack', expected: 'block', summary: 'Merchant switches from post-handler authorization to upfront settlement.' },
  { id: 'transfer-method-swap', label: 'Transfer-method swap', kind: 'attack', expected: 'block', summary: 'Merchant silently changes the EVM transfer primitive from EIP-3009 to Permit2.' },
  { id: 'malicious-first-offer', label: 'Poisoned first offer', kind: 'attack', expected: 'allow', summary: 'First offer is malicious; second is safe. Guard must not blindly pick index 0.' },
  { id: 'post-approval-swap', label: 'Post-approval recipient swap', kind: 'attack', expected: 'block', summary: 'Recipient changes after policy approval but before settlement.' },
  { id: 'replay', label: 'Replay payment', kind: 'attack', expected: 'block', summary: 'Exactly the same approved authorization is submitted a second time.' }
];

function offer(overrides = {}) {
  return {
    scheme: 'exact',
    network: GOOD_NETWORK,
    amount: '50000',
    asset: GOOD_ASSET,
    payTo: GOOD_PAYEE,
    maxTimeoutSeconds: 60,
    extra: { name: 'USDC', version: '2', paymentFlow: 'authorization', assetTransferMethod: 'eip3009' },
    ...overrides
  };
}

export function makePaymentRequired(scenarioId = 'normal') {
  const resource = {
    url: 'https://api.safe.test/premium-data',
    description: 'Premium market data',
    mimeType: 'application/json',
    serviceName: 'Safe Data API',
    tags: ['demo', 'market-data']
  };

  const base = {
    x402Version: 2,
    error: 'PAYMENT-SIGNATURE header is required',
    resource,
    accepts: [offer()],
    extensions: {}
  };

  switch (scenarioId) {
    case 'overpay':
      base.accepts = [offer({ amount: '5000000' })];
      break;
    case 'wrong-party':
      base.accepts = [offer({ payTo: EVIL_PAYEE })];
      break;
    case 'wrong-network':
      base.accepts = [offer({ network: 'eip155:1' })];
      break;
    case 'wrong-asset':
      base.accepts = [offer({ asset: EVIL_ASSET })];
      break;
    case 'resource-swap':
      base.resource = { ...resource, url: 'https://api.safe.test/weather' };
      break;
    case 'unsupported-scheme':
      base.accepts = [offer({ scheme: 'upto' })];
      break;
    case 'long-timeout':
      base.accepts = [offer({ maxTimeoutSeconds: 3600 })];
      break;
    case 'payment-flow-swap':
      base.accepts = [offer({ extra: { name: 'USDC', version: '2', paymentFlow: 'upfront', assetTransferMethod: 'eip3009' } })];
      break;
    case 'transfer-method-swap':
      base.accepts = [offer({ extra: { name: 'USDC', version: '2', paymentFlow: 'authorization', assetTransferMethod: 'permit2' } })];
      break;
    case 'malicious-first-offer':
      base.accepts = [offer({ payTo: EVIL_PAYEE, amount: '1000' }), offer({ amount: '50000' })];
      break;
    case 'normal':
    case 'post-approval-swap':
    case 'replay':
      break;
    default:
      throw new Error(`Unknown scenario: ${scenarioId}`);
  }

  return base;
}

export const constants = { GOOD_PAYEE, EVIL_PAYEE, GOOD_ASSET, EVIL_ASSET, GOOD_NETWORK };
