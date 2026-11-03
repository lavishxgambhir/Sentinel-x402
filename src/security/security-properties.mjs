export const securityProperties = Object.freeze([
  { id: 'P1', name: 'Valid x402 request', codes: ['MALFORMED_REQUEST', 'MALFORMED_REQUIREMENTS', 'MALFORMED_AUTHORIZATION', 'INVALID_RESOURCE_URL'] },
  { id: 'P2', name: 'Resource binding', codes: ['RESOURCE_BINDING', 'ALLOWED_PATH', 'KNOWN_MERCHANT', 'PERMIT_RESOURCE_ORIGIN', 'PERMIT_RESOURCE_PATH', 'PERMIT_RESOURCE_URL', 'PERMIT_METHOD'] },
  { id: 'P3', name: 'Counterparty binding', codes: ['RECIPIENT', 'INTENT_RECIPIENT', 'SETTLED_RECIPIENT', 'FROM'] },
  { id: 'P4', name: 'Amount and budget', codes: ['POSITIVE_AMOUNT', 'AMOUNT_LIMIT', 'INTENT_AMOUNT', 'BUDGET', 'RESERVATION', 'SETTLED_AMOUNT'] },
  { id: 'P5', name: 'Payment capabilities', codes: ['SCHEME', 'PAYMENT_FLOW', 'TRANSFER_METHOD', 'NETWORK', 'ASSET', 'INTENT_SCHEME', 'INTENT_FLOW', 'INTENT_TRANSFER_METHOD', 'INTENT_NETWORK', 'INTENT_ASSET', 'SETTLED_NETWORK', 'SETTLED_ASSET'] },
  { id: 'P6', name: 'Time and replay', codes: ['TIMEOUT', 'INTENT_TIMEOUT', 'TIME_WINDOW', 'INVALID_EVALUATION_TIME', 'UNTRUSTED_TIMESTAMP', 'NONCE', 'REPLAY', 'PERMIT_REPLAY', 'PERMIT_USES'] },
  { id: 'P7', name: 'Signed intent', codes: ['PERMIT_REQUIRED', 'PERMIT_AUTHORITY', 'PERMIT_SIGNATURE', 'PERMIT_SUBJECT', 'PERMIT_POLICY_DIGEST', 'PERMIT_TIME', 'POLICY_DIGEST'] },
  { id: 'P8', name: 'Wallet relationship review', codes: ['COMPLIANCE', 'WALLET_CLOSURE', 'WALLET_RELATIONSHIP_REVIEW'] },
  { id: 'P9', name: 'Settlement correspondence', codes: ['APPROVAL_BINDING', 'RESOURCE_BINDING', 'AMOUNT', 'RECIPIENT', 'SETTLED_AMOUNT', 'SETTLED_RECIPIENT', 'SETTLED_NETWORK', 'SETTLED_ASSET'] }
]);

const byCode = new Map();
for (const property of securityProperties) {
  for (const code of property.codes) {
    const entries = byCode.get(code) ?? [];
    entries.push({ id: property.id, name: property.name });
    byCode.set(code, entries);
  }
}

export function propertyTagsFor(reasonCodes = [], checks = []) {
  const codes = new Set([
    ...(Array.isArray(reasonCodes) ? reasonCodes : []),
    ...(Array.isArray(checks) ? checks.map(check => check?.code).filter(Boolean) : [])
  ]);
  const tags = new Map();
  for (const code of codes) for (const property of byCode.get(code) ?? []) tags.set(property.id, property);
  return [...tags.values()].sort((a, b) => a.id.localeCompare(b.id));
}
