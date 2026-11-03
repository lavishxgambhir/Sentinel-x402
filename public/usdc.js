export const USDC_DECIMALS = 6;

// Exact decimal-string conversion; never use JavaScript floating-point math for
// user-entered token amounts.
export function usdcToAtomic(value, label = 'Amount') {
  const input = String(value ?? '').trim();
  if (!/^\d+(?:\.\d+)?$/.test(input)) {
    throw new Error(`${label} must be a non-negative USDC amount, such as 0.05`);
  }
  const [whole, fraction = ''] = input.split('.');
  if (fraction.length > USDC_DECIMALS) {
    throw new Error(`${label} supports at most ${USDC_DECIMALS} decimal places`);
  }
  const atomic = `${whole.replace(/^0+(?=\d)/, '')}${fraction.padEnd(USDC_DECIMALS, '0')}`
    .replace(/^0+(?=\d)/, '');
  return atomic || '0';
}

export function atomicToUsdc(value) {
  const atomic = String(value ?? '').trim();
  if (!/^\d+$/.test(atomic)) return '';
  const padded = atomic.padStart(USDC_DECIMALS + 1, '0');
  const whole = padded.slice(0, -USDC_DECIMALS);
  const fraction = padded.slice(-USDC_DECIMALS).replace(/0+$/, '');
  return fraction ? `${whole}.${fraction}` : whole;
}
