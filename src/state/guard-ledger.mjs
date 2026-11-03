export class GuardLedger {
  constructor() {
    this.spentByDay = new Map();
    this.approvals = new Map();
    this.reservations = new Map();
    this.usedNonces = new Set();
    this.usedPermits = new Map();
    this.permitClaims = new Map();
    this.paymentHistory = [];
    this.knownRecipients = new Set();
  }

  dayKey(now = new Date()) {
    return now.toISOString().slice(0, 10);
  }

  spentToday(now = new Date()) {
    return this.spentByDay.get(this.dayKey(now)) ?? 0n;
  }

  pruneExpiredReservations(now = new Date()) {
    const nowSeconds = Math.floor(now.getTime() / 1000);
    for (const [id, reservation] of this.reservations) {
      if (nowSeconds > reservation.expiresAt) this.reservations.delete(id);
    }
  }

  reservedToday(now = new Date()) {
    this.pruneExpiredReservations(now);
    const day = this.dayKey(now);
    let total = 0n;
    for (const reservation of this.reservations.values()) {
      if (reservation.day === day) total += reservation.amount;
    }
    return total;
  }

  reserve(id, amount, limit, now = new Date(), expiresAt) {
    if (typeof id !== 'string' || !id) throw new Error('Approval ID is required');
    if (this.reservations.has(id)) throw new Error('Approval already has a budget reservation');
    const value = BigInt(amount);
    if (value <= 0n) throw new Error('Reservation amount must be positive');
    if (this.remainingBudget(limit, now) < value) throw new Error('Daily budget exhausted by pending approvals');
    this.reservations.set(id, { amount: value, day: this.dayKey(now), expiresAt: Number(expiresAt) });
  }

  getReservation(id, now = new Date()) {
    this.pruneExpiredReservations(now);
    return this.reservations.get(id) ?? null;
  }

  release(id) {
    if (!id) return false;
    return this.reservations.delete(id);
  }

  remainingBudget(limit, now = new Date()) {
    const remaining = BigInt(limit) - this.spentToday(now) - this.reservedToday(now);
    return remaining > 0n ? remaining : 0n;
  }

  recordSpend(amount, now = new Date(), recipient = null) {
    const value = BigInt(amount);
    const key = this.dayKey(now);
    this.spentByDay.set(key, this.spentToday(now) + value);
    const item = { at: now.getTime(), amount: value, recipient: recipient ? String(recipient).toLowerCase() : null };
    this.paymentHistory.push(item);
    if (item.recipient) this.knownRecipients.add(item.recipient);
  }

  recentPaymentCount(windowMs, now = new Date()) {
    const cutoff = now.getTime() - Number(windowMs);
    return this.paymentHistory.filter(item => item.at >= cutoff).length;
  }

  recentSpend(windowMs, now = new Date()) {
    const cutoff = now.getTime() - Number(windowMs);
    return this.paymentHistory.filter(item => item.at >= cutoff).reduce((sum, item) => sum + item.amount, 0n);
  }

  isKnownRecipient(recipient) {
    return this.knownRecipients.has(String(recipient).toLowerCase());
  }

  saveApproval(id, approval) {
    this.approvals.set(id, structuredClone(approval));
  }

  getApproval(id) {
    const value = this.approvals.get(id);
    return value ? structuredClone(value) : null;
  }

  markNonceUsed(nonce) {
    this.usedNonces.add(nonce);
  }

  isNonceUsed(nonce) {
    return this.usedNonces.has(nonce);
  }

  permitUses(permitId) {
    return this.usedPermits.get(permitId) ?? 0;
  }

  consumePermitForApproval(permitId, approvalId, maxUses) {
    if (typeof permitId !== 'string' || !permitId || typeof approvalId !== 'string' || !approvalId) {
      throw new Error('Permit and approval IDs are required');
    }
    if (!Number.isSafeInteger(maxUses) || maxUses < 1 || this.permitClaims.has(approvalId)) {
      throw new Error('Invalid permit use limit or duplicate approval');
    }
    const used = this.permitUses(permitId);
    if (used >= maxUses) throw new Error('Intent permit has no remaining uses');
    this.usedPermits.set(permitId, used + 1);
    this.permitClaims.set(approvalId, permitId);
  }

  hasPermitClaim(permitId, approvalId) {
    return this.permitClaims.get(approvalId) === permitId;
  }

  rollbackPermitClaim(approvalId) {
    const permitId = this.permitClaims.get(approvalId);
    if (!permitId) return;
    this.permitClaims.delete(approvalId);
    const used = this.permitUses(permitId);
    if (used <= 1) this.usedPermits.delete(permitId);
    else this.usedPermits.set(permitId, used - 1);
  }

  snapshot(policy, now = new Date()) {
    return {
      spentToday: this.spentToday(now).toString(),
      reservedToday: this.reservedToday(now).toString(),
      dailyBudget: String(policy.dailyBudget),
      remainingBudget: this.remainingBudget(policy.dailyBudget, now).toString(),
      approvalsIssued: this.approvals.size,
      usedNonces: this.usedNonces.size,
      usedPermits: [...this.usedPermits.values()].reduce((a,b)=>a+b,0),
      knownRecipients: this.knownRecipients.size,
      recentPayments1m: this.recentPaymentCount(60_000, now)
    };
  }
}
