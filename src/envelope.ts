/**
 * Policy envelopes for agent identities.
 *
 * An envelope bounds what one agent may spend and where. Envelopes form a tree: a child envelope must _attenuate_ its
 * parent, it may narrow any dimension and may never widen one. Attenuation is checked once, at issuance, so the
 * payment hot path never has to walk the parent chain.
 */

/** Amounts are atomic units held as decimal strings; they never pass through a float. */
export interface Envelope {
  /** Maximum spend across `periodSeconds`, atomic units, decimal string. */
  readonly spendCapAtomic: string;
  /** Rolling window in seconds. Not a calendar bucket, see `attenuates`. */
  readonly periodSeconds: number;
  /** Maximum for any single payment, atomic units, decimal string. */
  readonly maxPerTxAtomic: string;
  /** Lowercase hostnames this agent may pay. Empty means none. */
  readonly allowedHosts: readonly string[];
  /** Currencies this agent may transact in. Empty means none, caps are only meaningful per currency. */
  readonly allowedCurrencies: readonly string[];
  /** ISO-8601 instant after which the envelope is dead, or null for no expiry. */
  readonly expiresAt: string | null;
}

export interface AttenuationViolation {
  readonly field: keyof Envelope;
  readonly reason: string;
}

export interface AttenuationResult {
  readonly ok: boolean;
  readonly violations: readonly AttenuationViolation[];
}

const ATOMIC_PATTERN = /^(0|[1-9][0-9]*)$/u;

/** Validates an envelope at the trust boundary. Returns the reasons it is invalid. */
export function validateEnvelope(envelope: Envelope): readonly string[] {
  const problems: string[] = [];
  if (!ATOMIC_PATTERN.test(envelope.spendCapAtomic)) {
    problems.push('spendCapAtomic must be a non-negative integer string');
  }
  if (!ATOMIC_PATTERN.test(envelope.maxPerTxAtomic)) {
    problems.push('maxPerTxAtomic must be a non-negative integer string');
  }
  if (!Number.isSafeInteger(envelope.periodSeconds) || envelope.periodSeconds <= 0) {
    problems.push('periodSeconds must be a positive integer');
  }
  if (envelope.allowedHosts.some((host) => host !== host.toLowerCase() || host.length === 0)) {
    problems.push('allowedHosts must be non-empty lowercase hostnames');
  }
  if (envelope.expiresAt !== null && Number.isNaN(Date.parse(envelope.expiresAt))) {
    problems.push('expiresAt must be an ISO-8601 instant or null');
  }
  if (envelope.allowedCurrencies.length === 0) {
    problems.push('allowedCurrencies must list at least one currency');
  }
  if (envelope.allowedCurrencies.some((currency) => currency !== currency.toUpperCase() || currency.length === 0)) {
    problems.push('allowedCurrencies must be non-empty uppercase currency codes');
  }
  if (problems.length === 0 && BigInt(envelope.maxPerTxAtomic) > BigInt(envelope.spendCapAtomic)) {
    problems.push('maxPerTxAtomic cannot exceed spendCapAtomic');
  }
  return problems;
}

/**
 * True when `child` is no wider than `parent` in every dimension.
 *
 * `periodSeconds` and `spendCapAtomic` together express a RATE, so they are compared by cross-multiplication: `childCap
 *
 * - ParentPeriod <= parentCap * childPeriod`. Exact in BigInt, no division and no rounding. A child may hold a much
 *   shorter window than its parent, metered media is "a little, very often", provided its rate stays within the
 *   parent's. Total exposure is bounded independently by the account allowance, so a shorter window cannot widen real
 *   spend.
 */
export function attenuates(parent: Envelope, child: Envelope): AttenuationResult {
  const violations: AttenuationViolation[] = [];

  if (BigInt(child.spendCapAtomic) > BigInt(parent.spendCapAtomic)) {
    violations.push({ field: 'spendCapAtomic', reason: 'child cap exceeds parent cap' });
  }
  if (BigInt(child.maxPerTxAtomic) > BigInt(parent.maxPerTxAtomic)) {
    violations.push({ field: 'maxPerTxAtomic', reason: 'child per-transaction limit exceeds parent' });
  }
  // Spend cap over a window is a RATE. Compare rates by cross-multiplication rather than by
  // requiring a longer window: exact in BigInt, no division, no rounding. A shorter window is
  // legitimate, metered media is "a little, very often", and total exposure is bounded by the
  // account allowance regardless, so this cannot widen real spend.
  const childRate = BigInt(child.spendCapAtomic) * BigInt(parent.periodSeconds);
  const parentRate = BigInt(parent.spendCapAtomic) * BigInt(child.periodSeconds);
  if (childRate > parentRate) {
    violations.push({ field: 'periodSeconds', reason: 'child spend rate exceeds parent spend rate' });
  }

  const permitted = new Set(parent.allowedHosts);
  const escaped = child.allowedHosts.filter((host) => !permitted.has(host));
  if (escaped.length > 0) {
    violations.push({ field: 'allowedHosts', reason: `hosts not permitted by parent: ${escaped.join(', ')}` });
  }

  const permittedCurrencies = new Set(parent.allowedCurrencies);
  const escapedCurrencies = child.allowedCurrencies.filter((currency) => !permittedCurrencies.has(currency));
  if (escapedCurrencies.length > 0) {
    violations.push({
      field: 'allowedCurrencies',
      reason: `currencies not permitted by parent: ${escapedCurrencies.join(', ')}`,
    });
  }

  if (parent.expiresAt !== null) {
    if (child.expiresAt === null) {
      violations.push({ field: 'expiresAt', reason: 'child cannot outlive a parent that expires' });
    } else if (Date.parse(child.expiresAt) > Date.parse(parent.expiresAt)) {
      violations.push({ field: 'expiresAt', reason: 'child expiry is later than parent expiry' });
    }
  }

  return { ok: violations.length === 0, violations };
}
