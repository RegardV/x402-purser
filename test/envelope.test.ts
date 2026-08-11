import { describe, expect, it } from 'vitest';
import { attenuates, validateEnvelope, type Envelope } from '../src/envelope.js';

const parent: Envelope = {
  spendCapAtomic: '1000000',
  periodSeconds: 86_400,
  maxPerTxAtomic: '100000',
  allowedHosts: ['api.example.com', 'data.example.com'],
  allowedCurrencies: ['USDC'],
  expiresAt: '2026-12-31T00:00:00.000Z',
};

function child(overrides: Partial<Envelope> = {}): Envelope {
  return { ...parent, ...overrides };
}

describe('validateEnvelope', () => {
  it('accepts a well-formed envelope', () => {
    expect(validateEnvelope(parent)).toEqual([]);
  });

  it('rejects non-integer, negative, and float-shaped amounts', () => {
    expect(validateEnvelope(child({ spendCapAtomic: '1.5' }))).not.toEqual([]);
    expect(validateEnvelope(child({ spendCapAtomic: '-1' }))).not.toEqual([]);
    expect(validateEnvelope(child({ maxPerTxAtomic: '1e3' }))).not.toEqual([]);
  });

  it('rejects a non-positive period', () => {
    expect(validateEnvelope(child({ periodSeconds: 0 }))).not.toEqual([]);
  });

  it('rejects uppercase or empty hosts', () => {
    expect(validateEnvelope(child({ allowedHosts: ['API.example.com'] }))).not.toEqual([]);
    expect(validateEnvelope(child({ allowedHosts: [''] }))).not.toEqual([]);
  });

  it('rejects an unparseable expiry', () => {
    expect(validateEnvelope(child({ expiresAt: 'whenever' }))).not.toEqual([]);
  });

  it('rejects a per-transaction limit above the total cap', () => {
    expect(validateEnvelope(child({ maxPerTxAtomic: '2000000' }))).not.toEqual([]);
  });
});

describe('attenuates', () => {
  it('accepts an identical envelope', () => {
    expect(attenuates(parent, child()).ok).toBe(true);
  });

  it('accepts a strictly narrower envelope', () => {
    const narrower = child({
      spendCapAtomic: '500000',
      maxPerTxAtomic: '1000',
      periodSeconds: 172_800,
      allowedHosts: ['api.example.com'],
      expiresAt: '2026-06-30T00:00:00.000Z',
    });
    expect(attenuates(parent, narrower).ok).toBe(true);
  });

  it.each([
    ['spendCapAtomic', child({ spendCapAtomic: '1000001' })],
    ['maxPerTxAtomic', child({ maxPerTxAtomic: '100001' })],
    ['periodSeconds', child({ periodSeconds: 3600 })],
    ['allowedHosts', child({ allowedHosts: ['api.example.com', 'evil.example.com'] })],
    ['expiresAt', child({ expiresAt: '2027-01-01T00:00:00.000Z' })],
  ])('rejects a child that widens %s', (field, widened) => {
    const result = attenuates(parent, widened);
    expect(result.ok).toBe(false);
    expect(result.violations.map((violation) => violation.field)).toContain(field);
  });

  it('rejects a child with no expiry under a parent that expires', () => {
    const result = attenuates(parent, child({ expiresAt: null }));
    expect(result.ok).toBe(false);
    expect(result.violations.map((violation) => violation.field)).toContain('expiresAt');
  });

  it('allows a child with no expiry when the parent never expires', () => {
    const immortal = child({ expiresAt: null });
    expect(attenuates(immortal, child({ expiresAt: null })).ok).toBe(true);
  });

  it('reports every violated field at once, not just the first', () => {
    const result = attenuates(
      parent,
      child({ spendCapAtomic: '9999999', maxPerTxAtomic: '999999', periodSeconds: 60 }),
    );
    expect(result.violations.length).toBeGreaterThanOrEqual(3);
  });

  it('refuses a child that truly out-burns its parent by refilling faster', () => {
    // Parent 1000 per hour; child 900 per minute is 54000 per hour. The cap check alone
    // passes (900 <= 1000), only the period check catches this.
    const hourly = { ...parent, spendCapAtomic: '1000', periodSeconds: 3600 };
    const perMinute = { ...hourly, spendCapAtomic: '900', periodSeconds: 60 };
    const result = attenuates(hourly, perMinute);
    expect(result.ok).toBe(false);
    expect(result.violations.map((violation) => violation.field)).toContain('periodSeconds');
  });

  it('rejects an envelope with no currencies', () => {
    expect(validateEnvelope(child({ allowedCurrencies: [] }))).not.toEqual([]);
  });

  it('rejects a child that adds a currency its parent does not allow', () => {
    const result = attenuates(parent, child({ allowedCurrencies: ['USDC', 'WBTC'] }));
    expect(result.ok).toBe(false);
    expect(result.violations.map((violation) => violation.field)).toContain('allowedCurrencies');
  });

  it('accepts a child that narrows the currency set', () => {
    const wide = child({ allowedCurrencies: ['USDC', 'PYUSD'] });
    expect(attenuates(wide, child({ allowedCurrencies: ['USDC'] })).ok).toBe(true);
  });

  it('accepts a shorter window whose rate is within the parent', () => {
    // 1 per second under 100 per minute is 60/min against 100/min. Rate-safe, and the old
    // longer-window rule refused it outright, which forbade metered media entirely.
    const perMinute = { ...parent, spendCapAtomic: '100', periodSeconds: 60 };
    const perSecond = { ...perMinute, spendCapAtomic: '1', periodSeconds: 1 };
    expect(attenuates(perMinute, perSecond).ok).toBe(true);
  });
});
