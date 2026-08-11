import { describe, expect, it } from 'vitest';
import { quoteFromRequirements } from '../src/gate.js';

const REQUIREMENTS = {
  scheme: 'exact',
  network: 'eip155:8453',
  asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  amount: '1000',
  payTo: '0x000000000000000000000000000000000000dEaD',
  maxTimeoutSeconds: 3600,
  extra: { name: 'USD Coin', version: '2' },
};

describe('quoteFromRequirements', () => {
  it('carries price, recipient and asset straight from the seller response', () => {
    const quote = quoteFromRequirements(REQUIREMENTS as never, 'USDC');
    expect(quote.priceAtomic).toBe('1000');
    expect(quote.payTo).toBe('0x000000000000000000000000000000000000dEaD');
    expect(quote.asset).toBe('0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913');
    expect(quote.network).toBe('eip155:8453');
    expect(quote.currency).toBe('USDC');
  });

  it('derives validBefore from maxTimeoutSeconds', () => {
    const now = 1_800_000_000_000;
    const quote = quoteFromRequirements(REQUIREMENTS as never, 'USDC', () => new Date(now));
    expect(quote.validBefore).toBe(Math.floor(now / 1000) + 3600);
  });

  it('refuses requirements whose amount is not an atomic integer string', () => {
    expect(() => quoteFromRequirements({ ...REQUIREMENTS, amount: '1.5' } as never, 'USDC')).toThrow();
    expect(() => quoteFromRequirements({ ...REQUIREMENTS, amount: '-1' } as never, 'USDC')).toThrow();
  });

  it('refuses a scheme other than exact', () => {
    expect(() =>
      quoteFromRequirements({ ...REQUIREMENTS, scheme: 'batch-settlement' } as never, 'USDC'),
    ).toThrow(/scheme/u);
  });
});
