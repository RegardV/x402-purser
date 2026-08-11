import { describe, expect, it } from 'vitest';
import {
  canonicalClaim,
  mintInstrumentKeypair,
  signClaim,
  verifyClaim,
  type PaymentClaim,
} from '../src/credential.js';

const CLAIM: PaymentClaim = {
  agentRef: 'abc',
  resourceUrl: 'https://api.example.com/x',
  ceilingAtomic: '100',
  currency: 'USDC',
  nonce: 'n-1',
  timestamp: '2026-01-01T00:00:00.000Z',
};

describe('instrument credentials', () => {
  it('verifies a signature made by the matching private key', () => {
    const keypair = mintInstrumentKeypair();
    expect(verifyClaim(CLAIM, signClaim(CLAIM, keypair.privateKeyPem), keypair.publicKeyPem)).toBe(true);
  });

  it('rejects a signature from a different instrument', () => {
    const a = mintInstrumentKeypair();
    const b = mintInstrumentKeypair();
    expect(verifyClaim(CLAIM, signClaim(CLAIM, a.privateKeyPem), b.publicKeyPem)).toBe(false);
  });

  it.each([
    ['agentRef', { agentRef: 'other' }],
    ['resourceUrl', { resourceUrl: 'https://evil.example.com/x' }],
    ['ceilingAtomic', { ceilingAtomic: '101' }],
    ['currency', { currency: 'WBTC' }],
    ['nonce', { nonce: 'n-2' }],
    ['timestamp', { timestamp: '2026-01-02T00:00:00.000Z' }],
  ])('rejects a signature when %s is altered', (_field, override) => {
    const keypair = mintInstrumentKeypair();
    const signature = signClaim(CLAIM, keypair.privateKeyPem);
    expect(verifyClaim({ ...CLAIM, ...override }, signature, keypair.publicKeyPem)).toBe(false);
  });

  it('produces a canonical form independent of key order', () => {
    const reordered: PaymentClaim = {
      timestamp: CLAIM.timestamp,
      nonce: CLAIM.nonce,
      currency: CLAIM.currency,
      ceilingAtomic: CLAIM.ceilingAtomic,
      resourceUrl: CLAIM.resourceUrl,
      agentRef: CLAIM.agentRef,
    };
    expect(canonicalClaim(reordered)).toBe(canonicalClaim(CLAIM));
  });

  it('returns false rather than throwing on a malformed signature', () => {
    const keypair = mintInstrumentKeypair();
    expect(verifyClaim(CLAIM, 'not-base64-!!', keypair.publicKeyPem)).toBe(false);
  });
});
