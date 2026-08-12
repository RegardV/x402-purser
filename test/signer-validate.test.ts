import { describe, expect, it } from 'vitest';
import { SignerRefusedError, validateSigningRequest, type SignerPolicy } from '../src/signer/validate.js';
import type { TypedDataMessage } from '../src/wallet.js';

const SELF = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const NOW = new Date('2026-08-12T00:00:00.000Z');
const VALID_BEFORE = BigInt(Math.floor(NOW.getTime() / 1000) + 3600);

const POLICY: SignerPolicy = {
  tokens: ['0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'],
  chainIds: [8453],
  maxValueAtomic: 5000n,
  maxValidityWindowSeconds: 86_400,
};

const TYPES = { TransferWithAuthorization: [
  { name: 'from', type: 'address' }, { name: 'to', type: 'address' },
  { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' },
  { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' } ] };

function payment(overrides: Partial<TypedDataMessage> = {}): TypedDataMessage {
  return {
    domain: { name: 'USD Coin', version: '2', chainId: 8453,
              verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' },
    types: TYPES,
    primaryType: 'TransferWithAuthorization',
    message: { from: SELF, to: '0x000000000000000000000000000000000000dEaD',
      value: 1000n, validAfter: 0n, validBefore: VALID_BEFORE,
      nonce: '0xf84e6d30534bfb2ec7380c923f5baea20e7bd3017a6c8e461c4354117112d9ad' },
    ...overrides,
  };
}

function refusalCode(message: TypedDataMessage): string {
  try {
    validateSigningRequest(message, POLICY, SELF, NOW);
  } catch (cause) {
    if (cause instanceof SignerRefusedError) return cause.code;
    throw cause;
  }
  return 'ACCEPTED';
}

describe('signer validation', () => {
  it('accepts a payment inside policy', () => {
    expect(refusalCode(payment())).toBe('ACCEPTED');
  });

  // The whole point of the split. A compromised daemon must not get a transaction signed.
  it('refuses anything that is not a transfer authorization', () => {
    expect(refusalCode(payment({
      primaryType: 'Permit',
      types: { Permit: [{ name: 'owner', type: 'address' }, { name: 'spender', type: 'address' }] },
    }))).toBe('not_a_payment');
  });

  it('refuses an unknown token contract', () => {
    expect(refusalCode(payment({
      domain: { name: 'Evil', version: '1', chainId: 8453,
                verifyingContract: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' },
    }))).toBe('unknown_token');
  });

  it('refuses an unknown chain', () => {
    expect(refusalCode(payment({
      domain: { name: 'USD Coin', version: '2', chainId: 1,
                verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' },
    }))).toBe('unknown_chain');
  });

  it('refuses paying from an address that is not ours', () => {
    const m = payment();
    expect(refusalCode({ ...m, message: { ...m.message, from: '0x000000000000000000000000000000000000bEEF' } }))
      .toBe('wrong_payer');
  });

  it('refuses a value over the signer ceiling', () => {
    const m = payment();
    expect(refusalCode({ ...m, message: { ...m.message, value: 5001n } })).toBe('exceeds_signer_ceiling');
  });

  it('refuses an already expired authorization', () => {
    const m = payment();
    expect(refusalCode({ ...m, message: { ...m.message, validBefore: 1n } })).toBe('bad_validity_window');
  });

  it('refuses a validity window beyond the horizon', () => {
    const m = payment();
    const tooFar = BigInt(Math.floor(NOW.getTime() / 1000) + 86_401 + 60);
    expect(refusalCode({ ...m, message: { ...m.message, validBefore: tooFar } })).toBe('bad_validity_window');
  });

  // A tampered types block changes what the signature commits to while the message looks normal.
  it('refuses a tampered types block', () => {
    expect(refusalCode(payment({
      types: { TransferWithAuthorization: [
        { name: 'from', type: 'address' }, { name: 'to', type: 'address' },
        { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' },
        { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'uint256' } ] },
    }))).toBe('unexpected_types');
  });

  it('refuses extra types smuggled alongside the real one', () => {
    expect(refusalCode(payment({
      types: { ...TYPES, Permit: [{ name: 'owner', type: 'address' }] },
    }))).toBe('unexpected_types');
  });

  it('refuses a non bigint value, which would hash differently', () => {
    const m = payment();
    expect(refusalCode({ ...m, message: { ...m.message, value: '1000' } })).toBe('malformed_message');
  });
});
