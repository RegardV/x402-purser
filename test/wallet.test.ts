import { describe, expect, it } from 'vitest';
import { unlockWallet, WalletLockedError } from '../src/wallet.js';

// A well-known test key. Never used for real funds.
const KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';

const MESSAGE = {
  domain: {
    name: 'USD Coin',
    version: '2',
    chainId: 8453,
    verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  },
  types: {
    TransferWithAuthorization: [
      { name: 'from', type: 'address' },
      { name: 'to', type: 'address' },
      { name: 'value', type: 'uint256' },
      { name: 'validAfter', type: 'uint256' },
      { name: 'validBefore', type: 'uint256' },
      { name: 'nonce', type: 'bytes32' },
    ],
  },
  primaryType: 'TransferWithAuthorization',
  message: {
    from: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    to: '0x000000000000000000000000000000000000dEaD',
    value: 1000n,
    validAfter: 0n,
    validBefore: 1893456000n,
    nonce: '0x0000000000000000000000000000000000000000000000000000000000000001',
  },
};

describe('wallet', () => {
  it('exposes the address derived from the key', () => {
    const wallet = unlockWallet(KEY);
    expect(wallet.address.toLowerCase()).toBe('0x70997970c51812dc3a010c7d01b50e0d17dc79c8');
    expect(wallet.isUnlocked()).toBe(true);
  });

  it('signs typed data and returns a 65-byte signature', async () => {
    const wallet = unlockWallet(KEY);
    const signature = await wallet.signTypedData(MESSAGE);
    expect(signature).toMatch(/^0x[0-9a-f]{130}$/u);
  });

  it('refuses to sign once locked', async () => {
    const wallet = unlockWallet(KEY);
    wallet.lock();
    expect(wallet.isUnlocked()).toBe(false);
    await expect(wallet.signTypedData(MESSAGE)).rejects.toThrow(WalletLockedError);
  });

  it('rejects a malformed key rather than producing a bad address', () => {
    expect(() => unlockWallet('not-a-key')).toThrow();
    expect(() => unlockWallet('0x00')).toThrow();
  });
});
