import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { startSigner } from '../src/signer/server.js';
import { connectSignerWallet } from '../src/socket-wallet.js';
import { unlockWallet, WalletLockedError } from '../src/wallet.js';
import type { SignerPolicy } from '../src/signer/validate.js';
import type { TypedDataMessage } from '../src/wallet.js';

const KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const SELF = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const NOW = new Date('2026-08-12T00:00:00.000Z');
const VALID_BEFORE = BigInt(Math.floor(NOW.getTime() / 1000) + 3600);
const POLICY: SignerPolicy = {
  tokens: ['0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'],
  chainIds: [8453], maxValueAtomic: 5000n, maxValidityWindowSeconds: 86_400,
};
const PAYMENT: TypedDataMessage = {
  domain: { name: 'USD Coin', version: '2', chainId: 8453,
            verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' },
  types: { TransferWithAuthorization: [
    { name: 'from', type: 'address' }, { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' } ] },
  primaryType: 'TransferWithAuthorization',
  message: { from: SELF, to: '0x000000000000000000000000000000000000dEaD',
    value: 1000n, validAfter: 0n, validBefore: VALID_BEFORE,
    nonce: '0xf84e6d30534bfb2ec7380c923f5baea20e7bd3017a6c8e461c4354117112d9ad' },
};

describe('socket wallet', () => {
  let dir: string; let close: () => Promise<void>;
  let wallet: Awaited<ReturnType<typeof connectSignerWallet>>;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'purser-sw-'));
    const path = join(dir, 'signer.sock');
    const server = await startSigner(path, unlockWallet(KEY), POLICY, () => NOW);
    close = () => server.close();
    wallet = await connectSignerWallet(path);
  });

  afterEach(async () => { await close(); rmSync(dir, { recursive: true, force: true }); });

  it('adopts the signer address', () => {
    expect(wallet.address).toBe(SELF);
  });

  it('produces the same signature the local key would', async () => {
    const direct = await privateKeyToAccount(KEY).signTypedData(PAYMENT as never);
    expect(await wallet.signTypedData(PAYMENT)).toBe(direct);
  });

  it('surfaces a refusal as a thrown error rather than a bad signature', async () => {
    await expect(wallet.signTypedData({ ...PAYMENT,
      message: { ...PAYMENT.message, value: 999_999n } })).rejects.toThrow(/exceeds_signer_ceiling/u);
  });

  it('refuses locally once locked, without asking the signer', async () => {
    wallet.lock();
    expect(wallet.isUnlocked()).toBe(false);
    await expect(wallet.signTypedData(PAYMENT)).rejects.toThrow(WalletLockedError);
  });
});
