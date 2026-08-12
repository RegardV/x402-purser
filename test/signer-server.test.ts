import { createConnection } from 'node:net';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { startSigner } from '../src/signer/server.js';
import { decodeJson, encodeJson } from '../src/signer/protocol.js';
import { unlockWallet } from '../src/wallet.js';
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

function ask(path: string, request: unknown): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(path, () => socket.write(`${encodeJson(request)}\n`));
    let buffer = '';
    socket.on('data', (chunk) => {
      buffer += chunk.toString();
      if (buffer.includes('\n')) {
        socket.end();
        resolve(decodeJson(buffer.split('\n')[0]!) as Record<string, unknown>);
      }
    });
    socket.on('error', reject);
  });
}

describe('signer server', () => {
  let dir: string; let path: string; let close: () => Promise<void>;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'purser-signer-'));
    path = join(dir, 'signer.sock');
    const server = await startSigner(path, unlockWallet(KEY), POLICY, () => NOW);
    close = () => server.close();
  });

  afterEach(async () => { await close(); rmSync(dir, { recursive: true, force: true }); });

  it('reports its address', async () => {
    expect((await ask(path, { v: 1, op: 'address' }))['address']).toBe(SELF);
  });

  // The signature produced through the socket must be the one the key would have produced
  // directly. Anything else is an unspendable payment.
  it('signs a payment to the identical bytes as the local key', async () => {
    const direct = await privateKeyToAccount(KEY).signTypedData(PAYMENT as never);
    const reply = await ask(path, { v: 1, op: 'sign', payload: PAYMENT });
    expect(reply['signature']).toBe(direct);
  });

  it('refuses a transaction shaped payload', async () => {
    const reply = await ask(path, { v: 1, op: 'sign', payload: { ...PAYMENT,
      primaryType: 'Permit', types: { Permit: [{ name: 'owner', type: 'address' }] } } });
    expect(reply['signature']).toBeUndefined();
    expect(String(reply['error'])).toMatch(/not_a_payment/u);
  });

  it('refuses an unknown op rather than guessing', async () => {
    expect(String((await ask(path, { v: 1, op: 'sign_digest', digest: '0xdead' }))['error']))
      .toMatch(/unsupported_op/u);
  });

  it('rejects an unknown protocol version', async () => {
    expect(String((await ask(path, { v: 99, op: 'address' }))['error'])).toMatch(/version/u);
  });

  it('survives malformed input and keeps serving', async () => {
    expect(String((await ask(path, { nonsense: true }))['error'])).toMatch(/version/u);
    expect((await ask(path, { v: 1, op: 'address' }))['address']).toBe(SELF);
  });

  it('creates the socket 0660 so only the owner and its group can connect', () => {
    expect(statSync(path).mode & 0o777).toBe(0o660);
  });
});
