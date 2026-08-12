import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { startSigner } from '../src/signer/server.js';
import { connectSignerWallet } from '../src/socket-wallet.js';
import { pay } from '../src/pay.js';
import { openRepository } from '../src/storage.js';
import { AgentStore } from '../src/store.js';
import { AgentLedger } from '../src/ledger.js';
import { AllowanceStore } from '../src/allowance.js';
import { IntentStore } from '../src/intent.js';
import { signClaim } from '../src/credential.js';
import { unlockWallet } from '../src/wallet.js';
import type { SignerPolicy } from '../src/signer/validate.js';
import type { Envelope } from '../src/envelope.js';

const KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const ENVELOPE: Envelope = {
  spendCapAtomic: '5000', periodSeconds: 3600, maxPerTxAtomic: '2000',
  allowedHosts: ['api.example.com'], allowedCurrencies: ['USDC'], expiresAt: null,
};
const POLICY: SignerPolicy = {
  tokens: ['0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'],
  chainIds: [8453], maxValueAtomic: 5000n, maxValidityWindowSeconds: 86_400,
};

function requiredHeader(amount: string) {
  return Buffer.from(JSON.stringify({
    x402Version: 2, resource: { url: 'https://api.example.com/thing' },
    accepts: [{ scheme: 'exact', network: 'eip155:8453',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', amount,
      payTo: '0x000000000000000000000000000000000000dEaD', maxTimeoutSeconds: 3600,
      extra: { credentialTypes: ['authorization'], name: 'USD Coin', version: '2' } }],
  })).toString('base64');
}

describe('daemon paying through the signer process', () => {
  it('pays with the key in the other process, and the ledger records it', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'purser-split-'));
    const server = await startSigner(join(dir, 'signer.sock'), unlockWallet(KEY), POLICY);
    const wallet = await connectSignerWallet(server.path);

    const repo = openRepository(':memory:');
    const clock = new Date();
    repo.rawDatabase().prepare(`INSERT INTO principals (id, label, created_at) VALUES (1, 'p', '2026-01-01T00:00:00Z')`).run();
    const allowances = new AllowanceStore(repo, () => clock);
    allowances.set(1, { allowanceAtomic: '5000', periodSeconds: 3600, currency: 'USDC' });
    const store = new AgentStore(repo, allowances, () => clock);
    const issued = store.create(1, 'agent', ENVELOPE);
    const ledger = new AgentLedger(repo, () => clock);

    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(new Response('pay', { status: 402, headers: { 'PAYMENT-REQUIRED': requiredHeader('1000') } }))
      .mockResolvedValueOnce(new Response('goods', { status: 200 }));

    const claim = { agentRef: issued.agent.agentRef, resourceUrl: 'https://api.example.com/thing',
      ceilingAtomic: '2000', currency: 'USDC', nonce: 'split-1', timestamp: clock.toISOString() };

    const result = await pay(
      { store, ledger, allowances, intents: new IntentStore(repo, () => clock),
        now: () => clock, wallet, currencyForAsset: () => 'USDC' } as never,
      { claim, signature: signClaim(claim, issued.privateKeyPem), intentId: null },
      fetchImpl as never,
    );

    expect(result.status).toBe('paid');
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(1000n);

    repo.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  });
});
