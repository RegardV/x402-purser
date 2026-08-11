import { describe, expect, it, vi } from 'vitest';
import { pay } from '../src/pay.js';
import { openRepository } from '../src/storage.js';
import { AgentStore } from '../src/store.js';
import { AgentLedger } from '../src/ledger.js';
import { AllowanceStore } from '../src/allowance.js';
import { IntentStore } from '../src/intent.js';
import { signClaim } from '../src/credential.js';
import { unlockWallet } from '../src/wallet.js';
import type { Envelope } from '../src/envelope.js';

const KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const ENVELOPE: Envelope = {
  spendCapAtomic: '10000',
  periodSeconds: 3600,
  maxPerTxAtomic: '5000',
  allowedHosts: ['api.example.com'],
  allowedCurrencies: ['USDC'],
  expiresAt: null,
};

function harness(ceiling = '2000') {
  const repo = openRepository(':memory:');
  const clock = new Date('2026-01-01T00:00:00.000Z');
  repo
    .rawDatabase()
    .prepare(`INSERT INTO principals (id, label, created_at) VALUES (1, 'p', '2026-01-01T00:00:00Z')`)
    .run();
  const allowances = new AllowanceStore(repo, () => clock);
  allowances.set(1, { allowanceAtomic: '10000', periodSeconds: 3600, currency: 'USDC' });
  const store = new AgentStore(repo, allowances, () => clock);
  const issued = store.create(1, 'agent', ENVELOPE);
  const ledger = new AgentLedger(repo, () => clock);
  const claim = {
    agentRef: issued.agent.agentRef,
    resourceUrl: 'https://api.example.com/thing',
    ceilingAtomic: ceiling,
    currency: 'USDC',
    nonce: `n-${ceiling}`,
    timestamp: clock.toISOString(),
  };
  const deps = {
    store,
    ledger,
    allowances,
    intents: new IntentStore(repo, () => clock),
    now: () => clock,
    wallet: unlockWallet(KEY),
    currencyForAsset: () => 'USDC',
  };
  return {
    deps,
    repo,
    ledger,
    pending: { claim, signature: signClaim(claim, issued.privateKeyPem), intentId: null },
  };
}

const REQUIRED = Buffer.from(
  JSON.stringify({
    x402Version: 2,
    // Shape copied from real Bazaar entries: resource at the top level, and credentialTypes in
    // extra. Omitting either makes createPaymentPayload throw.
    resource: { url: 'https://api.example.com/thing' },
    accepts: [
      {
        scheme: 'exact',
        network: 'eip155:8453',
        asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        amount: '1000',
        payTo: '0x000000000000000000000000000000000000dEaD',
        maxTimeoutSeconds: 3600,
        extra: { credentialTypes: ['authorization'], name: 'USD Coin', version: '2' },
      },
    ],
  }),
).toString('base64');

function stubFetch(second: { status: number; body: string }) {
  return vi
    .fn()
    .mockResolvedValueOnce(
      new Response('payment required', { status: 402, headers: { 'PAYMENT-REQUIRED': REQUIRED } }),
    )
    .mockResolvedValueOnce(new Response(second.body, { status: second.status }));
}

describe('pay', () => {
  it('returns the resource and confirms the reservation when the seller accepts', async () => {
    const { deps, pending, ledger, repo } = harness();
    const result = await pay(deps, pending, stubFetch({ status: 200, body: 'the goods' }) as never);
    expect(result.status).toBe('paid');
    if (result.status === 'paid') expect(result.body).toBe('the goods');
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(1000n);
    repo.close();
  });

  it('releases the reservation when the seller rejects the payment', async () => {
    const { deps, pending, ledger, repo } = harness();
    const result = await pay(deps, pending, stubFetch({ status: 402, body: 'still unpaid' }) as never);
    expect(result.status).toBe('seller_error');
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(0n);
    repo.close();
  });

  it('refuses after the probe but before the replay when the quote exceeds the ceiling', async () => {
    const { deps, pending, ledger, repo } = harness('500');
    const fetchImpl = stubFetch({ status: 200, body: 'never reached' });
    const result = await pay(deps, pending, fetchImpl as never);
    expect(result.status).toBe('refused');
    // the probe is how the quote is obtained, so exactly one call; the replay never happens
    expect((fetchImpl as unknown as { mock: { calls: unknown[] } }).mock.calls).toHaveLength(1);
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(0n);
    repo.close();
  });

  it('passes through a resource that needs no payment', async () => {
    const { deps, pending, repo } = harness();
    const fetchImpl = vi.fn().mockResolvedValue(new Response('free goods', { status: 200 }));
    const result = await pay(deps, pending, fetchImpl as never);
    expect(result.status).toBe('free');
    repo.close();
  });
});
