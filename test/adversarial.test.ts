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
  spendCapAtomic: '5000',
  periodSeconds: 3600,
  maxPerTxAtomic: '2000',
  allowedHosts: ['api.example.com'],
  allowedCurrencies: ['USDC'],
  expiresAt: null,
};

// The shape matters. Without resource and credentialTypes the x402 library throws while building
// the payload, every case below would return 'refused' for that reason instead of the gate's, and
// the whole suite would pass without ever exercising the gate.
function requiredHeader(amount: string, payTo = '0x000000000000000000000000000000000000dEaD') {
  return Buffer.from(
    JSON.stringify({
      x402Version: 2,
      resource: { url: 'https://api.example.com/thing' },
      accepts: [
        {
          scheme: 'exact',
          network: 'eip155:8453',
          asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
          amount,
          payTo,
          maxTimeoutSeconds: 3600,
          extra: { credentialTypes: ['authorization'], name: 'USD Coin', version: '2' },
        },
      ],
    }),
  ).toString('base64');
}

function harness() {
  const repo = openRepository(':memory:');
  const clock = new Date('2026-01-01T00:00:00.000Z');
  repo.rawDatabase().prepare(`INSERT INTO principals (id, label, created_at) VALUES (1, 'p', '2026-01-01T00:00:00Z')`).run();
  const allowances = new AllowanceStore(repo, () => clock);
  allowances.set(1, { allowanceAtomic: '5000', periodSeconds: 3600, currency: 'USDC' });
  const store = new AgentStore(repo, allowances, () => clock);
  const a = store.create(1, 'agent-a', ENVELOPE);
  const b = store.create(1, 'agent-b', ENVELOPE);
  const ledger = new AgentLedger(repo, () => clock);
  const deps = {
    store,
    ledger,
    allowances,
    intents: new IntentStore(repo, () => clock),
    now: () => clock,
    wallet: unlockWallet(KEY),
    currencyForAsset: () => 'USDC',
  };
  return { deps, repo, ledger, a, b, clock };
}

function claimFor(agentRef: string, ceiling: string, nonce: string, clock: Date, host = 'api.example.com') {
  return {
    agentRef,
    resourceUrl: `https://${host}/thing`,
    ceilingAtomic: ceiling,
    currency: 'USDC',
    nonce,
    timestamp: clock.toISOString(),
  };
}

function fetchReturning(amount: string, payTo?: string) {
  return vi
    .fn()
    .mockResolvedValueOnce(new Response('pay', { status: 402, headers: { 'PAYMENT-REQUIRED': requiredHeader(amount, payTo) } }))
    .mockResolvedValueOnce(new Response('goods', { status: 200 }));
}

describe('adversarial', () => {
  // The control. If this ever stops paying, every refusal below proves nothing.
  it('a payment inside the envelope succeeds', async () => {
    const { deps, a, ledger, clock, repo } = harness();
    const claim = claimFor(a.agent.agentRef, '2000', 'n-0', clock);
    const result = await pay(deps, { claim, signature: signClaim(claim, a.privateKeyPem), intentId: null }, fetchReturning('1000') as never);
    expect(result.status).toBe('paid');
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(1000n);
    repo.close();
  });

  it('agent A cannot spend using agent B identity', async () => {
    const { deps, a, b, ledger, clock, repo } = harness();
    const claim = claimFor(b.agent.agentRef, '2000', 'n-1', clock);
    // signed with A's key, claiming to be B
    const result = await pay(deps, { claim, signature: signClaim(claim, a.privateKeyPem), intentId: null }, fetchReturning('1000') as never);
    expect(result.status).toBe('refused');
    if (result.status === 'refused') expect(result.reason).toMatch(/bad_signature/u);
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(0n);
    repo.close();
  });

  it('a host outside the envelope is refused even with a valid signature', async () => {
    const { deps, a, ledger, clock, repo } = harness();
    const claim = claimFor(a.agent.agentRef, '2000', 'n-2', clock, 'evil.example.com');
    const result = await pay(deps, { claim, signature: signClaim(claim, a.privateKeyPem), intentId: null }, fetchReturning('1000') as never);
    expect(result.status).toBe('refused');
    if (result.status === 'refused') expect(result.reason).toMatch(/host_not_allowed/u);
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(0n);
    repo.close();
  });

  it('a seller quoting above the envelope is refused, whatever the agent claimed', async () => {
    const { deps, a, clock, repo } = harness();
    // the agent asks for a ceiling above its own envelope; the envelope still wins
    const claim = claimFor(a.agent.agentRef, '99999', 'n-3', clock);
    const result = await pay(deps, { claim, signature: signClaim(claim, a.privateKeyPem), intentId: null }, fetchReturning('4000') as never);
    expect(result.status).toBe('refused');
    if (result.status === 'refused') expect(result.reason).toMatch(/exceeds_per_transaction_limit/u);
    repo.close();
  });

  it('the account allowance bounds the sum across agents', async () => {
    const { deps, a, b, ledger, clock, repo } = harness();
    for (const [agent, key, nonce] of [
      [a.agent.agentRef, a.privateKeyPem, 'n-a1'],
      [a.agent.agentRef, a.privateKeyPem, 'n-a2'],
      [b.agent.agentRef, b.privateKeyPem, 'n-b1'],
    ] as const) {
      const claim = claimFor(agent, '2000', nonce, clock);
      await pay(deps, { claim, signature: signClaim(claim, key), intentId: null }, fetchReturning('2000') as never);
    }
    // 3 x 2000 = 6000 requested against a 5000 allowance
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBeLessThanOrEqual(5000n);
    // and the pool really was used, so the bound is not passing because everything refused
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(4000n);
    repo.close();
  });

  it('a revoked agent cannot spend', async () => {
    const { deps, a, ledger, clock, repo } = harness();
    deps.store.revoke(1, a.agent.agentRef);
    const claim = claimFor(a.agent.agentRef, '2000', 'n-5', clock);
    const result = await pay(deps, { claim, signature: signClaim(claim, a.privateKeyPem), intentId: null }, fetchReturning('1000') as never);
    expect(result.status).toBe('refused');
    if (result.status === 'refused') expect(result.reason).toMatch(/agent_revoked/u);
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(0n);
    repo.close();
  });

  it('a locked wallet cannot sign, and no reservation is left stranded', async () => {
    const { deps, a, ledger, clock, repo } = harness();
    deps.wallet.lock();
    const claim = claimFor(a.agent.agentRef, '2000', 'n-6', clock);
    const result = await pay(deps, { claim, signature: signClaim(claim, a.privateKeyPem), intentId: null }, fetchReturning('1000') as never);
    expect(result.status).not.toBe('paid');
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(0n);
    repo.close();
  });
});
