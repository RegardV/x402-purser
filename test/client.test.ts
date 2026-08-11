import { describe, expect, it } from 'vitest';
import { buildClient } from '../src/client.js';
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
const REQUIREMENTS = {
  scheme: 'exact',
  network: 'eip155:8453',
  asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  amount: '1000',
  payTo: '0x000000000000000000000000000000000000dEaD',
  maxTimeoutSeconds: 3600,
};

function harness(price: string) {
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
  const claim = {
    agentRef: issued.agent.agentRef,
    resourceUrl: 'https://api.example.com/thing',
    ceilingAtomic: '2000',
    currency: 'USDC',
    nonce: `n-${price}`,
    timestamp: clock.toISOString(),
  };
  const deps = {
    store,
    ledger: new AgentLedger(repo, () => clock),
    allowances,
    intents: new IntentStore(repo, () => clock),
    now: () => clock,
    wallet: unlockWallet(KEY),
    currencyForAsset: () => 'USDC',
  };
  const pending = { claim, signature: signClaim(claim, issued.privateKeyPem), intentId: null };
  return { deps, pending, repo, requirements: { ...REQUIREMENTS, amount: price } };
}

function hookOf(client: unknown): (c: unknown) => Promise<unknown> {
  const hooks = (client as { beforePaymentCreationHooks: ((c: unknown) => Promise<unknown>)[] })
    .beforePaymentCreationHooks;
  const hook = hooks[0];
  if (hook === undefined) throw new Error('no before-payment hook registered');
  return hook;
}

describe('purser x402 client', () => {
  it('admits a compliant quote and records the decision', async () => {
    const { deps, pending, requirements, repo } = harness('1000');
    const { client, decisions } = buildClient(deps, pending);
    const result = await hookOf(client)({ paymentRequired: {}, selectedRequirements: requirements });
    expect(result).toBeUndefined();
    expect(decisions).toHaveLength(1);
    expect(decisions[0]?.quote.priceAtomic).toBe('1000');
    repo.close();
  });

  it('aborts with a reason when the quote exceeds the intent ceiling', async () => {
    const { deps, pending, requirements, repo } = harness('3000');
    const { client, decisions } = buildClient(deps, pending);
    const result = (await hookOf(client)({ paymentRequired: {}, selectedRequirements: requirements })) as {
      abort: true;
      reason: string;
    };
    expect(result.abort).toBe(true);
    expect(result.reason).toMatch(/exceeds_intent_ceiling/u);
    expect(decisions).toHaveLength(0);
    repo.close();
  });

  it('aborts rather than throwing, so the client can report the reason', async () => {
    const { deps, pending, requirements, repo } = harness('9999');
    const { client } = buildClient(deps, pending);
    await expect(
      hookOf(client)({ paymentRequired: {}, selectedRequirements: requirements }),
    ).resolves.toMatchObject({ abort: true });
    repo.close();
  });
});
