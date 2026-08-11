import { createRequire } from 'node:module';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  AgentLedger,
  AgentStore,
  AllowanceStore,
  IntentStore,
  signClaim,
  type Envelope,
  type PaymentClaim,
} from '../src/index.js';
import { admit, GateRefusedError, type GateDeps, type Quote } from '../src/gate.js';

interface TestDb {
  close(): void;
  exec(sql: string): void;
  prepare(sql: string): {
    all(...v: unknown[]): unknown[];
    get(...v: unknown[]): unknown;
    run(...v: unknown[]): unknown;
  };
}
const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as {
  DatabaseSync: new (filename: string) => TestDb;
};

const ENVELOPE: Envelope = {
  spendCapAtomic: '1000',
  periodSeconds: 3600,
  maxPerTxAtomic: '400',
  allowedHosts: ['api.example.com'],
  allowedCurrencies: ['USDC'],
  expiresAt: '2026-12-31T00:00:00.000Z',
};

const QUOTE: Quote = {
  priceAtomic: '100',
  currency: 'USDC',
  payTo: '0x000000000000000000000000000000000000dEaD',
  asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  network: 'base',
  validBefore: 1893456000,
};

describe('policy gate', () => {
  let tmpDir: string;
  let db: TestDb;
  let deps: GateDeps;
  let store: AgentStore;
  let ledger: AgentLedger;
  let agentRef: string;
  let privateKeyPem: string;
  let otherKeyPem: string;
  let clock: Date;
  let counter = 0;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'purser-gate-'));
    db = new DatabaseSync(join(tmpDir, 'test.sqlite3'));
    db.exec(`
      PRAGMA foreign_keys = ON;
      CREATE TABLE agents (
        id INTEGER PRIMARY KEY, principal_id INTEGER NOT NULL, agent_ref TEXT NOT NULL,
        label TEXT NOT NULL, parent_agent_id INTEGER REFERENCES agents(id) ON DELETE CASCADE,
        payload_version INTEGER NOT NULL, payload BLOB NOT NULL, public_key TEXT, payload_mac TEXT,
        envelope_version INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL, revoked_at TEXT, UNIQUE(principal_id, agent_ref)
      );
      CREATE TABLE intents (
        id INTEGER PRIMARY KEY, principal_id INTEGER NOT NULL, agent_id INTEGER NOT NULL,
        resource_url TEXT NOT NULL, ceiling_atomic TEXT NOT NULL, currency TEXT NOT NULL,
        envelope_version INTEGER NOT NULL, refund_rule TEXT NOT NULL DEFAULT 'dispute_only',
        created_at TEXT NOT NULL
      );
      CREATE TABLE agent_ledger (
        id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL, principal_id INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('reserved','confirmed','released','in_doubt','disputed')),
        amount_atomic TEXT NOT NULL, currency TEXT NOT NULL,
        clock_source TEXT NOT NULL DEFAULT 'server',
        intent_id INTEGER, attempt_no INTEGER NOT NULL DEFAULT 1,
        authorization_nonce TEXT, typed_data_hash TEXT, signature TEXT,
        resource_url TEXT, transaction_ref TEXT, reserved_at TEXT NOT NULL, settled_at TEXT
      );
      CREATE TABLE principal_allowance (
        principal_id INTEGER PRIMARY KEY, allowance_atomic TEXT NOT NULL,
        period_seconds INTEGER NOT NULL, currency TEXT NOT NULL,
        payload_mac TEXT NOT NULL, updated_at TEXT NOT NULL
      );
    `);
    let depth = 0;
    const repository = {
      writeTransactionSync<T>(work: () => T): T {
        if (depth > 0) return work();
        db.exec('BEGIN IMMEDIATE');
        depth += 1;
        try {
          const r = work();
          db.exec('COMMIT');
          return r;
        } catch (cause) {
          db.exec('ROLLBACK');
          throw cause;
        } finally {
          depth -= 1;
        }
      },
      rawDatabase: () => db,
    };
    clock = new Date('2026-01-01T00:00:00.000Z');
    const allowances = new AllowanceStore(repository, () => clock);
    allowances.set(1, { allowanceAtomic: '1000', periodSeconds: 3600, currency: 'USDC' });
    store = new AgentStore(repository, allowances, () => clock);
    ledger = new AgentLedger(repository, () => clock);
    const issued = store.create(1, 'agent', ENVELOPE);
    agentRef = issued.agent.agentRef;
    privateKeyPem = issued.privateKeyPem;
    otherKeyPem = store.create(1, 'other', ENVELOPE).privateKeyPem;
    deps = { store, ledger, allowances, intents: new IntentStore(repository, () => clock), now: () => clock };
  });

  afterEach(() => {
    db.close();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  function claimFor(overrides: Partial<PaymentClaim> = {}): PaymentClaim {
    counter += 1;
    return {
      agentRef,
      resourceUrl: 'https://api.example.com/x',
      ceilingAtomic: '200',
      currency: 'USDC',
      nonce: `n-${counter}`,
      timestamp: clock.toISOString(),
      ...overrides,
    };
  }

  function run(claim: PaymentClaim, quote: Quote = QUOTE, intentId: number | null = null, key = privateKeyPem) {
    return admit(deps, claim, signClaim(claim, key), quote, intentId);
  }

  it('admits a compliant request and reserves against the pool', () => {
    const decision = run(claimFor());
    expect(decision.reservationId).toBeGreaterThan(0);
    expect(decision.attemptNo).toBe(1);
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(100n);
  });

  it('refuses a claim signed by another instrument', () => {
    expect(() => run(claimFor(), QUOTE, null, otherKeyPem)).toThrow(GateRefusedError);
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(0n);
  });

  it('refuses a quote above the intent ceiling even when the envelope allows it', () => {
    expect(() => run(claimFor({ ceilingAtomic: '200' }), { ...QUOTE, priceAtomic: '300' })).toThrow(
      /exceeds_intent_ceiling/u,
    );
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(0n);
  });

  it('refuses a quote above the envelope even when the intent ceiling allows it', () => {
    expect(() => run(claimFor({ ceilingAtomic: '900' }), { ...QUOTE, priceAtomic: '500' })).toThrow(
      /exceeds_per_transaction_limit/u,
    );
  });

  it('does not let a re-quote inherit the first approval', () => {
    const first = run(claimFor({ ceilingAtomic: '150' }));
    expect(() => run(claimFor({ ceilingAtomic: '150' }), { ...QUOTE, priceAtomic: '160' }, first.intentId)).toThrow(
      /exceeds_intent_ceiling/u,
    );
  });

  it('numbers each attempt against the same intent', () => {
    const first = run(claimFor());
    const second = run(claimFor(), QUOTE, first.intentId);
    expect(first.intentId).toBe(second.intentId);
    expect(second.attemptNo).toBe(2);
  });

  it('refuses a cleartext resource', () => {
    expect(() => run(claimFor({ resourceUrl: 'http://api.example.com/x' }))).toThrow(/insecure_scheme/u);
  });

  it('refuses a currency the envelope does not allow', () => {
    expect(() => run(claimFor({ currency: 'WBTC' }), { ...QUOTE, currency: 'WBTC' })).toThrow(/currency_not_allowed/u);
  });

  it('refuses a stale claim', () => {
    expect(() => run(claimFor({ timestamp: new Date(clock.getTime() - 600_000).toISOString() }))).toThrow(
      /stale_claim/u,
    );
  });

  it('refuses a revoked agent', () => {
    store.revoke(1, agentRef);
    expect(() => run(claimFor())).toThrow(/agent_revoked/u);
  });
});
