import { createRequire } from 'node:module';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AgentLedger, PoolExceededError } from '../src/ledger.js';
import { AllowanceStore } from '../src/allowance.js';
import { AgentStore } from '../src/store.js';
import { authorizePayment, PaymentRefusedError, settlePayment } from '../src/enforcement.js';
import type { Envelope } from '../src/envelope.js';

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
const URL_OK = 'https://api.example.com/resource';

describe('payment enforcement', () => {
  let tmpDir: string;
  let db: TestDb;
  let store: AgentStore;
  let ledger: AgentLedger;
  let allowances: AllowanceStore;
  let agentRef: string;
  let clock: Date;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'purser-enforce-'));
    db = new DatabaseSync(join(tmpDir, 'test.sqlite3'));
    db.exec(`
      PRAGMA foreign_keys = ON;
      CREATE TABLE agents (
        id INTEGER PRIMARY KEY, principal_id INTEGER NOT NULL, agent_ref TEXT NOT NULL,
        label TEXT NOT NULL, parent_agent_id INTEGER REFERENCES agents(id) ON DELETE CASCADE,
        payload_version INTEGER NOT NULL, payload BLOB NOT NULL,
        public_key TEXT, payload_mac TEXT, envelope_version INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL, revoked_at TEXT, UNIQUE(principal_id, agent_ref)
      );
      CREATE TABLE agent_ledger (
        id INTEGER PRIMARY KEY,
        agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
        principal_id INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('reserved','confirmed','released','in_doubt')),
        amount_atomic TEXT NOT NULL, currency TEXT NOT NULL, resource_url TEXT,
        transaction_ref TEXT, reserved_at TEXT NOT NULL, settled_at TEXT,
        clock_source TEXT NOT NULL DEFAULT 'server',
        intent_id INTEGER, attempt_no INTEGER NOT NULL DEFAULT 1,
        authorization_nonce TEXT, typed_data_hash TEXT, signature TEXT
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
    allowances = new AllowanceStore(repository, () => clock);
    allowances.set(1, { allowanceAtomic: '1000', periodSeconds: 3600, currency: 'USDC' });
    store = new AgentStore(repository, allowances, () => clock);
    ledger = new AgentLedger(repository, () => clock);
    agentRef = store.create(1, 'agent', ENVELOPE).agent.agentRef;
  });

  afterEach(() => {
    db.close();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  function authorize(overrides: Partial<Parameters<typeof authorizePayment>[3]> = {}) {
    return authorizePayment(
      store,
      ledger,
      allowances,
      { principalId: 1, agentRef, resourceUrl: URL_OK, priceAtomic: '100', currency: 'USDC', ...overrides },
      () => clock,
    );
  }

  it('authorises a compliant payment and reserves against the pool', () => {
    const auth = authorize();
    expect(auth.reservationId).toBeGreaterThan(0);
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(100n);
  });

  it('writes a ledger row that references the real agent row', () => {
    authorize();
    const row = db.prepare(`SELECT agent_id FROM agent_ledger`).get() as { agent_id: number };
    const agent = db.prepare(`SELECT id FROM agents WHERE agent_ref = ?`).get(agentRef) as { id: number };
    expect(Number(row.agent_id)).toBe(Number(agent.id));
  });

  it.each([
    ['host_not_allowed', { resourceUrl: 'https://evil.example.com/x' }],
    ['exceeds_per_transaction_limit', { priceAtomic: '401' }],
    ['malformed_price', { priceAtomic: '1.5' }],
    ['malformed_resource_url', { resourceUrl: 'not a url' }],
  ])('refuses with %s before reserving anything', (reason, overrides) => {
    expect(() => authorize(overrides)).toThrow(PaymentRefusedError);
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(0n);
  });

  it('refuses a revoked agent', () => {
    store.revoke(1, agentRef);
    expect(() => authorize()).toThrow(/agent_revoked/u);
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(0n);
  });

  it('refuses an expired envelope', () => {
    clock = new Date('2027-01-01T00:00:00.000Z');
    expect(() => authorize()).toThrow(/envelope_expired/u);
  });

  it('refuses once the pooled cap is exhausted', () => {
    for (let i = 0; i < 10; i += 1) authorize();
    expect(() => authorize()).toThrow(PoolExceededError);
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(1000n);
  });

  it('releases the reservation when the payment definitively failed', () => {
    const auth = authorize();
    settlePayment(ledger, auth, { status: 'failed' });
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(0n);
  });

  it('keeps an unknown outcome consuming the pool instead of releasing it', () => {
    const auth = authorize();
    settlePayment(ledger, auth, { status: 'unknown', transactionRef: 'tx-?' });
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(100n);
    const row = db.prepare(`SELECT state FROM agent_ledger WHERE id = ?`).get(auth.reservationId) as { state: string };
    expect(row.state).toBe('in_doubt');
  });

  it('confirms a settled payment', () => {
    const auth = authorize();
    settlePayment(ledger, auth, { status: 'settled', transactionRef: 'tx-1' });
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(100n);
  });

  it('refuses a currency the envelope does not allow', () => {
    expect(() => authorize({ currency: 'WBTC' })).toThrow(/currency_not_allowed/u);
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(0n);
  });

  it('refuses a cleartext http resource', () => {
    expect(() => authorize({ resourceUrl: 'http://api.example.com/x' })).toThrow(/insecure_scheme/u);
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(0n);
  });

  it('returns the caller identity needed to settle', () => {
    const auth = authorize();
    expect(auth.caller.principalId).toBe(1);
    expect(auth.caller.agentId).toBeGreaterThan(0);
  });

  it('releases rather than stranding a reservation when no transaction id was obtained', () => {
    const auth = authorize();
    settlePayment(ledger, auth, { status: 'unknown', transactionRef: null });
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(0n);
  });
});
