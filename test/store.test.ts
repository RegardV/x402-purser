import { createRequire } from 'node:module';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AllowanceStore } from '../src/allowance.js';
import {
  AgentNotFoundError,
  AgentStore,
  EnvelopeRejectedError,
  IssuanceLimitError,
  type AgentStoreRepository,
} from '../src/store.js';
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

const ROOT: Envelope = {
  spendCapAtomic: '1000000',
  periodSeconds: 86_400,
  maxPerTxAtomic: '100000',
  allowedHosts: ['api.example.com', 'data.example.com'],
  allowedCurrencies: ['USDC'],
  expiresAt: null,
};

describe('AgentStore', () => {
  let tmpDir: string;
  let db: TestDb;
  let store: AgentStore;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'purser-store-'));
    db = new DatabaseSync(join(tmpDir, 'test.sqlite3'));
    db.exec(`
      PRAGMA foreign_keys = ON;
      CREATE TABLE agents (
        id INTEGER PRIMARY KEY,
        principal_id INTEGER NOT NULL,
        agent_ref TEXT NOT NULL,
        label TEXT NOT NULL,
        parent_agent_id INTEGER REFERENCES agents(id) ON DELETE CASCADE,
        payload_version INTEGER NOT NULL,
        payload BLOB NOT NULL,
        public_key TEXT,
        payload_mac TEXT,
        envelope_version INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        revoked_at TEXT,
        UNIQUE(principal_id, agent_ref)
      );
      CREATE TABLE principal_allowance (
        principal_id INTEGER PRIMARY KEY,
        allowance_atomic TEXT NOT NULL,
        period_seconds INTEGER NOT NULL,
        currency TEXT NOT NULL,
        payload_mac TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
    `);
    let depth = 0;
    const repository: AgentStoreRepository = {
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
    const clock = (): Date => new Date('2026-01-01T00:00:00.000Z');
    const allowances = new AllowanceStore(repository, clock);
    allowances.set(1, { allowanceAtomic: '1000000', periodSeconds: 86_400, currency: 'USDC' });
    allowances.set(2, { allowanceAtomic: '1000000', periodSeconds: 86_400, currency: 'USDC' });
    store = new AgentStore(repository, allowances, clock, 3);
  });

  afterEach(() => {
    db.close();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('issues a root agent and round-trips its envelope', () => {
    const agent = store.create(1, 'root', ROOT).agent;
    expect(agent.agentRef).toMatch(/^[A-Za-z0-9_-]{22}$/u);
    expect(store.describe(1, agent.agentRef).envelope).toEqual(ROOT);
  });

  it('rejects a malformed envelope before touching the database', () => {
    expect(() => store.create(1, 'bad', { ...ROOT, spendCapAtomic: '-5' })).toThrow(EnvelopeRejectedError);
    expect(store.list(1)).toHaveLength(0);
  });

  it('rejects a child whose envelope widens its parent', () => {
    const parent = store.create(1, 'parent', ROOT).agent;
    expect(() => store.create(1, 'child', { ...ROOT, allowedHosts: ['evil.example.com'] }, parent.agentRef)).toThrow(
      EnvelopeRejectedError,
    );
  });

  it('accepts a child that narrows its parent', () => {
    const parent = store.create(1, 'parent', ROOT).agent;
    const child = store.create(
      1,
      'child',
      { ...ROOT, spendCapAtomic: '10', maxPerTxAtomic: '5' },
      parent.agentRef,
    ).agent;
    expect(child.parentRef).toBe(parent.agentRef);
  });

  it('refuses to issue beneath a revoked parent', () => {
    const parent = store.create(1, 'parent', ROOT).agent;
    store.revoke(1, parent.agentRef);
    expect(() => store.create(1, 'child', ROOT, parent.agentRef)).toThrow(EnvelopeRejectedError);
  });

  it('never includes the envelope in list output', () => {
    store.create(1, 'a', ROOT);
    const [summary] = store.list(1);
    expect(Object.keys(summary ?? {}).sort()).toEqual(['agentRef', 'createdAt', 'label', 'parentRef', 'revokedAt']);
  });

  it('revokes an entire subtree, not just the named agent', () => {
    const parent = store.create(1, 'parent', ROOT).agent;
    const child = store.create(1, 'child', ROOT, parent.agentRef).agent;
    const grandchild = store.create(1, 'grandchild', ROOT, child.agentRef).agent;
    expect(store.revoke(1, parent.agentRef)).toBe(3);
    for (const ref of [parent.agentRef, child.agentRef, grandchild.agentRef]) {
      expect(store.describe(1, ref).revokedAt).not.toBeNull();
    }
    expect(store.list(1)).toHaveLength(0);
    expect(store.list(1, true)).toHaveLength(3);
  });

  it('isolates agents between principals', () => {
    const mine = store.create(1, 'mine', ROOT).agent;
    store.create(2, 'theirs', ROOT);
    expect(store.list(2)).toHaveLength(1);
    expect(() => store.describe(2, mine.agentRef)).toThrow(AgentNotFoundError);
  });

  it('leaves an already-revoked agent untouched on a second revoke', () => {
    const parent = store.create(1, 'parent', ROOT).agent;
    expect(store.revoke(1, parent.agentRef)).toBe(1);
    expect(store.revoke(1, parent.agentRef)).toBe(0);
  });

  it('refuses a root envelope that exceeds the account allowance', () => {
    expect(() =>
      store.create(1, 'greedy', { ...ROOT, spendCapAtomic: '99999999', maxPerTxAtomic: '99999999' }),
    ).toThrow(EnvelopeRejectedError);
  });

  it('refuses to issue when no allowance is configured', () => {
    expect(() => store.create(999, 'orphan', ROOT)).toThrow(/no spend allowance configured/u);
  });

  it('caps the number of agents per principal', () => {
    for (let i = 0; i < 3; i += 1) store.create(1, `a${i}`, ROOT);
    expect(() => store.create(1, 'one-too-many', ROOT)).toThrow(IssuanceLimitError);
  });

  it('accepts an agent with a much shorter window whose rate fits the allowance', () => {
    // Metered media: 11 atomic units per second under 1000000 per day (~11.57/s).
    const perSecond = { ...ROOT, spendCapAtomic: '11', maxPerTxAtomic: '11', periodSeconds: 1 };
    expect(() => store.create(1, 'stream', perSecond)).not.toThrow();
  });

  it('returns the private key exactly once at issuance', () => {
    const issued = store.create(1, 'rootkey', ROOT);
    expect(issued.privateKeyPem).toContain('PRIVATE KEY');
    expect(issued.agent.publicKeyPem).toContain('PUBLIC KEY');
    expect(store.describe(1, issued.agent.agentRef)).not.toHaveProperty('privateKeyPem');
  });

  it('stamps an envelope version at issuance', () => {
    expect(store.create(1, 'v', ROOT).agent.envelopeVersion).toBe(1);
  });

  it('gives every instrument a distinct keypair', () => {
    const a = store.create(1, 'ka', ROOT);
    const b = store.create(1, 'kb', ROOT);
    expect(a.agent.publicKeyPem).not.toBe(b.agent.publicKeyPem);
    expect(a.privateKeyPem).not.toBe(b.privateKeyPem);
  });
});
