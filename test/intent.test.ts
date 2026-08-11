import { createRequire } from 'node:module';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { IntentStore } from '../src/intent.js';

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

describe('IntentStore', () => {
  let tmpDir: string;
  let db: TestDb;
  let store: IntentStore;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'purser-intent-'));
    db = new DatabaseSync(join(tmpDir, 'test.sqlite3'));
    db.exec(`
      CREATE TABLE intents (
        id INTEGER PRIMARY KEY, principal_id INTEGER NOT NULL, agent_id INTEGER NOT NULL,
        resource_url TEXT NOT NULL, ceiling_atomic TEXT NOT NULL, currency TEXT NOT NULL,
        envelope_version INTEGER NOT NULL, refund_rule TEXT NOT NULL DEFAULT 'dispute_only',
        created_at TEXT NOT NULL
      );
      CREATE TABLE agent_ledger (
        id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL, principal_id INTEGER NOT NULL,
        state TEXT NOT NULL, amount_atomic TEXT NOT NULL, currency TEXT NOT NULL,
        reserved_at TEXT NOT NULL, intent_id INTEGER, attempt_no INTEGER NOT NULL DEFAULT 1
      );
    `);
    let depth = 0;
    store = new IntentStore(
      {
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
      },
      () => new Date('2026-01-01T00:00:00.000Z'),
    );
  });

  afterEach(() => {
    db.close();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  function open() {
    return store.open({
      principalId: 1,
      agentId: 7,
      resourceUrl: 'https://api.example.com/x',
      ceilingAtomic: '100',
      currency: 'USDC',
      envelopeVersion: 3,
    });
  }

  it('records what the agent asked for, including the policy that decided it', () => {
    const intent = open();
    expect(intent.ceilingAtomic).toBe('100');
    expect(intent.envelopeVersion).toBe(3);
    expect(intent.refundRule).toBe('dispute_only');
  });

  it('starts attempt numbering at one', () => {
    const intent = open();
    expect(store.attemptCount(intent.id)).toBe(0);
    expect(store.nextAttemptNo(intent.id)).toBe(1);
  });

  it('counts attempts recorded against the intent', () => {
    const intent = open();
    for (const amount of ['40', '60']) {
      db.prepare(
        `INSERT INTO agent_ledger (agent_id, principal_id, state, amount_atomic, currency, reserved_at, intent_id, attempt_no)
         VALUES (7, 1, 'released', ?, 'USDC', '2026-01-01T00:00:00Z', ?, ?)`,
      ).run(amount, intent.id, store.nextAttemptNo(intent.id));
    }
    expect(store.attemptCount(intent.id)).toBe(2);
    expect(store.nextAttemptNo(intent.id)).toBe(3);
  });

  it('rejects a malformed ceiling', () => {
    expect(() =>
      store.open({
        principalId: 1,
        agentId: 7,
        resourceUrl: 'https://a.example.com/x',
        ceilingAtomic: '-5',
        currency: 'USDC',
        envelopeVersion: 1,
      }),
    ).toThrow();
  });

  it('keeps intents separate per agent', () => {
    const a = open();
    const b = store.open({
      principalId: 1,
      agentId: 8,
      resourceUrl: 'https://api.example.com/y',
      ceilingAtomic: '10',
      currency: 'USDC',
      envelopeVersion: 1,
    });
    expect(a.id).not.toBe(b.id);
    expect(store.attemptCount(b.id)).toBe(0);
  });
});
