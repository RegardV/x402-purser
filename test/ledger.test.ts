import { createRequire } from 'node:module';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  AgentLedger,
  CurrencyMismatchError,
  PoolExceededError,
  type LedgerRepository,
} from '../src/ledger.js';

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

const CAP = '1000';
const PERIOD = 3600;

describe('AgentLedger', () => {
  let tmpDir: string;
  let db: TestDb;
  let repository: LedgerRepository;
  let ledger: AgentLedger;
  let clock: Date;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'purser-ledger-'));
    db = new DatabaseSync(join(tmpDir, 'test.sqlite3'));
    db.exec(`
      PRAGMA foreign_keys = ON;
      CREATE TABLE agent_ledger (
        id INTEGER PRIMARY KEY,
        agent_id INTEGER NOT NULL,
        principal_id INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('reserved','confirmed','released','in_doubt')),
        amount_atomic TEXT NOT NULL,
        currency TEXT NOT NULL,
        resource_url TEXT,
        transaction_ref TEXT,
        reserved_at TEXT NOT NULL,
        settled_at TEXT,
        clock_source TEXT NOT NULL DEFAULT 'server',
        intent_id INTEGER, attempt_no INTEGER NOT NULL DEFAULT 1,
        authorization_nonce TEXT, typed_data_hash TEXT, signature TEXT
      );
    `);
    let depth = 0;
    repository = {
      writeTransactionSync<T>(work: () => T): T {
        if (depth > 0) return work();
        db.exec('BEGIN IMMEDIATE');
        depth += 1;
        try {
          const result = work();
          db.exec('COMMIT');
          return result;
        } catch (cause) {
          db.exec('ROLLBACK');
          throw cause;
        } finally {
          depth -= 1;
        }
      },
      rawDatabase: () => db,
    };
    clock = new Date('2026-01-01T12:00:00.000Z');
    ledger = new AgentLedger(repository, () => clock);
  });

  afterEach(() => {
    db.close();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  const ALLOWANCE = { allowanceAtomic: CAP, periodSeconds: PERIOD, currency: 'USDC' };
  const CALLER = { agentId: 1, principalId: 1 };

  function reserve(
    amount: string,
    overrides: Partial<{ agentId: number; principalId: number; currency: string }> = {},
  ): number {
    return ledger.reserve({
      agentId: 1,
      principalId: 1,
      amountAtomic: amount,
      currency: 'USDC',
      resourceUrl: 'https://api.example.com/x',
      allowance: ALLOWANCE,
      clockSource: 'server',
      ...overrides,
    });
  }

  it('counts a reservation against the pool immediately', () => {
    reserve('400');
    expect(ledger.committedAtomic(1, PERIOD, 'USDC')).toBe(400n);
  });

  it('refuses a reservation that would breach the cap', () => {
    reserve('900');
    expect(() => reserve('200')).toThrow(PoolExceededError);
    expect(ledger.committedAtomic(1, PERIOD, 'USDC')).toBe(900n);
  });

  it('admits only the subset that fits when many reservations race the same cap', () => {
    let admitted = 0;
    for (let attempt = 0; attempt < 20; attempt += 1) {
      try {
        reserve('100');
        admitted += 1;
      } catch (cause) {
        expect(cause).toBeInstanceOf(PoolExceededError);
      }
    }
    expect(admitted).toBe(10);
    expect(ledger.committedAtomic(1, PERIOD, 'USDC')).toBeLessThanOrEqual(BigInt(CAP));
  });

  it('restores the pool when a reservation is released', () => {
    const id = reserve('500');
    ledger.release(id, CALLER);
    expect(ledger.committedAtomic(1, PERIOD, 'USDC')).toBe(0n);
  });

  it('keeps an in_doubt reservation counted against the pool', () => {
    const id = reserve('500');
    ledger.markInDoubt(id, CALLER, 'tx-doubt');
    expect(ledger.committedAtomic(1, PERIOD, 'USDC')).toBe(500n);
  });

  it('refuses to release an in_doubt reservation', () => {
    const id = reserve('500');
    ledger.markInDoubt(id, CALLER, 'tx-doubt');
    expect(() => ledger.release(id, CALLER)).toThrow(/illegal ledger transition/u);
    expect(ledger.committedAtomic(1, PERIOD, 'USDC')).toBe(500n);
  });

  it('resolves an in_doubt reservation only through reconciliation', () => {
    const settledId = reserve('100');
    ledger.markInDoubt(settledId, CALLER, 'tx-1');
    ledger.reconcileInDoubt(settledId, CALLER, {
      transactionRef: 'tx-1',
      status: 'SETTLED',
      observedAt: '2026-01-01T12:00:00.000Z',
    });

    const lostId = reserve('100');
    ledger.markInDoubt(lostId, CALLER, 'tx-2');
    ledger.reconcileInDoubt(lostId, CALLER, {
      transactionRef: 'tx-2',
      status: 'FAILED',
      observedAt: '2026-01-01T12:00:00.000Z',
    });

    expect(ledger.committedAtomic(1, PERIOD, 'USDC')).toBe(100n);
  });

  it('drops spend that has aged out of the rolling window', () => {
    reserve('900');
    clock = new Date(clock.getTime() + (PERIOD + 60) * 1000);
    expect(ledger.committedAtomic(1, PERIOD, 'USDC')).toBe(0n);
    expect(() => reserve('900')).not.toThrow();
  });

  it('isolates pools between principals', () => {
    reserve('900');
    const other = reserve('900', { agentId: 2, principalId: 2 });
    expect(other).toBeGreaterThan(0);
    expect(ledger.committedAtomic(2, PERIOD, 'USDC')).toBe(900n);
  });

  it('rejects a double confirm', () => {
    const id = reserve('100');
    ledger.confirm(id, CALLER, 'tx-9');
    expect(() => ledger.confirm(id, CALLER, 'tx-9')).toThrow(/illegal ledger transition/u);
  });

  it('uses the account allowance as the ceiling, not the calling agent', () => {
    reserve('900', { agentId: 2 });
    expect(() => reserve('200', { agentId: 3 })).toThrow(PoolExceededError);
  });

  it('refuses a reservation whose currency is not the allowance currency', () => {
    expect(() => reserve('1', { currency: 'WBTC' })).toThrow(CurrencyMismatchError);
  });

  it('never sums spend across currencies', () => {
    reserve('500');
    expect(ledger.committedAtomic(1, PERIOD, 'USDC')).toBe(500n);
    expect(ledger.committedAtomic(1, PERIOD, 'WBTC')).toBe(0n);
  });

  it('refuses to let another agent release a reservation', () => {
    const id = reserve('500');
    expect(() => ledger.release(id, { agentId: 99, principalId: 1 })).toThrow(/illegal ledger transition/u);
    expect(ledger.committedAtomic(1, PERIOD, 'USDC')).toBe(500n);
  });

  it('refuses to let another principal touch a reservation', () => {
    const id = reserve('500');
    expect(() => ledger.confirm(id, { agentId: 1, principalId: 42 }, 'tx')).toThrow(/illegal ledger transition/u);
  });

  it('refuses evidence whose transactionRef does not match the row', () => {
    const id = reserve('100');
    ledger.markInDoubt(id, CALLER, 'tx-real');
    expect(() =>
      ledger.reconcileInDoubt(id, CALLER, {
        transactionRef: 'tx-other',
        status: 'FAILED',
        observedAt: '2026-01-01T12:00:00.000Z',
      }),
    ).toThrow(/evidence/u);
    expect(ledger.committedAtomic(1, PERIOD, 'USDC')).toBe(100n);
  });

  it('leaves a row in_doubt when the evidence status is not terminal', () => {
    const id = reserve('100');
    ledger.markInDoubt(id, CALLER, 'tx-1');
    ledger.reconcileInDoubt(id, CALLER, {
      transactionRef: 'tx-1',
      status: 'PENDING',
      observedAt: '2026-01-01T12:00:00.000Z',
    });
    expect(ledger.committedAtomic(1, PERIOD, 'USDC')).toBe(100n);
  });
});
