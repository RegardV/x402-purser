import { createRequire } from 'node:module';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AllowanceNotConfiguredError, AllowanceStore } from '../src/allowance.js';

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

describe('AllowanceStore', () => {
  let tmpDir: string;
  let db: TestDb;
  let store: AllowanceStore;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'purser-allowance-'));
    db = new DatabaseSync(join(tmpDir, 'test.sqlite3'));
    db.exec(`
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
    store = new AllowanceStore(
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

  it('fails closed when no allowance is configured', () => {
    expect(() => store.require(1)).toThrow(AllowanceNotConfiguredError);
  });

  it('round-trips a configured allowance', () => {
    store.set(1, { allowanceAtomic: '5000', periodSeconds: 86_400, currency: 'USDC' });
    expect(store.require(1)).toEqual({ allowanceAtomic: '5000', periodSeconds: 86_400, currency: 'USDC' });
  });

  it('replaces rather than duplicates on a second set', () => {
    store.set(1, { allowanceAtomic: '5000', periodSeconds: 86_400, currency: 'USDC' });
    store.set(1, { allowanceAtomic: '10', periodSeconds: 60, currency: 'USDC' });
    expect(store.require(1).allowanceAtomic).toBe('10');
  });

  it('rejects a malformed allowance', () => {
    expect(() => store.set(1, { allowanceAtomic: '-1', periodSeconds: 86_400, currency: 'USDC' })).toThrow();
    expect(() => store.set(1, { allowanceAtomic: '10', periodSeconds: 0, currency: 'USDC' })).toThrow();
    expect(() => store.set(1, { allowanceAtomic: '10', periodSeconds: 60, currency: '' })).toThrow();
  });

  it('isolates allowances between principals', () => {
    store.set(1, { allowanceAtomic: '5000', periodSeconds: 86_400, currency: 'USDC' });
    expect(() => store.require(2)).toThrow(AllowanceNotConfiguredError);
  });
});
