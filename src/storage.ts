/**
 * Storage.
 *
 * A single SQLite file holding principals, agents, intents, the ledger and the account allowance.
 * Purser owns this schema outright; nothing here is shared with another application.
 *
 * `node:sqlite` is loaded through `createRequire` rather than a static import because bundlers
 * cannot pre-bundle a built-in that only exists at runtime, and a static import fails under
 * several of them.
 */

import { createRequire } from 'node:module';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export interface SqliteStatement {
  all(...values: unknown[]): unknown[];
  get(...values: unknown[]): unknown;
  run(...values: unknown[]): unknown;
}

export interface SqliteDatabase {
  close(): void;
  exec(sql: string): void;
  prepare(sql: string): SqliteStatement;
}

const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as {
  DatabaseSync: new (filename: string) => SqliteDatabase;
};

/** Everything the policy modules need from storage. Kept narrow so they stay testable. */
export interface Repository {
  writeTransactionSync<T>(work: () => T): T;
  rawDatabase(): SqliteDatabase;
  close(): void;
}

const SCHEMA = `
  PRAGMA foreign_keys = ON;
  PRAGMA journal_mode = WAL;
  PRAGMA synchronous = FULL;
  PRAGMA busy_timeout = 5000;

  CREATE TABLE IF NOT EXISTS principals (
    id INTEGER PRIMARY KEY,
    label TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS principal_allowance (
    principal_id INTEGER PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE,
    allowance_atomic TEXT NOT NULL,
    period_seconds INTEGER NOT NULL,
    currency TEXT NOT NULL,
    payload_mac TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS agents (
    id INTEGER PRIMARY KEY,
    principal_id INTEGER NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
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

  CREATE TABLE IF NOT EXISTS intents (
    id INTEGER PRIMARY KEY,
    principal_id INTEGER NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    resource_url TEXT NOT NULL,
    ceiling_atomic TEXT NOT NULL,
    currency TEXT NOT NULL,
    envelope_version INTEGER NOT NULL,
    refund_rule TEXT NOT NULL DEFAULT 'dispute_only',
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS agent_ledger (
    id INTEGER PRIMARY KEY,
    agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    principal_id INTEGER NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    state TEXT NOT NULL CHECK(state IN ('reserved', 'confirmed', 'released', 'in_doubt', 'disputed')),
    amount_atomic TEXT NOT NULL,
    currency TEXT NOT NULL,
    clock_source TEXT NOT NULL DEFAULT 'server' CHECK(clock_source IN ('server', 'local')),
    intent_id INTEGER REFERENCES intents(id) ON DELETE SET NULL,
    attempt_no INTEGER NOT NULL DEFAULT 1,
    authorization_nonce TEXT,
    typed_data_hash TEXT,
    signature TEXT,
    resource_url TEXT,
    transaction_ref TEXT,
    reserved_at TEXT NOT NULL,
    settled_at TEXT
  );

  CREATE TABLE IF NOT EXISTS used_nonces (
    nonce TEXT PRIMARY KEY,
    agent_ref TEXT NOT NULL,
    seen_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS clock_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS agents_principal_idx ON agents(principal_id, revoked_at);
  CREATE INDEX IF NOT EXISTS agent_ledger_pool_idx ON agent_ledger(principal_id, state, reserved_at);
  CREATE INDEX IF NOT EXISTS intents_agent_idx ON intents(agent_id, created_at);
  CREATE INDEX IF NOT EXISTS used_nonces_seen_idx ON used_nonces(seen_at);
`;

/** Opens the store, creating the schema if absent. Pass ':memory:' for tests. */
export function openRepository(databasePath: string): Repository {
  if (databasePath !== ':memory:') mkdirSync(dirname(databasePath), { recursive: true });
  const db = new DatabaseSync(databasePath);
  db.exec(SCHEMA);
  let depth = 0;
  return {
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
    close: () => db.close(),
  };
}

/**
 * Creates the principal if it is not already there, and returns its id.
 *
 * v1 serves one principal, the owner of the unlocked wallet, so this is idempotent by label rather
 * than a general principal registry.
 */
export function ensurePrincipal(repo: Repository, label: string): number {
  const db = repo.rawDatabase();
  const existing = db.prepare('SELECT id FROM principals WHERE label = ?').get(label) as { id: number } | undefined;
  if (existing !== undefined) return existing.id;
  db.prepare('INSERT INTO principals (label, created_at) VALUES (?, ?)').run(label, new Date().toISOString());
  const created = db.prepare('SELECT id FROM principals WHERE label = ?').get(label) as { id: number };
  return created.id;
}
