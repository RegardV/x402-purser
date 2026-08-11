/**
 * Agent records under a principal.
 *
 * One human approval creates a principal; agents are then issued beneath it without further approval, each bounded by
 * an envelope that must attenuate its parent. Attenuation is checked here, at issuance, so the payment path never walks
 * the parent chain.
 */

import { randomBytes } from 'node:crypto';
import { AllowanceStore } from './allowance.js';
import { mintInstrumentKeypair } from './credential.js';
import { attenuates, validateEnvelope, type Envelope } from './envelope.js';

/** Everything `list` returns. Deliberately excludes the envelope, see `describe`. */
export interface AgentSummary {
  readonly agentRef: string;
  readonly label: string;
  readonly parentRef: string | null;
  readonly createdAt: string;
  readonly revokedAt: string | null;
}

export interface AgentDetail extends AgentSummary {
  readonly envelope: Envelope;
  /** Internal row id. Needed for ledger foreign keys; never surfaced by `list`. */
  readonly agentId: number;
  readonly publicKeyPem: string;
  /** Pinned by an intent so a decision records which policy actually decided it. */
  readonly envelopeVersion: number;
}

export interface IssuedAgent {
  readonly agent: AgentDetail;
  /** Returned once at issuance and never stored. Losing it means re-issuing the instrument. */
  readonly privateKeyPem: string;
}

export class EnvelopeRejectedError extends Error {
  constructor(readonly reasons: readonly string[]) {
    super(`envelope rejected: ${reasons.join('; ')}`);
    this.name = 'EnvelopeRejectedError';
  }
}

export class IssuanceLimitError extends Error {
  constructor(limit: number) {
    super(`principal already has the maximum of ${limit} agents`);
    this.name = 'IssuanceLimitError';
  }
}

export class AgentNotFoundError extends Error {
  constructor(agentRef: string) {
    super(`no agent ${agentRef} for this principal`);
    this.name = 'AgentNotFoundError';
  }
}

interface SqliteLike {
  prepare(sql: string): {
    all(...values: unknown[]): unknown[];
    get(...values: unknown[]): unknown;
    run(...values: unknown[]): unknown;
  };
}

export interface AgentStoreRepository {
  writeTransactionSync<T>(work: () => T): T;
  rawDatabase(): SqliteLike;
}

interface AgentRow {
  id: number;
  agent_ref: string;
  label: string;
  parent_ref: string | null;
  created_at: string;
  revoked_at: string | null;
  payload: Uint8Array;
  public_key: string | null;
  envelope_version: number;
}

const SUMMARY_COLUMNS = `
  a.id            AS id,
  a.agent_ref     AS agent_ref,
  a.label         AS label,
  p.agent_ref     AS parent_ref,
  a.created_at    AS created_at,
  a.revoked_at    AS revoked_at`;

function newAgentRef(): string {
  return randomBytes(16).toString('base64url');
}

export class AgentStore {
  constructor(
    private readonly repository: AgentStoreRepository,
    private readonly allowances: AllowanceStore,
    private readonly now: () => Date = () => new Date(),
    private readonly maxAgents = 100,
  ) {}

  /**
   * Issues an agent. A parent reference forces the envelope through attenuation; without one the envelope stands alone
   * and is only validated.
   */
  create(principalId: number, label: string, envelope: Envelope, parentRef: string | null = null): IssuedAgent {
    const problems = validateEnvelope(envelope);
    if (problems.length > 0) throw new EnvelopeRejectedError(problems);

    // The account allowance is the ceiling every envelope attenuates against, roots included.
    // Without this a root agent has the whole account as its blast radius, finding C1.
    const allowance = this.allowances.require(principalId);
    const ceiling: Envelope = {
      spendCapAtomic: allowance.allowanceAtomic,
      periodSeconds: allowance.periodSeconds,
      maxPerTxAtomic: allowance.allowanceAtomic,
      // The account constrains how much and in what currency, not which hosts, so mirror the
      // child's hosts to make that dimension vacuous here.
      allowedHosts: envelope.allowedHosts,
      allowedCurrencies: [allowance.currency],
      expiresAt: null,
    };
    // Periods compare by RATE, so an agent may hold a far shorter window than the account
    // (metered media) provided its rate stays within the allowance.
    const againstAccount = attenuates(ceiling, envelope);
    if (!againstAccount.ok) {
      throw new EnvelopeRejectedError(againstAccount.violations.map((v) => `${v.field}: ${v.reason}`));
    }

    return this.repository.writeTransactionSync(() => {
      const count = this.repository
        .rawDatabase()
        .prepare(`SELECT COUNT(*) AS n FROM agents WHERE principal_id = ? AND revoked_at IS NULL`)
        .get(principalId) as { n: number };
      if (Number(count.n) >= this.maxAgents) throw new IssuanceLimitError(this.maxAgents);

      let parentId: number | null = null;
      if (parentRef !== null) {
        const parent = this.requireRow(principalId, parentRef);
        if (parent.revoked_at !== null) {
          throw new EnvelopeRejectedError(['parent agent is revoked']);
        }
        const result = attenuates(this.envelopeOf(parent), envelope);
        if (!result.ok) {
          throw new EnvelopeRejectedError(result.violations.map((v) => `${v.field}: ${v.reason}`));
        }
        parentId = parent.id;
      }

      const agentRef = newAgentRef();
      const keypair = mintInstrumentKeypair();
      this.repository
        .rawDatabase()
        .prepare(
          `INSERT INTO agents (principal_id, agent_ref, label, parent_agent_id, payload_version, payload, public_key, envelope_version, created_at)
           VALUES (?, ?, ?, ?, 1, ?, ?, 1, ?)`,
        )
        .run(
          principalId,
          agentRef,
          label,
          parentId,
          new TextEncoder().encode(JSON.stringify(envelope)),
          keypair.publicKeyPem,
          this.now().toISOString(),
        );
      return { agent: this.describe(principalId, agentRef), privateKeyPem: keypair.privateKeyPem };
    });
  }

  /** Identifying fields only. The envelope is never included; use `describe`. */
  list(principalId: number, includeRevoked = false): AgentSummary[] {
    const rows = this.repository
      .rawDatabase()
      .prepare(
        `SELECT ${SUMMARY_COLUMNS}
           FROM agents a LEFT JOIN agents p ON p.id = a.parent_agent_id
          WHERE a.principal_id = ? ${includeRevoked ? '' : 'AND a.revoked_at IS NULL'}
          ORDER BY a.id`,
      )
      .all(principalId) as AgentRow[];
    return rows.map((row) => this.summaryOf(row));
  }

  describe(principalId: number, agentRef: string): AgentDetail {
    const row = this.requireRow(principalId, agentRef);
    return {
      ...this.summaryOf(row),
      envelope: this.envelopeOf(row),
      agentId: Number(row.id),
      publicKeyPem: row.public_key ?? '',
      envelopeVersion: Number(row.envelope_version),
    };
  }

  /** Soft-deletes the agent and every descendant. Already-revoked rows keep their timestamp. */
  revoke(principalId: number, agentRef: string): number {
    return this.repository.writeTransactionSync(() => {
      const root = this.requireRow(principalId, agentRef);
      const result = this.repository
        .rawDatabase()
        .prepare(
          `WITH RECURSIVE subtree(id) AS (
             SELECT ? UNION ALL
             SELECT a.id FROM agents a JOIN subtree s ON a.parent_agent_id = s.id
           )
           UPDATE agents SET revoked_at = ?
            WHERE id IN (SELECT id FROM subtree) AND revoked_at IS NULL`,
        )
        .run(root.id, this.now().toISOString()) as { changes?: number | bigint };
      return Number(result.changes ?? 0);
    });
  }

  private requireRow(principalId: number, agentRef: string): AgentRow {
    const row = this.repository
      .rawDatabase()
      .prepare(
        `SELECT ${SUMMARY_COLUMNS}, a.payload AS payload, a.public_key AS public_key, a.envelope_version AS envelope_version
           FROM agents a LEFT JOIN agents p ON p.id = a.parent_agent_id
          WHERE a.principal_id = ? AND a.agent_ref = ?`,
      )
      .get(principalId, agentRef) as AgentRow | undefined;
    if (row === undefined) throw new AgentNotFoundError(agentRef);
    return row;
  }

  private summaryOf(row: AgentRow): AgentSummary {
    return {
      agentRef: row.agent_ref,
      label: row.label,
      parentRef: row.parent_ref,
      createdAt: row.created_at,
      revokedAt: row.revoked_at,
    };
  }

  private envelopeOf(row: AgentRow): Envelope {
    return JSON.parse(new TextDecoder().decode(row.payload)) as Envelope;
  }
}
