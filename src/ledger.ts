/**
 * Pooled budget ledger for agent spending.
 *
 * Every payment reserves against a pool shared by all agents under one principal, so total exposure equals the
 * principal's cap no matter how many agents exist. Reservation happens _before_ the payment executes; the outcome then
 * confirms or releases it.
 *
 * The state an unwary implementation gets wrong is `in_doubt`. When a payment's outcome is unknown, timeout, ambiguous
 * response, the money may or may not have moved. Releasing that reservation is the one bug that lets the pool be spent
 * twice. `in_doubt` therefore counts against the pool exactly like a confirmed spend, and only explicit reconciliation
 * against the payment transaction may resolve it.
 */

import type { Allowance } from './allowance.js';

export type LedgerState = 'reserved' | 'confirmed' | 'released' | 'in_doubt';

/** Statuses from `GET /v1/transactions/{id}/x402` that end the question. */
const TERMINAL_SETTLED: readonly string[] = ['SETTLED', 'COMPLETED', 'CONFIRMED'];
const TERMINAL_FAILED: readonly string[] = ['FAILED', 'CANCELLED', 'EXPIRED', 'REJECTED'];

export interface LedgerCaller {
  readonly agentId: number;
  readonly principalId: number;
}

/** A server observation, not a caller's opinion. */
export interface SettlementEvidence {
  readonly transactionRef: string;
  readonly status: string;
  readonly observedAt: string;
}

export class CurrencyMismatchError extends Error {
  constructor(requested: string, allowed: string) {
    super(`currency ${requested} does not match the account allowance currency ${allowed}`);
    this.name = 'CurrencyMismatchError';
  }
}

export class EvidenceRejectedError extends Error {
  constructor(reason: string) {
    super(`settlement evidence rejected: ${reason}`);
    this.name = 'EvidenceRejectedError';
  }
}

/** States that consume pool capacity. `released` is absent by design; `in_doubt` is present. */
const CONSUMING_STATES: readonly LedgerState[] = ['reserved', 'confirmed', 'in_doubt'];

export interface ReserveRequest {
  readonly agentId: number;
  readonly principalId: number;
  readonly amountAtomic: string;
  readonly currency: string;
  readonly resourceUrl: string;
  /** The ACCOUNT allowance, never the calling agent's envelope. This is the C1 fix. */
  readonly allowance: Allowance;
  readonly clockSource: 'server' | 'local';
  /**
   * The intent this attempt belongs to, and its position in that intent. A reservation IS an attempt, so the linkage is
   * written in the same statement, otherwise attempts cannot be counted and a retry could not be told apart from a
   * fresh request.
   */
  readonly intentId?: number;
  readonly attemptNo?: number;
}

export class PoolExceededError extends Error {
  constructor(
    readonly requestedAtomic: string,
    readonly committedAtomic: string,
    readonly capAtomic: string,
  ) {
    // L8: the committed total is the account's business, not the calling agent's. Fields are
    // retained for local logging; the message an agent sees discloses nothing.
    super('pooled budget exceeded for this account');
    this.name = 'PoolExceededError';
  }
}

interface SqliteLike {
  prepare(sql: string): {
    all(...values: unknown[]): unknown[];
    get(...values: unknown[]): unknown;
    run(...values: unknown[]): unknown;
  };
}

export interface LedgerRepository {
  writeTransactionSync<T>(work: () => T): T;
  rawDatabase(): SqliteLike;
}

export class AgentLedger {
  constructor(
    private readonly repository: LedgerRepository,
    private readonly now: () => Date = () => new Date(),
  ) {}

  /** Sum of pool-consuming rows inside the rolling window. */
  /**
   * Sum of pool-consuming rows inside the rolling window, for ONE currency.
   *
   * Atomic units are not fungible across currencies, one unit of an 18-decimal token is not one unit of a 6-decimal
   * stablecoin, so summing across them would make every cap meaningless.
   */
  committedAtomic(principalId: number, periodSeconds: number, currency: string): bigint {
    const since = new Date(this.now().getTime() - periodSeconds * 1000).toISOString();
    const placeholders = CONSUMING_STATES.map(() => '?').join(', ');
    const rows = this.repository
      .rawDatabase()
      .prepare(
        `SELECT amount_atomic AS amount FROM agent_ledger
          WHERE principal_id = ? AND currency = ? AND reserved_at > ? AND state IN (${placeholders})`,
      )
      .all(principalId, currency, since, ...CONSUMING_STATES) as { amount: string }[];
    return rows.reduce((total, row) => total + BigInt(row.amount), 0n);
  }

  reserve(request: ReserveRequest): number {
    if (request.currency !== request.allowance.currency) {
      throw new CurrencyMismatchError(request.currency, request.allowance.currency);
    }
    return this.repository.writeTransactionSync(() => {
      const committed = this.committedAtomic(request.principalId, request.allowance.periodSeconds, request.currency);
      const requested = BigInt(request.amountAtomic);
      const cap = BigInt(request.allowance.allowanceAtomic);
      if (committed + requested > cap) {
        throw new PoolExceededError(request.amountAtomic, committed.toString(), request.allowance.allowanceAtomic);
      }
      this.repository
        .rawDatabase()
        .prepare(
          `INSERT INTO agent_ledger
             (agent_id, principal_id, state, amount_atomic, currency, resource_url, reserved_at, clock_source, intent_id, attempt_no)
           VALUES (?, ?, 'reserved', ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          request.agentId,
          request.principalId,
          request.amountAtomic,
          request.currency,
          request.resourceUrl,
          this.now().toISOString(),
          request.clockSource,
          request.intentId ?? null,
          request.attemptNo ?? 1,
        );
      const row = this.repository.rawDatabase().prepare(`SELECT last_insert_rowid() AS id`).get() as { id: number };
      return Number(row.id);
    });
  }

  confirm(reservationId: number, caller: LedgerCaller, transactionRef: string): void {
    this.transition(reservationId, caller, 'confirmed', transactionRef, ['reserved', 'in_doubt']);
  }

  /** Only legal from `reserved`. An `in_doubt` row can never be released this way. */
  release(reservationId: number, caller: LedgerCaller): void {
    this.transition(reservationId, caller, 'released', null, ['reserved']);
  }

  /**
   * A transactionRef is required. A reservation with no transaction id was never a payment, that case must be
   * released, not left permanently consuming the pool.
   */
  markInDoubt(reservationId: number, caller: LedgerCaller, transactionRef: string): void {
    if (transactionRef.length === 0) throw new EvidenceRejectedError('in_doubt requires a transaction reference');
    this.transition(reservationId, caller, 'in_doubt', transactionRef, ['reserved']);
  }

  /**
   * Resolves an `in_doubt` row from a server observation, the only path out of `in_doubt`. A non-terminal status
   * leaves the row alone, still consuming the pool.
   */
  reconcileInDoubt(reservationId: number, caller: LedgerCaller, evidence: SettlementEvidence): void {
    const row = this.repository
      .rawDatabase()
      .prepare(`SELECT transaction_ref AS ref FROM agent_ledger WHERE id = ? AND agent_id = ? AND principal_id = ?`)
      .get(reservationId, caller.agentId, caller.principalId) as { ref: string | null } | undefined;
    if (row === undefined) throw new EvidenceRejectedError('no such reservation for this caller');
    if (row.ref !== evidence.transactionRef) {
      throw new EvidenceRejectedError('evidence transactionRef does not match the reservation');
    }
    const status = evidence.status.toUpperCase();
    if (TERMINAL_SETTLED.includes(status)) {
      this.transition(reservationId, caller, 'confirmed', evidence.transactionRef, ['in_doubt']);
      return;
    }
    if (TERMINAL_FAILED.includes(status)) {
      this.transition(reservationId, caller, 'released', evidence.transactionRef, ['in_doubt']);
    }
    // Non-terminal: leave it in_doubt. It keeps consuming the pool until the truth is known.
  }

  private transition(
    reservationId: number,
    caller: LedgerCaller,
    next: LedgerState,
    transactionRef: string | null,
    allowedFrom: readonly LedgerState[],
  ): void {
    this.repository.writeTransactionSync(() => {
      const placeholders = allowedFrom.map(() => '?').join(', ');
      const result = this.repository
        .rawDatabase()
        .prepare(
          `UPDATE agent_ledger
              SET state = ?, transaction_ref = COALESCE(?, transaction_ref), settled_at = ?
            WHERE id = ? AND agent_id = ? AND principal_id = ? AND state IN (${placeholders})`,
        )
        .run(
          next,
          transactionRef,
          this.now().toISOString(),
          reservationId,
          caller.agentId,
          caller.principalId,
          ...allowedFrom,
        ) as { changes?: number | bigint };
      if (Number(result.changes ?? 0) !== 1) {
        throw new Error(
          `illegal ledger transition to ${next} for reservation ${reservationId}: row missing, not owned by this caller, or not in ${allowedFrom.join('/')}`,
        );
      }
    });
  }
}
