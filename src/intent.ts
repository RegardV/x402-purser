/**
 * Intents and attempts.
 *
 * An intent is what the agent asked for: one URL, one ceiling, one envelope version, one moment. An attempt is one
 * quote and one authorisation decision. Many attempts per intent.
 *
 * The split exists to answer a question the ledger alone could not: who authorised the retry after the price changed?
 * Without it, a seller that fails and re-quotes higher inherits the first approval, and approval leaks into habit.
 *
 * Most of an attempt is contractual rather than ours. An EIP-3009 signature already binds the amount, the recipient and
 * the expiry, so the ledger stores a reference to that signature, the nonce, the typed-data hash and the signature
 * itself, not a re-description of it. What lives here is only what spans many payments, because the chain has no
 * memory of those.
 */

const ATOMIC_PATTERN = /^(0|[1-9][0-9]*)$/u;

/** V1 records that goods were paid for and not delivered. It cannot claw anything back. */
export type RefundRule = 'dispute_only';

export interface Intent {
  readonly id: number;
  readonly principalId: number;
  readonly agentId: number;
  readonly resourceUrl: string;
  readonly ceilingAtomic: string;
  readonly currency: string;
  readonly envelopeVersion: number;
  readonly refundRule: RefundRule;
  readonly createdAt: string;
}

export interface OpenIntentInput {
  readonly principalId: number;
  readonly agentId: number;
  readonly resourceUrl: string;
  readonly ceilingAtomic: string;
  readonly currency: string;
  readonly envelopeVersion: number;
}

export class IntentRejectedError extends Error {
  constructor(reason: string) {
    super(`intent rejected: ${reason}`);
    this.name = 'IntentRejectedError';
  }
}

interface SqliteLike {
  prepare(sql: string): {
    all(...values: unknown[]): unknown[];
    get(...values: unknown[]): unknown;
    run(...values: unknown[]): unknown;
  };
}

export interface IntentRepository {
  writeTransactionSync<T>(work: () => T): T;
  rawDatabase(): SqliteLike;
}

export class IntentStore {
  constructor(
    private readonly repository: IntentRepository,
    private readonly now: () => Date = () => new Date(),
  ) {}

  open(input: OpenIntentInput): Intent {
    if (!ATOMIC_PATTERN.test(input.ceilingAtomic)) {
      throw new IntentRejectedError('ceilingAtomic must be a non-negative integer string');
    }
    return this.repository.writeTransactionSync(() => {
      const createdAt = this.now().toISOString();
      this.repository
        .rawDatabase()
        .prepare(
          `INSERT INTO intents
             (principal_id, agent_id, resource_url, ceiling_atomic, currency, envelope_version, refund_rule, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 'dispute_only', ?)`,
        )
        .run(
          input.principalId,
          input.agentId,
          input.resourceUrl,
          input.ceilingAtomic,
          input.currency,
          input.envelopeVersion,
          createdAt,
        );
      const row = this.repository.rawDatabase().prepare(`SELECT last_insert_rowid() AS id`).get() as { id: number };
      return {
        id: Number(row.id),
        principalId: input.principalId,
        agentId: input.agentId,
        resourceUrl: input.resourceUrl,
        ceilingAtomic: input.ceilingAtomic,
        currency: input.currency,
        envelopeVersion: input.envelopeVersion,
        refundRule: 'dispute_only',
        createdAt,
      };
    });
  }

  /** Attempts already recorded. Visible rather than hidden, so retries cannot accumulate quietly. */
  attemptCount(intentId: number): number {
    const row = this.repository
      .rawDatabase()
      .prepare(`SELECT COUNT(*) AS n FROM agent_ledger WHERE intent_id = ?`)
      .get(intentId) as { n: number };
    return Number(row.n);
  }

  nextAttemptNo(intentId: number): number {
    return this.attemptCount(intentId) + 1;
  }
}
