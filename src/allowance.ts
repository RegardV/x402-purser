/**
 * Account-level spend allowance.
 *
 * This is the pool every agent under a principal draws from. It exists because per-agent envelopes are meaningless
 * without an account-level ceiling to attenuate against, an agent issued with an arbitrary cap would otherwise have
 * the whole account as its blast radius.
 *
 * Absent means no agent may spend. An unconfigured install fails closed rather than transacting unbounded.
 */

const ATOMIC_PATTERN = /^(0|[1-9][0-9]*)$/u;

export interface Allowance {
  /** Pool ceiling across `periodSeconds`, atomic units, decimal string. */
  readonly allowanceAtomic: string;
  /** Rolling window in seconds. */
  readonly periodSeconds: number;
  /** The single currency this allowance is denominated in. */
  readonly currency: string;
}

export class AllowanceNotConfiguredError extends Error {
  constructor(principalId: number) {
    super(`no spend allowance configured for principal ${principalId}; no agent may spend until one is set`);
    this.name = 'AllowanceNotConfiguredError';
  }
}

export class AllowanceRejectedError extends Error {
  constructor(reasons: readonly string[]) {
    super(`allowance rejected: ${reasons.join('; ')}`);
    this.name = 'AllowanceRejectedError';
  }
}

interface SqliteLike {
  prepare(sql: string): {
    all(...values: unknown[]): unknown[];
    get(...values: unknown[]): unknown;
    run(...values: unknown[]): unknown;
  };
}

export interface AllowanceRepository {
  writeTransactionSync<T>(work: () => T): T;
  rawDatabase(): SqliteLike;
}

export class AllowanceStore {
  constructor(
    private readonly repository: AllowanceRepository,
    private readonly now: () => Date = () => new Date(),
  ) {}

  set(principalId: number, allowance: Allowance): void {
    const problems: string[] = [];
    if (!ATOMIC_PATTERN.test(allowance.allowanceAtomic)) {
      problems.push('allowanceAtomic must be a non-negative integer string');
    }
    if (!Number.isSafeInteger(allowance.periodSeconds) || allowance.periodSeconds <= 0) {
      problems.push('periodSeconds must be a positive integer');
    }
    if (allowance.currency.length === 0) problems.push('currency must be non-empty');
    if (problems.length > 0) throw new AllowanceRejectedError(problems);

    this.repository.writeTransactionSync(() => {
      this.repository
        .rawDatabase()
        .prepare(
          `INSERT INTO principal_allowance (principal_id, allowance_atomic, period_seconds, currency, payload_mac, updated_at)
           VALUES (?, ?, ?, ?, '', ?)
           ON CONFLICT(principal_id) DO UPDATE SET
             allowance_atomic = excluded.allowance_atomic,
             period_seconds = excluded.period_seconds,
             currency = excluded.currency,
             updated_at = excluded.updated_at`,
        )
        .run(
          principalId,
          allowance.allowanceAtomic,
          allowance.periodSeconds,
          allowance.currency,
          this.now().toISOString(),
        );
    });
  }

  /** Throws rather than defaulting. There is no safe default for a spend ceiling. */
  require(principalId: number): Allowance {
    const row = this.repository
      .rawDatabase()
      .prepare(
        `SELECT allowance_atomic AS a, period_seconds AS p, currency AS c
           FROM principal_allowance WHERE principal_id = ?`,
      )
      .get(principalId) as { a: string; p: number; c: string } | undefined;
    if (row === undefined) throw new AllowanceNotConfiguredError(principalId);
    return { allowanceAtomic: row.a, periodSeconds: Number(row.p), currency: row.c };
  }
}
