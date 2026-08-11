/**
 * Payment authorisation for agent identities.
 *
 * `authorizePayment` runs every check and takes the pool reservation _before_ the caller performs any network call, so
 * a refusal never costs a request. The caller then executes the payment and reports the outcome to `settlePayment`.
 *
 * The outcome split is the part that matters. A failure releases the reservation; an _unknown_ outcome does not.
 * Unknown means the money may already have moved, so the reservation becomes `in_doubt` and keeps consuming the pool
 * until reconciliation establishes what actually happened.
 */

import type { Envelope } from './envelope.js';
import { AllowanceStore } from './allowance.js';
import { AgentLedger, type LedgerCaller } from './ledger.js';
import type { AgentStore } from './store.js';

export type RefusalReason =
  | 'agent_revoked'
  | 'envelope_expired'
  | 'host_not_allowed'
  | 'exceeds_per_transaction_limit'
  | 'malformed_price'
  | 'malformed_resource_url'
  | 'currency_not_allowed'
  | 'insecure_scheme';

export class PaymentRefusedError extends Error {
  constructor(
    readonly reason: RefusalReason,
    detail: string,
  ) {
    super(`payment refused (${reason}): ${detail}`);
    this.name = 'PaymentRefusedError';
  }
}

export interface AuthorizationRequest {
  readonly principalId: number;
  readonly agentRef: string;
  readonly resourceUrl: string;
  readonly priceAtomic: string;
  readonly currency: string;
}

export interface Authorization {
  readonly reservationId: number;
  readonly envelope: Envelope;
  /** Required to settle. Without it any caller could mutate any reservation, finding C3. */
  readonly caller: LedgerCaller;
}

/** Settled: money moved. Failed: it definitively did not. Unknown: nobody can say yet. */
export type PaymentOutcome =
  | { readonly status: 'settled'; readonly transactionRef: string }
  | { readonly status: 'failed' }
  | { readonly status: 'unknown'; readonly transactionRef: string | null };

const ATOMIC_PATTERN = /^(0|[1-9][0-9]*)$/u;

function hostOf(resourceUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(resourceUrl);
  } catch {
    throw new PaymentRefusedError('malformed_resource_url', resourceUrl);
  }
  const host = parsed.hostname.toLowerCase();
  const loopback = host === 'localhost' || host === '127.0.0.1' || host === '::1';
  // M6: an allowlist entry is a host, not a scheme. Without this check a cleartext http URL to an
  // allowed host passes, and the payment traffic is interceptable.
  if (parsed.protocol !== 'https:' && !loopback) {
    throw new PaymentRefusedError('insecure_scheme', `${parsed.protocol}//${host}`);
  }
  return host;
}

export function authorizePayment(
  store: AgentStore,
  ledger: AgentLedger,
  allowances: AllowanceStore,
  request: AuthorizationRequest,
  now: () => Date = () => new Date(),
): Authorization {
  if (!ATOMIC_PATTERN.test(request.priceAtomic)) {
    throw new PaymentRefusedError('malformed_price', request.priceAtomic);
  }
  const host = hostOf(request.resourceUrl);
  const agent = store.describe(request.principalId, request.agentRef);

  if (agent.revokedAt !== null) {
    throw new PaymentRefusedError('agent_revoked', `revoked at ${agent.revokedAt}`);
  }

  const envelope = agent.envelope;
  if (envelope.expiresAt !== null && now().getTime() > Date.parse(envelope.expiresAt)) {
    throw new PaymentRefusedError('envelope_expired', `expired at ${envelope.expiresAt}`);
  }
  if (!envelope.allowedHosts.includes(host)) {
    throw new PaymentRefusedError('host_not_allowed', host);
  }
  if (!envelope.allowedCurrencies.includes(request.currency)) {
    throw new PaymentRefusedError('currency_not_allowed', request.currency);
  }
  if (BigInt(request.priceAtomic) > BigInt(envelope.maxPerTxAtomic)) {
    throw new PaymentRefusedError(
      'exceeds_per_transaction_limit',
      `${request.priceAtomic} > ${envelope.maxPerTxAtomic}`,
    );
  }

  const caller: LedgerCaller = { agentId: agent.agentId, principalId: request.principalId };
  // Throws PoolExceededError if the shared cap has no room. Taken before any network call, and
  // bounded by the ACCOUNT allowance rather than this agent's own envelope, finding C1.
  const reservationId = ledger.reserve({
    agentId: agent.agentId,
    principalId: request.principalId,
    amountAtomic: request.priceAtomic,
    currency: request.currency,
    resourceUrl: request.resourceUrl,
    allowance: allowances.require(request.principalId),
    clockSource: 'server',
  });

  return { reservationId, envelope, caller };
}

/** Applies a payment's outcome. `unknown` never releases, see the module note. */
export function settlePayment(ledger: AgentLedger, authorization: Authorization, outcome: PaymentOutcome): void {
  switch (outcome.status) {
    case 'settled':
      ledger.confirm(authorization.reservationId, authorization.caller, outcome.transactionRef);
      return;
    case 'failed':
      ledger.release(authorization.reservationId, authorization.caller);
      return;
    case 'unknown':
      if (outcome.transactionRef === null) {
        // No transaction id was ever obtained, so no payment exists to be in doubt about.
        // Leaving it in_doubt would consume pool capacity forever with nothing to reconcile.
        ledger.release(authorization.reservationId, authorization.caller);
        return;
      }
      ledger.markInDoubt(authorization.reservationId, authorization.caller, outcome.transactionRef);
      return;
  }
}
