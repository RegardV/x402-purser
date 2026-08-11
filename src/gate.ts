/**
 * The policy gate.
 *
 * Everything is checked here, before the daemon signs anything and before any money can move. The order matters: the
 * signature is verified first, so an unsigned or wrongly signed request never reaches the intent table or the ledger
 * and leaves no trace.
 *
 * Two ceilings apply and both bind. The envelope is what the operator granted the agent. The intent ceiling is what the
 * agent said it was willing to spend for this request. The lower wins. An agent may bind itself tighter than its
 * envelope; it can never bind itself looser.
 *
 * The quote never comes from the agent. It is read from the seller's own 402 response, because an agent that supplied
 * `payTo` could name an allowed host and substitute its own address.
 */

import { verifyClaim, type PaymentClaim } from './credential.js';
import type { AgentLedger } from './ledger.js';
import type { AgentStore } from './store.js';
import type { AllowanceStore } from './allowance.js';
import type { IntentStore } from './intent.js';

export type GateRefusal =
  | 'bad_signature'
  | 'stale_claim'
  | 'agent_revoked'
  | 'envelope_expired'
  | 'host_not_allowed'
  | 'currency_not_allowed'
  | 'exceeds_intent_ceiling'
  | 'exceeds_per_transaction_limit'
  | 'insecure_scheme';

export class GateRefusedError extends Error {
  constructor(
    readonly reason: GateRefusal,
    detail: string,
  ) {
    super(`refused (${reason}): ${detail}`);
    this.name = 'GateRefusedError';
  }
}

/** What the seller actually asked for, read from its own 402 response. Never from the agent. */
export interface Quote {
  readonly priceAtomic: string;
  readonly currency: string;
  readonly payTo: string;
  readonly asset: string;
  readonly network: string;
  readonly validBefore: number;
}

export interface GateDeps {
  readonly store: AgentStore;
  readonly ledger: AgentLedger;
  readonly allowances: AllowanceStore;
  readonly intents: IntentStore;
  readonly now: () => Date;
}

export interface GateDecision {
  readonly intentId: number;
  readonly attemptNo: number;
  readonly reservationId: number;
  readonly quote: Quote;
  readonly agentId: number;
  readonly principalId: number;
}

const ATOMIC_PATTERN = /^(0|[1-9][0-9]*)$/u;
const MAX_CLAIM_SKEW_MS = 60_000;

function hostOf(resourceUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(resourceUrl);
  } catch {
    throw new GateRefusedError('insecure_scheme', resourceUrl);
  }
  const host = parsed.hostname.toLowerCase();
  const loopback = host === 'localhost' || host === '127.0.0.1' || host === '::1';
  if (parsed.protocol !== 'https:' && !loopback) {
    throw new GateRefusedError('insecure_scheme', `${parsed.protocol}//${host}`);
  }
  return host;
}

/**
 * Admits or refuses one attempt.
 *
 * Pass `intentId` to record a retry against an existing intent, or null to open a new one. A retry re-checks the NEW
 * quote against both ceilings. It never inherits the decision that admitted the first attempt, that is the whole
 * reason intents and attempts are separate.
 *
 * Ponytail: principalId is fixed at 1. The daemon serves one unlocked wallet belonging to one principal, so there is
 * nothing yet to resolve it from. Task 11 replaces this with the principal the daemon unlocked; it must not survive
 * past that task.
 */
export interface AuthenticatedAgent {
  readonly principalId: number;
  readonly agent: ReturnType<AgentStore['describe']>;
  readonly now: Date;
  readonly host: string;
}

/**
 * Proves who is asking, before anything is fetched or signed.
 *
 * Split out of admit because these checks do not depend on a quote, and a free resource must not
 * skip them: the signature is the agent's authentication for the whole request, not just for the
 * payment. Calling pay() on a 200 resource without this would let anyone holding the socket drive
 * arbitrary fetches, including an agent whose key has been revoked.
 */
export function authenticate(deps: GateDeps, claim: PaymentClaim, signature: string): AuthenticatedAgent {
  const principalId = 1;
  const agent = deps.store.describe(principalId, claim.agentRef);

  if (!verifyClaim(claim, signature, agent.publicKeyPem)) {
    throw new GateRefusedError('bad_signature', claim.agentRef);
  }

  const now = deps.now();
  const skew = Math.abs(now.getTime() - Date.parse(claim.timestamp));
  if (Number.isNaN(skew) || skew > MAX_CLAIM_SKEW_MS) {
    throw new GateRefusedError('stale_claim', claim.timestamp);
  }

  if (agent.revokedAt !== null) {
    throw new GateRefusedError('agent_revoked', `revoked at ${agent.revokedAt}`);
  }

  const envelope = agent.envelope;
  if (envelope.expiresAt !== null && now.getTime() > Date.parse(envelope.expiresAt)) {
    throw new GateRefusedError('envelope_expired', envelope.expiresAt);
  }

  const host = hostOf(claim.resourceUrl);
  if (!envelope.allowedHosts.includes(host)) {
    throw new GateRefusedError('host_not_allowed', host);
  }

  return { principalId, agent, now, host };
}

export function admit(
  deps: GateDeps,
  claim: PaymentClaim,
  signature: string,
  quote: Quote,
  intentId: number | null,
): GateDecision {
  const { principalId, agent, now } = authenticate(deps, claim, signature);
  const envelope = agent.envelope;

  if (!envelope.allowedCurrencies.includes(quote.currency)) {
    throw new GateRefusedError('currency_not_allowed', quote.currency);
  }
  if (!ATOMIC_PATTERN.test(quote.priceAtomic)) {
    throw new GateRefusedError('exceeds_per_transaction_limit', quote.priceAtomic);
  }

  const price = BigInt(quote.priceAtomic);
  if (price > BigInt(claim.ceilingAtomic)) {
    throw new GateRefusedError('exceeds_intent_ceiling', `${quote.priceAtomic} > ${claim.ceilingAtomic}`);
  }
  if (price > BigInt(envelope.maxPerTxAtomic)) {
    throw new GateRefusedError('exceeds_per_transaction_limit', `${quote.priceAtomic} > ${envelope.maxPerTxAtomic}`);
  }

  const intent =
    intentId ??
    deps.intents.open({
      principalId,
      agentId: agent.agentId,
      resourceUrl: claim.resourceUrl,
      ceilingAtomic: claim.ceilingAtomic,
      currency: quote.currency,
      envelopeVersion: agent.envelopeVersion,
    }).id;

  const attemptNo = deps.intents.nextAttemptNo(intent);
  const reservationId = deps.ledger.reserve({
    agentId: agent.agentId,
    principalId,
    amountAtomic: quote.priceAtomic,
    currency: quote.currency,
    resourceUrl: claim.resourceUrl,
    allowance: deps.allowances.require(principalId),
    clockSource: 'server',
    intentId: intent,
    attemptNo,
  });

  return { intentId: intent, attemptNo, reservationId, quote, agentId: agent.agentId, principalId };
}

/** Minimal shape we consume from @x402/core's PaymentRequirements. */
export interface RequirementsLike {
  readonly scheme: string;
  readonly network: string;
  readonly asset: string;
  readonly amount: string;
  readonly payTo: string;
  readonly maxTimeoutSeconds: number;
}

/**
 * Maps the seller's own requirements into a Quote.
 *
 * Everything here comes from the 402 response. Nothing comes from the agent, because an agent
 * that supplied payTo could name an allowed host and substitute its own address.
 */
export function quoteFromRequirements(
  requirements: RequirementsLike,
  currency: string,
  now: () => Date = () => new Date(),
): Quote {
  if (requirements.scheme !== 'exact') {
    throw new GateRefusedError('insecure_scheme', `unsupported scheme ${requirements.scheme}`);
  }
  if (!ATOMIC_PATTERN.test(requirements.amount)) {
    throw new GateRefusedError('exceeds_per_transaction_limit', `malformed amount ${requirements.amount}`);
  }
  return {
    priceAtomic: requirements.amount,
    currency,
    payTo: requirements.payTo,
    asset: requirements.asset,
    network: requirements.network,
    validBefore: Math.floor(now().getTime() / 1000) + requirements.maxTimeoutSeconds,
  };
}
