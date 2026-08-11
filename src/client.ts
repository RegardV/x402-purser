/**
 * The x402 client, with Purser's gate installed.
 *
 * @x402/core already runs the 402 flow: select requirements, sign, retry. We do not reimplement
 * any of it. What we add is a decision point before the signature exists.
 *
 * The gate runs in onBeforePaymentCreation because it is the only hook that can abort with a
 * reason. A refusal there costs no signature.
 */

import { x402Client } from '@x402/core/client';
import { registerExactEvmScheme } from '@x402/evm/exact/client';
import { admit, quoteFromRequirements, type GateDecision, type GateDeps, type RequirementsLike } from './gate.js';
import type { PaymentClaim } from './credential.js';
import type { Wallet } from './wallet.js';

export interface PendingRequest {
  readonly claim: PaymentClaim;
  readonly signature: string;
  /** Pass an existing intent to record a retry against it. Null opens a new one. */
  readonly intentId: number | null;
}

export interface PurserClientDeps extends GateDeps {
  readonly wallet: Wallet;
  /** The protocol carries an asset address, not a symbol. Envelopes are written against symbols. */
  currencyForAsset(asset: string): string;
}

export function buildClient(
  deps: PurserClientDeps,
  pending: PendingRequest,
): { client: x402Client; decisions: GateDecision[] } {
  const decisions: GateDecision[] = [];
  const client = new x402Client();

  registerExactEvmScheme(client, { signer: deps.wallet });

  client.onBeforePaymentCreation(async (context) => {
    const requirements = context.selectedRequirements as unknown as RequirementsLike;
    try {
      const quote = quoteFromRequirements(requirements, deps.currencyForAsset(requirements.asset), deps.now);
      decisions.push(admit(deps, pending.claim, pending.signature, quote, pending.intentId));
      return;
    } catch (cause) {
      // Abort rather than throw, so the caller receives the reason instead of a stack trace.
      return { abort: true, reason: cause instanceof Error ? cause.message : String(cause) };
    }
  });

  return { client, decisions };
}
