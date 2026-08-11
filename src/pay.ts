/**
 * Drives one paid request.
 *
 * Purser fetches the resource, reads the seller's own 402, lets the gate decide, signs, and
 * replays the request itself. Replaying here rather than handing a payload back to the agent is
 * what makes settlement an observation instead of the agent's report of its own outcome.
 */

import { x402HTTPClient } from '@x402/core/client';
import { buildClient, type PendingRequest, type PurserClientDeps } from './client.js';
import type { GateDecision } from './gate.js';

export type PayResult =
  | { readonly status: 'paid'; readonly body: string; readonly decision: GateDecision }
  | { readonly status: 'refused'; readonly reason: string }
  | { readonly status: 'free'; readonly body: string }
  | { readonly status: 'seller_error'; readonly httpStatus: number };

export async function pay(
  deps: PurserClientDeps,
  pending: PendingRequest,
  fetchImpl: typeof fetch = fetch,
): Promise<PayResult> {
  const { client, decisions } = buildClient(deps, pending);
  const http = new x402HTTPClient(client);

  const probe = await fetchImpl(pending.claim.resourceUrl);
  if (probe.status !== 402) {
    if (probe.ok) return { status: 'free', body: await probe.text() };
    return { status: 'seller_error', httpStatus: probe.status };
  }

  // createPaymentPayload is what runs the beforePaymentCreation hooks and signs. Do not use
  // handlePaymentRequired here: it only dispatches onPaymentRequired hooks and returns null when
  // none of them supply headers, so the gate would never see the quote.
  let headers: Record<string, string>;
  try {
    const paymentRequired = http.getPaymentRequiredResponse(
      (name) => probe.headers.get(name),
      await probe.clone().text(),
    );
    const payload = await http.createPaymentPayload(paymentRequired);
    headers = http.encodePaymentSignatureHeader(payload);
  } catch (cause) {
    // A gate refusal surfaces as a thrown abort from inside the hook.
    return { status: 'refused', reason: cause instanceof Error ? cause.message : String(cause) };
  }

  const decision = decisions[decisions.length - 1];
  if (decision === undefined) {
    return { status: 'refused', reason: 'the gate declined this quote' };
  }

  const caller = { agentId: decision.agentId, principalId: decision.principalId };
  const replay = await fetchImpl(pending.claim.resourceUrl, { headers });

  if (replay.ok) {
    const transactionRef = replay.headers.get('PAYMENT-RESPONSE') ?? `settled-${decision.reservationId}`;
    deps.ledger.confirm(decision.reservationId, caller, transactionRef);
    return { status: 'paid', body: await replay.text(), decision };
  }

  // The seller saw the payload and still refused, so no money moved.
  deps.ledger.release(decision.reservationId, caller);
  return { status: 'seller_error', httpStatus: replay.status };
}
