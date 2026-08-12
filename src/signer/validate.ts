/**
 * What the signer will and will not sign.
 *
 * This is the reason the signer exists. A cloud KMS signs any digest handed to it, so a compromised
 * caller can have a wallet draining transaction signed. This process only ever signs an EIP-3009
 * transfer authorization, so the worst a compromised daemon achieves is a payment that was already
 * inside policy.
 *
 * The ceiling here deliberately duplicates the daemon's envelope. The envelope is the primary
 * control; this is the backstop for when the daemon is the thing that failed.
 */

import type { TypedDataMessage } from '../wallet.js';

export interface SignerPolicy {
  /** Lowercase token contract addresses this signer will pay. */
  readonly tokens: readonly string[];
  readonly chainIds: readonly number[];
  /** Hard per-payment ceiling, atomic units. Set at startup, unreachable over the socket. */
  readonly maxValueAtomic: bigint;
  readonly maxValidityWindowSeconds: number;
}

export class SignerRefusedError extends Error {
  constructor(readonly code: string, detail: string) {
    super(`${code}: ${detail}`);
    this.name = 'SignerRefusedError';
  }
}

const EXPECTED_FIELDS = [
  ['from', 'address'], ['to', 'address'], ['value', 'uint256'],
  ['validAfter', 'uint256'], ['validBefore', 'uint256'], ['nonce', 'bytes32'],
] as const;

const PRIMARY_TYPE = 'TransferWithAuthorization';

function requireBigint(message: Record<string, unknown>, field: string): bigint {
  const value = message[field];
  if (typeof value !== 'bigint') {
    throw new SignerRefusedError('malformed_message', `${field} must be a bigint, got ${typeof value}`);
  }
  return value;
}

export function validateSigningRequest(
  message: TypedDataMessage,
  policy: SignerPolicy,
  selfAddress: string,
  now: Date,
): void {
  if (message.primaryType !== PRIMARY_TYPE) {
    throw new SignerRefusedError('not_a_payment', `primaryType was ${message.primaryType}`);
  }

  const typeKeys = Object.keys(message.types);
  if (typeKeys.length !== 1 || typeKeys[0] !== PRIMARY_TYPE) {
    throw new SignerRefusedError('unexpected_types', `types contained ${typeKeys.join(', ')}`);
  }
  const fields = message.types[PRIMARY_TYPE];
  if (!Array.isArray(fields) || fields.length !== EXPECTED_FIELDS.length) {
    throw new SignerRefusedError('unexpected_types', 'field count does not match EIP-3009');
  }
  for (const [index, [name, type]] of EXPECTED_FIELDS.entries()) {
    const actual = fields[index] as { name?: unknown; type?: unknown } | undefined;
    if (actual?.name !== name || actual.type !== type) {
      throw new SignerRefusedError('unexpected_types', `field ${index} was not ${name}:${type}`);
    }
  }

  const chainId = message.domain['chainId'];
  if (typeof chainId !== 'number' || !policy.chainIds.includes(chainId)) {
    throw new SignerRefusedError('unknown_chain', String(chainId));
  }

  const contract = message.domain['verifyingContract'];
  if (typeof contract !== 'string' || !policy.tokens.includes(contract.toLowerCase())) {
    throw new SignerRefusedError('unknown_token', String(contract));
  }

  const from = message.message['from'];
  if (typeof from !== 'string' || from.toLowerCase() !== selfAddress.toLowerCase()) {
    throw new SignerRefusedError('wrong_payer', String(from));
  }

  const value = requireBigint(message.message, 'value');
  requireBigint(message.message, 'validAfter');
  if (value > policy.maxValueAtomic) {
    throw new SignerRefusedError('exceeds_signer_ceiling', `${value} > ${policy.maxValueAtomic}`);
  }

  const validBefore = requireBigint(message.message, 'validBefore');
  const seconds = BigInt(Math.floor(now.getTime() / 1000));
  if (validBefore <= seconds) {
    throw new SignerRefusedError('bad_validity_window', `expired at ${validBefore}`);
  }
  if (validBefore - seconds > BigInt(policy.maxValidityWindowSeconds)) {
    throw new SignerRefusedError('bad_validity_window', 'valid for longer than the horizon allows');
  }
}
