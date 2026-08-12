/**
 * Wire codec for the signer socket.
 *
 * EIP-712 payloads carry uint256 fields as bigint, and JSON.stringify throws on those. Encoding
 * them as strings and reviving them as strings would be worse than throwing: viem would hash a
 * different value and produce a valid signature over the wrong payment. Bigints are tagged so they
 * come back as bigints or not at all.
 */

export const SIGNER_PROTOCOL_VERSION = 1;

const BIGINT_TAG = '$bigint';
const INTEGER = /^-?(0|[1-9][0-9]*)$/u;

export function encodeJson(value: unknown): string {
  return JSON.stringify(value, (_key, raw: unknown) =>
    typeof raw === 'bigint' ? { [BIGINT_TAG]: raw.toString() } : raw,
  );
}

export function decodeJson(text: string): unknown {
  return JSON.parse(text, (_key, raw: unknown) => {
    if (raw === null || typeof raw !== 'object') return raw;
    const tagged = raw as Record<string, unknown>;
    if (!(BIGINT_TAG in tagged)) return raw;
    const digits = tagged[BIGINT_TAG];
    if (typeof digits !== 'string' || !INTEGER.test(digits)) {
      throw new Error(`malformed bigint on the wire: ${String(digits)}`);
    }
    return BigInt(digits);
  });
}
