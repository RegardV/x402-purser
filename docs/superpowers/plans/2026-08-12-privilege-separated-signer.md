# Privilege Separated Signer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the wallet key out of the Purser daemon into a separate, networkless process that refuses to sign anything except an EIP-3009 payment.

**Architecture:** The `Wallet` interface already isolates signing, so the signer becomes a second process behind a unix socket. The daemon links `connectSignerWallet()` where it used `unlockWallet()`. The signer receives structured EIP-712 typed data, never a raw digest, validates it against its own policy, and only then signs. There is no code path in the signer that produces a signature over a caller supplied hash.

**Tech Stack:** Node 24, TypeScript, `node:net`, viem, vitest. No new runtime dependencies.

## Global Constraints

- No em-dashes anywhere, in code, comments, docs or commit messages.
- Node >= 24. No new runtime dependencies; viem and the x402 packages are already present.
- The signer must never sign a caller supplied digest. Structured typed data only.
- Existing tests must not regress. The suite is 126 tests before this plan.
- Every refusal uses a stable lowercase snake_case code, matching the existing `GateRefusedError` convention.
- Amounts are atomic units as decimal strings or bigints, never floats.

## Ground truth: the payload actually signed

Captured from a real run of `pay()` on 2026-08-12. Every task depends on this shape being exact.

```json
{
  "domain": { "name": "USD Coin", "version": "2", "chainId": 8453,
              "verifyingContract": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" },
  "types": { "TransferWithAuthorization": [
      { "name": "from", "type": "address" }, { "name": "to", "type": "address" },
      { "name": "value", "type": "uint256" }, { "name": "validAfter", "type": "uint256" },
      { "name": "validBefore", "type": "uint256" }, { "name": "nonce", "type": "bytes32" } ] },
  "primaryType": "TransferWithAuthorization",
  "message": { "from": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "to": "0x000000000000000000000000000000000000dEaD",
    "value": 1000n, "validAfter": 0n, "validBefore": 1786529574n,
    "nonce": "0xf84e6d30534bfb2ec7380c923f5baea20e7bd3017a6c8e461c4354117112d9ad" }
}
```

`value`, `validAfter` and `validBefore` are **bigint**. `JSON.stringify` throws on them. `chainId` is a plain number.

## File structure

| File | Responsibility |
| --- | --- |
| `src/signer/protocol.ts` | Wire codec that survives bigint. Shared by both processes. |
| `src/signer/validate.ts` | Pure policy validation. No IO, exhaustively testable. |
| `src/signer/server.ts` | The signer process: socket, validate, sign. |
| `src/signer/cli.ts` | The `purser-signer` binary. |
| `src/socket-wallet.ts` | `connectSignerWallet()`, a `Wallet` that forwards over the socket. |
| `deploy/purser-signer.service` | systemd unit with the hardening that makes this worth doing. |

---

### Task 1: Wire codec that survives bigint

**Files:**
- Create: `src/signer/protocol.ts`, `test/signer-protocol.test.ts`

**Interfaces:**
- Consumes: `TypedDataMessage` from `src/wallet.ts`.
- Produces:
  - `const SIGNER_PROTOCOL_VERSION = 1`
  - `function encodeJson(value: unknown): string`
  - `function decodeJson(text: string): unknown`
  - Bigints are encoded as `{ "$bigint": "1000" }` and revived as bigint.

- [ ] **Step 1: Write the failing test**

Create `test/signer-protocol.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { decodeJson, encodeJson } from '../src/signer/protocol.js';
import type { TypedDataMessage } from '../src/wallet.js';

const KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';

const PAYLOAD: TypedDataMessage = {
  domain: { name: 'USD Coin', version: '2', chainId: 8453,
            verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' },
  types: { TransferWithAuthorization: [
    { name: 'from', type: 'address' }, { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' } ] },
  primaryType: 'TransferWithAuthorization',
  message: { from: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    to: '0x000000000000000000000000000000000000dEaD',
    value: 1000n, validAfter: 0n, validBefore: 1786529574n,
    nonce: '0xf84e6d30534bfb2ec7380c923f5baea20e7bd3017a6c8e461c4354117112d9ad' },
};

describe('signer protocol codec', () => {
  it('round trips bigint as bigint, not string', () => {
    const back = decodeJson(encodeJson(PAYLOAD)) as TypedDataMessage;
    expect(typeof back.message['value']).toBe('bigint');
    expect(back.message['value']).toBe(1000n);
    expect(back.message['validAfter']).toBe(0n);
    expect(back).toEqual(PAYLOAD);
  });

  it('leaves chainId a plain number', () => {
    const back = decodeJson(encodeJson(PAYLOAD)) as TypedDataMessage;
    expect(typeof back.domain['chainId']).toBe('number');
  });

  // The gate that matters. A codec that alters the payload produces a different signature,
  // and a different signature is an unspendable payment that looks fine in every other test.
  it('a round tripped payload signs to the identical bytes', async () => {
    const account = privateKeyToAccount(KEY);
    const direct = await account.signTypedData(PAYLOAD as never);
    const viaWire = await account.signTypedData(decodeJson(encodeJson(PAYLOAD)) as never);
    expect(viaWire).toBe(direct);
  });

  it('rejects a bigint that is not an integer string', () => {
    expect(() => decodeJson('{"$bigint":"not-a-number"}')).toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run test/signer-protocol --reporter=basic`
Expected: FAIL, cannot resolve `../src/signer/protocol.js`.

- [ ] **Step 3: Write the implementation**

Create `src/signer/protocol.ts`:

```ts
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run test/signer-protocol --reporter=basic`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add src/signer/protocol.ts test/signer-protocol.test.ts
git commit -m "feat: bigint safe wire codec for the signer socket"
```

---

### Task 2: The validator

**Files:**
- Create: `src/signer/validate.ts`, `test/signer-validate.test.ts`

**Interfaces:**
- Consumes: `TypedDataMessage` from `src/wallet.ts`.
- Produces:
  - `interface SignerPolicy { readonly tokens: readonly string[]; readonly chainIds: readonly number[]; readonly maxValueAtomic: bigint; readonly maxValidityWindowSeconds: number }`
  - `class SignerRefusedError extends Error { readonly code: string }`
  - `function validateSigningRequest(message: TypedDataMessage, policy: SignerPolicy, selfAddress: string, now: Date): void`

- [ ] **Step 1: Write the failing test**

Create `test/signer-validate.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { SignerRefusedError, validateSigningRequest, type SignerPolicy } from '../src/signer/validate.js';
import type { TypedDataMessage } from '../src/wallet.js';

const SELF = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const NOW = new Date('2026-08-12T00:00:00.000Z');
const VALID_BEFORE = BigInt(Math.floor(NOW.getTime() / 1000) + 3600);

const POLICY: SignerPolicy = {
  tokens: ['0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'],
  chainIds: [8453],
  maxValueAtomic: 5000n,
  maxValidityWindowSeconds: 86_400,
};

const TYPES = { TransferWithAuthorization: [
  { name: 'from', type: 'address' }, { name: 'to', type: 'address' },
  { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' },
  { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' } ] };

function payment(overrides: Partial<TypedDataMessage> = {}): TypedDataMessage {
  return {
    domain: { name: 'USD Coin', version: '2', chainId: 8453,
              verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' },
    types: TYPES,
    primaryType: 'TransferWithAuthorization',
    message: { from: SELF, to: '0x000000000000000000000000000000000000dEaD',
      value: 1000n, validAfter: 0n, validBefore: VALID_BEFORE,
      nonce: '0xf84e6d30534bfb2ec7380c923f5baea20e7bd3017a6c8e461c4354117112d9ad' },
    ...overrides,
  };
}

function refusalCode(message: TypedDataMessage): string {
  try {
    validateSigningRequest(message, POLICY, SELF, NOW);
  } catch (cause) {
    if (cause instanceof SignerRefusedError) return cause.code;
    throw cause;
  }
  return 'ACCEPTED';
}

describe('signer validation', () => {
  it('accepts a payment inside policy', () => {
    expect(refusalCode(payment())).toBe('ACCEPTED');
  });

  // The whole point of the split. A compromised daemon must not get a transaction signed.
  it('refuses anything that is not a transfer authorization', () => {
    expect(refusalCode(payment({
      primaryType: 'Permit',
      types: { Permit: [{ name: 'owner', type: 'address' }, { name: 'spender', type: 'address' }] },
    }))).toBe('not_a_payment');
  });

  it('refuses an unknown token contract', () => {
    expect(refusalCode(payment({
      domain: { name: 'Evil', version: '1', chainId: 8453,
                verifyingContract: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' },
    }))).toBe('unknown_token');
  });

  it('refuses an unknown chain', () => {
    expect(refusalCode(payment({
      domain: { name: 'USD Coin', version: '2', chainId: 1,
                verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' },
    }))).toBe('unknown_chain');
  });

  it('refuses paying from an address that is not ours', () => {
    const m = payment();
    expect(refusalCode({ ...m, message: { ...m.message, from: '0x000000000000000000000000000000000000bEEF' } }))
      .toBe('wrong_payer');
  });

  it('refuses a value over the signer ceiling', () => {
    const m = payment();
    expect(refusalCode({ ...m, message: { ...m.message, value: 5001n } })).toBe('exceeds_signer_ceiling');
  });

  it('refuses an already expired authorization', () => {
    const m = payment();
    expect(refusalCode({ ...m, message: { ...m.message, validBefore: 1n } })).toBe('bad_validity_window');
  });

  it('refuses a validity window beyond the horizon', () => {
    const m = payment();
    const tooFar = BigInt(Math.floor(NOW.getTime() / 1000) + 86_401 + 60);
    expect(refusalCode({ ...m, message: { ...m.message, validBefore: tooFar } })).toBe('bad_validity_window');
  });

  // A tampered types block changes what the signature commits to while the message looks normal.
  it('refuses a tampered types block', () => {
    expect(refusalCode(payment({
      types: { TransferWithAuthorization: [
        { name: 'from', type: 'address' }, { name: 'to', type: 'address' },
        { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' },
        { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'uint256' } ] },
    }))).toBe('unexpected_types');
  });

  it('refuses extra types smuggled alongside the real one', () => {
    expect(refusalCode(payment({
      types: { ...TYPES, Permit: [{ name: 'owner', type: 'address' }] },
    }))).toBe('unexpected_types');
  });

  it('refuses a non bigint value, which would hash differently', () => {
    const m = payment();
    expect(refusalCode({ ...m, message: { ...m.message, value: '1000' } })).toBe('malformed_message');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run test/signer-validate --reporter=basic`
Expected: FAIL, cannot resolve `../src/signer/validate.js`.

- [ ] **Step 3: Write the implementation**

Create `src/signer/validate.ts`:

```ts
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
    throw new SignerRefusedError('bad_validity_window', `valid for longer than the horizon allows`);
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run test/signer-validate --reporter=basic`
Expected: PASS, 11 tests.

- [ ] **Step 5: Commit**

```bash
git add src/signer/validate.ts test/signer-validate.test.ts
git commit -m "feat: signer refuses anything that is not an eip-3009 payment"
```

---

### Task 3: The signer process

**Files:**
- Create: `src/signer/server.ts`, `test/signer-server.test.ts`

**Interfaces:**
- Consumes: `encodeJson`, `decodeJson`, `SIGNER_PROTOCOL_VERSION` from Task 1; `validateSigningRequest`, `SignerPolicy`, `SignerRefusedError` from Task 2; `Wallet` from `src/wallet.ts`.
- Produces:
  - `interface SignerServer { readonly path: string; close(): Promise<void> }`
  - `function startSigner(socketPath: string, wallet: Wallet, policy: SignerPolicy, now?: () => Date): Promise<SignerServer>`
  - Wire ops: `{ v: 1, op: 'address' }` returns `{ v: 1, address }`; `{ v: 1, op: 'sign', payload }` returns `{ v: 1, signature }` or `{ v: 1, error: 'code: detail' }`.

- [ ] **Step 1: Write the failing test**

Create `test/signer-server.test.ts`:

```ts
import { createConnection } from 'node:net';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { startSigner } from '../src/signer/server.js';
import { decodeJson, encodeJson } from '../src/signer/protocol.js';
import { unlockWallet } from '../src/wallet.js';
import type { SignerPolicy } from '../src/signer/validate.js';
import type { TypedDataMessage } from '../src/wallet.js';

const KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const SELF = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const NOW = new Date('2026-08-12T00:00:00.000Z');
const VALID_BEFORE = BigInt(Math.floor(NOW.getTime() / 1000) + 3600);

const POLICY: SignerPolicy = {
  tokens: ['0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'],
  chainIds: [8453], maxValueAtomic: 5000n, maxValidityWindowSeconds: 86_400,
};

const PAYMENT: TypedDataMessage = {
  domain: { name: 'USD Coin', version: '2', chainId: 8453,
            verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' },
  types: { TransferWithAuthorization: [
    { name: 'from', type: 'address' }, { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' } ] },
  primaryType: 'TransferWithAuthorization',
  message: { from: SELF, to: '0x000000000000000000000000000000000000dEaD',
    value: 1000n, validAfter: 0n, validBefore: VALID_BEFORE,
    nonce: '0xf84e6d30534bfb2ec7380c923f5baea20e7bd3017a6c8e461c4354117112d9ad' },
};

function ask(path: string, request: unknown): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(path, () => socket.write(`${encodeJson(request)}\n`));
    let buffer = '';
    socket.on('data', (chunk) => {
      buffer += chunk.toString();
      if (buffer.includes('\n')) {
        socket.end();
        resolve(decodeJson(buffer.split('\n')[0]!) as Record<string, unknown>);
      }
    });
    socket.on('error', reject);
  });
}

describe('signer server', () => {
  let dir: string; let path: string; let close: () => Promise<void>;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'purser-signer-'));
    path = join(dir, 'signer.sock');
    const server = await startSigner(path, unlockWallet(KEY), POLICY, () => NOW);
    close = () => server.close();
  });

  afterEach(async () => { await close(); rmSync(dir, { recursive: true, force: true }); });

  it('reports its address', async () => {
    expect((await ask(path, { v: 1, op: 'address' }))['address']).toBe(SELF);
  });

  // The signature produced through the socket must be the one the key would have produced
  // directly. Anything else is an unspendable payment.
  it('signs a payment to the identical bytes as the local key', async () => {
    const direct = await privateKeyToAccount(KEY).signTypedData(PAYMENT as never);
    const reply = await ask(path, { v: 1, op: 'sign', payload: PAYMENT });
    expect(reply['signature']).toBe(direct);
  });

  it('refuses a transaction shaped payload', async () => {
    const reply = await ask(path, { v: 1, op: 'sign', payload: { ...PAYMENT,
      primaryType: 'Permit', types: { Permit: [{ name: 'owner', type: 'address' }] } } });
    expect(reply['signature']).toBeUndefined();
    expect(String(reply['error'])).toMatch(/not_a_payment/u);
  });

  it('refuses an unknown op rather than guessing', async () => {
    expect(String((await ask(path, { v: 1, op: 'sign_digest', digest: '0xdead' }))['error']))
      .toMatch(/unsupported_op/u);
  });

  it('rejects an unknown protocol version', async () => {
    expect(String((await ask(path, { v: 99, op: 'address' }))['error'])).toMatch(/version/u);
  });

  it('survives malformed input and keeps serving', async () => {
    expect(String((await ask(path, { nonsense: true }))['error'])).toMatch(/version/u);
    expect((await ask(path, { v: 1, op: 'address' }))['address']).toBe(SELF);
  });

  it('creates the socket 0660 so only the owner and its group can connect', () => {
    expect(statSync(path).mode & 0o777).toBe(0o660);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run test/signer-server --reporter=basic`
Expected: FAIL, cannot resolve `../src/signer/server.js`.

- [ ] **Step 3: Write the implementation**

Create `src/signer/server.ts`:

```ts
/**
 * The process that holds the key.
 *
 * It has exactly two operations and neither takes a digest. Everything it signs is structured typed
 * data it has validated itself, so there is no path from this socket to a signature over caller
 * chosen bytes. Deployed with PrivateNetwork=yes it has no route to the internet at all.
 */

import { createServer, type Server } from 'node:net';
import { chmodSync, rmSync } from 'node:fs';
import { decodeJson, encodeJson, SIGNER_PROTOCOL_VERSION } from './protocol.js';
import { SignerRefusedError, validateSigningRequest, type SignerPolicy } from './validate.js';
import type { TypedDataMessage, Wallet } from '../wallet.js';

export interface SignerServer {
  readonly path: string;
  close(): Promise<void>;
}

interface WireRequest {
  v?: number;
  op?: string;
  payload?: TypedDataMessage;
}

async function handle(
  line: string,
  wallet: Wallet,
  policy: SignerPolicy,
  now: () => Date,
): Promise<Record<string, unknown>> {
  let request: WireRequest;
  try {
    request = decodeJson(line) as WireRequest;
  } catch (cause) {
    return { error: `malformed_request: ${cause instanceof Error ? cause.message : String(cause)}` };
  }
  if (request.v !== SIGNER_PROTOCOL_VERSION) {
    return { error: `unsupported protocol version ${String(request.v)}` };
  }
  if (request.op === 'address') return { address: wallet.address };
  if (request.op !== 'sign') return { error: `unsupported_op: ${String(request.op)}` };
  if (request.payload === undefined) return { error: 'malformed_request: no payload' };

  try {
    validateSigningRequest(request.payload, policy, wallet.address, now());
    return { signature: await wallet.signTypedData(request.payload) };
  } catch (cause) {
    if (cause instanceof SignerRefusedError) return { error: cause.message };
    return { error: `signing_failed: ${cause instanceof Error ? cause.message : String(cause)}` };
  }
}

export function startSigner(
  socketPath: string,
  wallet: Wallet,
  policy: SignerPolicy,
  now: () => Date = () => new Date(),
): Promise<SignerServer> {
  rmSync(socketPath, { force: true });
  const server: Server = createServer((socket) => {
    let buffer = '';
    socket.on('data', (chunk) => {
      buffer += chunk.toString();
      let index = buffer.indexOf('\n');
      while (index !== -1) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);
        void handle(line, wallet, policy, now).then((result) =>
          socket.write(`${encodeJson({ v: SIGNER_PROTOCOL_VERSION, ...result })}\n`),
        );
        index = buffer.indexOf('\n');
      }
    });
    socket.on('error', () => socket.destroy());
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      // 0660 rather than 0600: the daemon runs as a different user in the same group.
      chmodSync(socketPath, 0o660);
      resolve({
        path: socketPath,
        close: () =>
          new Promise<void>((done) => {
            server.close(() => {
              rmSync(socketPath, { force: true });
              done();
            });
          }),
      });
    });
  });
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run test/signer-server --reporter=basic`
Expected: PASS, 7 tests.

- [ ] **Step 5: Commit**

```bash
git add src/signer/server.ts test/signer-server.test.ts
git commit -m "feat: signer process with two operations and no digest path"
```

---

### Task 4: The daemon side wallet

**Files:**
- Create: `src/socket-wallet.ts`, `test/socket-wallet.test.ts`

**Interfaces:**
- Consumes: `encodeJson`, `decodeJson`, `SIGNER_PROTOCOL_VERSION` from Task 1; `startSigner` from Task 3; `Wallet`, `WalletLockedError` from `src/wallet.ts`.
- Produces: `function connectSignerWallet(socketPath: string): Promise<Wallet>`

`Wallet.address` is a plain property, so the address is fetched once at connect time rather than on every call.

- [ ] **Step 1: Write the failing test**

Create `test/socket-wallet.test.ts`:

```ts
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { startSigner } from '../src/signer/server.js';
import { connectSignerWallet } from '../src/socket-wallet.js';
import { unlockWallet, WalletLockedError } from '../src/wallet.js';
import type { SignerPolicy } from '../src/signer/validate.js';
import type { TypedDataMessage } from '../src/wallet.js';

const KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const SELF = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const NOW = new Date('2026-08-12T00:00:00.000Z');
const VALID_BEFORE = BigInt(Math.floor(NOW.getTime() / 1000) + 3600);
const POLICY: SignerPolicy = {
  tokens: ['0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'],
  chainIds: [8453], maxValueAtomic: 5000n, maxValidityWindowSeconds: 86_400,
};
const PAYMENT: TypedDataMessage = {
  domain: { name: 'USD Coin', version: '2', chainId: 8453,
            verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' },
  types: { TransferWithAuthorization: [
    { name: 'from', type: 'address' }, { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' } ] },
  primaryType: 'TransferWithAuthorization',
  message: { from: SELF, to: '0x000000000000000000000000000000000000dEaD',
    value: 1000n, validAfter: 0n, validBefore: VALID_BEFORE,
    nonce: '0xf84e6d30534bfb2ec7380c923f5baea20e7bd3017a6c8e461c4354117112d9ad' },
};

describe('socket wallet', () => {
  let dir: string; let close: () => Promise<void>; let wallet: Awaited<ReturnType<typeof connectSignerWallet>>;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'purser-sw-'));
    const path = join(dir, 'signer.sock');
    const server = await startSigner(path, unlockWallet(KEY), POLICY, () => NOW);
    close = () => server.close();
    wallet = await connectSignerWallet(path);
  });

  afterEach(async () => { await close(); rmSync(dir, { recursive: true, force: true }); });

  it('adopts the signer address', () => {
    expect(wallet.address).toBe(SELF);
  });

  it('produces the same signature the local key would', async () => {
    const direct = await privateKeyToAccount(KEY).signTypedData(PAYMENT as never);
    expect(await wallet.signTypedData(PAYMENT)).toBe(direct);
  });

  it('surfaces a refusal as a thrown error rather than a bad signature', async () => {
    await expect(wallet.signTypedData({ ...PAYMENT,
      message: { ...PAYMENT.message, value: 999_999n } })).rejects.toThrow(/exceeds_signer_ceiling/u);
  });

  it('refuses locally once locked, without asking the signer', async () => {
    wallet.lock();
    expect(wallet.isUnlocked()).toBe(false);
    await expect(wallet.signTypedData(PAYMENT)).rejects.toThrow(WalletLockedError);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run test/socket-wallet --reporter=basic`
Expected: FAIL, cannot resolve `../src/socket-wallet.js`.

- [ ] **Step 3: Write the implementation**

Create `src/socket-wallet.ts`:

```ts
/**
 * A Wallet backed by the signer process rather than by a key in this process.
 *
 * Drop in replacement for unlockWallet inside the daemon. lock() is local only: it stops this
 * process asking for signatures, and does not lock the signer, because a compromised daemon should
 * not be able to disable the signer for everyone. Revoking for real means stopping the signer.
 */

import { createConnection } from 'node:net';
import { decodeJson, encodeJson, SIGNER_PROTOCOL_VERSION } from './signer/protocol.js';
import { WalletLockedError, type TypedDataMessage, type Wallet } from './wallet.js';

function ask(socketPath: string, request: unknown): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(socketPath, () => socket.write(`${encodeJson(request)}\n`));
    let buffer = '';
    socket.on('data', (chunk) => {
      buffer += chunk.toString();
      const index = buffer.indexOf('\n');
      if (index === -1) return;
      socket.end();
      try {
        resolve(decodeJson(buffer.slice(0, index)) as Record<string, unknown>);
      } catch (cause) {
        reject(cause instanceof Error ? cause : new Error(String(cause)));
      }
    });
    socket.on('error', reject);
  });
}

export async function connectSignerWallet(socketPath: string): Promise<Wallet> {
  const hello = await ask(socketPath, { v: SIGNER_PROTOCOL_VERSION, op: 'address' });
  const address = hello['address'];
  if (typeof address !== 'string' || !/^0x[0-9a-fA-F]{40}$/u.test(address)) {
    throw new Error(`signer at ${socketPath} did not report a usable address`);
  }

  let unlocked = true;
  return {
    address: address as `0x${string}`,
    async signTypedData(message: TypedDataMessage): Promise<`0x${string}`> {
      if (!unlocked) throw new WalletLockedError();
      const reply = await ask(socketPath, { v: SIGNER_PROTOCOL_VERSION, op: 'sign', payload: message });
      const signature = reply['signature'];
      if (typeof signature !== 'string') {
        throw new Error(String(reply['error'] ?? 'signer returned no signature'));
      }
      return signature as `0x${string}`;
    },
    lock(): void {
      unlocked = false;
    },
    isUnlocked(): boolean {
      return unlocked;
    },
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run test/socket-wallet --reporter=basic`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add src/socket-wallet.ts test/socket-wallet.test.ts
git commit -m "feat: daemon side wallet backed by the signer socket"
```

---

### Task 5: The binary and the hardening

**Files:**
- Create: `src/signer/cli.ts`, `deploy/purser-signer.service`, `deploy/README.md`
- Modify: `package.json` (add `purser-signer` to `bin`)

**Interfaces:**
- Consumes: `startSigner` from Task 3, `unlockWallet` from `src/wallet.ts`, `SignerPolicy` from Task 2.
- Produces: a `purser-signer` binary. No new exported functions.

- [ ] **Step 1: Write the implementation**

Create `src/signer/cli.ts`:

```ts
#!/usr/bin/env node
/**
 * The purser-signer binary.
 *
 * Reads the wallet key from stdin, exactly as the daemon used to, then never lets it out again.
 * The policy here is a backstop rather than the primary control, so the flags are deliberately
 * coarse: one ceiling, one token list, one chain list.
 */

import { parseArgs } from 'node:util';
import { createInterface } from 'node:readline';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { startSigner } from './server.js';
import { unlockWallet } from '../wallet.js';
import type { SignerPolicy } from './validate.js';

function fail(message: string): never {
  process.stderr.write(`purser-signer: ${message}\n`);
  process.exit(1);
}

async function readSecret(prompt: string): Promise<string> {
  process.stderr.write(prompt);
  const rl = createInterface({ input: process.stdin });
  try {
    for await (const line of rl) return line.trim();
  } finally {
    rl.close();
    process.stderr.write('\n');
  }
  return fail('no key on stdin');
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    args: process.argv.slice(2),
    options: {
      socket: { type: 'string' },
      tokens: { type: 'string' },
      chains: { type: 'string' },
      'max-value': { type: 'string' },
      'max-validity': { type: 'string' },
    },
  });

  const tokens = values.tokens;
  const chains = values.chains;
  const maxValue = values['max-value'];
  if (typeof tokens !== 'string' || typeof chains !== 'string' || typeof maxValue !== 'string') {
    fail('usage: purser-signer --tokens 0x..,0x.. --chains 8453 --max-value N [--socket PATH] [--max-validity SECONDS]');
  }

  const policy: SignerPolicy = {
    tokens: tokens.split(',').map((t) => t.trim().toLowerCase()),
    chainIds: chains.split(',').map((c) => Number(c.trim())),
    maxValueAtomic: BigInt(maxValue),
    maxValidityWindowSeconds: Number(values['max-validity'] ?? 86_400),
  };
  if (policy.chainIds.some((id) => !Number.isInteger(id))) fail('--chains must be integers');

  const wallet = unlockWallet(await readSecret('wallet private key (input hidden): '));
  const socketPath = values.socket ?? join(homedir(), '.purser', 'signer.sock');
  const server = await startSigner(socketPath, wallet, policy);

  process.stdout.write(`purser-signer listening on ${server.path}\nwallet ${wallet.address}\n`);
  process.stdout.write(`ceiling ${policy.maxValueAtomic} on chains ${policy.chainIds.join(',')}\n`);

  const shutdown = (): void => {
    wallet.lock();
    void server.close().then(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((cause: unknown) => fail(cause instanceof Error ? cause.message : String(cause)));
```

- [ ] **Step 2: Add the binary to package.json**

```bash
node -e "const f='package.json',d=require('./'+f);d.bin['purser-signer']='./dist/signer/cli.js';require('fs').writeFileSync(f,JSON.stringify(d,null,2)+'\n')"
```

- [ ] **Step 3: Write the systemd unit**

Create `deploy/purser-signer.service`:

```ini
[Unit]
Description=Purser signer, holds the wallet key and signs only EIP-3009 payments
Before=purser.service

[Service]
Type=simple
User=purser-signer
Group=purser
UMask=0007
ExecStart=/usr/local/bin/purser-signer --socket /run/purser/signer.sock --tokens 0x833589fcd6edb6e08f4c7c32d4f71b54bda02913 --chains 8453 --max-value 5000000
StandardInput=file:/run/credentials/purser-signer/key
RuntimeDirectory=purser
RuntimeDirectoryMode=0770

# The reason this split is worth doing. No network namespace means a compromised signer
# cannot post the key anywhere; it can only answer on the socket.
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
IPAddressDeny=any

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectProc=invisible
MemoryDenyWriteExecute=yes
LockPersonality=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
```

Create `deploy/README.md`:

```markdown
# Deploying the split

Two users, so the daemon cannot read the signer's memory.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin purser-signer
sudo useradd --system --no-create-home --shell /usr/sbin/nologin purser
sudo usermod -aG purser purser-signer      # the daemon's group owns the socket
sudo install -m 0755 deploy/purser-signer.service /etc/systemd/system/
sudo systemctl daemon-reload
```

The key reaches the signer through systemd credentials rather than a flag or an environment
variable. Put it in an encrypted credential:

```bash
sudo systemd-ask-password | sudo systemd-creds encrypt --name=key - /etc/purser/key.cred
```

Then reference it from the unit with `LoadCredentialEncrypted=key:/etc/purser/key.cred` and point
`StandardInput=` at the resulting credential path.

Verify the hardening actually applied:

```bash
systemd-analyze security purser-signer.service
```

Anything above 4.0 means a directive is not taking effect. The unit as shipped should score in the
low ones.

## Checking the isolation is real

```bash
sudo -u purser cat /proc/$(pidof purser-signer)/mem   # must fail
sudo -u purser nsenter -t $(pidof purser-signer) -n ip addr   # must show no usable interfaces
```
```

- [ ] **Step 4: Verify the binary runs**

Run:
```bash
pnpm build
echo '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d' | \
  timeout 5 node dist/signer/cli.js --socket /tmp/sig-check.sock \
  --tokens 0x833589fcd6edb6e08f4c7c32d4f71b54bda02913 --chains 8453 --max-value 5000
```
Expected: prints `purser-signer listening on /tmp/sig-check.sock` and `wallet 0x70997970C51812dc3A010C7d01b50e0d17dc79C8`, then exits on the timeout.

- [ ] **Step 5: Commit**

```bash
git add src/signer/cli.ts deploy/ package.json
git commit -m "feat: purser-signer binary and hardened systemd unit"
```

---

### Task 6: Wire the daemon to the signer, end to end

**Files:**
- Modify: `src/cli.ts` (add `--signer-socket` to `cmdRun`), `src/index.ts` (exports), `README.md`
- Create: `test/split-e2e.test.ts`

**Interfaces:**
- Consumes: `connectSignerWallet` from Task 4, `startSigner` from Task 3.
- Produces: no new API. `purser run --signer-socket PATH` skips the stdin prompt entirely.

- [ ] **Step 1: Write the failing test**

Create `test/split-e2e.test.ts`:

```ts
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { startSigner } from '../src/signer/server.js';
import { connectSignerWallet } from '../src/socket-wallet.js';
import { pay } from '../src/pay.js';
import { openRepository } from '../src/storage.js';
import { AgentStore } from '../src/store.js';
import { AgentLedger } from '../src/ledger.js';
import { AllowanceStore } from '../src/allowance.js';
import { IntentStore } from '../src/intent.js';
import { signClaim } from '../src/credential.js';
import { unlockWallet } from '../src/wallet.js';
import type { SignerPolicy } from '../src/signer/validate.js';
import type { Envelope } from '../src/envelope.js';

const KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const ENVELOPE: Envelope = {
  spendCapAtomic: '5000', periodSeconds: 3600, maxPerTxAtomic: '2000',
  allowedHosts: ['api.example.com'], allowedCurrencies: ['USDC'], expiresAt: null,
};
const POLICY: SignerPolicy = {
  tokens: ['0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'],
  chainIds: [8453], maxValueAtomic: 5000n, maxValidityWindowSeconds: 86_400,
};

function requiredHeader(amount: string) {
  return Buffer.from(JSON.stringify({
    x402Version: 2, resource: { url: 'https://api.example.com/thing' },
    accepts: [{ scheme: 'exact', network: 'eip155:8453',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', amount,
      payTo: '0x000000000000000000000000000000000000dEaD', maxTimeoutSeconds: 3600,
      extra: { credentialTypes: ['authorization'], name: 'USD Coin', version: '2' } }],
  })).toString('base64');
}

describe('daemon paying through the signer process', () => {
  it('pays with the key in the other process, and the ledger records it', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'purser-split-'));
    const server = await startSigner(join(dir, 'signer.sock'), unlockWallet(KEY), POLICY);
    const wallet = await connectSignerWallet(server.path);

    const repo = openRepository(':memory:');
    const clock = new Date();
    repo.rawDatabase().prepare(`INSERT INTO principals (id, label, created_at) VALUES (1, 'p', '2026-01-01T00:00:00Z')`).run();
    const allowances = new AllowanceStore(repo, () => clock);
    allowances.set(1, { allowanceAtomic: '5000', periodSeconds: 3600, currency: 'USDC' });
    const store = new AgentStore(repo, allowances, () => clock);
    const issued = store.create(1, 'agent', ENVELOPE);
    const ledger = new AgentLedger(repo, () => clock);

    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(new Response('pay', { status: 402, headers: { 'PAYMENT-REQUIRED': requiredHeader('1000') } }))
      .mockResolvedValueOnce(new Response('goods', { status: 200 }));

    const claim = { agentRef: issued.agent.agentRef, resourceUrl: 'https://api.example.com/thing',
      ceilingAtomic: '2000', currency: 'USDC', nonce: 'split-1', timestamp: clock.toISOString() };

    const result = await pay(
      { store, ledger, allowances, intents: new IntentStore(repo, () => clock),
        now: () => clock, wallet, currencyForAsset: () => 'USDC' } as never,
      { claim, signature: signClaim(claim, issued.privateKeyPem), intentId: null },
      fetchImpl as never,
    );

    expect(result.status).toBe('paid');
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(1000n);

    repo.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  });
});
```

- [ ] **Step 2: Run test to verify it fails or passes**

Run: `pnpm vitest run test/split-e2e --reporter=basic`
Expected: PASS if Tasks 1 to 4 are complete. This test is a regression guard on the seam rather than a driver for new code, so a pass here is the correct outcome and a failure means an earlier task is wrong.

- [ ] **Step 3: Add the daemon flag**

In `src/cli.ts`, in `cmdRun`, replace the unconditional key prompt so a signer socket is used when given:

```ts
  const { values } = parseArgs({ args: argv, options: {
    socket: { type: 'string' }, db: { type: 'string' }, 'signer-socket': { type: 'string' } } });
  const socketPath = values.socket ?? join(homedir(), '.purser', 'purser.sock');
  const databasePath = values.db ?? defaultDatabase();

  // With a signer socket the key never enters this process at all.
  const signerSocket = values['signer-socket'];
  const wallet = signerSocket === undefined
    ? unlockWallet(await readSecret('wallet private key (input hidden): '))
    : await connectSignerWallet(signerSocket);
```

Add the import at the top of `src/cli.ts`:

```ts
import { connectSignerWallet } from './socket-wallet.js';
```

And extend the usage text in `src/cli.ts`:

```
  run [--socket PATH] [--signer-socket PATH]
      Start the daemon. With --signer-socket the key never enters this process.
      Without it, the wallet key is read from stdin.
```

- [ ] **Step 4: Export the new surface**

Append to `src/index.ts`:

```ts
export { connectSignerWallet } from './socket-wallet.js';
export { startSigner } from './signer/server.js';
export type { SignerServer } from './signer/server.js';
export { SignerRefusedError, validateSigningRequest } from './signer/validate.js';
export type { SignerPolicy } from './signer/validate.js';
export { SIGNER_PROTOCOL_VERSION, decodeJson, encodeJson } from './signer/protocol.js';
```

- [ ] **Step 5: Rewrite the README security section**

In `README.md`, replace the `**Key custody.**` paragraph under `## Security model` with:

```markdown
**Key custody.** In the recommended deployment the wallet key is not in the Purser daemon at all.
It lives in a separate `purser-signer` process, running as a different user with no network
namespace, which will only ever sign an EIP-3009 transfer authorization. Purser sends structured
typed data over a socket and gets a signature back; it cannot ask for a signature over an arbitrary
hash, so a compromised daemon cannot have a wallet draining transaction signed. This is stronger
than a cloud KMS, which signs whatever digest it is given and can only restrict who calls it.

Running `purser run` without `--signer-socket` keeps the key in the daemon, read from stdin. That
is fine for development and is the weaker configuration. In either case the key is never accepted
as a flag or an environment variable: flags land in shell history and `ps` output, and environment
variables are inherited by every child process.

See [deploy/README.md](deploy/README.md) for the two user setup and the hardened unit.
```

Also add to the "It does not claim" list in `README.md`:

```markdown
- **The signer still holds the key in memory.** It is a far smaller and better contained process
  than the daemon, with no network access, but it is not a hardware boundary. A YubiHSM 2 supports
  secp256k1 and fits the same seam when that matters. TPM 2.0 and YubiKey PIV do not; both are
  NIST curve devices and cannot sign secp256k1.
```

- [ ] **Step 6: Run the full suite and the typecheck**

Run: `pnpm vitest run --reporter=basic && pnpm typecheck && pnpm build && pnpm smoke`
Expected: 152 tests passing (126 carried plus 26 added), typecheck clean, build clean, smoke passes.

- [ ] **Step 7: Check the standing rules, then commit**

```bash
grep -rlP '\x{2014}' src test docs deploy README.md && echo 'EM-DASHES FOUND, fix before committing' || echo 'no em-dashes'
git add -A
git commit -m "feat: run the daemon with the key in a separate process

purser run --signer-socket takes the key out of the daemon entirely. The daemon
sends structured typed data and receives a signature; it has no way to ask for a
signature over an arbitrary hash, so compromising the component that parses seller
responses no longer puts the wallet at risk."
```

---

## Coverage map

| Spec requirement | Task |
| --- | --- |
| Signer never accepts a raw digest | 2, 3 |
| primaryType, token, chain, from, value, validity, types checks | 2 |
| Ceiling duplicated as a backstop, set at startup, unreachable over the socket | 2, 5 |
| Wire protocol, newline delimited JSON, bigint safe | 1 |
| Socket 0660, separate users | 3, 5 |
| `socketWallet` drop in for `unlockWallet` | 4 |
| systemd hardening with PrivateNetwork=yes | 5 |
| Daemon uses the signer end to end | 6 |
| README states the stronger claim and the remaining limit | 6 |

## Self-review notes

Four things fixed while writing:

1. The captured payload proved `value`, `validAfter` and `validBefore` are bigint. A plain
   `JSON.stringify` wire format would have thrown at runtime, and a naive string encoding would
   have silently signed a different payload. Task 1 exists because of that capture, and its
   byte-identical test is the gate.
2. `Wallet.address` is a property rather than a method, so `connectSignerWallet` has to be async
   and fetch the address once at connect time. An `address` op was added to the protocol for this.
3. `lock()` on the socket wallet is local only. Forwarding it would let a compromised daemon
   disable signing for every other consumer, which turns a containment feature into a denial of
   service handle.
4. The signer's socket is `0660`, not `0600` like the daemon's. Two different users have to share
   it, so the daemon's group needs access. `RuntimeDirectoryMode=0770` and `UMask=0007` in the unit
   exist for the same reason.
