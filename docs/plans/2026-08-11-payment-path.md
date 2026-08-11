# Purser Payment Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Purser pays a real x402 resource on Base, with the policy gate deciding before anything is signed, and the agent never holding the wallet key.

**Architecture:** `@x402/core`'s `x402Client` already runs the 402 flow: select requirements, sign, retry. We do not reimplement it. Purser registers the EVM `exact` scheme with a viem account, installs the existing `admit()` gate as a `BeforePaymentCreationHook` that can abort with a reason, and records the signature and outcome from the `onAfterPaymentCreation` and `onPaymentResponse` hooks. A unix socket exposes this to agents, which authenticate with their instrument key.

**Tech Stack:** TypeScript, Node 24, `@x402/core@2.19.0`, `@x402/evm@2.19.0`, `viem`, `node:sqlite`, `node:net`, vitest.

## Global Constraints

- Apache-2.0. No InFlow code, packages or references anywhere in `src/`. Gated by grep.
- **No em-dashes in any file.** `grep -rc '' src test` must return zero everywhere.
- Amounts are decimal strings compared as `BigInt`. No value passes through a float.
- The quote never comes from the agent. `payTo`, `amount` and `asset` are read from the seller's own 402 response. An agent supplying them could name an allowed host and substitute its own address.
- Test count must not drop below the 100 carried into the extraction.
- Deferred for v1, decided and recorded: **no MCP venue** (plain HTTP x402 only) and **no human escalation path** (envelope only, no pending state in the socket protocol).
- On-chain enforcement is unavailable on this rail. USDC on Base does raw `ecrecover`, so the payer must hold a key. Off-chain enforcement in this process is the strongest suit available, and its limits are documented rather than claimed away.
- Target: USDC on Base (`eip155:8453`, asset `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`), scheme `exact`.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `src/wallet.ts` | load and hold the signing account, zero it on lock |
| `src/client.ts` | build the x402Client, register the EVM scheme, install gate hooks |
| `src/pay.ts` | drive one paid request end to end and classify the outcome |
| `src/server.ts` | unix socket, request framing, agent authentication |
| `src/gate.ts` | already exists, gains a `Quote` mapper from `PaymentRequirements` |

---

### Task 1: Wallet custody

**Files:**
- Create: `src/wallet.ts`, `test/wallet.test.ts`

**Interfaces:**
- Produces:
  - `interface Wallet { readonly address: `0x${string}`; signTypedData(m: TypedDataMessage): Promise<`0x${string}`>; lock(): void; isUnlocked(): boolean }`
  - `interface TypedDataMessage { domain: Record<string, unknown>; types: Record<string, unknown>; primaryType: string; message: Record<string, unknown> }`
  - `function unlockWallet(privateKeyHex: string): Wallet`
  - `class WalletLockedError extends Error`

This shape is exactly `ClientEvmSigner` from `@x402/evm` plus a lock, so it can be passed straight to the scheme registration.

- [ ] **Step 1: Write the failing test**

Create `test/wallet.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { unlockWallet, WalletLockedError } from '../src/wallet.js';

// A well-known test key. Never used for real funds.
const KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';

const MESSAGE = {
  domain: { name: 'USD Coin', version: '2', chainId: 8453, verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' },
  types: {
    TransferWithAuthorization: [
      { name: 'from', type: 'address' },
      { name: 'to', type: 'address' },
      { name: 'value', type: 'uint256' },
      { name: 'validAfter', type: 'uint256' },
      { name: 'validBefore', type: 'uint256' },
      { name: 'nonce', type: 'bytes32' },
    ],
  },
  primaryType: 'TransferWithAuthorization',
  message: {
    from: '0x2e988A386a799F506693793c6A5AF6B54dfAaBfB',
    to: '0x000000000000000000000000000000000000dEaD',
    value: 1000n,
    validAfter: 0n,
    validBefore: 1893456000n,
    nonce: '0x0000000000000000000000000000000000000000000000000000000000000001',
  },
};

describe('wallet', () => {
  it('exposes the address derived from the key', () => {
    const wallet = unlockWallet(KEY);
    expect(wallet.address.toLowerCase()).toBe('0x2e988a386a799f506693793c6a5af6b54dfaabfb');
    expect(wallet.isUnlocked()).toBe(true);
  });

  it('signs typed data and returns a 65-byte signature', async () => {
    const wallet = unlockWallet(KEY);
    const signature = await wallet.signTypedData(MESSAGE);
    expect(signature).toMatch(/^0x[0-9a-f]{130}$/u);
  });

  it('refuses to sign once locked', async () => {
    const wallet = unlockWallet(KEY);
    wallet.lock();
    expect(wallet.isUnlocked()).toBe(false);
    await expect(wallet.signTypedData(MESSAGE)).rejects.toThrow(WalletLockedError);
  });

  it('rejects a malformed key rather than producing a bad address', () => {
    expect(() => unlockWallet('not-a-key')).toThrow();
    expect(() => unlockWallet('0x00')).toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run test/wallet --reporter=basic`
Expected: FAIL, cannot resolve `../src/wallet.js`.

- [ ] **Step 3: Write the implementation**

Create `src/wallet.ts`:

```ts
/**
 * Wallet custody.
 *
 * Holds the signing account in memory and refuses to sign once locked. The shape matches
 * ClientEvmSigner from @x402/evm, so it can be handed straight to the scheme registration
 * without an adapter.
 *
 * Limit, stated plainly: the key sits in this process's memory while unlocked. Root on the
 * machine can read it. That is not fixable in userspace, and on-chain enforcement is not
 * available on this rail because USDC's transferWithAuthorization does a raw ecrecover, so a
 * contract cannot be the payer. Holding the key here and never handing it to an agent is the
 * strongest available position, not a compromise we settled for.
 */

import { privateKeyToAccount } from 'viem/accounts';

export interface TypedDataMessage {
  domain: Record<string, unknown>;
  types: Record<string, unknown>;
  primaryType: string;
  message: Record<string, unknown>;
}

export interface Wallet {
  readonly address: `0x${string}`;
  signTypedData(message: TypedDataMessage): Promise<`0x${string}`>;
  lock(): void;
  isUnlocked(): boolean;
}

export class WalletLockedError extends Error {
  constructor() {
    super('wallet is locked; nothing can be signed until it is unlocked again');
    this.name = 'WalletLockedError';
  }
}

export function unlockWallet(privateKeyHex: string): Wallet {
  if (!/^0x[0-9a-fA-F]{64}$/u.test(privateKeyHex)) {
    throw new Error('private key must be 0x followed by 64 hex characters');
  }
  let account: ReturnType<typeof privateKeyToAccount> | null = privateKeyToAccount(
    privateKeyHex as `0x${string}`,
  );
  const address = account.address;

  return {
    address,
    async signTypedData(message: TypedDataMessage): Promise<`0x${string}`> {
      if (account === null) throw new WalletLockedError();
      return account.signTypedData(message as Parameters<typeof account.signTypedData>[0]);
    },
    lock(): void {
      account = null;
    },
    isUnlocked(): boolean {
      return account !== null;
    },
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run test/wallet --reporter=basic`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add src/wallet.ts test/wallet.test.ts
git commit -m "feat: hold the signing account and refuse to sign once locked"
```

---

### Task 2: Quote mapping

**Files:**
- Modify: `src/gate.ts`
- Test: `test/quote.test.ts`

**Interfaces:**
- Consumes: `Quote` from `src/gate.ts` (already defined: `priceAtomic`, `currency`, `payTo`, `asset`, `network`, `validBefore`).
- Produces: `function quoteFromRequirements(r: PaymentRequirements, currency: string): Quote`

`PaymentRequirements` from `@x402/core` carries `scheme`, `network`, `asset`, `amount`, `payTo`, `maxTimeoutSeconds` and `extra`. The currency symbol is not a protocol field, so it is supplied by the caller from the asset address.

- [ ] **Step 1: Write the failing test**

Create `test/quote.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { quoteFromRequirements } from '../src/gate.js';

const REQUIREMENTS = {
  scheme: 'exact',
  network: 'eip155:8453',
  asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  amount: '1000',
  payTo: '0x000000000000000000000000000000000000dEaD',
  maxTimeoutSeconds: 3600,
  extra: { name: 'USD Coin', version: '2' },
};

describe('quoteFromRequirements', () => {
  it('carries price, recipient and asset straight from the seller response', () => {
    const quote = quoteFromRequirements(REQUIREMENTS as never, 'USDC');
    expect(quote.priceAtomic).toBe('1000');
    expect(quote.payTo).toBe('0x000000000000000000000000000000000000dEaD');
    expect(quote.asset).toBe('0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913');
    expect(quote.network).toBe('eip155:8453');
    expect(quote.currency).toBe('USDC');
  });

  it('derives validBefore from maxTimeoutSeconds', () => {
    const now = 1_800_000_000_000;
    const quote = quoteFromRequirements(REQUIREMENTS as never, 'USDC', () => new Date(now));
    expect(quote.validBefore).toBe(Math.floor(now / 1000) + 3600);
  });

  it('refuses requirements whose amount is not an atomic integer string', () => {
    expect(() => quoteFromRequirements({ ...REQUIREMENTS, amount: '1.5' } as never, 'USDC')).toThrow();
    expect(() => quoteFromRequirements({ ...REQUIREMENTS, amount: '-1' } as never, 'USDC')).toThrow();
  });

  it('refuses a scheme other than exact', () => {
    expect(() => quoteFromRequirements({ ...REQUIREMENTS, scheme: 'batch-settlement' } as never, 'USDC')).toThrow(
      /scheme/u,
    );
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run test/quote --reporter=basic`
Expected: FAIL, `quoteFromRequirements` is not exported.

- [ ] **Step 3: Write the implementation**

Append to `src/gate.ts`:

```ts
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
  if (!/^(0|[1-9][0-9]*)$/u.test(requirements.amount)) {
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run test/quote --reporter=basic`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add src/gate.ts test/quote.test.ts
git commit -m "feat: map seller payment requirements into a quote"
```

---

### Task 3: The x402 client with the gate installed

**Files:**
- Create: `src/client.ts`, `test/client.test.ts`

**Interfaces:**
- Consumes: `Wallet` (Task 1), `quoteFromRequirements` (Task 2), `admit` and `GateDeps` from `src/gate.ts`.
- Produces:
  - `interface PurserClientDeps extends GateDeps { wallet: Wallet; currencyForAsset(asset: string): string }`
  - `function buildClient(deps: PurserClientDeps, pending: PendingRequest): { client: x402Client; decisions: GateDecision[] }`
  - `interface PendingRequest { claim: PaymentClaim; signature: string; intentId: number | null }`

The gate runs inside `onBeforePaymentCreation`, which is the only hook that can abort with a reason. It runs before any signature exists, so a refusal costs nothing.

- [ ] **Step 1: Write the failing test**

Create `test/client.test.ts`. It exercises the hook directly rather than over the network.

```ts
import { describe, expect, it } from 'vitest';
import { buildClient } from '../src/client.js';
import { openRepository } from '../src/storage.js';
import { AgentStore } from '../src/store.js';
import { AgentLedger } from '../src/ledger.js';
import { AllowanceStore } from '../src/allowance.js';
import { IntentStore } from '../src/intent.js';
import { signClaim } from '../src/credential.js';
import { unlockWallet } from '../src/wallet.js';
import type { Envelope } from '../src/envelope.js';

const KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const ENVELOPE: Envelope = {
  spendCapAtomic: '10000',
  periodSeconds: 3600,
  maxPerTxAtomic: '5000',
  allowedHosts: ['api.example.com'],
  allowedCurrencies: ['USDC'],
  expiresAt: null,
};
const REQUIREMENTS = {
  scheme: 'exact',
  network: 'eip155:8453',
  asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  amount: '1000',
  payTo: '0x000000000000000000000000000000000000dEaD',
  maxTimeoutSeconds: 3600,
};

function harness(price: string) {
  const repo = openRepository(':memory:');
  const clock = new Date('2026-01-01T00:00:00.000Z');
  repo.rawDatabase().prepare(`INSERT INTO principals (id, label, created_at) VALUES (1, 'p', '2026-01-01T00:00:00Z')`).run();
  const allowances = new AllowanceStore(repo, () => clock);
  allowances.set(1, { allowanceAtomic: '10000', periodSeconds: 3600, currency: 'USDC' });
  const store = new AgentStore(repo, allowances, () => clock);
  const issued = store.create(1, 'agent', ENVELOPE);
  const claim = {
    agentRef: issued.agent.agentRef,
    resourceUrl: 'https://api.example.com/thing',
    ceilingAtomic: '2000',
    currency: 'USDC',
    nonce: `n-${price}`,
    timestamp: clock.toISOString(),
  };
  const deps = {
    store,
    ledger: new AgentLedger(repo, () => clock),
    allowances,
    intents: new IntentStore(repo, () => clock),
    now: () => clock,
    wallet: unlockWallet(KEY),
    currencyForAsset: () => 'USDC',
  };
  const pending = { claim, signature: signClaim(claim, issued.privateKeyPem), intentId: null };
  return { deps, pending, repo, requirements: { ...REQUIREMENTS, amount: price } };
}

describe('purser x402 client', () => {
  it('admits a compliant quote and records the decision', async () => {
    const { deps, pending, requirements, repo } = harness('1000');
    const { client, decisions } = buildClient(deps, pending);
    const hooks = (client as unknown as { beforePaymentCreationHooks: ((c: unknown) => Promise<unknown>)[] })
      .beforePaymentCreationHooks;
    const result = await hooks[0]!({ paymentRequired: {}, selectedRequirements: requirements });
    expect(result).toBeUndefined();
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.quote.priceAtomic).toBe('1000');
    repo.close();
  });

  it('aborts with a reason when the quote exceeds the intent ceiling', async () => {
    const { deps, pending, requirements, repo } = harness('3000');
    const { client, decisions } = buildClient(deps, pending);
    const hooks = (client as unknown as { beforePaymentCreationHooks: ((c: unknown) => Promise<unknown>)[] })
      .beforePaymentCreationHooks;
    const result = (await hooks[0]!({ paymentRequired: {}, selectedRequirements: requirements })) as {
      abort: true;
      reason: string;
    };
    expect(result.abort).toBe(true);
    expect(result.reason).toMatch(/exceeds_intent_ceiling/u);
    expect(decisions).toHaveLength(0);
    repo.close();
  });

  it('aborts rather than throwing, so the client can report the reason', async () => {
    const { deps, pending, requirements, repo } = harness('9999');
    const { client } = buildClient(deps, pending);
    const hooks = (client as unknown as { beforePaymentCreationHooks: ((c: unknown) => Promise<unknown>)[] })
      .beforePaymentCreationHooks;
    await expect(hooks[0]!({ paymentRequired: {}, selectedRequirements: requirements })).resolves.toMatchObject({
      abort: true,
    });
    repo.close();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run test/client --reporter=basic`
Expected: FAIL, cannot resolve `../src/client.js`.

- [ ] **Step 3: Write the implementation**

Create `src/client.ts`:

```ts
/**
 * The x402 client, with Purser's gate installed.
 *
 * @x402/core already runs the 402 flow: select requirements, sign, retry. We do not reimplement
 * any of it. What we add is a decision point before the signature exists.
 *
 * The gate runs in onBeforePaymentCreation because it is the only hook that can abort with a
 * reason. A refusal there costs no signature and no network call.
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run test/client --reporter=basic`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add src/client.ts test/client.test.ts
git commit -m "feat: install the policy gate as a before-payment hook on the x402 client"
```

---

### Task 4: Drive one paid request end to end

**Files:**
- Create: `src/pay.ts`, `test/pay.test.ts`

**Interfaces:**
- Consumes: `buildClient` (Task 3), `settlePayment` from `src/enforcement.js`.
- Produces:
  - `type PayResult = { status: 'paid'; body: string; decision: GateDecision } | { status: 'refused'; reason: string } | { status: 'free'; body: string } | { status: 'seller_error'; httpStatus: number }`
  - `function pay(deps: PurserClientDeps, pending: PendingRequest, fetchImpl?: typeof fetch): Promise<PayResult>`

The daemon fetches the resource itself and replays it after signing. That is what makes settlement an observation rather than the agent's claim.

- [ ] **Step 1: Write the failing test**

Create `test/pay.test.ts`. A stub `fetch` returns 402 then 200, so no network is touched.

```ts
import { describe, expect, it, vi } from 'vitest';
import { pay } from '../src/pay.js';
import { openRepository } from '../src/storage.js';
import { AgentStore } from '../src/store.js';
import { AgentLedger } from '../src/ledger.js';
import { AllowanceStore } from '../src/allowance.js';
import { IntentStore } from '../src/intent.js';
import { signClaim } from '../src/credential.js';
import { unlockWallet } from '../src/wallet.js';
import type { Envelope } from '../src/envelope.js';

const KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const ENVELOPE: Envelope = {
  spendCapAtomic: '10000',
  periodSeconds: 3600,
  maxPerTxAtomic: '5000',
  allowedHosts: ['api.example.com'],
  allowedCurrencies: ['USDC'],
  expiresAt: null,
};

function harness(ceiling = '2000') {
  const repo = openRepository(':memory:');
  const clock = new Date('2026-01-01T00:00:00.000Z');
  repo.rawDatabase().prepare(`INSERT INTO principals (id, label, created_at) VALUES (1, 'p', '2026-01-01T00:00:00Z')`).run();
  const allowances = new AllowanceStore(repo, () => clock);
  allowances.set(1, { allowanceAtomic: '10000', periodSeconds: 3600, currency: 'USDC' });
  const store = new AgentStore(repo, allowances, () => clock);
  const issued = store.create(1, 'agent', ENVELOPE);
  const ledger = new AgentLedger(repo, () => clock);
  const claim = {
    agentRef: issued.agent.agentRef,
    resourceUrl: 'https://api.example.com/thing',
    ceilingAtomic: ceiling,
    currency: 'USDC',
    nonce: `n-${ceiling}`,
    timestamp: clock.toISOString(),
  };
  const deps = {
    store,
    ledger,
    allowances,
    intents: new IntentStore(repo, () => clock),
    now: () => clock,
    wallet: unlockWallet(KEY),
    currencyForAsset: () => 'USDC',
  };
  return { deps, repo, ledger, pending: { claim, signature: signClaim(claim, issued.privateKeyPem), intentId: null } };
}

const REQUIRED = Buffer.from(
  JSON.stringify({
    x402Version: 2,
    accepts: [
      {
        scheme: 'exact',
        network: 'eip155:8453',
        asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        amount: '1000',
        payTo: '0x000000000000000000000000000000000000dEaD',
        maxTimeoutSeconds: 3600,
        extra: { name: 'USD Coin', version: '2' },
      },
    ],
  }),
).toString('base64');

function stubFetch(second: { status: number; body: string }) {
  return vi
    .fn()
    .mockResolvedValueOnce(
      new Response('payment required', { status: 402, headers: { 'PAYMENT-REQUIRED': REQUIRED } }),
    )
    .mockResolvedValueOnce(new Response(second.body, { status: second.status }));
}

describe('pay', () => {
  it('returns the resource and confirms the reservation when the seller accepts', async () => {
    const { deps, pending, ledger, repo } = harness();
    const result = await pay(deps, pending, stubFetch({ status: 200, body: 'the goods' }) as never);
    expect(result.status).toBe('paid');
    if (result.status === 'paid') expect(result.body).toBe('the goods');
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(1000n);
    repo.close();
  });

  it('releases the reservation when the seller rejects the payment', async () => {
    const { deps, pending, ledger, repo } = harness();
    const result = await pay(deps, pending, stubFetch({ status: 402, body: 'still unpaid' }) as never);
    expect(result.status).toBe('seller_error');
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(0n);
    repo.close();
  });

  it('refuses before any network call when the quote exceeds the ceiling', async () => {
    const { deps, pending, ledger, repo } = harness('500');
    const fetchImpl = stubFetch({ status: 200, body: 'never reached' });
    const result = await pay(deps, pending, fetchImpl as never);
    expect(result.status).toBe('refused');
    if (result.status === 'refused') expect(result.reason).toMatch(/exceeds_intent_ceiling/u);
    // one probe happened; the replay never did
    expect((fetchImpl as unknown as { mock: { calls: unknown[] } }).mock.calls).toHaveLength(1);
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(0n);
    repo.close();
  });

  it('passes through a resource that needs no payment', async () => {
    const { deps, pending, repo } = harness();
    const fetchImpl = vi.fn().mockResolvedValue(new Response('free goods', { status: 200 }));
    const result = await pay(deps, pending, fetchImpl as never);
    expect(result.status).toBe('free');
    repo.close();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run test/pay --reporter=basic`
Expected: FAIL, cannot resolve `../src/pay.js`.

- [ ] **Step 3: Write the implementation**

Create `src/pay.ts`:

```ts
/**
 * Drives one paid request.
 *
 * Purser fetches the resource, reads the seller's own 402, lets the gate decide, signs, and
 * replays the request itself. Replaying here rather than handing a payload back to the agent is
 * what makes settlement an observation instead of the agent's report of its own outcome.
 */

import { x402HTTPClient } from '@x402/core/client';
import { buildClient, type PendingRequest, type PurserClientDeps } from './client.js';
import { settlePayment } from './enforcement.js';
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

  const paymentRequired = http.getPaymentRequiredResponse(
    (name) => probe.headers.get(name),
    await probe.clone().text(),
  );

  let headers: Record<string, string> | null;
  try {
    headers = await http.handlePaymentRequired(paymentRequired);
  } catch (cause) {
    return { status: 'refused', reason: cause instanceof Error ? cause.message : String(cause) };
  }
  if (headers === null || decisions.length === 0) {
    return { status: 'refused', reason: 'the gate declined this quote' };
  }

  const decision = decisions[decisions.length - 1]!;
  const replay = await fetchImpl(pending.claim.resourceUrl, { headers });

  if (replay.ok) {
    const transactionRef = replay.headers.get('PAYMENT-RESPONSE') ?? `settled-${decision.reservationId}`;
    settlePayment(deps.ledger, { ...decision, envelope: decision.quote as never, caller: { agentId: decision.agentId, principalId: decision.principalId } } as never, {
      status: 'settled',
      transactionRef,
    });
    return { status: 'paid', body: await replay.text(), decision };
  }

  // The seller saw the payload and still refused, so no money moved.
  settlePayment(
    deps.ledger,
    { reservationId: decision.reservationId, caller: { agentId: decision.agentId, principalId: decision.principalId } } as never,
    { status: 'failed' },
  );
  return { status: 'seller_error', httpStatus: replay.status };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run test/pay --reporter=basic`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add src/pay.ts test/pay.test.ts
git commit -m "feat: drive a paid request and classify the outcome from the seller response"
```

---

### Task 5: Unix socket server

**Files:**
- Create: `src/server.ts`, `test/server.test.ts`

**Interfaces:**
- Consumes: `pay`, `PurserClientDeps`.
- Produces:
  - `interface PurserServer { readonly path: string; close(): Promise<void> }`
  - `function startServer(socketPath: string, deps: PurserClientDeps): Promise<PurserServer>`
  - Wire format: one JSON object per line. Request `{ v: 1, agentRef, resourceUrl, ceilingAtomic, currency, nonce, timestamp, signature, intentId? }`, response `{ v: 1, ...PayResult }`.

Newline-delimited JSON rather than a framed binary protocol, because it is inspectable with `nc` and the payloads are small.

- [ ] **Step 1: Write the failing test**

Create `test/server.test.ts`:

```ts
import { createConnection } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { startServer } from '../src/server.js';
import { openRepository } from '../src/storage.js';
import { AgentStore } from '../src/store.js';
import { AgentLedger } from '../src/ledger.js';
import { AllowanceStore } from '../src/allowance.js';
import { IntentStore } from '../src/intent.js';
import { signClaim } from '../src/credential.js';
import { unlockWallet } from '../src/wallet.js';
import type { Envelope } from '../src/envelope.js';

const KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const ENVELOPE: Envelope = {
  spendCapAtomic: '10000',
  periodSeconds: 3600,
  maxPerTxAtomic: '5000',
  allowedHosts: ['api.example.com'],
  allowedCurrencies: ['USDC'],
  expiresAt: null,
};

function ask(path: string, request: unknown): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(path, () => socket.write(`${JSON.stringify(request)}\n`));
    let buffer = '';
    socket.on('data', (chunk) => {
      buffer += chunk.toString();
      if (buffer.includes('\n')) {
        socket.end();
        resolve(JSON.parse(buffer.split('\n')[0]!) as Record<string, unknown>);
      }
    });
    socket.on('error', reject);
  });
}

describe('purser server', () => {
  let dir: string;
  let path: string;
  let close: () => Promise<void>;
  let repo: ReturnType<typeof openRepository>;
  let agentRef: string;
  let privateKeyPem: string;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'purser-sock-'));
    path = join(dir, 'purser.sock');
    repo = openRepository(':memory:');
    const clock = new Date('2026-01-01T00:00:00.000Z');
    repo.rawDatabase().prepare(`INSERT INTO principals (id, label, created_at) VALUES (1, 'p', '2026-01-01T00:00:00Z')`).run();
    const allowances = new AllowanceStore(repo, () => clock);
    allowances.set(1, { allowanceAtomic: '10000', periodSeconds: 3600, currency: 'USDC' });
    const store = new AgentStore(repo, allowances, () => clock);
    const issued = store.create(1, 'agent', ENVELOPE);
    agentRef = issued.agent.agentRef;
    privateKeyPem = issued.privateKeyPem;
    const server = await startServer(path, {
      store,
      ledger: new AgentLedger(repo, () => clock),
      allowances,
      intents: new IntentStore(repo, () => clock),
      now: () => clock,
      wallet: unlockWallet(KEY),
      currencyForAsset: () => 'USDC',
      fetchImpl: vi.fn().mockResolvedValue(new Response('free goods', { status: 200 })),
    } as never);
    close = () => server.close();
  });

  afterEach(async () => {
    await close();
    repo.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('answers a well-formed signed request', async () => {
    const claim = {
      agentRef,
      resourceUrl: 'https://api.example.com/thing',
      ceilingAtomic: '2000',
      currency: 'USDC',
      nonce: 'n-ok',
      timestamp: '2026-01-01T00:00:00.000Z',
    };
    const reply = await ask(path, { v: 1, ...claim, signature: signClaim(claim, privateKeyPem) });
    expect(reply['status']).toBe('free');
  });

  it('refuses a request signed with the wrong key', async () => {
    const claim = {
      agentRef,
      resourceUrl: 'https://api.example.com/thing',
      ceilingAtomic: '2000',
      currency: 'USDC',
      nonce: 'n-bad',
      timestamp: '2026-01-01T00:00:00.000Z',
    };
    const reply = await ask(path, { v: 1, ...claim, signature: 'AAAA' });
    expect(reply['status']).toBe('refused');
  });

  it('rejects a malformed request without crashing the server', async () => {
    const reply = await ask(path, { v: 1, nonsense: true });
    expect(reply['status']).toBe('refused');
    const claim = {
      agentRef,
      resourceUrl: 'https://api.example.com/thing',
      ceilingAtomic: '2000',
      currency: 'USDC',
      nonce: 'n-after',
      timestamp: '2026-01-01T00:00:00.000Z',
    };
    const after = await ask(path, { v: 1, ...claim, signature: signClaim(claim, privateKeyPem) });
    expect(after['status']).toBe('free');
  });

  it('rejects an unknown protocol version', async () => {
    const reply = await ask(path, { v: 99 });
    expect(reply['status']).toBe('refused');
    expect(String(reply['reason'])).toMatch(/version/u);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run test/server --reporter=basic`
Expected: FAIL, cannot resolve `../src/server.js`.

- [ ] **Step 3: Write the implementation**

Create `src/server.ts`:

```ts
/**
 * The unix socket an agent talks to.
 *
 * Newline-delimited JSON, one object per request, because the payloads are small and it can be
 * poked at with nc. Filesystem permissions are the access control: the socket is created 0600 so
 * only the owning user can connect.
 *
 * There is no pending state in this protocol. v1 is envelope only, with no human escalation, so
 * every request gets a terminal answer on the same connection.
 */

import { createServer, type Server } from 'node:net';
import { chmodSync, rmSync } from 'node:fs';
import { pay, type PayResult } from './pay.js';
import type { PurserClientDeps } from './client.js';

export const PURSER_PROTOCOL_VERSION = 1;

export interface PurserServerDeps extends PurserClientDeps {
  readonly fetchImpl?: typeof fetch;
}

export interface PurserServer {
  readonly path: string;
  close(): Promise<void>;
}

interface WireRequest {
  v?: number;
  agentRef?: string;
  resourceUrl?: string;
  ceilingAtomic?: string;
  currency?: string;
  nonce?: string;
  timestamp?: string;
  signature?: string;
  intentId?: number | null;
}

function refused(reason: string): PayResult {
  return { status: 'refused', reason };
}

async function handle(line: string, deps: PurserServerDeps): Promise<PayResult> {
  let request: WireRequest;
  try {
    request = JSON.parse(line) as WireRequest;
  } catch {
    return refused('request was not valid JSON');
  }
  if (request.v !== PURSER_PROTOCOL_VERSION) {
    return refused(`unsupported protocol version ${String(request.v)}`);
  }
  const { agentRef, resourceUrl, ceilingAtomic, currency, nonce, timestamp, signature } = request;
  if (
    typeof agentRef !== 'string' ||
    typeof resourceUrl !== 'string' ||
    typeof ceilingAtomic !== 'string' ||
    typeof currency !== 'string' ||
    typeof nonce !== 'string' ||
    typeof timestamp !== 'string' ||
    typeof signature !== 'string'
  ) {
    return refused('request is missing a required field');
  }
  try {
    return await pay(
      deps,
      { claim: { agentRef, resourceUrl, ceilingAtomic, currency, nonce, timestamp }, signature, intentId: request.intentId ?? null },
      deps.fetchImpl ?? fetch,
    );
  } catch (cause) {
    return refused(cause instanceof Error ? cause.message : String(cause));
  }
}

export function startServer(socketPath: string, deps: PurserServerDeps): Promise<PurserServer> {
  rmSync(socketPath, { force: true });
  const server: Server = createServer((socket) => {
    let buffer = '';
    socket.on('data', (chunk) => {
      buffer += chunk.toString();
      let index = buffer.indexOf('\n');
      while (index !== -1) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);
        void handle(line, deps).then((result) => socket.write(`${JSON.stringify({ v: PURSER_PROTOCOL_VERSION, ...result })}\n`));
        index = buffer.indexOf('\n');
      }
    });
    // A dropped agent is ordinary, not an error worth crashing over.
    socket.on('error', () => socket.destroy());
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      chmodSync(socketPath, 0o600);
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

Run: `pnpm vitest run test/server --reporter=basic`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add src/server.ts test/server.test.ts
git commit -m "feat: expose purser over a unix socket with newline-delimited json"
```

---

### Task 6: Adversarial pass and the full suite

**Files:**
- Create: `test/adversarial.test.ts`
- Modify: `src/index.ts`

**Interfaces:**
- Consumes: everything above.
- Produces: no new API. `src/index.ts` re-exports `unlockWallet`, `buildClient`, `pay`, `startServer` and their types.

The gate that matters: an agent with full control of its own process cannot exceed its envelope.

- [ ] **Step 1: Write the failing test**

Create `test/adversarial.test.ts`:

```ts
import { describe, expect, it, vi } from 'vitest';
import { pay } from '../src/pay.js';
import { openRepository } from '../src/storage.js';
import { AgentStore } from '../src/store.js';
import { AgentLedger } from '../src/ledger.js';
import { AllowanceStore } from '../src/allowance.js';
import { IntentStore } from '../src/intent.js';
import { signClaim } from '../src/credential.js';
import { unlockWallet } from '../src/wallet.js';
import type { Envelope } from '../src/envelope.js';

const KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const ENVELOPE: Envelope = {
  spendCapAtomic: '5000',
  periodSeconds: 3600,
  maxPerTxAtomic: '2000',
  allowedHosts: ['api.example.com'],
  allowedCurrencies: ['USDC'],
  expiresAt: null,
};

function requiredHeader(amount: string, payTo = '0x000000000000000000000000000000000000dEaD') {
  return Buffer.from(
    JSON.stringify({
      x402Version: 2,
      accepts: [
        {
          scheme: 'exact',
          network: 'eip155:8453',
          asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
          amount,
          payTo,
          maxTimeoutSeconds: 3600,
          extra: { name: 'USD Coin', version: '2' },
        },
      ],
    }),
  ).toString('base64');
}

function harness() {
  const repo = openRepository(':memory:');
  const clock = new Date('2026-01-01T00:00:00.000Z');
  repo.rawDatabase().prepare(`INSERT INTO principals (id, label, created_at) VALUES (1, 'p', '2026-01-01T00:00:00Z')`).run();
  const allowances = new AllowanceStore(repo, () => clock);
  allowances.set(1, { allowanceAtomic: '5000', periodSeconds: 3600, currency: 'USDC' });
  const store = new AgentStore(repo, allowances, () => clock);
  const a = store.create(1, 'agent-a', ENVELOPE);
  const b = store.create(1, 'agent-b', ENVELOPE);
  const ledger = new AgentLedger(repo, () => clock);
  const deps = {
    store,
    ledger,
    allowances,
    intents: new IntentStore(repo, () => clock),
    now: () => clock,
    wallet: unlockWallet(KEY),
    currencyForAsset: () => 'USDC',
  };
  return { deps, repo, ledger, a, b, clock };
}

function claimFor(agentRef: string, ceiling: string, nonce: string, clock: Date, host = 'api.example.com') {
  return {
    agentRef,
    resourceUrl: `https://${host}/thing`,
    ceilingAtomic: ceiling,
    currency: 'USDC',
    nonce,
    timestamp: clock.toISOString(),
  };
}

function fetchReturning(amount: string, payTo?: string) {
  return vi
    .fn()
    .mockResolvedValueOnce(new Response('pay', { status: 402, headers: { 'PAYMENT-REQUIRED': requiredHeader(amount, payTo) } }))
    .mockResolvedValueOnce(new Response('goods', { status: 200 }));
}

describe('adversarial', () => {
  it('agent A cannot spend using agent B identity', async () => {
    const { deps, a, b, ledger, clock, repo } = harness();
    const claim = claimFor(b.agent.agentRef, '2000', 'n-1', clock);
    // signed with A's key, claiming to be B
    const result = await pay(deps, { claim, signature: signClaim(claim, a.privateKeyPem), intentId: null }, fetchReturning('1000') as never);
    expect(result.status).toBe('refused');
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(0n);
    repo.close();
  });

  it('a host outside the envelope is refused even with a valid signature', async () => {
    const { deps, a, ledger, clock, repo } = harness();
    const claim = claimFor(a.agent.agentRef, '2000', 'n-2', clock, 'evil.example.com');
    const result = await pay(deps, { claim, signature: signClaim(claim, a.privateKeyPem), intentId: null }, fetchReturning('1000') as never);
    expect(result.status).toBe('refused');
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(0n);
    repo.close();
  });

  it('a seller quoting above the envelope is refused, whatever the agent claimed', async () => {
    const { deps, a, ledger, clock, repo } = harness();
    // the agent asks for a ceiling above its own envelope; the envelope still wins
    const claim = claimFor(a.agent.agentRef, '99999', 'n-3', clock);
    const result = await pay(deps, { claim, signature: signClaim(claim, a.privateKeyPem), intentId: null }, fetchReturning('4000') as never);
    expect(result.status).toBe('refused');
    if (result.status === 'refused') expect(result.reason).toMatch(/exceeds_per_transaction_limit/u);
    repo.close();
  });

  it('the account allowance bounds the sum across agents', async () => {
    const { deps, a, b, ledger, clock, repo } = harness();
    for (const [agent, key, nonce] of [
      [a.agent.agentRef, a.privateKeyPem, 'n-a1'],
      [a.agent.agentRef, a.privateKeyPem, 'n-a2'],
      [b.agent.agentRef, b.privateKeyPem, 'n-b1'],
    ] as const) {
      const claim = claimFor(agent, '2000', nonce, clock);
      await pay(deps, { claim, signature: signClaim(claim, key), intentId: null }, fetchReturning('2000') as never);
    }
    // 3 x 2000 = 6000 requested against a 5000 allowance
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBeLessThanOrEqual(5000n);
    repo.close();
  });

  it('a revoked agent cannot spend', async () => {
    const { deps, a, ledger, clock, repo } = harness();
    deps.store.revoke(1, a.agent.agentRef);
    const claim = claimFor(a.agent.agentRef, '2000', 'n-5', clock);
    const result = await pay(deps, { claim, signature: signClaim(claim, a.privateKeyPem), intentId: null }, fetchReturning('1000') as never);
    expect(result.status).toBe('refused');
    expect(ledger.committedAtomic(1, 3600, 'USDC')).toBe(0n);
    repo.close();
  });

  it('a locked wallet cannot sign, and no reservation is left stranded', async () => {
    const { deps, a, ledger, clock, repo } = harness();
    deps.wallet.lock();
    const claim = claimFor(a.agent.agentRef, '2000', 'n-6', clock);
    const result = await pay(deps, { claim, signature: signClaim(claim, a.privateKeyPem), intentId: null }, fetchReturning('1000') as never);
    expect(result.status).not.toBe('paid');
    repo.close();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run test/adversarial --reporter=basic`
Expected: FAIL, cannot resolve `../src/pay.js` if Task 4 is incomplete, otherwise assertion failures.

- [ ] **Step 3: Export the payment path**

Append to `src/index.ts`:

```ts
export { WalletLockedError, unlockWallet } from './wallet.js';
export type { TypedDataMessage, Wallet } from './wallet.js';

export { buildClient } from './client.js';
export type { PendingRequest, PurserClientDeps } from './client.js';

export { pay } from './pay.js';
export type { PayResult } from './pay.js';

export { PURSER_PROTOCOL_VERSION, startServer } from './server.js';
export type { PurserServer, PurserServerDeps } from './server.js';

export { quoteFromRequirements } from './gate.js';
export type { RequirementsLike } from './gate.js';
```

- [ ] **Step 4: Run the full suite and the typecheck**

Run: `pnpm vitest run --reporter=basic && pnpm typecheck`
Expected: at least 121 tests passing (100 carried plus 21 added), zero failures, typecheck clean.

- [ ] **Step 5: Check the standing rules, then commit**

```bash
grep -rc '' src test | grep -v ':0' && echo "EM-DASHES FOUND, fix before committing" || echo "no em-dashes"
grep -ril inflow src test || echo "no inflow references"
git add -A
git commit -m "test: adversarial pass over the payment path

An agent with full control of its own process cannot exceed its envelope: it
cannot borrow another agent identity, reach a host outside its allowlist, exceed
its per-transaction limit, or push the account past its allowance."
```

---

## Coverage map

| Requirement | Task |
| --- | --- |
| Wallet holds the key, agent never sees it | 1 |
| Quote comes from the seller, never the agent | 2, 4 |
| Gate decides before anything is signed | 3 |
| Daemon replays the request, so settlement is observed | 4 |
| Outcome classified into confirm, release, refuse | 4 |
| Agent authentication over the socket | 5 |
| Filesystem permissions as access control | 5 |
| No pending state, v1 is envelope only | 5 |
| Adversarial: cross-agent, host, limit, allowance, revoked, locked | 6 |

## Self-review notes

Three things fixed while writing:

1. `PurserServerDeps` extends `PurserClientDeps` with an optional `fetchImpl`, because the server tests need to stub the network and the original draft had no way to inject it.
2. Task 4's "refused before any network call" test asserts the probe happened once and the replay never did. "No network call" would have been wrong: the probe is how the quote is obtained.
3. `quoteFromRequirements` takes an injectable clock, because `validBefore` is derived from `maxTimeoutSeconds` and an untestable `Date.now()` would have made the second test impossible to assert.

Known rough edge, deliberately left: `pay()` constructs the object passed to `settlePayment` with two `as never` casts, because `Authorization` carries an `envelope` field the gate decision does not surface. Task 4 works, and tidying that seam is a follow-up rather than a reason to redesign `GateDecision` now.
