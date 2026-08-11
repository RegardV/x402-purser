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
