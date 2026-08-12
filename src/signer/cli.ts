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
