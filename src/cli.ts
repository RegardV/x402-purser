#!/usr/bin/env node
/**
 * The operator's surface. Everything an agent cannot be trusted to do itself lives here.
 *
 * Key custody rule: the wallet key is read from stdin and never from a flag or an environment
 * variable. Flags land in shell history and process listings, environment variables are inherited
 * by every child process including the agents this daemon exists to constrain. Pipe it from a
 * password manager, or paste it at the prompt.
 */

import { parseArgs } from 'node:util';
import { createInterface } from 'node:readline';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { openRepository, ensurePrincipal } from './storage.js';
import { AllowanceStore } from './allowance.js';
import { AgentStore } from './store.js';
import { AgentLedger } from './ledger.js';
import { IntentStore } from './intent.js';
import { unlockWallet } from './wallet.js';
import { startServer } from './server.js';
import { connectSignerWallet } from './socket-wallet.js';
import { currencyForAsset } from './currency.js';
import type { Envelope } from './envelope.js';

const PRINCIPAL_LABEL = 'owner';

function defaultDatabase(): string {
  return process.env['PURSER_DB'] ?? join(homedir(), '.purser', 'purser.db');
}

function fail(message: string): never {
  process.stderr.write(`purser: ${message}\n`);
  process.exit(1);
}

function required(values: Record<string, unknown>, name: string): string {
  const value = values[name];
  if (typeof value !== 'string') fail(`--${name} is required`);
  return value;
}

/** Reads one line without echoing it. No output stream is passed, so readline does not echo. */
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

function openStores(databasePath: string) {
  const repo = openRepository(databasePath);
  const now = () => new Date();
  const allowances = new AllowanceStore(repo, now);
  return { repo, now, allowances, store: new AgentStore(repo, allowances, now) };
}

async function cmdInit(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      allowance: { type: 'string' },
      period: { type: 'string' },
      currency: { type: 'string' },
      db: { type: 'string' },
    },
  });
  const databasePath = values.db ?? defaultDatabase();
  const { repo, allowances } = openStores(databasePath);
  const principalId = ensurePrincipal(repo, PRINCIPAL_LABEL);
  allowances.set(principalId, {
    allowanceAtomic: required(values, 'allowance'),
    periodSeconds: Number(required(values, 'period')),
    currency: required(values, 'currency'),
  });
  repo.close();
  process.stdout.write(`initialised ${databasePath}\nprincipal ${principalId} allowance set\n`);
}

async function cmdAgentAdd(argv: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      cap: { type: 'string' },
      'per-tx': { type: 'string' },
      hosts: { type: 'string' },
      currencies: { type: 'string' },
      period: { type: 'string' },
      expires: { type: 'string' },
      db: { type: 'string' },
    },
  });
  const label = positionals[0];
  if (label === undefined) fail('usage: purser agent add <label> --cap N --per-tx N --period S --hosts a,b --currencies USDC');

  const envelope: Envelope = {
    spendCapAtomic: required(values, 'cap'),
    periodSeconds: Number(required(values, 'period')),
    maxPerTxAtomic: required(values, 'per-tx'),
    allowedHosts: required(values, 'hosts').split(',').map((h) => h.trim().toLowerCase()),
    allowedCurrencies: required(values, 'currencies').split(',').map((c) => c.trim()),
    expiresAt: values.expires ?? null,
  };

  const { repo, store } = openStores(values.db ?? defaultDatabase());
  const principalId = ensurePrincipal(repo, PRINCIPAL_LABEL);
  const issued = store.create(principalId, label, envelope);
  repo.close();

  // Printed once and never stored in recoverable form. Losing it means issuing a new agent.
  process.stdout.write(`agent_ref: ${issued.agent.agentRef}\n`);
  process.stdout.write(`private_key (shown once, give this to the agent):\n${issued.privateKeyPem}\n`);
}

async function cmdAgentList(argv: string[]): Promise<void> {
  const { values } = parseArgs({ args: argv, options: { db: { type: 'string' }, all: { type: 'boolean' } } });
  const { repo, store } = openStores(values.db ?? defaultDatabase());
  const principalId = ensurePrincipal(repo, PRINCIPAL_LABEL);
  const agents = store.list(principalId, values.all === true);
  repo.close();
  if (agents.length === 0) {
    process.stdout.write('no agents\n');
    return;
  }
  for (const agent of agents) process.stdout.write(`${JSON.stringify(agent)}\n`);
}

async function cmdAgentRevoke(argv: string[]): Promise<void> {
  const { values, positionals } = parseArgs({ args: argv, allowPositionals: true, options: { db: { type: 'string' } } });
  const agentRef = positionals[0];
  if (agentRef === undefined) fail('usage: purser agent revoke <agent_ref>');
  const { repo, store } = openStores(values.db ?? defaultDatabase());
  const principalId = ensurePrincipal(repo, PRINCIPAL_LABEL);
  store.revoke(principalId, agentRef);
  repo.close();
  process.stdout.write(`revoked ${agentRef}\n`);
}

async function cmdRun(argv: string[]): Promise<void> {
  const { values } = parseArgs({ args: argv, options: {
    socket: { type: 'string' }, db: { type: 'string' }, 'signer-socket': { type: 'string' } } });
  const socketPath = values.socket ?? join(homedir(), '.purser', 'purser.sock');
  const databasePath = values.db ?? defaultDatabase();

  // With a signer socket the key never enters this process at all.
  const signerSocket = values['signer-socket'];
  const wallet =
    signerSocket === undefined
      ? unlockWallet(await readSecret('wallet private key (input hidden): '))
      : await connectSignerWallet(signerSocket);

  const repo = openRepository(databasePath);
  const now = () => new Date();
  const allowances = new AllowanceStore(repo, now);
  const server = await startServer(socketPath, {
    store: new AgentStore(repo, allowances, now),
    ledger: new AgentLedger(repo, now),
    allowances,
    intents: new IntentStore(repo, now),
    now,
    wallet,
    currencyForAsset: (asset: string) => currencyForAsset(asset),
  });

  process.stdout.write(`purser listening on ${server.path}\nwallet ${wallet.address}\n`);

  const shutdown = () => {
    wallet.lock();
    void server.close().then(() => {
      repo.close();
      process.exit(0);
    });
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

const USAGE = `purser <command>

  init --allowance N --period SECONDS --currency USDC
      Create the account and set the pooled allowance every agent shares.

  agent add <label> --cap N --per-tx N --period SECONDS --hosts a,b --currencies USDC [--expires ISO]
      Issue an agent. Prints its private key once.

  agent list [--all]
  agent revoke <agent_ref>

  run [--socket PATH] [--signer-socket PATH]
      Start the daemon. With --signer-socket the key never enters this process.
      Without it, the wallet key is read from stdin, never from a flag.

Amounts are atomic units. --db or PURSER_DB overrides the database path.
`;

async function main(): Promise<void> {
  const [command, sub, ...rest] = process.argv.slice(2);
  switch (command) {
    case 'init':
      return cmdInit(process.argv.slice(3));
    case 'agent':
      if (sub === 'add') return cmdAgentAdd(rest);
      if (sub === 'list') return cmdAgentList(rest);
      if (sub === 'revoke') return cmdAgentRevoke(rest);
      return fail(`unknown agent subcommand ${String(sub)}`);
    case 'run':
      return cmdRun(process.argv.slice(3));
    default:
      process.stdout.write(USAGE);
      if (command !== undefined && command !== 'help') process.exit(1);
  }
}

main().catch((cause: unknown) => fail(cause instanceof Error ? cause.message : String(cause)));
